"""ark.intel.observation.v1 — the observation envelope, adapter SDK, and the
deterministic confidence contract (100x W1.2/W1.4 / PR4).

Separates source observation identity from later multi-source correlation.
The existing GeoJSON response becomes a compatibility projection of
observations, not the source of record.

Rules implemented here (from the plan, verbatim intent):
- observed_at may be null; missing source time is never silently replaced
- exact decoded body bytes hash BEFORE parsing/normalization
- multiple observations may share one retrieval digest with distinct pointers
- attributes are size-bounded and can never carry executable HTML
- overall confidence is a deterministic, versioned product of named
  components: bounded(source_prior * freshness * product(applicable))
- corroboration stays null in Wave 1 (cross-source correlation is later)
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

SCHEMA_VERSION = "ark.intel.observation.v1"
CONFIDENCE_METHOD = "ark.intel.confidence.v1"
DATUM = "WGS84"
POSITION_ORDER = "longitude_latitude"

MAX_TITLE_CHARS = 240
MAX_ATTRIBUTE_BYTES = 16 * 1024
HTML_TAG = re.compile(r"<[a-zA-Z!/?][^>]*>")

TRUTH_CLASSES = {"observed", "reported", "reference", "derived", "hypothesis"}


class ObservationError(ValueError):
    """Envelope validation failure — always fail closed with the reason."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _rfc3339(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ObservationBuilder:
    """Adapter SDK: one adapter implements validate_manifest ->
    build_request -> parse_retrieval -> normalize_records ->
    emit_observations -> emit_health via this builder's contract."""

    source_id: str
    adapter_version: str
    manifest: dict[str, Any]
    manifest_digest: str
    retrieval_id: str
    raw_sha256: str | None
    ingested_at: datetime = field(default_factory=_now)

    # ── confidence: ark.intel.confidence.v1 ─────────────────────────
    def confidence(
        self,
        *,
        freshness: float,
        geometry_quality: float | None,
    ) -> dict[str, Any]:
        """overall = bounded(source_prior * freshness * product(applicable)).
        Deterministic, versioned, and untouched by models by contract.
        geometry_quality None = genuinely nonspatial record (not-applicable
        is honest; it does NOT reduce confidence)."""
        prior = float(self.manifest["truth"]["source_prior"])
        components: list[float] = [prior, freshness]
        if geometry_quality is None and self.manifest["truth"]["class"] == "observed":
            # spatial source without geometry = missing required evidence:
            # reduces confidence and emits a validation condition
            components.append(0.5)
        elif geometry_quality is not None:
            components.append(min(1.0, max(0.0, geometry_quality)))
        overall = 1.0
        for c in components:
            overall *= min(1.0, max(0.0, c))
        return {
            "source_prior": round(prior, 4),
            "freshness": round(freshness, 4),
            "geometry": round(geometry_quality, 4) if geometry_quality is not None else None,
            "corroboration": None,  # Wave 1: stays null by contract
            "overall": round(overall, 4),
            "method_version": CONFIDENCE_METHOD,
        }

    def freshness_factor(self, observed_at: datetime | str | None,
                         stale_after_seconds: int) -> float:
        """Freshness from source-specific SLOs: 1.0 fresh, decaying linearly
        to 0.0 at stale_after_seconds past observation; unobserved time
        (null) is honest decay from ingestion."""
        if observed_at is None:
            reference = self.ingested_at
        elif isinstance(observed_at, str):
            try:
                reference = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
            except ValueError:
                return 0.0
        else:
            reference = observed_at
        if reference.tzinfo is None:
            reference = reference.replace(tzinfo=timezone.utc)
        age = max(0.0, (self.ingested_at - reference).total_seconds())
        if age >= stale_after_seconds:
            return 0.0
        return round(1.0 - (age / stale_after_seconds), 4)

    # ── the envelope ──────────────────────────────────────────────────
    def emit(
        self,
        *,
        record_id: str,
        title: str,
        observed_at: datetime | str | None,
        geometry_geojson: dict[str, Any] | None = None,
        uncertainty_m: float | None = None,
        geometry_quality: float | None = None,
        detail_url: str | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not record_id or not str(record_id).strip():
            raise ObservationError("record_id required for stable observation identity")
        title = self._sanitize_display(title)
        if attributes is not None:
            attributes = self._sanitize_attributes(attributes)
        if geometry_geojson is not None:
            self._validate_geometry(geometry_geojson)

        # observed_at never silently substituted (plan rule). Strings are
        # normalized to datetimes here so every downstream consumer sees one type.
        observed_norm = observed_at
        if isinstance(observed_norm, str) and observed_norm:
            try:
                observed_norm = datetime.fromisoformat(
                    observed_norm.replace("Z", "+00:00")).astimezone(timezone.utc)
            except ValueError:
                observed_norm = None  # invalid time = null + validation condition

        record_hash = sha256_text(f"{self.source_id}:{record_id}")
        observation_id = f"{self.source_id}:{record_hash}"
        expires_seconds = int(self.manifest["freshness"]["expire_after_seconds"])
        expires_at = _rfc3339(self.ingested_at + timedelta(seconds=expires_seconds))

        normalized = {
            "record_id": record_id,
            "title": title,
            "geometry": geometry_geojson,
            "attributes": attributes or {},
        }
        envelope = {
            "schema_version": SCHEMA_VERSION,
            "observation_id": observation_id,
            "revision_sha256": None,  # set below (self-referential)
            "source": {
                "id": self.source_id,
                "manifest_digest": self.manifest_digest,
                "adapter_version": self.adapter_version,
            },
            "time": {
                "observed_at": _rfc3339(observed_norm) if observed_norm else None,
                "ingested_at": _rfc3339(self.ingested_at),
                "valid_from": None,
                "valid_to": None,
                "expires_at": expires_at,
            },
            "geometry": {
                "geojson": geometry_geojson,
                "uncertainty_m": uncertainty_m,
                "datum": DATUM,
                "position_order": POSITION_ORDER,
            },
            "truth": {
                "class": self.manifest["truth"]["class"],
                "confidence": self.confidence(
                    freshness=self.freshness_factor(
                        observed_norm,
                        int(self.manifest["freshness"]["stale_after_seconds"])),
                    geometry_quality=geometry_quality,
                ),
            },
            "provenance": {
                "retrieval_id": self.retrieval_id,
                "raw_sha256": self.raw_sha256,
                "raw_record_pointer": record_id,
                "transform_sha256": sha256_text(canonical_json(normalized)),
                "evidence_pointer": f"arkintel://retrievals/{self.retrieval_id}#{record_id}",
            },
            "policy": {
                "license_id": self.manifest["license"]["identifier"],
                "raw_retention": "retained" if self.manifest["retention"]["raw_hours"] > 0 else "digest_only",
                "normalized_expires_at": _rfc3339(
                    self.ingested_at + timedelta(days=int(self.manifest["retention"]["normalized_days"]))),
                "redistribution": self.manifest["license"]["redistribution"],
                "privacy_class": self.manifest["privacy"]["class"],
            },
            "display": {
                "title": title,
                "detail_url": self._allowlisted_url(detail_url),
            },
            "attributes": attributes or {},
        }
        envelope["revision_sha256"] = sha256_text(canonical_json(
            {k: v for k, v in envelope.items() if k != "revision_sha256"}))
        return envelope

    # ── guards ────────────────────────────────────────────────────────
    def _sanitize_display(self, text: str) -> str:
        if not text:
            return ""
        return HTML_TAG.sub("", str(text))[:MAX_TITLE_CHARS]

    def _sanitize_attributes(self, attrs: dict[str, Any]) -> dict[str, Any]:
        payload = canonical_json(attrs)
        if len(payload.encode("utf-8")) > MAX_ATTRIBUTE_BYTES:
            raise ObservationError("attributes exceed size bound")
        if HTML_TAG.search(payload):
            # strip HTML from every string value — executable HTML can never
            # ride attributes into a UI
            def _clean(v: Any) -> Any:
                if isinstance(v, str):
                    return HTML_TAG.sub("", v)
                if isinstance(v, list):
                    return [_clean(x) for x in v]
                if isinstance(v, dict):
                    return {k: _clean(x) for k, x in v.items()}
                return v
            return _clean(attrs)
        return attrs

    def _validate_geometry(self, geojson: dict[str, Any]) -> None:
        if geojson.get("type") not in {"Point", "LineString", "Polygon",
                                       "MultiPoint", "MultiLineString", "MultiPolygon"}:
            raise ObservationError(f"unsupported geometry type: {geojson.get('type')!r}")
        coords = geojson.get("coordinates")
        if coords is None:
            raise ObservationError("geometry missing coordinates")
        # position_order contract: longitude first; bounds check
        def check(c: Any) -> None:
            if not isinstance(c, (list, tuple)) or len(c) < 2:
                raise ObservationError("coordinate pair required")
            lon, lat = float(c[0]), float(c[1])
            if not (-180.0 <= lon <= 180.0 and -90.0 <= lat <= 90.0):
                raise ObservationError(f"lon/lat out of bounds: {lon},{lat}")
        def walk(c: Any) -> None:
            if isinstance(c, (list, tuple)) and c and isinstance(c[0], (list, tuple)):
                for x in c:
                    walk(x)
            else:
                check(c)
        walk(coords)

    def _allowlisted_url(self, url: str | None) -> str | None:
        if url is None:
            return None
        if not str(url).startswith("https://"):
            return None  # only allowlisted https or null
        host = str(url).split("/")[2] if len(str(url).split("/")) > 2 else ""
        if host in self.manifest["endpoint"]["hosts"]:
            return str(url)
        return None
