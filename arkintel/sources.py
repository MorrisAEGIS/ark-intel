"""Allowlisted passive-source broker and provenance normalizer."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from pathlib import Path
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable

from .transport import TransportPolicyError

import httpx

from .config import get_settings


@dataclass(frozen=True)
class SourceDefinition:
    id: str
    label: str
    group: str
    url: str
    license: str
    truth_class: str
    availability: str = "ready"
    note: str = ""


SOURCES: tuple[SourceDefinition, ...] = (
    SourceDefinition("usgs-earthquakes", "USGS Earthquakes", "Hazards", "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_day.geojson", "US government public domain", "observed"),
    SourceDefinition("nasa-eonet-fires", "NASA EONET Wildfires", "Hazards", "https://eonet.gsfc.nasa.gov/api/v3/events?category=wildfires&status=open&limit=100", "NASA open data", "reported"),
    SourceDefinition("noaa-alerts", "NOAA Weather Alerts", "Hazards", "https://api.weather.gov/alerts/active", "US government public domain", "reported"),
    SourceDefinition("opensky-flights", "OpenSky Live Flights", "Movement", "https://opensky-network.org/api/states/all", "OpenSky API terms; non-commercial attribution required", "observed"),
    SourceDefinition("celestrak-satellites", "CelesTrak Active Satellites", "Movement", "https://celestrak.org/NORAD/elements/gp.php?GROUP=active&FORMAT=json", "CelesTrak data terms", "reported"),
    SourceDefinition("gdelt-conflicts", "GDELT Conflict Geo", "Geopolitics", "https://api.gdeltproject.org/api/v2/geo/geo?query=conflict%20OR%20military&mode=PointData&format=geojson&maxrecords=100&timespan=24h", "GDELT open data", "reported"),
    SourceDefinition("gdelt-live-news", "GDELT Live News", "Live Media", "https://api.gdeltproject.org/api/v2/doc/doc?query=conflict%20OR%20cyber%20OR%20disaster&mode=ArtList&format=json&maxrecords=50&timespan=24h", "GDELT open data", "reported"),
    SourceDefinition("cisa-kev", "CISA Known Exploited Vulnerabilities", "Cyber", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "US government public data", "reported"),
    SourceDefinition("coingecko-markets", "CoinGecko Market Pulse", "Markets / Chain", "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,ethereum,solana&vs_currencies=usd&include_last_updated_at=true&include_24hr_change=true", "CoinGecko API terms", "reported"),
    SourceDefinition("cloudflare-radar", "Cloudflare Radar", "Infrastructure", "https://api.cloudflare.com/client/v4/radar", "Cloudflare API terms", "reported", "credential_required", "Enable only with a dedicated read-only Radar token."),
    SourceDefinition("global-fishing-watch", "Global Fishing Watch", "Movement", "https://gateway.api.globalfishingwatch.org", "Global Fishing Watch API terms", "reported", "credential_required", "Maritime events require a separately governed API token."),
    SourceDefinition("osiris-submarine-cables", "OSIRIS Submarine Cables", "Infrastructure", "upstream://public/data/submarine-cables-filtered.json", "provenance review required", "reference", "provenance_pending", "Bundled upstream data is not served until its original license is verified."),
    SourceDefinition("osiris-cctv", "OSIRIS CCTV", "Live Media", "upstream://src/app/api/cctv", "mixed upstream sources", "reported", "policy_disabled", "Disabled: upstream contains unsafe credential and TLS patterns."),
)


SOURCE_INDEX = {source.id: source for source in SOURCES}
READY_SOURCE_IDS = tuple(source.id for source in SOURCES if source.availability == "ready")
_OBSERVATIONS: dict[str, list[dict[str, Any]]] = {}

_MANIFEST_CACHE: dict[str, dict[str, Any]] = {}
_MANIFEST_DIR = Path(__file__).resolve().parent / "manifests"


_RAW_STORE = None
_LAST_RETRIEVAL: dict[str, dict[str, str]] = {}


def _get_raw_store():
    global _RAW_STORE
    if _RAW_STORE is None:
        from .raw_store import RawStore
        _RAW_STORE = RawStore()
    return _RAW_STORE


_CACHE: dict[str, tuple[float, list[dict[str, Any]], dict[str, Any]]] = {}


def _iso(value: Any = None) -> str:
    if isinstance(value, (int, float)):
        seconds = value / 1000 if value > 10_000_000_000 else value
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
    if isinstance(value, str) and value:
        return value
    return datetime.now(timezone.utc).isoformat()


def _emit_observation(
    source: SourceDefinition,
    feature: dict[str, Any],
    source_record_id: str,
    digest: str,
) -> dict[str, Any] | None:
    """Emit the ark.intel.observation.v1 envelope for one legacy feature
    (100x cutover-3). The envelope becomes the source of record for
    observation identity; the legacy GeoJSON stays as the compatibility
    projection. Emission failures are recorded, never fatal — the legacy
    path must never break on envelope strictness."""
    from .manifest_loader import manifest_digest as _md
    from .observation import ObservationBuilder
    retrieval = _LAST_RETRIEVAL.get(source.id)
    raw_sha = retrieval.get("body_sha256") if retrieval else None
    retrieval_id = retrieval.get("retrieval_id") if retrieval else None
    if not raw_sha:
        raw_sha = digest  # record-level digest fallback (pre-capture era)
        retrieval_id = retrieval_id or "uncaptured"
    manifest = _MANIFEST_CACHE.get(source.id)
    if manifest is None:
        try:
            from .manifest_loader import load_manifest
            _MANIFEST_CACHE[source.id] = manifest = load_manifest(
                _MANIFEST_DIR / f"{source.id}.json")
        except Exception:
            return None  # no manifest = no envelope (honest absence)
    builder = ObservationBuilder(
        source_id=source.id,
        adapter_version="legacy_projection_v1",
        manifest=manifest,
        manifest_digest=_md(manifest),
        retrieval_id=str(retrieval_id),
        raw_sha256=raw_sha,
    )
    try:
        envelope = builder.emit(
            record_id=str(source_record_id),
            title=str(feature["properties"].get("title") or source.id),
            observed_at=feature["properties"].get("observed_at"),
            geometry_geojson=feature.get("geometry"),
            detail_url=feature["properties"].get("source_url"),
            attributes={k: v for k, v in feature["properties"].items()
                        if k not in ("title", "observed_at", "source_url")},
        )
    except Exception:
        return None
    _OBSERVATIONS.setdefault(source.id, []).append(envelope)
    return envelope


def _feature(
    source: SourceDefinition,
    source_record_id: str,
    *,
    title: str,
    geometry: dict[str, Any] | None,
    observed_at: Any = None,
    confidence: float = 0.8,
    detail_url: str | None = None,
    properties: dict[str, Any] | None = None,
) -> dict[str, Any]:
    retrieved = datetime.now(timezone.utc)
    raw_material = json.dumps(
        {"source": source.id, "id": source_record_id, "title": title, "geometry": geometry, "properties": properties or {}},
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(raw_material.encode("utf-8")).hexdigest()
    event_id = f"{source.id}:{hashlib.sha256(str(source_record_id).encode()).hexdigest()[:20]}"
    normalized = {
        "title": title,
        "source_id": source.id,
        "source_group": source.group,
        "source_url": detail_url or source.url,
        "license": source.license,
        "observed_at": _iso(observed_at),
        "retrieved_at": retrieved.isoformat(),
        "expires_at": (retrieved + timedelta(minutes=15)).isoformat(),
        "truth_class": source.truth_class,
        "confidence": max(0.0, min(1.0, confidence)),
        "synthetic": False,
        "raw_sha256": digest,
        "evidence_pointer": f"arkintel://events/{event_id}#sha256={digest}",
        **(properties or {}),
    }
    feature = {"type": "Feature", "id": event_id, "geometry": geometry, "properties": normalized}
    _emit_observation(source, feature, source_record_id, digest)
    return feature


async def _get_json(client: httpx.AsyncClient, source: SourceDefinition) -> Any:
    """Governed fetch (100x cutover): the TransportGovernor enforces the
    ark.intel.source.v1 manifest policy for every byte fetched from a
    source — allowlist, redirects denied, post-resolution SSRF rejection,
    manifest bounds, rate/concurrency, circuit breaker — with sanitized
    failure codes only. Exact decoded bytes are captured for the bounded
    raw-evidence store before parsing."""
    import uuid

    from .manifest_loader import manifest_digest
    from .transport import get_governor

    gov = get_governor()
    retrieval_id = str(uuid.uuid4())
    captured: dict[str, str] = {}

    def _capture(source_id: str, body: bytes, status: int,
                  content_type: str | None, content_encoding: str | None) -> None:
        store = _get_raw_store()
        manifest = gov.manifests[source_id]
        rec = store.store(
            retrieval_id=retrieval_id,
            source_id=source_id,
            body=body,
            manifest=manifest,
            response_status=status,
            content_type=content_type,
            content_encoding=content_encoding,
        )
        captured["body_sha256"] = rec["body_sha256"]
        captured["retention_mode"] = rec["retention_mode"]

    payload = await gov.get_json(source.id, source.url, on_body=_capture)
    _LAST_RETRIEVAL[source.id] = {
        "retrieval_id": retrieval_id,
        "body_sha256": captured.get("body_sha256"),
        "retention_mode": captured.get("retention_mode"),
        "manifest_digest": manifest_digest(gov.manifests[source.id]),
    }
    return payload


async def _usgs(client: httpx.AsyncClient, source: SourceDefinition) -> list[dict[str, Any]]:
    payload = await _get_json(client, source)
    events = []
    for row in payload.get("features", []):
        props = row.get("properties") or {}
        events.append(_feature(source, str(row.get("id") or props.get("code") or props.get("time")), title=str(props.get("title") or "Earthquake"), geometry=row.get("geometry"), observed_at=props.get("time"), confidence=0.98, detail_url=props.get("url"), properties={"severity": props.get("mag"), "place": props.get("place"), "event_type": props.get("type", "earthquake")}))
    return events


async def _eonet(client: httpx.AsyncClient, source: SourceDefinition) -> list[dict[str, Any]]:
    payload = await _get_json(client, source)
    events = []
    for row in payload.get("events", []):
        observations = row.get("geometry") or []
        latest = observations[-1] if observations else {}
        coords = latest.get("coordinates")
        geometry = {"type": latest.get("type", "Point"), "coordinates": coords} if coords else None
        events.append(_feature(source, str(row.get("id")), title=str(row.get("title") or "Wildfire"), geometry=geometry, observed_at=latest.get("date"), confidence=0.86, detail_url=(row.get("sources") or [{}])[0].get("url"), properties={"event_type": "wildfire", "categories": [item.get("title") for item in row.get("categories", [])]}))
    return events


async def _noaa(client: httpx.AsyncClient, source: SourceDefinition) -> list[dict[str, Any]]:
    payload = await _get_json(client, source)
    events = []
    for row in payload.get("features", []):
        props = row.get("properties") or {}
        events.append(_feature(source, str(row.get("id") or props.get("id")), title=str(props.get("headline") or props.get("event") or "Weather alert"), geometry=row.get("geometry"), observed_at=props.get("sent") or props.get("onset"), confidence=0.94, detail_url=props.get("@id") or row.get("id"), properties={"event_type": props.get("event"), "severity": props.get("severity"), "certainty": props.get("certainty"), "area": props.get("areaDesc")}))
    return events


async def _opensky(client: httpx.AsyncClient, source: SourceDefinition) -> list[dict[str, Any]]:
    payload = await _get_json(client, source)
    events = []
    for row in (payload.get("states") or [])[:500]:
        if len(row) < 11 or row[5] is None or row[6] is None:
            continue
        events.append(_feature(source, str(row[0]), title=str((row[1] or row[0]).strip()), geometry={"type": "Point", "coordinates": [row[5], row[6]]}, observed_at=row[3] or row[4], confidence=0.82, properties={"event_type": "aircraft", "origin_country": row[2], "altitude_m": row[7], "on_ground": bool(row[8]), "velocity_mps": row[9], "heading_deg": row[10]}))
    return events


async def _celestrak(client: httpx.AsyncClient, source: SourceDefinition) -> list[dict[str, Any]]:
    payload = await _get_json(client, source)
    events = []
    for row in payload[:200]:
        events.append(_feature(source, str(row.get("NORAD_CAT_ID") or row.get("OBJECT_ID")), title=str(row.get("OBJECT_NAME") or "Satellite"), geometry=None, observed_at=row.get("EPOCH"), confidence=0.9, properties={"event_type": "satellite_catalog", "object_type": row.get("OBJECT_TYPE"), "country_code": row.get("COUNTRY_CODE"), "orbit_center": row.get("CENTER_NAME")}))
    return events


async def _gdelt_geo(client: httpx.AsyncClient, source: SourceDefinition) -> list[dict[str, Any]]:
    payload = await _get_json(client, source)
    events = []
    for index, row in enumerate(payload.get("features", [])):
        props = row.get("properties") or {}
        record_id = props.get("url") or props.get("name") or f"record-{index}"
        events.append(_feature(source, str(record_id), title=str(props.get("name") or props.get("title") or "GDELT event"), geometry=row.get("geometry"), observed_at=props.get("date") or props.get("timestamp"), confidence=0.66, detail_url=props.get("url"), properties={"event_type": "reported_conflict", "html": None, "count": props.get("count")}))
    return events


async def _gdelt_news(client: httpx.AsyncClient, source: SourceDefinition) -> list[dict[str, Any]]:
    payload = await _get_json(client, source)
    events = []
    for index, row in enumerate(payload.get("articles", [])):
        url = row.get("url")
        events.append(_feature(source, str(url or f"article-{index}"), title=str(row.get("title") or "Live report"), geometry=None, observed_at=row.get("seendate"), confidence=0.62, detail_url=url, properties={"event_type": "news_report", "domain": row.get("domain"), "language": row.get("language"), "source_country": row.get("sourcecountry")}))
    return events


async def _cisa(client: httpx.AsyncClient, source: SourceDefinition) -> list[dict[str, Any]]:
    payload = await _get_json(client, source)
    events = []
    for row in (payload.get("vulnerabilities") or [])[:500]:
        cve = str(row.get("cveID") or "unknown")
        events.append(_feature(source, cve, title=f"{cve} · {row.get('vulnerabilityName', 'Known exploited vulnerability')}", geometry=None, observed_at=row.get("dateAdded"), confidence=0.98, detail_url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}", properties={"event_type": "known_exploited_vulnerability", "vendor": row.get("vendorProject"), "product": row.get("product"), "due_date": row.get("dueDate"), "ransomware_use": row.get("knownRansomwareCampaignUse")}))
    return events


async def _markets(client: httpx.AsyncClient, source: SourceDefinition) -> list[dict[str, Any]]:
    payload = await _get_json(client, source)
    events = []
    for asset, quote in payload.items():
        events.append(_feature(source, asset, title=f"{asset.title()} market pulse", geometry=None, observed_at=quote.get("last_updated_at"), confidence=0.9, properties={"event_type": "market_quote", "asset": asset, "usd": quote.get("usd"), "usd_24h_change": quote.get("usd_24h_change")}))
    return events


ADAPTERS: dict[str, Callable[[httpx.AsyncClient, SourceDefinition], Awaitable[list[dict[str, Any]]]]] = {
    "usgs-earthquakes": _usgs,
    "nasa-eonet-fires": _eonet,
    "noaa-alerts": _noaa,
    "opensky-flights": _opensky,
    "celestrak-satellites": _celestrak,
    "gdelt-conflicts": _gdelt_geo,
    "gdelt-live-news": _gdelt_news,
    "cisa-kev": _cisa,
    "coingecko-markets": _markets,
}


def source_catalog() -> list[dict[str, Any]]:
    return [asdict(source) for source in SOURCES]


async def fetch_source(source_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    source = SOURCE_INDEX[source_id]
    if source.availability != "ready":
        return [], {"source_id": source.id, "status": source.availability, "detail": source.note}
    settings = get_settings()
    cached = _CACHE.get(source_id)
    if cached and time.monotonic() - cached[0] < settings.event_cache_seconds:
        return cached[1], {**cached[2], "cached": True}
    adapter = ADAPTERS[source_id]
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(settings.source_timeout_seconds),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            events = await adapter(client, source)
        status = {"source_id": source.id, "status": "ready", "count": len(events), "cached": False}
        retrieval = _LAST_RETRIEVAL.get(source.id)
        if retrieval:
            status["retrieval_evidence"] = retrieval
        _CACHE[source_id] = (time.monotonic(), events, status)
        return events, status
    except TransportPolicyError as tpe:
        # sanitized failure codes only — no bodies/URLs/raw exceptions
        return [], {"source_id": source.id, "status": "degraded",
                    "detail": tpe.code, "count": 0, "cached": False}
    except Exception as exc:
        return [], {"source_id": source.id, "status": "degraded", "detail": str(exc)[:120], "count": 0, "cached": False}


async def fetch_events(
    source_ids: list[str] | None = None,
    *,
    groups: set[str] | None = None,
    limit: int = 1000,
) -> dict[str, Any]:
    selected = source_ids or list(READY_SOURCE_IDS)
    unknown = sorted(set(selected) - set(SOURCE_INDEX))
    if unknown:
        raise ValueError(f"Unknown source IDs: {', '.join(unknown)}")
    if groups:
        selected = [source_id for source_id in selected if SOURCE_INDEX[source_id].group in groups]
    results = await asyncio.gather(*(fetch_source(source_id) for source_id in selected))
    features: list[dict[str, Any]] = []
    statuses: list[dict[str, Any]] = []
    for source_features, source_status in results:
        statuses.append(source_status)
        features.extend(source_features)
    features.sort(key=lambda item: item["properties"].get("observed_at", ""), reverse=True)
    return {
        "type": "FeatureCollection",
        "features": features[:limit],
        "source_statuses": statuses,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "truncated": len(features) > limit,
        "truth_note": "Reported and observed public-source records; not independently verified unless stated.",
    }
