"""ark.intel.observation.v1 adapter-SDK contract tests (100x W1.4 / PR4).

Covers the plan's fixture list: valid fixture; missing identifiers and
timestamps; invalid longitude/latitude order and bounds; oversized
strings/attributes; malformed time; malicious HTML; duplicate/stable IDs;
deterministic confidence components; exact raw digest + record pointer;
detail_url allowlisting.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from arkintel.manifest_loader import load_manifest, manifest_digest
from arkintel.observation import (
    ObservationBuilder, ObservationError, SCHEMA_VERSION,
)

ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = ROOT / "arkintel" / "manifests"


@pytest.fixture()
def builder() -> ObservationBuilder:
    m = load_manifest(MANIFESTS / "usgs-earthquakes.json")
    return ObservationBuilder(
        source_id="usgs-earthquakes",
        adapter_version="usgs_geojson_v1@1",
        manifest=m,
        manifest_digest=manifest_digest(m),
        retrieval_id="ret-0001",
        raw_sha256="a" * 64,
    )


def test_valid_fixture_produces_full_envelope(builder: ObservationBuilder) -> None:
    obs = builder.emit(
        record_id="us-1234",
        title="M 4.2 earthquake",
        observed_at="2026-09-21T10:00:00Z",
        geometry_geojson={"type": "Point", "coordinates": [-102.3, 32.1]},
        geometry_quality=1.0,
        detail_url=None,
        attributes={"magnitude": 4.2},
    )
    assert obs["schema_version"] == SCHEMA_VERSION
    assert obs["observation_id"].startswith("usgs-earthquakes:")
    assert obs["source"]["manifest_digest"].startswith("sha256:")
    assert obs["truth"]["class"] == "observed"
    assert obs["geometry"]["position_order"] == "longitude_latitude"
    assert obs["revision_sha256"]


def test_missing_identifier_fails_closed(builder: ObservationBuilder) -> None:
    with pytest.raises(ObservationError):
        builder.emit(record_id="", title="x", observed_at=None)


def test_missing_observed_time_is_null_never_substituted(builder: ObservationBuilder) -> None:
    obs = builder.emit(record_id="r1", title="no time", observed_at=None)
    assert obs["time"]["observed_at"] is None
    assert obs["time"]["ingested_at"]  # ingestion time present, observed stays null


def test_malformed_time_becomes_null_with_decay(builder: ObservationBuilder) -> None:
    obs = builder.emit(record_id="r2", title="bad time", observed_at="not-a-time")
    assert obs["time"]["observed_at"] is None
    # freshness decays from ingestion (honest), never fabricates a source time
    assert obs["truth"]["confidence"]["freshness"] == 1.0  # just ingested


def test_longitude_latitude_order_and_bounds(builder: ObservationBuilder) -> None:
    # lat/lon swapped = out of bounds (lat 102 > 90) -> fail closed
    with pytest.raises(ObservationError):
        builder.emit(record_id="r3", title="swapped",
                     observed_at=None,
                     geometry_geojson={"type": "Point", "coordinates": [32.1, -102.3]})
    with pytest.raises(ObservationError):
        builder.emit(record_id="r4", title="oob",
                     observed_at=None,
                     geometry_geojson={"type": "Point", "coordinates": [-200.0, 32.1]})


def test_oversized_attributes_fail_closed(builder: ObservationBuilder) -> None:
    big = {"blob": "x" * 20000}
    with pytest.raises(ObservationError):
        builder.emit(record_id="r5", title="big", observed_at=None, attributes=big)


def test_malicious_html_never_rides_attributes_or_title(builder: ObservationBuilder) -> None:
    obs = builder.emit(
        record_id="r6",
        title="<script>alert(1)</script>Quake",
        observed_at=None,
        attributes={"note": "<img src=x onerror=alert(1)>shady"},
    )
    assert "<" not in obs["display"]["title"] or "<script" not in obs["display"]["title"]
    assert "onerror" not in json.dumps(obs["attributes"])
    assert "onerror" not in obs["display"]["title"]


def test_duplicate_record_ids_are_stable(builder: ObservationBuilder) -> None:
    a = builder.emit(record_id="same", title="one", observed_at=None)
    b = builder.emit(record_id="same", title="one", observed_at=None)
    assert a["observation_id"] == b["observation_id"]
    assert a["revision_sha256"] == b["revision_sha256"]


def test_confidence_is_deterministic_and_versioned(builder: ObservationBuilder) -> None:
    c1 = builder.confidence(freshness=0.9, geometry_quality=1.0)
    c2 = builder.confidence(freshness=0.9, geometry_quality=1.0)
    assert c1 == c2
    assert c1["method_version"] == "ark.intel.confidence.v1"
    expected = round(round(0.98, 4) * 0.9 * 1.0, 4)
    assert abs(c1["overall"] - expected) < 0.001


def test_corroboration_stays_null_wave1(builder: ObservationBuilder) -> None:
    obs = builder.emit(record_id="r7", title="x", observed_at=None)
    assert obs["truth"]["confidence"]["corroboration"] is None


def test_exact_raw_digest_and_pointer(builder: ObservationBuilder) -> None:
    obs = builder.emit(record_id="rec-9", title="x", observed_at=None)
    assert obs["provenance"]["raw_sha256"] == "a" * 64
    assert obs["provenance"]["raw_record_pointer"] == "rec-9"
    assert obs["provenance"]["evidence_pointer"] == "arkintel://retrievals/ret-0001#rec-9"


def test_detail_url_allowlisted(builder: ObservationBuilder) -> None:
    good = builder.emit(record_id="r8", title="x", observed_at=None,
                        detail_url="https://earthquake.usgs.gov/earthquakes/feed/v1.0/detail/x")
    assert good["display"]["detail_url"] is not None
    bad = builder.emit(record_id="r9", title="x", observed_at=None,
                       detail_url="https://evil.example/steal")
    assert bad["display"]["detail_url"] is None
    http = builder.emit(record_id="r10", title="x", observed_at=None,
                        detail_url="http://earthquake.usgs.gov/x")
    assert http["display"]["detail_url"] is None


def test_policy_fields_reflect_manifest(builder: ObservationBuilder) -> None:
    obs = builder.emit(record_id="r11", title="x", observed_at=None)
    assert obs["policy"]["license_id"] == "US-PD"
    assert obs["policy"]["raw_retention"] == "retained"
    assert obs["policy"]["redistribution"] == "allowed"
