"""Governed-fetch cutover contract (100x cutover PR).

The live fetch path routes through the TransportGovernor: adapters keep
their parse behavior; failures surface sanitized policy codes; and the
compatibility guarantee holds — ready sources still produce features,
non-ready sources still return their availability status, and degraded
fetches carry TransportPolicyError codes, not raw exception text.
"""
from __future__ import annotations

from pathlib import Path

import pytest

import arkintel.sources as S
from arkintel.sources import SOURCES, SOURCE_INDEX, fetch_source
from arkintel.transport import TransportPolicyError

MANIFESTS = Path(__file__).resolve().parents[1] / "arkintel" / "manifests"


@pytest.mark.asyncio
async def test_governed_get_json_passes_manifest_policy(monkeypatch) -> None:
    """_get_json must call the governor (the cutover core)."""
    calls = {}

    class FakeGov:
        async def get_json(self, source_id, url):
            calls["source_id"] = source_id
            calls["url"] = url
            return {"features": []}

    import arkintel.transport as T
    monkeypatch.setattr(T, "get_governor", lambda: FakeGov())
    source = SOURCE_INDEX["usgs-earthquakes"]
    payload = await S._get_json(None, source)
    assert payload == {"features": []}
    assert calls["source_id"] == "usgs-earthquakes"
    assert calls["url"] == source.url


@pytest.mark.asyncio
async def test_degraded_fetch_carries_policy_code_not_raw_exception(monkeypatch) -> None:
    import arkintel.transport as T

    class ExplodingGov:
        async def get_json(self, source_id, url):
            raise TransportPolicyError("policy_ip_blocked", source_id)

    monkeypatch.setattr(T, "get_governor", lambda: ExplodingGov())
    events, status = await fetch_source("usgs-earthquakes")
    assert events == []
    assert status["status"] == "degraded"
    assert status["detail"] == "policy_ip_blocked"  # sanitized code only


@pytest.mark.asyncio
async def test_non_ready_sources_keep_availability_status(monkeypatch) -> None:
    """credential_required / policy_disabled / provenance_pending sources
    never fetch and report their availability (unchanged behavior)."""
    events, status = await fetch_source("cloudflare-radar")
    assert status["status"] == "credential_required"
    events, status = await fetch_source("osiris-cctv")
    assert status["status"] == "policy_disabled"
    events, status = await fetch_source("osiris-submarine-cables")
    assert status["status"] == "provenance_pending"


@pytest.mark.asyncio
async def test_every_ready_source_parses_fixture_payloads_through_governor(monkeypatch) -> None:
    """End-to-end adapter compatibility: every READY source's adapter runs
    against a canned payload through the governed path and yields features
    with the legacy shape."""
    fixtures = {
        "usgs-earthquakes": {"features": [{"id": "q1", "geometry": {"type": "Point", "coordinates": [-102.3, 32.1]}, "properties": {"mag": 4.2, "title": "M4.2 quake", "time": 1759000000000, "url": "https://earthquake.usgs.gov/x"}}]},
        "nasa-eonet-fires": {"events": [{"id": "E1", "geometry": [{"date": "2026-09-21T00:00:00Z", "type": "Point", "coordinates": [-102.3, 32.1]}], "title": "Fire"}]},
        "noaa-alerts": {"features": [{"id": "n1", "geometry": {"type": "Point", "coordinates": [-102.3, 32.1]}, "properties": {"event": "Flood Warning", "sent": "2026-09-21T00:00:00Z", "effective": "2026-09-21T01:00:00Z", "ends": "2026-09-21T06:00:00Z"}}]},
        "opensky-flights": {"states": [["abc", "CALL1", "US", 1759000000, 1759000000, -102.3, 32.1, 1000.0, False, 100.0, 50.0, None, None, 100.0, None, False, 0]]},
        "celestrak-satellites": [{"OBJECT_NAME": "SAT-1", "EPOCH": "2026-09-21T00:00:00.000Z", "NORAD_CAT_ID": 1, "ECCENTRICITY": 0.001, "INCLINATION": 50.0, "RA_OF_ASC_NODE": 100.0, "ARG_OF_PERICENTER": 0.0, "MEAN_ANOMALY": 0.0, "MEAN_MOTION": 15.0}],
        "gdelt-conflicts": {"features": [{"type": "Feature", "properties": {"name": "Incident", "eventdate": "2026-09-21"}, "geometry": {"type": "Point", "coordinates": [-102.3, 32.1]}}]},
        "gdelt-live-news": {"articles": [{"url": "https://example.com/a", "title": "Headline", "seendate": "20260921T000000Z"}]},
        "cisa-kev": {"vulnerabilities": [{"cveID": "CVE-2026-0001", "dateAdded": "2026-09-21T00:00:00.000", "vulnerabilityName": "X"}]},
        "coingecko-markets": {"bitcoin": {"usd": 100000.0, "last_updated_at": 1759000000}},
    }

    class FixtureGov:
        async def get_json(self, source_id, url):
            return fixtures[source_id]

    import arkintel.transport as T
    monkeypatch.setattr(T, "get_governor", lambda: FixtureGov())
    ready = [s for s in SOURCES if s.availability == "ready"]
    assert len(ready) == 9
    for source in ready:
        events, status = await fetch_source(source.id)
        assert status["status"] == "ready", source.id
        assert len(events) >= 1, source.id
        f = events[0]
        assert f["type"] == "Feature"  # legacy GeoJSON shape preserved
        assert "properties" in f
