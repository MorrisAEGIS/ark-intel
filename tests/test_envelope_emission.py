"""Cutover-3 contract: every legacy feature emits its observation envelope.

Proves: emission happens through the real ObservationBuilder (identity,
confidence, policy from the manifest); the legacy GeoJSON feature is
unchanged; envelope strictness never breaks the legacy path; envelopes
are retrievable per source.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import arkintel.sources as S
from arkintel.sources import fetch_source
from arkintel.manifest_loader import load_all_manifests

MANIFESTS = Path(__file__).resolve().parents[1] / "arkintel" / "manifests"


class _NoopStore:
    def store(self, **kw):
        return {"body_sha256": "b" * 64, "retention_mode": "digest_only"}

    def get_body(self, rid):
        return None

    def catalog_row(self, rid):
        return None

    def stats(self):
        return {}


class _QuakeGov:
    def __init__(self):
        self.manifests = load_all_manifests(MANIFESTS)

    async def get_json(self, source_id, url, *, on_body=None):
        body = json.dumps({"features": [{
            "id": "env-1",
            "geometry": {"type": "Point", "coordinates": [-102.3, 32.1]},
            "properties": {"mag": 4.2, "title": "M 4.2 quake", "time": 1759000000000,
                           "url": "https://earthquake.usgs.gov/x"},
        }]}).encode()
        if on_body is not None:
            on_body(source_id, body, 200, "application/json", None)
        return json.loads(body)


@pytest.mark.asyncio
async def test_every_feature_emits_its_envelope(monkeypatch) -> None:
    import arkintel.transport as T
    monkeypatch.setattr(T, "get_governor", lambda: _QuakeGov())
    monkeypatch.setattr(S, "_get_raw_store", lambda: _NoopStore())
    S._CACHE.clear()
    S._OBSERVATIONS.clear()
    S._LAST_RETRIEVAL.clear()

    events, status = await fetch_source("usgs-earthquakes")
    assert status["status"] == "ready"
    assert len(events) == 1
    f = events[0]
    # legacy feature unchanged
    assert f["type"] == "Feature"
    assert f["properties"]["title"] == "M 4.2 quake"
    # the envelope was emitted for the same record
    envs = S._OBSERVATIONS.get("usgs-earthquakes", [])
    assert len(envs) == 1
    env = envs[0]
    assert env["schema_version"] == "ark.intel.observation.v1"
    assert env["source"]["id"] == "usgs-earthquakes"
    # identity is derived, stable, and distinct from the legacy id
    assert env["observation_id"].startswith("usgs-earthquakes:")
    assert env["provenance"]["raw_record_pointer"] == "env-1"
    # confidence is the deterministic method's
    assert env["truth"]["confidence"]["method_version"] == "ark.intel.confidence.v1"
    # provenance: the captured raw body sha + retrieval id
    assert env["provenance"]["raw_sha256"] == "b" * 64
    assert env["provenance"]["retrieval_id"]
    # policy projected from the manifest
    assert env["policy"]["license_id"]


@pytest.mark.asyncio
async def test_envelope_strictness_never_breaks_legacy(monkeypatch) -> None:
    """A record the envelope contract REJECTS (swapped lat/lon geometry)
    must still pass through the legacy path unchanged — emission failure
    is recorded silence, never a legacy break."""
    import arkintel.transport as T

    class BadGeomGov:
        def __init__(self):
            self.manifests = load_all_manifests(MANIFESTS)

        async def get_json(self, source_id, url, *, on_body=None):
            # swapped coordinates: lat/lon out of order -> envelope rejects
            body = json.dumps({"features": [{
                "id": "bad-1",
                "geometry": {"type": "Point", "coordinates": [92.1, 132.1]},
                "properties": {"mag": 3.0, "title": "Bad geometry", "time": 1759000000000},
            }]}).encode()
            if on_body is not None:
                on_body(source_id, body, 200, "application/json", None)
            return json.loads(body)

    monkeypatch.setattr(T, "get_governor", lambda: BadGeomGov())
    monkeypatch.setattr(S, "_get_raw_store", lambda: _NoopStore())
    S._CACHE.clear()
    S._OBSERVATIONS.clear()
    S._LAST_RETRIEVAL.clear()

    events, status = await fetch_source("usgs-earthquakes")
    assert status["status"] == "ready"
    assert len(events) == 1  # legacy path carried it through
    assert S._OBSERVATIONS.get("usgs-earthquakes", []) == []  # envelope honestly absent
