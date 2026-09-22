"""Cutover-2 contract: exact bytes captured pre-parse into the raw store.

Proves the W1.2 rule end-to-end: the governor hands decoded body bytes to
the capture hook BEFORE parsing; the RawStore records the retrieval with
manifest-driven retention; the fetch status carries the evidence pointer.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import arkintel.sources as S
from arkintel.sources import SOURCE_INDEX, fetch_source
from arkintel.manifest_loader import load_all_manifests

MANIFESTS = Path(__file__).resolve().parents[1] / "arkintel" / "manifests"


class _FakeStore:
    stored = None

    def store(self, **kw):
        _FakeStore.stored = kw
        return {"body_sha256": hashlib.sha256(kw["body"]).hexdigest(),
                "retention_mode": "retained"}

    def get_body(self, rid):
        return None

    def catalog_row(self, rid):
        return None

    def stats(self):
        return {}


@pytest.mark.asyncio
async def test_exact_bytes_captured_pre_parse(monkeypatch) -> None:
    body = b'{"features": [{"id": "capture-1"}]}'
    calls = {}

    class CaptureGov:
        def __init__(self):
            self.manifests = load_all_manifests(MANIFESTS)

        async def get_json(self, source_id, url, *, on_body=None):
            if on_body is not None:
                on_body(source_id, body, 200, "application/json", None)
            calls["fired"] = True
            return json.loads(body)

    import arkintel.transport as T
    monkeypatch.setattr(T, "get_governor", lambda: CaptureGov())
    monkeypatch.setattr(S, "_get_raw_store", lambda: _FakeStore())

    source = SOURCE_INDEX["usgs-earthquakes"]
    payload = await S._get_json(None, source)
    assert payload == {"features": [{"id": "capture-1"}]}
    assert calls["fired"]
    assert _FakeStore.stored is not None
    assert _FakeStore.stored["body"] == body
    assert _FakeStore.stored["content_type"] == "application/json"


@pytest.mark.asyncio
async def test_real_store_roundtrip_in_fetch(tmp_path, monkeypatch) -> None:
    from arkintel.raw_store import RawStore
    import arkintel.transport as T

    body = b'{"features": [{"id": "rt-1", "properties": {"title": "Quake", "time": 1759000000000, "url": "https://earthquake.usgs.gov/x"}, "geometry": {"type": "Point", "coordinates": [-102.3, 32.1]}}]}'
    store = RawStore(root=tmp_path / "data")

    class Gov:
        def __init__(self):
            self.manifests = load_all_manifests(MANIFESTS)

        async def get_json(self, source_id, url, *, on_body=None):
            on_body(source_id, body, 200, "application/json", None)
            return json.loads(body)

    monkeypatch.setattr(T, "get_governor", lambda: Gov())
    monkeypatch.setattr(S, "_get_raw_store", lambda: store)
    S._CACHE.clear()

    events, status = await fetch_source("usgs-earthquakes")
    assert status["status"] == "ready"
    ev = status["retrieval_evidence"]
    assert ev["body_sha256"] == hashlib.sha256(body).hexdigest()
    assert ev["retention_mode"] == "retained"
    assert ev["manifest_digest"].startswith("sha256:")
    rid = ev["retrieval_id"]
    assert store.get_body(rid) == body
    assert events[0]["type"] == "Feature"
    assert events[0]["properties"]["raw_sha256"]
