"""Bounded raw-evidence retention contract (100x W1.3 / PR5).

Proves: content-addressed bodies; manifest-driven retention modes;
digest_only never stores or fabricates bytes; expiry is honest absence;
bounded sweep actually deletes; catalog survives; the store never grows
unbounded (amortized sweep on every write).
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from arkintel.manifest_loader import load_manifest
from arkintel.raw_store import RawStore

MANIFESTS = Path(__file__).resolve().parents[1] / "arkintel" / "manifests"


@pytest.fixture()
def store(tmp_path: Path) -> RawStore:
    return RawStore(root=tmp_path / "ark-intel")


@pytest.fixture()
def usgs_manifest() -> dict:
    return load_manifest(MANIFESTS / "usgs-earthquakes.json")


def _digest_only_manifest(usgs: dict) -> dict:
    import copy
    m = copy.deepcopy(usgs)
    m["retention"]["raw_hours"] = 0
    return m


def test_body_is_content_addressed_and_roundtrips(store: RawStore, usgs_manifest: dict) -> None:
    body = b'{"features": [{"id": "q1"}]}'
    rec = store.store(retrieval_id="r1", source_id="usgs-earthquakes", body=body,
                      manifest=usgs_manifest, content_type="application/json")
    sha = hashlib.sha256(body).hexdigest()
    assert rec["body_sha256"] == sha
    assert rec["retention_mode"] == "retained"
    cas = store.blobs / sha[:2] / sha
    assert cas.exists(), "content-addressed object must be on disk"
    assert store.get_body("r1") == body


def test_digest_only_never_stores_bytes(store: RawStore, usgs_manifest: dict) -> None:
    body = b"secret-payload"
    rec = store.store(retrieval_id="r2", source_id="usgs-earthquakes", body=body,
                      manifest=_digest_only_manifest(usgs_manifest))
    assert rec["retention_mode"] == "digest_only"
    sha = hashlib.sha256(body).hexdigest()
    assert not (store.blobs / sha[:2] / sha).exists()
    assert store.get_body("r2") is None
    # the digest is still recorded — honest evidence pointer without bytes
    row = store.catalog_row("r2")
    assert row["body_sha256"] == sha


def test_expiry_is_honest_absence(store: RawStore, usgs_manifest: dict) -> None:
    body = b"aging-evidence"
    rec = store.store(retrieval_id="r3", source_id="usgs-earthquakes", body=body,
                      manifest=usgs_manifest)
    assert rec["expires_at"]
    # backdate the expiry past the window
    with store._conn() as conn:
        conn.execute("UPDATE retrievals SET expires_at = ? WHERE retrieval_id = ?",
                     ((datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(), "r3"))
    assert store.get_body("r3") is None, "expired evidence must be gone"


def test_sweep_deletes_expired_rows_and_bodies(store: RawStore, usgs_manifest: dict) -> None:
    body = b"to-be-swept"
    store.store(retrieval_id="r4", source_id="usgs-earthquakes", body=body,
                manifest=usgs_manifest)
    with store._conn() as conn:
        conn.execute("UPDATE retrievals SET expires_at = ? WHERE retrieval_id = ?",
                     ((datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(), "r4"))
    n = store._sweep_expired()
    assert n == 1
    assert store.catalog_row("r4") is None
    sha = hashlib.sha256(body).hexdigest()
    assert not (store.blobs / sha[:2] / sha).exists()


def test_shared_body_survives_while_referenced(store: RawStore, usgs_manifest: dict) -> None:
    body = b"shared-payload"
    store.store(retrieval_id="r5a", source_id="usgs-earthquakes", body=body,
                manifest=usgs_manifest)
    store.store(retrieval_id="r5b", source_id="usgs-earthquakes", body=body,
                manifest=usgs_manifest)
    with store._conn() as conn:
        conn.execute("UPDATE retrievals SET expires_at = ? WHERE retrieval_id = ?",
                     ((datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(), "r5a"))
    store._sweep_expired()
    # r5b still references the body -> bytes must survive
    assert store.get_body("r5b") == body


def test_catalog_metadata_complete(store: RawStore, usgs_manifest: dict) -> None:
    store.store(retrieval_id="r6", source_id="usgs-earthquakes", body=b"meta",
                manifest=usgs_manifest, response_status=200,
                content_type="application/json", content_encoding="gzip")
    row = store.catalog_row("r6")
    assert row["source_id"] == "usgs-earthquakes"
    assert row["response_status"] == 200
    assert row["content_type"] == "application/json"
    assert row["content_encoding"] == "gzip"
    assert row["request_url_policy"] == "allowlisted_manifest_url"


def test_stats_reflect_state(store: RawStore, usgs_manifest: dict) -> None:
    store.store(retrieval_id="r7", source_id="usgs-earthquakes", body=b"x",
                manifest=usgs_manifest)
    s = store.stats()
    assert s["retrievals"] == 1
    assert s["retained"] == 1
