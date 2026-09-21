"""Bounded raw-evidence retention (100x W1.3 / PR5).

Exact response bodies are stored as compressed, content-addressed objects
on the existing ark-intel data volume; retrieval metadata lives in a
SQLite WAL catalog. No new database service (plan rule) — the same
volume that already holds ark-intel.sqlite3.

Retention is bounded per source by the ark.intel.source.v1 manifest:
  raw_hours  > 0 -> body retained, expires after raw_hours
  raw_hours == 0 -> digest_only (no body stored; the observation keeps
                    its raw_sha256 but no bytes survive)
Sweep is on-access (amortized): each store op may sweep a bounded batch
of expired objects + catalog rows. Nothing ever grows unbounded.
"""
from __future__ import annotations

import gzip
import hashlib
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

DEFAULT_ROOT = Path(os.environ.get("ARK_INTEL_DATA", "/var/lib/ark-intel"))
BLOBS_DIRNAME = "raw-evidence"
CATALOG_NAME = "raw-evidence.sqlite3"
SWEEP_BATCH = 64


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RawStore:
    def __init__(self, root: Path | None = None):
        self.root = Path(root) if root else DEFAULT_ROOT
        self.blobs = self.root / BLOBS_DIRNAME
        self.blobs.mkdir(parents=True, exist_ok=True)
        self.catalog_path = self.root / CATALOG_NAME
        self._lock = threading.Lock()
        self._init_catalog()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.catalog_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_catalog(self) -> None:
        with self._lock, self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS retrievals (
                    retrieval_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    status TEXT NOT NULL,
                    request_url_policy TEXT NOT NULL,
                    response_status INTEGER,
                    content_type TEXT,
                    content_encoding TEXT,
                    body_sha256 TEXT NOT NULL,
                    body_bytes INTEGER NOT NULL,
                    body_compressed_bytes INTEGER NOT NULL,
                    retention_mode TEXT NOT NULL,
                    expires_at TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_retrievals_expiry
                ON retrievals (expires_at)
            """)

    # ── store ───────────────────────────────────────────────────────
    def store(
        self,
        *,
        retrieval_id: str,
        source_id: str,
        body: bytes,
        manifest: dict[str, Any],
        response_status: int | None = 200,
        content_type: str | None = None,
        content_encoding: str | None = None,
        started_at: datetime | None = None,
    ) -> dict[str, Any]:
        """Store one retrieval: content-addressed body + catalog row.
        retention_mode: 'retained' (raw_hours > 0) or 'digest_only'."""
        sha = hashlib.sha256(body).hexdigest()
        raw_hours = int(manifest["retention"]["raw_hours"])
        mode = "retained" if raw_hours > 0 else "digest_only"
        expires = _utcnow() + timedelta(hours=raw_hours) if raw_hours > 0 else None
        started = started_at or _utcnow()

        if mode == "retained":
            cas_path = self.blobs / sha[:2] / sha
            cas_path.parent.mkdir(parents=True, exist_ok=True)
            compressed = gzip.compress(body, mtime=0)  # deterministic
            if not cas_path.exists():
                tmp = cas_path.with_suffix(".tmp")
                tmp.write_bytes(compressed)
                os.replace(tmp, cas_path)

        with self._lock, self._conn() as conn:
            conn.execute("""
                INSERT INTO retrievals
                    (retrieval_id, source_id, started_at, completed_at,
                     status, request_url_policy, response_status, content_type,
                     content_encoding, body_sha256, body_bytes,
                     body_compressed_bytes, retention_mode, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(retrieval_id) DO UPDATE SET
                    completed_at=excluded.completed_at,
                    status=excluded.status,
                    response_status=excluded.response_status,
                    content_type=excluded.content_type,
                    content_encoding=excluded.content_encoding,
                    body_sha256=excluded.body_sha256,
                    body_bytes=excluded.body_bytes,
                    body_compressed_bytes=excluded.body_compressed_bytes,
                    retention_mode=excluded.retention_mode,
                    expires_at=excluded.expires_at
            """, (
                retrieval_id, source_id, started.isoformat(),
                _utcnow().isoformat(), "ok", "allowlisted_manifest_url",
                response_status, content_type, content_encoding,
                sha, len(body), len(gzip.compress(body, mtime=0)),
                mode, expires.isoformat() if expires else None,
            ))
        # amortized bounded sweep
        self._sweep_expired()
        return {
            "retrieval_id": retrieval_id,
            "body_sha256": sha,
            "retention_mode": mode,
            "expires_at": expires.isoformat() if expires else None,
        }

    # ── fetch ───────────────────────────────────────────────────────
    def get_body(self, retrieval_id: str) -> bytes | None:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT body_sha256, retention_mode, expires_at FROM retrievals WHERE retrieval_id = ?",
                (retrieval_id,)).fetchone()
        if not row:
            return None
        sha, mode, expires = row
        if mode != "retained":
            return None  # digest_only: bytes never stored, never fabricated
        if expires and datetime.fromisoformat(expires) < _utcnow():
            return None  # expired evidence is gone — honest absence
        cas_path = self.blobs / sha[:2] / sha
        if not cas_path.exists():
            return None
        return gzip.decompress(cas_path.read_bytes())

    def catalog_row(self, retrieval_id: str) -> dict[str, Any] | None:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM retrievals WHERE retrieval_id = ?", (retrieval_id,)).fetchone()
        if not row:
            return None
        cols = ["retrieval_id", "source_id", "started_at", "completed_at",
                "status", "request_url_policy", "response_status", "content_type",
                "content_encoding", "body_sha256", "body_bytes",
                "body_compressed_bytes", "retention_mode", "expires_at"]
        return dict(zip(cols, row))

    # ── boundedness ──────────────────────────────────────────────────
    def _sweep_expired(self, batch: int = SWEEP_BATCH) -> int:
        """Delete expired catalog rows + orphaned bodies (amortized)."""
        now = _utcnow().isoformat()
        with self._lock, self._conn() as conn:
            expired = conn.execute(
                "SELECT retrieval_id, body_sha256, retention_mode FROM retrievals "
                "WHERE expires_at IS NOT NULL AND expires_at < ? LIMIT ?",
                (now, batch)).fetchall()
            for rid, sha, mode in expired:
                conn.execute("DELETE FROM retrievals WHERE retrieval_id = ?", (rid,))
                if mode == "retained":
                    cas_path = self.blobs / sha[:2] / sha
                    if cas_path.exists():
                        # only delete if no other row still references the body
                        still = conn.execute(
                            "SELECT COUNT(*) FROM retrievals WHERE body_sha256 = ?",
                            (sha,)).fetchone()[0]
                        if still == 0:
                            cas_path.unlink(missing_ok=True)
        return len(expired)

    def stats(self) -> dict[str, Any]:
        with self._lock, self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM retrievals").fetchone()[0]
            retained = conn.execute(
                "SELECT COUNT(*) FROM retrievals WHERE retention_mode = 'retained'").fetchone()[0]
            expired = conn.execute(
                "SELECT COUNT(*) FROM retrievals WHERE expires_at IS NOT NULL AND expires_at < ?",
                (_utcnow().isoformat(),)).fetchone()[0]
        return {"retrievals": total, "retained": retained, "expired_pending_sweep": expired}
