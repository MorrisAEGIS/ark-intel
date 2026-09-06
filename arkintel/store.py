"""Small durable job ledger; ArkGrid remains the case-system authority."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class JobStore:
    def __init__(self, path: Path, retention_days: int = 30):
        self.path = path
        self.retention_days = retention_days
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    result_json TEXT,
                    error TEXT
                )
                """
            )
            db.execute("CREATE INDEX IF NOT EXISTS jobs_created_at_idx ON jobs(created_at)")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    def prune(self) -> None:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.retention_days)).isoformat()
        with self._connect() as db:
            db.execute("DELETE FROM jobs WHERE created_at < ?", (cutoff,))

    def create(self, request: dict[str, Any]) -> dict[str, Any]:
        job_id = str(uuid.uuid4())
        timestamp = _now()
        with self._connect() as db:
            db.execute(
                "INSERT INTO jobs (id, state, created_at, updated_at, request_json) VALUES (?, 'queued', ?, ?, ?)",
                (job_id, timestamp, timestamp, json.dumps(request, sort_keys=True, default=str)),
            )
        return self.get(job_id)

    def update(self, job_id: str, *, state: str, result: dict[str, Any] | None = None, error: str | None = None) -> None:
        with self._connect() as db:
            db.execute(
                "UPDATE jobs SET state = ?, updated_at = ?, result_json = ?, error = ? WHERE id = ?",
                (state, _now(), json.dumps(result, sort_keys=True, default=str) if result is not None else None, error, job_id),
            )

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if row is None:
            return None
        return {
            "id": row["id"],
            "state": row["state"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "request": json.loads(row["request_json"]),
            "result": json.loads(row["result_json"]) if row["result_json"] else None,
            "error": row["error"],
        }
