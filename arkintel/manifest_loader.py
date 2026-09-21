"""Loader/validator for ark.intel.source.v1 admission manifests.

Admission policy becomes data (the 100x plan W1.1): each source's policy is
a schema-validated manifest reviewed independently of adapter code. The
loader is the single entry point — no constructor-string policy remains.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import jsonschema

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "ark.intel.source.v1.schema.json"
MANIFESTS_DIR = Path(__file__).resolve().parent / "manifests"

_SCHEMA_CACHE: dict[str, Any] | None = None


def _schema() -> dict[str, Any]:
    global _SCHEMA_CACHE
    if _SCHEMA_CACHE is None:
        _SCHEMA_CACHE = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return _SCHEMA_CACHE


def manifest_digest(manifest: dict[str, Any]) -> str:
    """Stable sha256 over the review-relevant content (excludes nothing yet:
    manifests carry no volatile timestamps by contract; reviewed_at is a
    date, not a generation instant)."""
    return "sha256:" + hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def load_manifest(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    jsonschema.validate(raw, _schema())
    return raw


def load_all_manifests(directory: Path | None = None) -> dict[str, dict[str, Any]]:
    directory = directory or MANIFESTS_DIR
    out: dict[str, dict[str, Any]] = {}
    for path in sorted(directory.glob("*.json")):
        manifest = load_manifest(path)
        if manifest["id"] in out:
            raise ValueError(f"duplicate manifest id: {manifest['id']}")
        out[manifest["id"]] = manifest
    return out


def catalog_from_manifests() -> list[dict[str, Any]]:
    """Compatibility projection: manifests -> the legacy source_catalog shape
    so the migration changes no external behavior."""
    manifests = load_all_manifests()
    return [
        {
            "id": m["id"],
            "label": m["label"],
            "group": m["group"],
            "endpoint": "/".join([m["endpoint"]["scheme"] + "://" + m["endpoint"]["hosts"][0],
                                  *m["endpoint"]["path_prefixes"]]).rstrip("/"),
            "license": m["license"]["identifier"],
            "truth_class": m["truth"]["class"],
            "availability": m.get("availability", "ready"),
            "admission_note": m.get("admission_note"),
        }
        for m in manifests.values()
    ]
