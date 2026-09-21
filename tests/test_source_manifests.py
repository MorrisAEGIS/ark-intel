"""PR2 (100x W1.1): source admission manifests replace constructor-string policy.

Exit criterion: all 13 sources load with UNCHANGED ready/credential/
provenance/disabled posture. No new source enabled.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
from arkintel.manifest_loader import (  # noqa: E402
    catalog_from_manifests, load_all_manifests, load_manifest, manifest_digest,
)
from arkintel.sources import SOURCES, SOURCE_INDEX  # noqa: E402

MANIFESTS = ROOT / "arkintel" / "manifests"


def test_all_13_manifests_load_and_validate() -> None:
    manifests = load_all_manifests()
    assert len(manifests) == 13


def test_manifest_ids_match_legacy_catalog_exactly() -> None:
    manifests = load_all_manifests()
    assert set(manifests) == set(SOURCE_INDEX)


def test_availability_posture_unchanged() -> None:
    """The plan's exit gate: ready/credential_required/policy_disabled
    posture is identical to the legacy constructor catalog."""
    manifests = load_all_manifests()
    for src in SOURCES:
        m = manifests[src.id]
        assert m["availability"] == src.availability, src.id


def test_truth_class_unchanged() -> None:
    manifests = load_all_manifests()
    for src in SOURCES:
        m = manifests[src.id]
        assert m["truth"]["class"] == src.truth_class, src.id


def test_disabled_and_pending_sources_carry_reasons() -> None:
    """The two non-ready classes stay exactly as the legacy catalog holds
    them: osiris-submarine-cables is provenance_pending (bundled upstream
    data unserved until license verification), osiris-cctv is
    policy_disabled (unsafe credential/TLS patterns)."""
    manifests = load_all_manifests()
    assert manifests["osiris-submarine-cables"]["availability"] == "provenance_pending"
    assert "license is verified" in manifests["osiris-submarine-cables"]["admission_note"]
    assert manifests["osiris-cctv"]["availability"] == "policy_disabled"
    assert "unsafe credential and TLS patterns" in manifests["osiris-cctv"]["admission_note"]


def test_credential_required_sources_carry_governance_notes() -> None:
    manifests = load_all_manifests()
    assert manifests["cloudflare-radar"]["credentials"]["class"] == "api_token_governed"
    assert manifests["global-fishing-watch"]["credentials"]["class"] == "api_token_governed"


def test_digest_is_stable_and_deterministic() -> None:
    m1 = load_manifest(MANIFESTS / "usgs-earthquakes.json")
    m2 = load_manifest(MANIFESTS / "usgs-earthquakes.json")
    assert manifest_digest(m1) == manifest_digest(m2)


def test_no_new_source_enabled() -> None:
    """Wave-1 rule: no provider enablement sneaks in with the migration."""
    manifests = load_all_manifests()
    ready = {k for k, v in manifests.items() if v["availability"] == "ready"}
    legacy_ready = {s.id for s in SOURCES if s.availability == "ready"}
    assert ready == legacy_ready


def test_compat_projection_covers_the_catalog() -> None:
    catalog = catalog_from_manifests()
    assert len(catalog) == 13
    ids = {c["id"] for c in catalog}
    assert ids == set(SOURCE_INDEX)
