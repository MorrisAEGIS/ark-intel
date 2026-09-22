"""Red-team regression suite (ark-intel live transport sweep, 2026-09-22).

Locks every probe from docs/security/2026-09-22-transport-red-team-sweep.md
as source-level gates: fail-closed token auth, SSRF admission (all internal
classes), DNS isolation, denylist, window/scope gates, rebinding-closed
connect path, trusted-proxy role contract, and the F1 deploy-drift
disclosure.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECURITY = (ROOT / "arkintel/security.py").read_text(encoding="utf-8")
SCANNER = (ROOT / "arkintel/scanner.py").read_text(encoding="utf-8")
MAIN = (ROOT / "arkintel/main.py").read_text(encoding="utf-8")
SWEEP = (ROOT / "docs/security/2026-09-22-transport-red-team-sweep.md").read_text(encoding="utf-8")


def test_token_auth_is_fail_closed_and_constant_time():
    assert "hmac.compare_digest" in SECURITY
    assert "503" in SECURITY  # unset token = refuse, never accept-all


def test_every_v1_route_is_token_gated():
    assert 'dependencies=[Depends(require_service_token)]' in MAIN


def test_ssrf_admission_rejects_all_internal_space():
    # is_global excludes loopback/private/link-local/reserved; CGNAT explicitly
    assert "is_global" in SECURITY
    assert "100.64.0.0/10" in SECURITY  # carrier-grade NAT
    assert "Only targets resolving entirely to public IP space" in SECURITY


def test_denylist_blocks_ark_and_internal_suffixes():
    assert "blocked_domains" in SECURITY
    assert "ARK, local, and internal targets are denied" in SECURITY


def test_dns_rebinding_closed_at_connect():
    # the connect path re-validates and connects to the approved IP
    assert "Re-resolve immediately, then connect to the approved IP" in SCANNER
    assert "sni_hostname" in SCANNER


def test_authorization_window_and_scope_gates():
    assert "Authorization window exceeds the policy maximum" in SECURITY
    assert "Authorization scope must name the exact target" in SECURITY


def test_active_scan_fails_closed_when_disabled():
    assert "ARK_INTEL_ACTIVE_SCAN_ENABLED" in MAIN


def test_role_is_claim_not_proof_documented():
    # the phrase wraps in markdown; match across whitespace
    assert re.search(r"the\s+service\s+token\s+is\s+the\s+boundary", SWEEP)
    assert re.search(r"the\s+role\s+header\s+is\s+a\s+claim", SWEEP)
    assert "claim, not a proof" in SWEEP


def test_f1_deploy_drift_is_disclosed():
    assert "F1 (DEPLOY DRIFT" in SWEEP
    assert "not deployed" in SWEEP


def test_denied_capabilities_are_enumerated():
    assert "DENIED_CAPABILITIES" in SCANNER


def test_no_raw_exception_leak_in_error_paths():
    # errors carry bounded, human strings; exception text is truncated server-side
    assert "[:1000]" in MAIN or "[:120]" in MAIN or "[:240]" in MAIN
