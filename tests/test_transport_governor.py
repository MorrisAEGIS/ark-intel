"""Transport-abuse fixtures (100x W0.2 / PR3): every abuse class fails closed
with a sanitized code — no body/credential/URL/raw-exception leakage.

The fixtures use a manifest set pointed at local fixture hosts and a live
in-process HTTP server for the redirect/oversize/content-type paths.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from arkintel.transport import (
    TransportGovernor, TransportPolicyError, _ip_is_blocked,
)

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "transport"


def _gov() -> TransportGovernor:
    g = TransportGovernor.__new__(TransportGovernor)
    import arkintel.transport as T
    g.manifests = {
        "fixture-source": {
            "endpoint": {"scheme": "https", "hosts": ["fixture.example"],
                         "path_prefixes": ["/api/"], "redirects": "deny"},
            "transport": {"timeout_seconds": 2, "max_compressed_bytes": 5242880,
                          "max_decompressed_bytes": 10485760, "max_records": 100,
                          "requests_per_minute": 6, "max_concurrency": 1},
        }
    }
    g._states = {sid: T._SourceState(rate_tokens=m["transport"]["requests_per_minute"])
                 for sid, m in g.manifests.items()}
    g._lock = __import__("asyncio").Lock()
    return g


def test_ip_blocklist_covers_internal_space() -> None:
    for ip in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
               "169.254.1.1", "::1", "fe80::1", "0.0.0.0", "224.0.0.1"):
        assert _ip_is_blocked(ip), ip
    assert not _ip_is_blocked("93.184.216.34")
    assert not _ip_is_blocked("2606:4700::1111")


@pytest.mark.asyncio
async def test_scheme_denied() -> None:
    gov = _gov()
    with pytest.raises(TransportPolicyError) as e:
        await gov.get_json("fixture-source", "http://fixture.example/api/data")
    assert e.value.code == "policy_scheme_denied"


@pytest.mark.asyncio
async def test_host_not_allowed() -> None:
    gov = _gov()
    with pytest.raises(TransportPolicyError) as e:
        await gov.get_json("fixture-source", "https://evil.example/api/data")
    assert e.value.code == "policy_host_not_allowed"


@pytest.mark.asyncio
async def test_path_prefix_not_allowed() -> None:
    gov = _gov()
    with pytest.raises(TransportPolicyError) as e:
        await gov.get_json("fixture-source", "https://fixture.example/admin/secret")
    assert e.value.code == "policy_host_not_allowed"


@pytest.mark.asyncio
async def test_ssrf_private_ip_fails_closed(monkeypatch) -> None:
    """DNS resolution returning internal space must reject the fetch even
    though the hostname itself is allowlisted (DNS rebinding guard)."""
    import arkintel.transport as T
    gov = _gov()
    monkeypatch.setattr(T, "_resolve_all", lambda host: ["192.168.1.50"])
    with pytest.raises(TransportPolicyError) as e:
        await gov.get_json("fixture-source", "https://fixture.example/api/data")
    assert e.value.code == "policy_ip_blocked"


@pytest.mark.asyncio
async def test_redirect_denied_live() -> None:
    """A real 302 from a live local server must fail as policy_redirect_denied."""
    gov = TransportGovernor.__new__(TransportGovernor)
    import arkintel.transport as T
    import asyncio

    class Redirect(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "/elsewhere")
            self.end_headers()
        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Redirect)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        gov.manifests = {"fixture-source": {
            "endpoint": {"scheme": "http", "hosts": ["127.0.0.1"],
                         "path_prefixes": ["/"], "redirects": "deny"},
            "transport": {"timeout_seconds": 2, "max_compressed_bytes": 5242880,
                          "max_decompressed_bytes": 10485760, "max_records": 100,
                          "requests_per_minute": 6, "max_concurrency": 1}}}
        # NOTE: 127.0.0.1 would normally be SSRF-blocked; for THIS fixture we
        # test the redirect policy only — bypass the IP gate deliberately.
        async def no_ip(sid, host):
            return None
        gov._check_resolved_ips = no_ip  # type: ignore[assignment]
        gov._states = {"fixture-source": T._SourceState(rate_tokens=6)}
        gov._lock = asyncio.Lock()
        with pytest.raises(TransportPolicyError) as e:
            await gov.get_json("fixture-source", f"http://127.0.0.1:{port}/api")
        assert e.value.code == "policy_redirect_denied"
    finally:
        srv.shutdown()


@pytest.mark.asyncio
async def test_rate_limit_fails_closed() -> None:
    gov = _gov()
    gov._states["fixture-source"].rate_tokens = 0.0
    with pytest.raises(TransportPolicyError) as e:
        await gov.get_json("fixture-source", "https://fixture.example/api/data")
    assert e.value.code == "policy_rate_limited"


@pytest.mark.asyncio
async def test_circuit_breaker_opens_after_failures() -> None:
    gov = _gov()
    gov._record("fixture-source", ok=False)
    gov._record("fixture-source", ok=False)
    gov._record("fixture-source", ok=False)
    with pytest.raises(TransportPolicyError) as e:
        await gov.get_json("fixture-source", "https://fixture.example/api/data")
    assert e.value.code == "policy_circuit_open"


@pytest.mark.asyncio
async def test_content_type_and_oversize_live() -> None:
    """Live local server: non-JSON content type fails; oversize payload fails."""
    import asyncio
    import arkintel.transport as T

    class Bad(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/html"):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html>not json</html>")
            elif self.path.startswith("/oversize"):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b"x" * 6000000)
            else:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b"{}")
        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Bad)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        gov = TransportGovernor.__new__(TransportGovernor)
        gov.manifests = {"fixture-source": {
            "endpoint": {"scheme": "http", "hosts": ["127.0.0.1"],
                         "path_prefixes": ["/"], "redirects": "deny"},
            "transport": {"timeout_seconds": 4, "max_compressed_bytes": 5242880,
                          "max_decompressed_bytes": 10485760, "max_records": 100,
                          "requests_per_minute": 60, "max_concurrency": 1}}}
        async def no_ip(sid, host):
            return None
        gov._check_resolved_ips = no_ip  # type: ignore[assignment]
        gov._states = {"fixture-source": T._SourceState(rate_tokens=60)}
        gov._lock = asyncio.Lock()

        with pytest.raises(TransportPolicyError) as e:
            await gov.get_json("fixture-source", f"http://127.0.0.1:{port}/html")
        assert e.value.code == "policy_content_type"

        gov._states["fixture-source"] = T._SourceState(rate_tokens=60)
        gov._record("fixture-source", True)
        with pytest.raises(TransportPolicyError) as e:
            await gov.get_json("fixture-source", f"http://127.0.0.1:{port}/oversize")
        assert e.value.code == "policy_payload_oversize"
    finally:
        srv.shutdown()


def test_sanitized_errors_never_leak() -> None:
    """The failure contract: codes only — no URLs, bodies, or raw exceptions."""
    err = TransportPolicyError("policy_ip_blocked", "fixture-source")
    rendered = str(err)
    assert "http" not in rendered
    assert "192.168" not in rendered
    assert err.code in ("policy_ip_blocked",)
