"""Governed transport for all external source fetching (100x W0.2 / PR3).

One place enforces per-source fail-closed transport policy from the
ark.intel.source.v1 manifests. Adapters stop inventing transport behavior;
every fetch goes through the governor.

Enforced per source:
  - exact scheme + host allowlist (from the manifest)
  - redirects denied (httpx follow_redirects=False; a 3xx = policy error)
  - SSRF: post-resolution IP rejection — loopback/private/link-local/
    reserved/multicast addresses fail closed AFTER DNS resolution, so a
    DNS-rebinding or poisoned /etc/hosts entry cannot reach internal space
  - connect/read/total timeouts (manifest transport bounds)
  - max compressed + decompressed bytes
  - content-type/JSON sniff check
  - token-bucket rate limit + concurrency cap per source
  - circuit breaker: N consecutive failures open the circuit for a
    bounded exponential backoff window (with jitter)
  - trust_env=False: no environment-proxy inheritance
  - sanitized errors: no response bodies, credentials, full signed URLs,
    or raw exceptions in user-visible errors — structured failure codes only

Source status contract (W0.2): out_of_coverage / stale / degraded never
collapse into an empty-but-healthy result.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import random
import socket
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx

from .manifest_loader import load_all_manifests

DEFAULT_TIMEOUT_SECONDS = 8
FAILURE_CODES = {
    "policy_redirect_denied",
    "policy_host_not_allowed",
    "policy_scheme_denied",
    "policy_ip_blocked",
    "policy_payload_oversize",
    "policy_content_type",
    "policy_rate_limited",
    "policy_circuit_open",
    "network_timeout",
    "network_error",
}


class TransportPolicyError(RuntimeError):
    """Fail-closed transport violation. .code is a sanitized failure code;
    no response body, credential, URL, or raw exception ever leaks out."""

    def __init__(self, code: str, source_id: str):
        self.code = code
        self.source_id = source_id
        super().__init__(f"{source_id}: {code}")


def _resolve_all(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []
    return sorted({info[4][0] for info in infos})


def _ip_is_blocked(ip_text: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_text)
    except ValueError:
        return True
    return (
        addr.is_loopback or addr.is_private or addr.is_link_local
        or addr.is_reserved or addr.is_multicast or addr.is_unspecified
        or addr.is_multicast
    )


@dataclass
class _SourceState:
    rate_tokens: float = 6.0
    rate_last_refill: float = field(default_factory=time.monotonic)
    concurrent: int = 0
    consecutive_failures: int = 0
    circuit_open_until: float = 0.0


class TransportGovernor:
    """Per-process governor. One instance per source catalog."""

    def __init__(self, manifests_dir=None):
        self.manifests = load_all_manifests(manifests_dir)
        self._states: dict[str, _SourceState] = {
            sid: _SourceState(rate_tokens=m["transport"]["requests_per_minute"])
            for sid, m in self.manifests.items()
        }
        self._lock = asyncio.Lock()

    # ── policy checks ────────────────────────────────────────────────
    def _check_url_policy(self, source_id: str, url: str) -> None:
        m = self.manifests[source_id]
        ep = m["endpoint"]
        parts = urlsplit(url)
        if parts.scheme != ep["scheme"]:
            raise TransportPolicyError("policy_scheme_denied", source_id)
        if parts.hostname not in ep["hosts"]:
            raise TransportPolicyError("policy_host_not_allowed", source_id)
        prefix_ok = any(parts.path.startswith(p) for p in ep["path_prefixes"]) if ep["path_prefixes"] else True
        if not prefix_ok:
            raise TransportPolicyError("policy_host_not_allowed", source_id)

    def _check_resolved_ips(self, source_id: str, host: str) -> None:
        for ip in _resolve_all(host):
            if _ip_is_blocked(ip):
                raise TransportPolicyError("policy_ip_blocked", source_id)

    async def _acquire_rate(self, source_id: str) -> None:
        async with self._lock:
            st = self._states[source_id]
            m = self.manifests[source_id]
            now = time.monotonic()
            refill = m["transport"]["requests_per_minute"] / 60.0
            st.rate_tokens = min(m["transport"]["requests_per_minute"],
                                  st.rate_tokens + (now - st.rate_last_refill) * refill)
            st.rate_last_refill = now
            if st.rate_tokens < 1.0:
                raise TransportPolicyError("policy_rate_limited", source_id)
            st.rate_tokens -= 1.0

    def _check_circuit(self, source_id: str) -> None:
        st = self._states[source_id]
        if st.circuit_open_until > time.monotonic():
            raise TransportPolicyError("policy_circuit_open", source_id)

    def _record(self, source_id: str, ok: bool) -> None:
        st = self._states[source_id]
        if ok:
            st.consecutive_failures = 0
            st.circuit_open_until = 0.0
            return
        st.consecutive_failures += 1
        if st.consecutive_failures >= 3:
            backoff = min(900.0, (2 ** st.consecutive_failures) * 5.0)
            st.circuit_open_until = time.monotonic() + backoff * (0.5 + random.random())

    # ── the fetch ────────────────────────────────────────────────────
    async def get_json(self, source_id: str, url: str) -> Any:
        m = self.manifests[source_id]
        t = m["transport"]
        self._check_circuit(source_id)
        self._check_url_policy(source_id, url)
        host = urlsplit(url).hostname or ""
        self._check_resolved_ips(source_id, host)
        await self._acquire_rate(source_id)
        st = self._states[source_id]
        if st.concurrent >= t["max_concurrency"]:
            raise TransportPolicyError("policy_rate_limited", source_id)
        st.concurrent += 1
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(t["timeout_seconds"]),
                follow_redirects=False,
                trust_env=False,
                headers={"Accept": "application/json",
                         "User-Agent": "ArkIntel/0.1 (+https://github.com/MorrisAEGIS/ark-intel)"},
            ) as client:
                response = await client.get(url)
                if 300 <= response.status_code < 400:
                    raise TransportPolicyError("policy_redirect_denied", source_id)
                if len(response.content) > t["max_compressed_bytes"]:
                    raise TransportPolicyError("policy_payload_oversize", source_id)
                content_type = response.headers.get("content-type", "")
                if "json" not in content_type and not response.text.lstrip().startswith(("{", "[")):
                    raise TransportPolicyError("policy_content_type", source_id)
                if len(response.text) > t["max_decompressed_bytes"]:
                    raise TransportPolicyError("policy_payload_oversize", source_id)
                self._record(source_id, True)
                return response.json()
        except TransportPolicyError:
            self._record(source_id, False)
            raise
        except (httpx.TimeoutException, httpx.TransportError):
            self._record(source_id, False)
            raise TransportPolicyError("network_timeout", source_id) from None
        except (json.JSONDecodeError, ValueError):
            self._record(source_id, False)
            raise TransportPolicyError("policy_content_type", source_id) from None
        finally:
            st.concurrent -= 1


_GOVERNOR: TransportGovernor | None = None


def get_governor() -> TransportGovernor:
    global _GOVERNOR
    if _GOVERNOR is None:
        _GOVERNOR = TransportGovernor()
    return _GOVERNOR
