"""Bounded investigation helpers with no exploit, brute-force, or port-sweep paths."""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

import httpx

from .config import get_settings
from .schemas import ScanPlan, ScanRequest
from .security import ValidatedTarget, validate_authorization, validate_public_target


ACTIVE_TYPES = {"quick", "ssl", "headers", "tech"}
PASSIVE_TYPES = {"rdns", "subdomains", "whois", "geoloc", "vuln"}
DENIED_CAPABILITIES = [
    "65K/deep port sweeps",
    "credential brute force",
    "exploit execution",
    "arbitrary service banners",
    "traceroute",
    "private, loopback, carrier-grade NAT, and ARK targets",
]


async def build_scan_plan(request: ScanRequest) -> tuple[ScanPlan, ValidatedTarget]:
    target = await validate_public_target(request.target)
    validate_authorization(target, request.authorization)
    plan = ScanPlan(
        target=request.target,
        host=target.host,
        resolved_ips=list(target.ips),
        scan_types=request.scan_types,
        active_steps=[name for name in request.scan_types if name in ACTIVE_TYPES],
        passive_steps=[name for name in request.scan_types if name in PASSIVE_TYPES],
        denied_capabilities=DENIED_CAPABILITIES,
        authorization_reference=request.authorization.reference,
        authorization_expires_at=request.authorization.expires_at,
    )
    return plan, target


def _ip_netloc(address: str, port: int | None = None) -> str:
    host = f"[{address}]" if ":" in address else address
    return f"{host}:{port}" if port is not None else host


async def _target_http(target: ValidatedTarget) -> tuple[str, httpx.Response]:
    # Re-resolve immediately, then connect to the approved IP instead of resolving
    # the hostname again inside the HTTP client. This closes the DNS-rebinding gap.
    fresh = await validate_public_target(target.host)
    timeout = httpx.Timeout(get_settings().source_timeout_seconds)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False) as client:
        errors: list[str] = []
        for scheme in ("https", "http"):
            display_url = f"{scheme}://{fresh.host}/"
            for address in fresh.ips[:8]:
                request_url = f"{scheme}://{_ip_netloc(address)}/"
                request_headers = {
                    "Host": fresh.host,
                    "User-Agent": "ArkIntel/0.1 authorized-security-review",
                }
                try:
                    response = await client.head(
                        request_url,
                        headers=request_headers,
                        extensions={"sni_hostname": fresh.host},
                    )
                    if response.status_code in {405, 501}:
                        response = await client.get(
                            request_url,
                            headers={**request_headers, "Range": "bytes=0-4095"},
                            extensions={"sni_hostname": fresh.host},
                        )
                    return display_url, response
                except (httpx.HTTPError, ssl.SSLError) as exc:
                    errors.append(f"{scheme}://{address}: {exc}")
        raise RuntimeError("; ".join(errors))


async def _quick(target: ValidatedTarget) -> dict[str, Any]:
    url, response = await _target_http(target)
    return {
        "resolved_ips": list(target.ips),
        "url": url,
        "status_code": response.status_code,
        "reachable": response.status_code < 500,
        "redirect_location": response.headers.get("location"),
    }


def _ssl_sync(host: str, ips: tuple[str, ...]) -> dict[str, Any]:
    context = ssl.create_default_context()
    errors: list[str] = []
    for address in ips[:8]:
        try:
            with socket.create_connection((address, 443), timeout=get_settings().source_timeout_seconds) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    certificate = tls.getpeercert()
                    return {
                        "protocol": tls.version(),
                        "cipher": tls.cipher()[0] if tls.cipher() else None,
                        "subject": dict(item[0] for item in certificate.get("subject", [])),
                        "issuer": dict(item[0] for item in certificate.get("issuer", [])),
                        "not_before": certificate.get("notBefore"),
                        "not_after": certificate.get("notAfter"),
                        "subject_alt_name_count": len(certificate.get("subjectAltName", [])),
                    }
        except (OSError, ssl.SSLError) as exc:
            errors.append(f"{address}: {exc}")
    raise RuntimeError("; ".join(errors))


async def _ssl(target: ValidatedTarget) -> dict[str, Any]:
    fresh = await validate_public_target(target.host)
    return await asyncio.to_thread(_ssl_sync, fresh.host, fresh.ips)


async def _headers(target: ValidatedTarget) -> dict[str, Any]:
    url, response = await _target_http(target)
    allow = {
        "server",
        "content-type",
        "content-security-policy",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
        "cache-control",
    }
    return {
        "url": url,
        "status_code": response.status_code,
        "headers": {key.lower(): value[:1000] for key, value in response.headers.items() if key.lower() in allow},
    }


async def _tech(target: ValidatedTarget) -> dict[str, Any]:
    data = await _headers(target)
    headers = data["headers"]
    hints: list[str] = []
    server = headers.get("server", "")
    if server:
        hints.append(f"server:{server}")
    content_type = headers.get("content-type", "")
    if content_type:
        hints.append(f"content-type:{content_type.split(';', 1)[0]}")
    if "content-security-policy" in headers:
        hints.append("csp:present")
    if "strict-transport-security" in headers:
        hints.append("hsts:present")
    return {**data, "technology_hints": hints, "method": "header inference only"}


def _rdns_sync(ips: tuple[str, ...]) -> list[dict[str, Any]]:
    rows = []
    for address in ips:
        try:
            hostname, aliases, _ = socket.gethostbyaddr(address)
            rows.append({"ip": address, "hostname": hostname, "aliases": aliases[:20]})
        except (socket.herror, socket.gaierror):
            rows.append({"ip": address, "hostname": None, "aliases": []})
    return rows


async def _rdns(target: ValidatedTarget) -> dict[str, Any]:
    return {"records": await asyncio.to_thread(_rdns_sync, target.ips)}


async def _provider_json(url: str, *, max_redirects: int = 3) -> Any:
    timeout = httpx.Timeout(get_settings().source_timeout_seconds)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False) as client:
        current = url
        for _ in range(max_redirects + 1):
            parsed = urlsplit(current)
            if parsed.scheme != "https" or not parsed.hostname:
                raise RuntimeError("intelligence provider redirect was not HTTPS")
            target = await validate_public_target(parsed.hostname)
            port = parsed.port
            request_headers = {
                "Accept": "application/json",
                "Host": parsed.hostname if port is None else f"{parsed.hostname}:{port}",
                "User-Agent": "ArkIntel/0.1 passive-research",
            }
            response = None
            errors: list[str] = []
            for address in target.ips[:8]:
                pinned_url = urlunsplit(
                    (parsed.scheme, _ip_netloc(address, port), parsed.path, parsed.query, "")
                )
                try:
                    response = await client.get(
                        pinned_url,
                        headers=request_headers,
                        extensions={"sni_hostname": parsed.hostname},
                    )
                    break
                except httpx.HTTPError as exc:
                    errors.append(f"{address}: {exc}")
            if response is None:
                raise RuntimeError("; ".join(errors))
            if response.is_redirect:
                location = response.headers.get("location")
                if not location:
                    raise RuntimeError("provider returned an empty redirect")
                current = urljoin(current, location)
                continue
            response.raise_for_status()
            if len(response.content) > get_settings().source_max_bytes:
                raise RuntimeError("provider response exceeded the size limit")
            return response.json()
    raise RuntimeError("provider redirect limit exceeded")


async def _subdomains(target: ValidatedTarget) -> dict[str, Any]:
    try:
        socket.inet_pton(socket.AF_INET, target.host)
        return {"names": [], "note": "Certificate transparency lookup requires a domain name"}
    except OSError:
        pass
    payload = await _provider_json(f"https://crt.sh/?q=%25.{quote(target.host)}&output=json")
    names: set[str] = set()
    for row in payload[:5000]:
        for name in str(row.get("name_value", "")).splitlines():
            candidate = name.strip().lower().removeprefix("*.")
            if candidate == target.host or candidate.endswith(f".{target.host}"):
                names.add(candidate)
    return {"names": sorted(names)[:500], "truncated": len(names) > 500, "method": "certificate transparency"}


async def _whois(target: ValidatedTarget) -> dict[str, Any]:
    try:
        socket.inet_pton(socket.AF_INET6 if ":" in target.host else socket.AF_INET, target.host)
        kind = "ip"
    except OSError:
        kind = "domain"
    payload = await _provider_json(f"https://rdap.org/{kind}/{quote(target.host)}")
    return {
        "handle": payload.get("handle"),
        "name": payload.get("name") or payload.get("ldhName"),
        "status": payload.get("status"),
        "entities": [row.get("handle") for row in payload.get("entities", [])[:20]],
        "events": payload.get("events", [])[:20],
        "notices": [row.get("title") for row in payload.get("notices", [])[:20]],
        "method": "RDAP",
    }


async def _geoloc(target: ValidatedTarget) -> dict[str, Any]:
    rows = []
    for address in target.ips:
        payload = await _provider_json(f"https://ipwho.is/{quote(address)}")
        rows.append({
            "ip": address,
            "country": payload.get("country"),
            "region": payload.get("region"),
            "city": payload.get("city"),
            "latitude": payload.get("latitude"),
            "longitude": payload.get("longitude"),
            "asn": (payload.get("connection") or {}).get("asn"),
            "org": (payload.get("connection") or {}).get("org"),
        })
    return {"records": rows, "method": "public IP registration/geolocation feed"}


async def _vuln(target: ValidatedTarget) -> dict[str, Any]:
    rows = []
    for address in target.ips:
        try:
            payload = await _provider_json(f"https://internetdb.shodan.io/{quote(address)}")
            rows.append({
                "ip": address,
                "cves": payload.get("vulns", [])[:200],
                "hostnames": payload.get("hostnames", [])[:50],
                "tags": payload.get("tags", [])[:50],
                "ports": payload.get("ports", [])[:100],
            })
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                rows.append({"ip": address, "cves": [], "hostnames": [], "tags": [], "ports": []})
            else:
                raise
    return {"records": rows, "method": "passive Shodan InternetDB; ArkIntel did not sweep ports"}


RUNNERS = {
    "quick": _quick,
    "ssl": _ssl,
    "headers": _headers,
    "rdns": _rdns,
    "subdomains": _subdomains,
    "tech": _tech,
    "whois": _whois,
    "geoloc": _geoloc,
    "vuln": _vuln,
}


async def execute_scan(plan: ScanPlan, target: ValidatedTarget) -> dict[str, Any]:
    results: dict[str, Any] = {}
    for scan_type in plan.scan_types:
        try:
            results[scan_type] = {
                "status": "complete",
                "data": await asyncio.wait_for(RUNNERS[scan_type](target), timeout=20),
            }
        except Exception as exc:
            results[scan_type] = {"status": "degraded", "error": str(exc)[:500]}
    return {
        "target": plan.host,
        "resolved_ips": list(target.ips),
        "authorization_reference": plan.authorization_reference,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "results": results,
        "denied_capabilities": DENIED_CAPABILITIES,
    }
