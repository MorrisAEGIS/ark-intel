"""Fail-closed authentication and public-target admission controls."""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
import re
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

from fastapi import Header, HTTPException, status

from .config import get_settings
from .schemas import ScanAuthorization


_HOST_RE = re.compile(r"^(?=.{1,253}\.?$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.?$")


@dataclass(frozen=True)
class ValidatedTarget:
    original: str
    host: str
    ips: tuple[str, ...]


def require_service_token(
    authorization: str = Header(default=""),
    x_ark_intel_token: str = Header(default=""),
) -> None:
    expected = get_settings().service_token
    if not expected:
        raise HTTPException(status_code=503, detail="ArkIntel service token is not configured")
    bearer = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
    supplied = x_ark_intel_token.strip() or bearer
    if not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid ArkIntel service token")


def require_scan_role(x_ark_user_role: str = Header(default="")) -> str:
    role = x_ark_user_role.strip().lower()
    if role not in get_settings().scan_roles:
        raise HTTPException(status_code=403, detail="Investigation role required")
    return role


def _is_public_ip(value: str) -> bool:
    address = ipaddress.ip_address(value)
    carrier_grade_nat = ipaddress.ip_network("100.64.0.0/10")
    return bool(address.is_global and address not in carrier_grade_nat)


def _normalized_host(target: str) -> str:
    candidate = target.strip()
    parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
    if parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="Credentials are not allowed in scan targets")
    host = parsed.hostname
    if not host:
        raise HTTPException(status_code=400, detail="A hostname or public IP is required")
    host = host.rstrip(".").lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise HTTPException(status_code=400, detail="Invalid international hostname") from exc
        if not _HOST_RE.fullmatch(host):
            raise HTTPException(status_code=400, detail="Invalid hostname")
    return host


async def validate_public_target(target: str) -> ValidatedTarget:
    host = _normalized_host(target)
    settings = get_settings()
    for suffix in settings.blocked_domains:
        normalized = suffix.lstrip(".")
        if host == normalized or host.endswith(suffix if suffix.startswith(".") else f".{suffix}"):
            raise HTTPException(status_code=403, detail="ARK, local, and internal targets are denied")

    try:
        direct = ipaddress.ip_address(host)
        ips = {str(direct)}
    except ValueError:
        loop = asyncio.get_running_loop()
        try:
            records = await loop.run_in_executor(None, socket.getaddrinfo, host, None, 0, socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise HTTPException(status_code=400, detail="Target does not resolve") from exc
        ips = {record[4][0] for record in records}

    if not ips or any(not _is_public_ip(value) for value in ips):
        raise HTTPException(status_code=403, detail="Only targets resolving entirely to public IP space are allowed")
    return ValidatedTarget(original=target, host=host, ips=tuple(sorted(ips)))


def validate_authorization(target: ValidatedTarget, authorization: ScanAuthorization) -> None:
    settings = get_settings()
    if not authorization.confirmed:
        raise HTTPException(status_code=403, detail="Explicit target authorization is required")
    expires = authorization.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    if expires <= now:
        raise HTTPException(status_code=403, detail="Target authorization has expired")
    delta_hours = (expires - now).total_seconds() / 3600
    if delta_hours > settings.max_scan_authorization_hours:
        raise HTTPException(status_code=403, detail="Authorization window exceeds the policy maximum")
    scope = authorization.scope.lower()
    exact_target = re.compile(
        rf"(?<![a-z0-9.-]){re.escape(target.host)}(?![a-z0-9.-])",
        re.IGNORECASE,
    )
    if exact_target.search(scope) is None:
        raise HTTPException(status_code=403, detail="Authorization scope must name the exact target")
