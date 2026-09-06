from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from arkintel.schemas import ScanAuthorization
from arkintel.scanner import _ip_netloc
from arkintel.security import ValidatedTarget, validate_authorization, validate_public_target


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["127.0.0.1", "10.0.0.1", "169.254.10.2", "100.64.0.1", "arkgrid.magaenergy.ai", "service.local"])
async def test_private_and_ark_targets_are_denied(target):
    with pytest.raises(HTTPException) as exc:
        await validate_public_target(target)
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_public_literal_is_allowed():
    target = await validate_public_target("8.8.8.8")
    assert target.host == "8.8.8.8"
    assert target.ips == ("8.8.8.8",)


def test_pinned_network_locations_handle_ipv4_and_ipv6():
    assert _ip_netloc("93.184.216.34") == "93.184.216.34"
    assert _ip_netloc("2606:2800:220:1:248:1893:25c8:1946", 8443) == "[2606:2800:220:1:248:1893:25c8:1946]:8443"


def test_authorization_must_name_exact_target():
    target = ValidatedTarget(original="example.com", host="example.com", ips=("93.184.216.34",))
    authorization = ScanAuthorization(
        confirmed=True,
        scope="security review of a different.example host",
        reference="ticket-123",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    with pytest.raises(HTTPException) as exc:
        validate_authorization(target, authorization)
    assert exc.value.status_code == 403


def test_authorization_rejects_hostname_as_part_of_a_different_domain():
    target = ValidatedTarget(original="example.com", host="example.com", ips=("93.184.216.34",))
    authorization = ScanAuthorization(
        confirmed=True,
        scope="Authorized review of notexample.com",
        reference="ticket-123",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    with pytest.raises(HTTPException) as exc:
        validate_authorization(target, authorization)
    assert exc.value.status_code == 403


def test_authorization_window_is_bounded():
    target = ValidatedTarget(original="example.com", host="example.com", ips=("93.184.216.34",))
    authorization = ScanAuthorization(
        confirmed=True,
        scope="authorized review of example.com",
        reference="ticket-123",
        expires_at=datetime.now(timezone.utc) + timedelta(days=3),
    )
    with pytest.raises(HTTPException) as exc:
        validate_authorization(target, authorization)
    assert "window" in exc.value.detail.lower()
