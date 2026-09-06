"""Public request and response contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


SAFE_SCAN_TYPES = ("quick", "ssl", "headers", "rdns", "subdomains", "tech", "whois", "geoloc", "vuln")


class ScanAuthorization(BaseModel):
    confirmed: bool
    scope: str = Field(min_length=3, max_length=500)
    reference: str = Field(min_length=3, max_length=200)
    expires_at: datetime


class ScanRequest(BaseModel):
    target: str = Field(min_length=3, max_length=253)
    scan_types: list[Literal["quick", "ssl", "headers", "rdns", "subdomains", "tech", "whois", "geoloc", "vuln"]]
    authorization: ScanAuthorization

    @field_validator("scan_types")
    @classmethod
    def dedupe_scan_types(cls, values: list[str]) -> list[str]:
        if not values:
            raise ValueError("At least one safe scan type is required")
        return list(dict.fromkeys(values))


class ScanPlan(BaseModel):
    target: str
    host: str
    resolved_ips: list[str]
    scan_types: list[str]
    active_steps: list[str]
    passive_steps: list[str]
    denied_capabilities: list[str]
    authorization_reference: str
    authorization_expires_at: datetime
    policy: str = "authorized-external-only"


class JobResponse(BaseModel):
    id: str
    state: str
    created_at: str
    updated_at: str
    request: dict[str, Any]
    result: dict[str, Any] | None = None
    error: str | None = None
