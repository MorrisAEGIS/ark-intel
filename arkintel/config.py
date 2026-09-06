"""Environment-only runtime configuration for ArkIntel."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ARK_INTEL_", extra="ignore")

    host: str = "127.0.0.1"
    port: int = 7010
    service_token: str = ""
    database_path: Path = Path("data/ark-intel.sqlite3")
    source_timeout_seconds: float = 8.0
    source_max_bytes: int = 5_000_000
    event_cache_seconds: int = 90
    active_scan_enabled: bool = False
    max_scan_authorization_hours: int = 24
    job_retention_days: int = 30
    blocked_domain_suffixes: str = ".magaenergy.ai,.internal,.local,.lan,localhost"
    allowed_roles: str = "admin,reviewer,gis_reviewer"
    upstream_commit: str = "d2c08c876b2a2228954ac42b2d15d00772e5df84"

    @property
    def scan_roles(self) -> set[str]:
        return {value.strip() for value in self.allowed_roles.split(",") if value.strip()}

    @property
    def blocked_domains(self) -> tuple[str, ...]:
        return tuple(value.strip().lower() for value in self.blocked_domain_suffixes.split(",") if value.strip())


@lru_cache
def get_settings() -> Settings:
    return Settings()
