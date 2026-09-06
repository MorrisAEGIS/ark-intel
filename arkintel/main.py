"""ArkIntel API: an internal-only, authenticated OSIRIS integration surface."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, FastAPI, Header, HTTPException, Query

from . import __version__
from .config import get_settings
from .scanner import ACTIVE_TYPES, build_scan_plan, execute_scan
from .schemas import JobResponse, ScanPlan, ScanRequest
from .security import require_scan_role, require_service_token
from .sources import SOURCE_INDEX, fetch_events, source_catalog
from .store import JobStore


logger = logging.getLogger("arkintel")
settings = get_settings()
store = JobStore(settings.database_path, settings.job_retention_days)


@asynccontextmanager
async def lifespan(_: FastAPI):
    store.prune()
    yield


app = FastAPI(
    title="ArkIntel",
    version=__version__,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)


@app.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "service": "ArkIntel",
        "version": __version__,
        "bind": f"{settings.host}:{settings.port}",
        "active_scan_enabled": settings.active_scan_enabled,
        "upstream": "simplifaisoul/osiris",
        "upstream_commit": settings.upstream_commit,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


router = APIRouter(prefix="/v1", dependencies=[Depends(require_service_token)])


@router.get("/policy")
async def policy() -> dict:
    return {
        "browser_direct_access": False,
        "public_ui": False,
        "active_scan_enabled": settings.active_scan_enabled,
        "allowed_scan_roles": sorted(settings.scan_roles),
        "allowed_scan_types": ["quick", "ssl", "headers", "rdns", "subdomains", "tech", "whois", "geoloc", "vuln"],
        "denied": ["deep ports", "brute force", "exploit", "arbitrary banners", "traceroute", "private or ARK targets"],
        "retention_days": settings.job_retention_days,
        "memory_promotion": "request-only; no automatic raw PII promotion",
    }


@router.get("/sources")
async def sources() -> dict:
    return {"sources": source_catalog(), "count": len(SOURCE_INDEX), "upstream_commit": settings.upstream_commit}


@router.get("/events")
async def events(
    source: Annotated[list[str] | None, Query()] = None,
    group: Annotated[list[str] | None, Query()] = None,
    limit: int = Query(default=1000, ge=1, le=5000),
) -> dict:
    try:
        return await fetch_events(source, groups=set(group or []), limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/scans/plan", response_model=ScanPlan)
async def scan_plan(
    request: ScanRequest,
    _role: str = Depends(require_scan_role),
) -> ScanPlan:
    plan, _ = await build_scan_plan(request)
    return plan


async def _run_job(job_id: str, plan: ScanPlan, target) -> None:
    store.update(job_id, state="running")
    try:
        result = await execute_scan(plan, target)
        store.update(job_id, state="complete", result=result)
    except Exception as exc:
        logger.exception("Scan job %s failed", job_id)
        store.update(job_id, state="failed", error=str(exc)[:1000])


@router.post("/scans/execute", response_model=JobResponse, status_code=202)
async def scan_execute(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    role: str = Depends(require_scan_role),
    x_ark_user_id: str = Header(default="unknown"),
) -> dict:
    if not settings.active_scan_enabled and any(name in ACTIVE_TYPES for name in request.scan_types):
        raise HTTPException(status_code=403, detail="Active scans are disabled by ARK_INTEL_ACTIVE_SCAN_ENABLED")
    plan, target = await build_scan_plan(request)
    job = store.create({
        "plan": plan.model_dump(mode="json"),
        "requested_by": x_ark_user_id[:200],
        "role": role,
    })
    background_tasks.add_task(_run_job, job["id"], plan, target)
    return job


@router.get("/jobs/{job_id}", response_model=JobResponse)
async def job(job_id: str) -> dict:
    found = store.get(job_id)
    if found is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return found


app.include_router(router)
