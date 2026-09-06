from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from arkintel import main


client = TestClient(main.app)


def _headers(role="admin"):
    return {
        "X-Ark-Intel-Token": "test-token",
        "X-Ark-User-Role": role,
        "X-Ark-User-Id": "operator@example.com",
    }


def _scan_body(target="8.8.8.8"):
    return {
        "target": target,
        "scan_types": ["quick", "ssl", "headers", "rdns", "subdomains", "tech", "whois", "geoloc", "vuln"],
        "authorization": {
            "confirmed": True,
            "scope": f"Authorized external review of {target}",
            "reference": "ARK-INTEL-TEST-1",
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        },
    }


def setup_module():
    main.settings.service_token = "test-token"
    main.settings.active_scan_enabled = False


def test_health_exposes_pinned_upstream_without_auth():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["upstream_commit"] == "d2c08c876b2a2228954ac42b2d15d00772e5df84"


def test_v1_requires_service_token():
    assert client.get("/v1/sources").status_code == 401
    response = client.get("/v1/sources", headers=_headers())
    assert response.status_code == 200
    assert response.json()["count"] >= 10


def test_scan_plan_rejects_unprivileged_role():
    response = client.post("/v1/scans/plan", headers=_headers("user"), json=_scan_body())
    assert response.status_code == 403


def test_scan_plan_lists_explicitly_denied_capabilities():
    response = client.post("/v1/scans/plan", headers=_headers(), json=_scan_body())
    assert response.status_code == 200
    payload = response.json()
    assert "65K/deep port sweeps" in payload["denied_capabilities"]
    assert payload["policy"] == "authorized-external-only"


def test_scan_execution_is_feature_gated():
    response = client.post("/v1/scans/execute", headers=_headers(), json=_scan_body())
    assert response.status_code == 403
    assert "ARK_INTEL_ACTIVE_SCAN_ENABLED" in response.json()["detail"]


def test_passive_lookup_is_not_blocked_by_active_scan_flag(monkeypatch):
    async def fake_run(job_id, plan, target):
        main.store.update(job_id, state="complete", result={"target": target.host, "results": {}})

    monkeypatch.setattr(main, "_run_job", fake_run)
    body = _scan_body()
    body["scan_types"] = ["rdns", "whois", "geoloc", "vuln"]
    response = client.post("/v1/scans/execute", headers=_headers(), json=body)
    assert response.status_code == 202


def test_scan_schema_does_not_accept_dangerous_types():
    body = _scan_body()
    body["scan_types"] = ["deep", "exploit"]
    response = client.post("/v1/scans/plan", headers=_headers(), json=body)
    assert response.status_code == 422
