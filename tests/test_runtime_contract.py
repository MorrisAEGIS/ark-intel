from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_container_runtime_is_pinned_and_non_root():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "python:3.12.11-slim-bookworm@sha256:" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "ARK_INTEL_DATABASE_PATH=/var/lib/ark-intel/ark-intel.sqlite3" in dockerfile


def test_compose_is_loopback_only_and_hardened():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert '"127.0.0.1:7010:7010"' in compose
    assert "read_only: true" in compose
    assert "cap_drop:\n      - ALL" in compose
    assert "no-new-privileges:true" in compose
    assert "ark-net:\n    external: true" in compose


def test_ci_has_no_registry_publish_permission_or_step():
    workflow = (ROOT / ".github/workflows/quality.yml").read_text(encoding="utf-8")
    assert "packages: write" not in workflow
    assert "docker/login-action" not in workflow
    assert "push: true" not in workflow
    assert "actions/checkout@11d5960a326750d5838078e36cf38b85af677262" in workflow
