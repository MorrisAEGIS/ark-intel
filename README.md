# ArkIntel

ArkIntel brings the useful public-source intelligence patterns from OSIRIS into the Ark Sovereign stack without exposing a second dashboard or inheriting unsafe browser and scanning behavior.

ArkGrid owns the human interface at `/global-intel`. ArkIntel is an authenticated, loopback-only broker on port `7010` that normalizes allowlisted public feeds into provenance-bearing GeoJSON and executes only the bounded investigation tools approved by ARK policy.

## Runtime contract

- Upstream: `simplifaisoul/osiris` at `d2c08c876b2a2228954ac42b2d15d00772e5df84`
- License: MIT; upstream attribution is retained in [UPSTREAM.md](UPSTREAM.md)
- Public UI: none
- Browser access: none
- Service API: `http://127.0.0.1:7010`
- Authentication: shared service token from `/home/novaadmin/.config/ark-intel/env`
- Active scans: feature-gated and target-authorization-gated
- Case authority: ArkGrid PostgreSQL, 30-day retention
- Research promotion: request-only; ArkResearch/Qdrant/Neo4j remain the durable knowledge authority

## API

- `GET /health`
- `GET /v1/policy`
- `GET /v1/sources`
- `GET /v1/events`
- `POST /v1/scans/plan`
- `POST /v1/scans/execute`
- `GET /v1/jobs/{id}`

All `/v1` routes require `X-Ark-Intel-Token`. Scan routes also require `X-Ark-User-Role` and a request body containing a target-specific, time-bounded authorization assertion.

## Local development

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
ARK_INTEL_SERVICE_TOKEN=development-only .venv/bin/uvicorn arkintel.main:app --host 127.0.0.1 --port 7010
```

Production uses the hardened Docker Compose profile on both the dedicated `ark-intel-net` network and the existing internal `ark-net` network. Only port `127.0.0.1:7010` is published on the host; ArkGrid reaches the service by its internal `ark-intel` name.

The legacy upstream Next.js source is reference-only. `docker compose up` and `scripts/install_local.sh` both start the hardened ArkIntel API, not the upstream dashboard.
