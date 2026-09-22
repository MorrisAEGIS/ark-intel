# ArkIntel Live Transport Surface — Red-Team Sweep (2026-09-22)

Scope: the deployed ark-intel service (container 3b6f48a8, created
2026-09-06, bound 127.0.0.1:7010, read-only rootfs) — the transport
surface behind the 13-source pipeline. Method: live probes with the
service's own token at plan-only routes (zero execution) + source
review. Claim 20260922101551.

## Verified clean (live-probed)

| Surface | Probe | Result |
|---|---|---|
| Service auth | no token / garbage token / forged Bearer | 401 — hmac.compare_digest, fail-closed 503 when unset |
| Route auth | /v1/* router carries `Depends(require_service_token)` | every route 401 unauth (events, sources, scans, jobs) |
| **SSRF admission (crown jewel)** | plan-only probes with token+role against loopback, RFC1918, lab rail (10.200.0.112), link-local, metadata IP (169.254.169.254), CGNAT (100.64/10 via is_global+CGNAT check), tailnet | **all 403 "Only targets resolving entirely to public IP space are allowed"** |
| DNS isolation | ark-1/litellm tailnet names from inside the container | 400 "Target does not resolve" — the container's resolver cannot see the tailnet |
| Denylist | localhost + .magaenergy.ai/.internal/.local/.lan suffixes | 403 "ARK, local, and internal targets are denied" |
| Authorization gates | window > policy max; scope not naming the target | 403 each — window and exact-scope gates both enforced |
| Positive control | example.com + named scope + 6h window | 200 plan admitted — the gate does not over-block |
| DNS rebinding (source) | `_target_http` re-resolves then **connects to the validated IP** (not the hostname); SNI pinned | the rebinding gap is closed in the connect path |
| Active-scan gate | ACTIVE_TYPES with the flag | 403 fail-closed when disabled; the deployed env has it SET (posture note F3) |
| Exposure | socket + compose | 127.0.0.1:7010 only; read_only rootfs; data volume isolated |
| Token hygiene | /health body, error details | token never appears in any response |

## Findings

### F1 (DEPLOY DRIFT — the big honest finding)
The running container (2026-09-06) predates the entire ark-intel
fabric: PRs #4–#10 (manifests, transport governor, observation
envelopes, raw-evidence store, governed fetch, capture, emission) are
merged to master but **not deployed** — the container's arkintel/ has
no transport.py, raw_store.py, or observation.py. All of today's live
probes tested the pre-fabric service. The new fabric's live proof
completes at the next image build + deploy (docker-compose pull/up) —
which is a release action for Sir to gate.

### F2 (LOW — accepted, trusted-proxy pattern)
`X-Ark-User-Role` is a raw header trusted by require_scan_role. The
trust chain is sound only because the service token authenticates the
CALLER (arkgrid), which derives the role from its VERIFIED JWT user
(`user.get("role")` in backend/services/intel.py) — external clients
cannot reach ark-intel without the token, and token holders already
hold everything the role gate protects. Standard trusted-proxy
pattern; documented so the trust boundary is explicit: **the service
token is the boundary, the role header is a claim, not a proof.**

### F3 (LOW — posture note)
`active_scan_enabled: true` in production, and /health discloses it
plus the upstream commit and bind address. Intentional (this is an
authorized-security-review tool), but the exposure means anyone with
loopback access knows the posture. No action beyond awareness.

## Posture

Fail-closed token auth on every route; the SSRF admission gate refuses
every internal class live (loopback/private/lab-rail/link-local/
metadata/CGNAT/tailnet) with DNS isolation preventing even name
resolution of internal space; authorization window + exact-scope
gates enforced; rebinding closed at the connect path; positive control
proves no over-blocking. **Zero exploitable findings; one deploy-drift
gap (the new fabric awaits its first deploy); two documented posture
notes.**
