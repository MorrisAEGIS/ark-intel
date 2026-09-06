# ArkIntel security policy

ArkIntel binds to `127.0.0.1:7010`, has no public hostname, and requires a service token for every `/v1` request. Browsers never call it directly; ArkGrid authenticates the human and proxies the request.

Active investigation is disabled unless `ARK_INTEL_ACTIVE_SCAN_ENABLED=true`. Even when enabled, only `admin`, `reviewer`, and `gis_reviewer` roles may submit a scan. Every request must carry a target-specific authorization assertion expiring within 24 hours.

The target guard rejects private, loopback, link-local, multicast, reserved, carrier-grade NAT, `.local`, `.lan`, `.internal`, and `*.magaenergy.ai` addresses. Redirects from target sites are not followed. The service does not expose deep port sweeps, credential attacks, exploits, arbitrary banner grabbing, or traceroute.

The upstream OSIRIS UI, Gemini routes, Umami middleware, browser-direct fetches, and CCTV routes are not imported or built by the production entrypoint. The bundled CCTV and submarine-cable sources remain policy-disabled until their security and provenance are independently cleared.

Report vulnerabilities privately to the MorrisAEGIS repository maintainers. Do not include credentials or live target data in an issue.
