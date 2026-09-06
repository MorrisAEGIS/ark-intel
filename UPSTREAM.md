# Upstream provenance

ArkIntel is a governed fork of [simplifaisoul/osiris](https://github.com/simplifaisoul/osiris), licensed under MIT.

- Audited integration baseline: `d2c08c876b2a2228954ac42b2d15d00772e5df84`
- Fork created: 2026-09-06
- Production entrypoint: `arkintel.main:app`
- Browser owner: ArkGrid `/global-intel`

The original Next.js dashboard remains in the fork as upstream reference code, but it is not the ARK production entrypoint. The default Docker and systemd paths run only the internal ArkIntel broker.

Upstream changes are reviewed and cherry-picked. They are never pulled directly into the live service.
