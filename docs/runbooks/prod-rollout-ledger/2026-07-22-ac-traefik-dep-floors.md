# 2026-07-22 · AC Traefik Go dependency security floors

- **Owner:** prod rollout coordinator
- **Sources:** https://github.com/advisories/GHSA-hrxh-6v49-42gf,
  https://github.com/advisories/GHSA-jpjm-c3r5-q96r

Roll the patched AC image through sandbox before production and verify the
edge's rebuilt Traefik binary embeds both reviewed dependency floors.

- [ ] Pre-rollout: confirm the PR's AC image Trivy scan has no
  GHSA-hrxh-6v49-42gf or CVE-2026-56852 finding and its build metadata reports
  Traefik `v3.6.24+dirty`, grpc-go `v1.82.1`, and x/text `v0.39.0`.
- [ ] Rollout: deploy the merged AC image to sandbox, then production through the normal image-promotion path.
- [ ] Post-rollout: verify each cell's AC fleet runs the promoted image digest,
  reports those exact Traefik/dependency versions, and keeps Traefik plus
  `nhp-acd` healthy.
- [ ] Rollback: if the rebuilt Traefik regresses edge traffic, restore the prior
  AC image tag and treat the reopened dependency finding as an active security
  incident until a corrected image is promoted.
