# 2026-07-22 · AC Traefik Go dependency security floors

- **Owner:** prod rollout coordinator
- **Sources:** https://github.com/advisories/GHSA-hrxh-6v49-42gf,
  https://github.com/advisories/GHSA-jpjm-c3r5-q96r,
  https://avd.aquasec.com/nvd/cve-2026-71327 (added 2026-08-07)

Roll the patched AC image through sandbox before production and verify the
edge's rebuilt Traefik binary embeds both reviewed dependency floors.

- [ ] Pre-rollout: confirm the PR's AC image Trivy scan has no
  GHSA-hrxh-6v49-42gf, CVE-2026-56852, or CVE-2026-71327 finding and its build
  metadata reports Traefik `v3.6.25+dirty`, grpc-go `v1.82.1`, and x/text
  `v0.40.0`.

  _Versions updated 2026-08-07 with the v3.6.24 -> v3.6.25 bump for
  CVE-2026-71327. v3.6.25 ships both floors in its own go.mod, so the x/text
  override this build previously applied is gone — pinning v0.39.0 against it
  would now downgrade the dependency._
- [ ] Rollout: deploy the merged AC image to sandbox, then production through the normal image-promotion path.
- [ ] Post-rollout: verify each cell's AC fleet runs the promoted image digest,
  reports those exact Traefik/dependency versions, and keeps Traefik plus
  `nhp-acd` healthy.
- [ ] Rollback: if the rebuilt Traefik regresses edge traffic, restore the prior
  AC image tag and treat the reopened dependency finding as an active security
  incident until a corrected image is promoted.
