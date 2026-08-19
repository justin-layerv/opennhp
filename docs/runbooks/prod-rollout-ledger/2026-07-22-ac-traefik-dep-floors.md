# 2026-07-22 · AC Traefik Go dependency security floors

- **Owner:** prod rollout coordinator
- **Sources:** https://github.com/advisories/GHSA-hrxh-6v49-42gf,
  https://github.com/advisories/GHSA-jpjm-c3r5-q96r,
  https://avd.aquasec.com/nvd/cve-2026-71327 (added 2026-08-07),
  https://pkg.go.dev/vuln/GO-2026-6179,
  https://pkg.go.dev/vuln/GO-2026-6180 (added 2026-08-19)

Roll the patched AC image through sandbox before production and verify the
edge's rebuilt Traefik binary embeds all reviewed dependency floors.

- [ ] Pre-rollout: confirm the PR's AC image Trivy scan has no
  GHSA-hrxh-6v49-42gf, CVE-2026-56852, CVE-2026-71327, CVE-2026-56864, or
  CVE-2026-56865 finding and its build metadata reports Traefik
  `v3.6.25+dirty`, grpc-go `v1.82.1`, x/crypto `v0.55.0`, x/mod `v0.40.0`,
  x/net `v0.58.0`, and x/text `v0.41.0`; its selected module graph also reports
  x/tools `v0.49.0`.

  _Versions updated 2026-08-07 with the v3.6.24 -> v3.6.25 bump for
  CVE-2026-71327. v3.6.25 ships those floors in its own go.mod, so the x/text
  override this build previously applied is gone — pinning v0.39.0 against it
  would now downgrade the dependency._

  _Floors updated 2026-08-19 because v3.6.25 still pins x/mod v0.37.0. No newer
  3.6.x release exists, so the source build applies the smallest fixed x/mod
  v0.40.0 override; Go MVS selects the matching x/crypto v0.55.0, x/net
  v0.58.0, x/text v0.41.0, and x/tools v0.49.0 graph._
- [ ] Rollout: deploy the merged AC image to sandbox, then production through the normal image-promotion path.
- [ ] Post-rollout: verify each cell's AC fleet runs the promoted image digest,
  reports those exact Traefik/dependency versions, and keeps Traefik plus
  `nhp-acd` healthy.
- [ ] Rollback: if the rebuilt Traefik regresses edge traffic, restore the prior
  AC image tag and treat the reopened dependency finding as an active security
  incident until a corrected image is promoted.
