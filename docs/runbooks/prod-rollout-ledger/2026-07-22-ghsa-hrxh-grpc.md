# 2026-07-22 · GHSA-hrxh-6v49-42gf · Patch shipped gRPC copies

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/advisories/GHSA-hrxh-6v49-42gf

Roll the patched AC image through sandbox before production and verify the
edge's rebuilt Traefik binary embeds grpc-go v1.82.1.

- [ ] Pre-rollout: confirm the PR's AC image Trivy scan has no GHSA-hrxh-6v49-42gf finding and its build metadata reports Traefik `v3.6.23+dirty` with grpc-go `v1.82.1`.
- [ ] Rollout: deploy the merged AC image to sandbox, then production through the normal image-promotion path.
- [ ] Post-rollout: verify each cell's AC fleet runs the promoted image digest and Traefik plus `nhp-acd` remain healthy.
- [ ] Rollback: if the rebuilt Traefik regresses edge traffic, restore the prior AC image tag and treat the reopened GHSA as an active security incident until a corrected image is promoted.
