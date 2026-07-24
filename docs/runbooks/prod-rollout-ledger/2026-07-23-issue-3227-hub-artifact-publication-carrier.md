# 2026-07-23 · Issue #3227 · Hub artifact publication carrier

- **Owner:** prod rollout coordinator
- **Source:** [issue #3227](https://github.com/layervai/nhp/issues/3227)

Publish and pin the immutable Hub artifact only after its environment-specific
foundation is applied and converged. This carrier never deploys a Hub runtime.

- [ ] Pre-rollout: prove the selected Control root is a refresh-enabled no-op; its Hub repository, dedicated publisher role, and `UNPUBLISHED` digest parameter match Terraform; and the selected dedicated GitHub Environment still passes the carrier's exact live reviewer/main-only-policy readback. Confirm the dispatch SHA is still live `main` at the carrier's pre-OIDC point of no return.
- [ ] Rollout: dispatch `publish-hub-image.yml` from current `main` for sandbox, approve only the `hub-publish-sandbox` deployment, and record the exact source SHA/run/attempt. Do not dispatch production until the separately reviewed production foundation is applied and converged.
- [ ] Post-rollout: retain the secret-free provenance artifact and independently read back the sole source-SHA tag, canonical manifest digest, linux/amd64 architecture, source/revision labels, completed zero-HIGH/CRITICAL ECR scan, and exact `/sandbox/nhp/control/hub/image-digest` value/version. Converge only the already-reviewed external digest-value Terraform normalization; do not create runtime infrastructure.
- [ ] Production: repeat from current `main` through `hub-publish-production` only after the production foundation/no-op gate. Verify the exact production account, repository, role, `/prod/nhp/control/hub/image-digest`, scan, and provenance independently.
- [ ] Rollback: preserve every immutable source-SHA image. If a later runtime must return to a prior image, first re-prove that prior digest's source/architecture/labels/scan evidence, then write/read back only that canonical digest; never add a mutable tag or destroy the repository.
