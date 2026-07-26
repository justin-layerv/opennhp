# 2026-07-25 · UDP proof controller repair

- **Owner:** sandbox UDP proof operator
- **Source:** This PR

Before the next attended sandbox proof, deploy and verify the corrected
controller boundary from reviewed `main`; do not substitute hand-authored
deployment values.

- [ ] Pre-rollout: apply `terraform/environments/sandbox-udp-proof-runner` from the reviewed merge commit and read back that the controller's dedicated JIT-key statement grants exactly service-bound `kms:Decrypt` and `kms:GenerateDataKey`.
- [ ] Pre-rollout: merge and deploy the trusted-main deployment producer before this controller. Freeze qurl-connector at `16cdff6260c20b671cdee735333a9096007b5f6e` and qurl-go at `aaf682e3cd8836cf874627e95a5d2d4b9e8b12ab`; verify both heads accept the canonical manifest/runtime sidecar plus producer run, attempt, head SHA, artifact ID, and artifact digest, require `dispatch_correlation_id`, and render only `UDP proof [corr:<value>]` as their dispatch run name. Run the producer with the two current PR numbers and exact trusted Connector canary run, retain its successful run/artifact ID and digest, and set the protected runner group to those exact workflow SHAs authenticated in that artifact. The controller receives only the producer run ID and rejects a producer artifact for any other candidate head. Any candidate movement requires a reviewed controller-pin update plus a fresh producer run and runner-group readback; evidence expiry also requires a fresh producer run/readback. Never substitute hand-authored deployment values.
- [ ] Post-rollout: run one attended Connector controller proof and one distinct attended qurl-go controller proof, preserving both controller and external run links; verify the JIT secret is consumed and the broker leaves no proof instance or secret behind.
- [ ] Rollback: if the controller or runner cleanup contract fails, stop dispatches, invoke the broker's exact run/attempt `stop` action, verify the dedicated EIP is detached and no proof instance remains, then revert the workflow/IAM merge before any new attempt. A red late OIDC refresh or strict stop-response-schema check is not alone proof of a stranded runner: read back the broker's independent five-minute sweep and the instance's boot-relative hard deadline, but do not accept proof evidence or start another run until the fleet and JIT secret are confirmed absent.
