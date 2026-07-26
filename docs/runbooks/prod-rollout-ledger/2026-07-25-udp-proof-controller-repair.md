# 2026-07-25 · UDP proof controller repair

- **Owner:** sandbox UDP proof operator
- **Source:** This PR

Before the next attended sandbox proof, deploy and verify the corrected
controller boundary from reviewed `main`; do not substitute hand-authored
deployment values.

- [ ] Pre-rollout: apply `terraform/environments/sandbox-udp-proof-runner` from the reviewed merge commit and read back that the controller's dedicated JIT-key statement grants exactly service-bound `kms:Decrypt` and `kms:GenerateDataKey`.
- [ ] Pre-rollout: freeze both candidate branches, verify their exact heads require `dispatch_correlation_id` and render only `UDP proof [corr:<value>]` as their dispatch run name, generate the canonical non-secret deployment manifest from those reviewed heads and live evidence, then set the protected runner group to those exact workflow SHAs. Any branch movement invalidates the attempt and requires a fresh manifest/read-back before dispatch.
- [ ] Post-rollout: run one attended Connector controller proof and one distinct attended qurl-go controller proof, preserving both controller and external run links; verify the JIT secret is consumed and the broker leaves no proof instance or secret behind.
- [ ] Rollback: if the controller or runner cleanup contract fails, stop dispatches, invoke the broker's exact run/attempt `stop` action, verify the dedicated EIP is detached and no proof instance remains, then revert the workflow/IAM merge before any new attempt. A red late OIDC refresh or strict stop-response-schema check is not alone proof of a stranded runner: read back the broker's independent five-minute sweep and the instance's boot-relative hard deadline, but do not accept proof evidence or start another run until the fleet and JIT secret are confirmed absent.
