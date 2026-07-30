# 2026-07-30 · HTTP lifecycle Terraform retirement preparation

- **Owner:** sandbox UDP retirement operator
- **Source:** This PR · [NHP #3597](https://github.com/layervai/nhp/pull/3597) · [qurl-service #1336](https://github.com/layervai/qurl-service/pull/1336)

Prepare the sandbox state and qurl-service task definition for the later exact
HTTP lifecycle deletion apply. This preparation must be applied first; it does
not itself delete any resource in the UDP retirement allowlist.

- [ ] Pre-rollout: require the complete pre-removal UDP customer-path proof before applying this preparation.
- [ ] Pre-rollout: restrict this temporary fence relaxation to the sandbox apply; do not run a production Terraform apply until the deletion revision has restored `force_destroy=false` and `prevent_destroy=true` for the surviving production module.
- [ ] Rollout: apply the reviewed merge commit while `deploy_bootstrap_alb=true`, then verify the saved plan/apply completed and the bootstrap access-log bucket state records `force_destroy=true`.
- [ ] Rollout: deploy the newly registered qurl-service task definition and verify its container definition omits `QURL_AGENT_BOOTSTRAP_ENABLED`, `NHP_SERVER_HOST`, `NHP_SERVER_PORT`, `QURL_AGENT_REGISTRATION_ENABLED`, `QURL_NHP_RELAY_BASE_URL`, `QURL_AGENT_OTP_ENABLED`, `QURL_AGENT_OTP_EMAIL_FROM`, and `QURL_AGENT_OTP_PEPPER`.
- [ ] Pre-rollout: do not merge or apply the separate exact deletion PR until the prepared qurl-service revision is active and healthy and NHP #3597 plus qurl-service #1336 are deployed.
- [ ] Rollback: before the exact deletion apply, revert this merge and redeploy qurl-service. After deletion, restore only from the coordinated source and Terraform rollback; the deleted access-log bucket and legacy OTP pepper are not recoverable.
