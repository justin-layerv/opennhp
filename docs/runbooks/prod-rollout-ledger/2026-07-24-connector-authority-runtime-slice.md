# 2026-07-24 · Connector Authority runtime slice (Step 4)

- **Owner:** prod rollout coordinator
- **Source:** draft PR `feat(control): add connector authority runtime slice` (branch `control/authority-runtime-slice`) · plan `prancy-mapping-wilkinson` Step 4 · depends on Step 3 (contract bind, nhp#3411/#3414)

Deploy the 3 Hub-facing Connector Authority Lambda functions
(`layerv-nhp-<env>-ca-{ia,ra,icr}`) with both closed blue/green aliases, steady
provisioned/reserved concurrency, per-operation execution roles, spillover
alarms, a dedicated function SG, and the lockstep opening of ONLY the DynamoDB
gateway + KMS interface endpoints. Sandbox measurement only; prod stays locked
dark. **This is a draft for careful human + independent review; do not apply
until the items below are closed.**

- [ ] Pre-rollout (CALIBRATION, blocks apply): Step 3 must be applied first
      (a bound `authority_runtime_contract`). Set `authority_runtime_functions_enabled = true`
      only via the Step-4 apply (the committed default is false; the module
      fails closed if the gate is set against a null contract). Generate the
      first real Step-4 `terraform plan -json` and reconcile the exact
      value-free create envelope of every runtime resource into
      `check-control-sandbox-first-apply.py` (the current extension enforces the
      inventory, all-or-nothing transition membership, the scoped
      endpoint/SG/trust security content, and the reserved/provisioned
      concurrency tie-back; the per-field provider-default envelope is the
      calibration). Confirm the interface-endpoint SG ingress renders with the
      function-SG reference visible; if the provider hides it, extend the
      ingress admission from the observed shape rather than loosening it.
- [ ] Pre-rollout (HANDLER RECONCILIATION, blocks apply): reconcile the
      per-operation execution-role IAM (DynamoDB actions/tables, qat1 KMS use)
      and the function environment/architecture against the published
      `layervai/qurl-service` `cmd/qurl-connector-authority` handler. The IAM is
      currently inferred from the plan prose (flagged in `authority_runtime.tf`)
      and MUST be verified before apply. Confirm the published image
      architecture matches `architectures` and that the SSM-pinned digest is the
      intended immutable pin (qurl-service auto-rolls it on every main push).
- [ ] Rollout (sandbox only): apply the exact `authority-runtime-slice`
      transition — 25 pure creates plus exactly the DynamoDB gateway, KMS
      interface, and interface-endpoint-SG opens; nothing else non-no-op. Wait
      for every provisioned-concurrency config to reach `READY` (init must reach
      KMS/DynamoDB through the opened endpoints). Verify with the extended
      `check-control-sandbox-first-apply.py state`/`live`: exactly the 3 hub
      functions live, DynamoDB+KMS scoped to the execution roles, every other
      endpoint (email, **lambda [caller-only]**, logs, monitoring,
      secretsmanager) still deny-all, and the OTP Redis SG still no-ingress.
      Record a refresh-enabled exact 75-resource sandbox no-op after apply.
- [ ] Rollout (DARK CALLER BOUNDARY — do not skip): this slice deliberately
      leaves the functions dark. There is NO caller identity policy, NO
      `aws_lambda_permission`, and the Lambda caller interface endpoint stays
      deny-all until the Hub role/runtime exists (Step 5). Inventory account
      principals and confirm no wildcard `lambda:InvokeFunction` on
      `layerv-nhp-<env>-ca-*` (including the shared apply-role) before any later
      caller-path opening.
- [ ] Production: remains blocked. Prod `authority_runtime_contract`,
      `authority_runtime_contract_evidence_verified`, and
      `authority_runtime_functions_enabled` are validation-locked to
      null/false/false throughout sandbox measurement. Do not reuse the sandbox
      transition; production Control has no foundation state. After the prod
      gates close, review a separate production first-apply contract for the
      then-current inventory.
- [ ] Post-rollout: alarm wiring for the spillover metric (SNS actions) plus the
      Throttles/Errors/Duration and custom admission/initialization-type alarms
      are a fast follow (this slice lands only the security-critical spillover
      guard). Prove `ProvisionedConcurrencySpilloverInvocations == 0`.
- [ ] Rollback: destroy the runtime slice by flipping
      `authority_runtime_functions_enabled` back to false (re-closes the
      endpoints and removes the 25 resources in one reviewed transition); the
      contract binding and dark foundation remain. Delete this ledger entry once
      the sandbox slice is live-proven and the calibration lands on main.
