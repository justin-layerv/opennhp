# 2026-07-26 · Attended-proof Authority mutation controls (contract + fences)

- **Owner:** UDP proof rollout coordinator
- **Source:** design `docs/design/AUTHORITY_PROOF_MUTATION_CONTROLS.md` · rollout plan `prancy-mapping-wilkinson`

This slice adds the `MutateProofAgent` operation family, its fences, and its
execution-role data confinement to the Connector Authority foundation. It is
dark: `authority_proof_mutation_controls_enabled` defaults false in both Control
roots and is validation-locked false in prod, so **no resource changes in either
environment**. The only prod-facing effect is three new validation-locked
variables in the prod root.

- [ ] Pre-rollout — prod plan confirmation: run the prod Control plan at this
      head and confirm it reports **no resource changes**. The three new prod
      variables are locked closed (`authority_proof_mutation_controls_enabled`
      false, `authority_proof_mutation_owner_id` null,
      `authority_proof_mutation_controller_role_arns` empty); any prod plan diff
      beyond variable declarations is a stop condition.
- [ ] Pre-rollout — sandbox plan confirmation: run the sandbox Control plan and
      confirm no resource changes while the gate is false.
- [ ] Blocked — do not enable: the gate may not be flipped until
      qurl-conformance exports `ConnectorAuthorityOperationMutateProofAgent` and
      a qurl-service Authority image implements the operation, the cross-cell
      move, and the proof directive store. Enabling it against the current image
      would create a function whose handler fails closed at init with
      `configuration_invalid`.
- [ ] Rollout (later slice) — bind a contract that budgets
      `layerv-nhp-sandbox-ca-pm` with `proof_controller` capacity of exactly one
      replica, one preinvoke limit, and burst/refill of one; set
      `authority_proof_mutation_owner_id` to the dedicated sandbox proof tenant
      and `authority_proof_mutation_controller_role_arns` to exactly the
      `layerv-nhp-sandbox-udp-proof-controller` role. Sandbox only.
- [ ] Rollout (later slice) — grant the proof controller
      `lambda:InvokeFunction` on the exact qualified proof alias ARN in the
      `udp-proof-runner` root. Do not grant it to the runner instance role, the
      Hub task role, or any cell server role.
- [ ] Post-rollout — confirm the deployed function inventory grew from 11 to 12
      in sandbox only, that the proof alias appears in no Hub or cell caller
      policy, and that the execution role's DynamoDB statements carry the
      `dynamodb:LeadingKeys` fence for the proof tenant partition.
- [ ] Rollback: set `authority_proof_mutation_controls_enabled` false in the
      sandbox root and re-apply. The function, aliases, and execution role are
      destroyed; no other operation is affected because the proof family is
      disjoint from the hub and cell graphs. Prod requires no rollback action.
