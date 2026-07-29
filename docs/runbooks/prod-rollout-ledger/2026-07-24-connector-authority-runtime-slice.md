# 2026-07-24 · Connector Authority runtime slice (Step 4)

- **Owner:** prod rollout coordinator
- **Source:** this PR, `feat(control): deploy complete connector authority graph`
  (branch `justin/feat/connector-authority-cell-catalog`) · plan
  `prancy-mapping-wilkinson` Step 4 · depends on Step 3 (contract bind,
  nhp#3411/#3414) and nhp#3452 (cell1 logical protocol environment)

Deploy the complete two-cell Connector Authority graph: three Hub functions
plus `iro/ar/cr/ccr` for each of `cell0` and `cell1` (11 total), with both
closed blue/green aliases, steady provisioned/reserved concurrency,
per-operation execution roles, spillover alarms, and exact private dependency
paths. This PR retains the opt-in cell caller capability, but both automatically
deployed sandbox cell roots remain null/dark by default. A later activation PR
gives each enabled cell one private-DNS Lambda endpoint and an invoke policy
restricted to its four same-color aliases; no Authority call uses NAT or a
public Lambda route. Sandbox measurement only; prod stays locked dark.
For this initial dark bootstrap, both color aliases intentionally target the
same first published version and only the selected color is provisioned. This
is not a working image rollout or rollback controller: the rollout capacity and
rollback-retention fields are validation-only until
[nhp#3456](https://github.com/layervai/nhp/issues/3456) is complete.
**Do not apply until the items below are closed.**

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
      function/Redis SG references visible; if the provider hides them, extend the
      ingress admission from the observed shape rather than loosening it.
- [ ] Pre-rollout (SECURITY-GROUP REPLACEMENT, blocks apply): review the exact
      Terraform 1.14.3 `authority-runtime-legacy-expansion` plan as **69 create,
      15 update, 1 destroy**. The one replacement must be only
      `aws_security_group.authority_lambda[0]`, with `replace_paths =
      [["name_prefix"]]`, moving from `-ca-fn-` to `-ca-fn-v2-`. Its predecessor
      must carry exactly the two observed legacy inline egress rules: TCP/443 to
      `10.102.0.0/16` and TCP/443 to the regional DynamoDB prefix list. Its
      replacement must carry no inline ingress/egress; the only post-replacement
      paths are the four reviewed standalone rules (function SG to interface
      endpoint SG on 443, function SG to DynamoDB prefix list on 443, and the
      bidirectional function-SG/Redis-SG pair on 6379). Reject a plan that keeps
      the VPC CIDR, substitutes any CIDR, rewires either SG edge, or replaces any
      other resource. Both automatically deployed cell caller roots remain
      null/dark, so this substrate PR cannot send cell-originated traffic during
      the replacement. No Terraform apply occurs in this PR.
- [ ] Pre-rollout (ARTIFACT + DEPENDENCIES, blocks apply): confirm the published
      qurl-service Authority image architecture matches Terraform
      `architectures`, the SSM-pinned digest is the intended immutable pin, and
      the staged-latency proof confirms the configured 10-second timeout and
      512-MiB memory size without consuming the request-path budget. Confirm the
      OTP pepper has one unambiguous `AWSCURRENT` value under the Authority data
      CMK, both IAM-only Redis users are attached, and the SES identity and
      configuration set are usable. The source-reviewed IAM is operation
      specific: only IA signs; only IRO/AR read the OTP secret and connect to
      their directional Redis identities; only IRO sends email.
- [ ] Pre-rollout (CELL1, blocks cell fleet apply): merge nhp#3452 and confirm
      cell1 keeps its distinct infrastructure namespace while rendering the
      shared `sandbox` protocol environment expected by the Authority aliases.
      Apply only a saved plan that replaces the live greenfield cell1
      `10.102.0.0/16` VPC with the reviewed `10.104.0.0/16` allocation and
      contains no unrelated destroy. The 2026-07-25 read-only preflight first
      rejected `10.103.0.0/16` because it contains the proof runner's
      `10.103.0.0/28`, then accepted `10.104.0.0/16` in all 17 enabled
      regions; no active IPAM, Transit Gateway attachment, VPN, Client VPN,
      Direct Connect connection/virtual interface/gateway, Cloud WAN core
      network, conflicting VPC, peering, or route was found. Re-run the exact
      fail-closed inventory immediately before apply and stop on any drift.
- [ ] Pre-rollout (CELL1 QURL-SERVICE TOPOLOGY, blocks two-cell proof): land a
      separate, narrowly reviewed PR that deploys a real cell1 qurl-service ECS
      service on cell1 private subnets with its exact task/execution IAM,
      secret/KMS access, service discovery, logs, alarms, and immutable deployed
      digest output. The live 2026-07-25 audit found only the cell0 qurl-service
      cluster. Do not call the provisioned-cell graph or two-cell Authority path
      complete until cell1 has its own healthy service. The eight-image proof
      manifest's `qurl_service_cell1` value must come from that deployed service,
      never from cell0 or an inferred ECR tag.
- [ ] Pre-rollout (HUB IDENTITY, blocks Hub worker apply): require the
      CREATE_ONLY seeder to produce the exact private/cookie secret and matching
      public-only
      `/${environment}/nhp/control/hub/identity/public-key` value without key
      material in Terraform state. The redacted invocation must accept exactly
      the three-key `private_key`, `active_cookie_key`, and
      `previous_cookie_key` schema at `AWSCURRENT`; any older or extra-key shape
      blocks apply without printing or exporting secret bytes. Verify the public
      parameter is no longer `pending-keygen`, derives from the persisted
      `AWSCURRENT` private key, and a retry repairs only a partial publication
      rather than rotating identity. Any third public value is a terminal
      conflict. The signed UDP
      manifest/assignment producer remains a separate slice and role; do not
      widen the Hub image publisher to read or publish discovery state.
- [ ] Rollout (sandbox only): apply the exact `authority-runtime-slice`
      transition — the 11-function graph plus exactly the DynamoDB, KMS,
      Secrets Manager, SES, interface-endpoint-SG, and Redis-SG opens; nothing
      else non-no-op. Wait
      for every provisioned-concurrency config to reach `READY` (init must reach
      dependencies through private endpoints). Verify with the extended
      `check-control-sandbox-first-apply.py state`/`live`: exactly 11 Authority
      functions live, endpoint policies name only the expected execution roles,
      no wildcard Authority invoke grant exists, the live function SG name has
      the `-ca-fn-v2-` generation, and neither it nor any standalone rule
      contains `10.102.0.0/16`, `0.0.0.0/0`, or another CIDR substitute.
- [ ] Rollout (CELL CALLERS — separate activation PRs, do not skip): after the
      saved-plan Control runtime apply is verified, land an explicit cell0
      activation PR that sets its complete four-alias graph, apply it, and
      refresh the NHP server ASG. Only after nhp#3452 and the cell1
      `10.104.0.0/16` replacement are applied and verified, repeat in a
      separate cell1 activation PR.
      Prove each endpoint policy and server identity policy agree on the exact
      role, aliases, and VPC endpoint ID. Confirm private DNS resolves the
      Lambda service to the cell endpoint, VPC Flow Logs show the calls on that
      endpoint, and no NAT/public Lambda path is used. The Hub continues to
      invoke only IA/RA/ICR through its separate Control-VPC endpoint. Do not
      enable either caller graph in this runtime-substrate PR: a merge to main
      automatically deploys the sandbox roots while the Control runtime apply
      is manual-only.
- [ ] Post-rollout (UDP proof): from each assigned cell, prove direct UDP
      `NHP_OTP`, `NHP_REG`/`NHP_RAK`, registration completion, and credential
      recovery including replay, wrong-cell alias, mixed-color, non-direct
      ingress, timeout, response-write, Redis denial, and SES failure cases.
      Run this only after both NHP and qurl-service are healthy in each tested
      cell. Keep customer traffic disabled unless every failure is fail closed.
- [ ] Rollout/rollback (DARK CA-PM CAPABILITY, sandbox only): first apply the
      proof-runner root to establish its deterministic controller role; that
      state owns no Authority policy, alias input, or cross-state alias output.
      Then apply the exact Control `authority-proof-enable` saved plan. Control
      must create ca-pm and attach one inline policy to
      `layerv-nhp-sandbox-udp-proof-controller` whose only action is
      `lambda:InvokeFunction` and only resource is Control's selected qualified
      ca-pm alias. IA/RA/ICR and all six aliases must remain no-ops: this slice
      is not the attended proof and must not bypass the later governed zero-spill
      consumer rollout. Rollback is the exact Control
      `authority-proof-disable` plan; its alias dependency removes the
      controller policy before deleting the ca-pm graph, proof
      caller/function, endpoint principal, and alias output. Finish with
      Control state/live checks and a refresh-enabled dark no-op. Partial
      deletion, foreign drift, a retained/inactive alias grant, or any
      IA/RA/ICR movement blocks the operation.
- [ ] Rollout/rollback (PROOF CONSUMER STAGING, sandbox only): after ca-pm is
      live, apply the consumer-staging gate. The saved plan may publish new
      IA/RA/ICR versions and update their exact execution policies, but both
      blue and green aliases for all three functions must remain byte-for-byte
      unchanged. Confirm the selected aliases still report
      `proof_policy_consumers_active=false`; the attended qurl-go handshake must
      fail closed with the governed-rollout-required error. Activate the staged
      versions only through the separate zero-spill controller, with
      provisioned concurrency READY and spillover remaining zero, then require
      authenticated deployment evidence to report
      `proof_policy_consumers_active=true` before the proof may arm. Roll back
      in reverse: governed alias rollback first, consumer-staging gate second,
      then govern both aliases onto the newly published non-proof version
      before disabling ca-pm. Any alias delta in the ca-pm-disable plan blocks
      that final operation.
- [ ] Production: remains blocked. Prod `authority_runtime_contract`,
      `authority_runtime_contract_evidence_verified`, and
      `authority_runtime_functions_enabled` are validation-locked to
      null/false/false throughout sandbox measurement. Do not reuse the sandbox
      transition; production Control has no foundation state. After the prod
      gates close, review a separate production first-apply contract for the
      then-current inventory.
- [ ] Post-rollout: complete
      [nhp#3455](https://github.com/layervai/nhp/issues/3455) before any caller
      activation or customer traffic: operator alarm wiring for the spillover
      metric (SNS actions) plus Throttles/Errors/Duration and custom
      admission/initialization-type alarms. This slice lands only the
      security-critical spillover metric guard; do not treat it as
      rollout-aborting until its actions are live. Prove
      `ProvisionedConcurrencySpilloverInvocations == 0`.
- [ ] Before the first post-bootstrap Authority image roll (and before any
      production activation): complete
      [nhp#3456](https://github.com/layervai/nhp/issues/3456). Prove distinct
      versions can be warmed on active/standby allocations, callers switch only
      as one same-color graph, failures abort or roll the whole graph back, and
      the previous version remains available for the governed retention window.
- [ ] Rollback: destroy the runtime slice by flipping
      `authority_runtime_functions_enabled` back to false (re-closes the
      Control dependency endpoints and removes the 11-function graph), then set
      each cell's `connector_authority_cell_config` to null and refresh both
      server ASGs to remove caller IAM, endpoints, and environment. The contract
      binding and dark foundation remain. Do not restore or reattach the legacy
      generation-1 function SG: rollback removes the runtime and its
      generation-2 SG; a later re-enable creates a clean standalone-rule-owned
      SG. Delete this entry once the two-cell sandbox path is live-proven and the
      calibration lands on main.
