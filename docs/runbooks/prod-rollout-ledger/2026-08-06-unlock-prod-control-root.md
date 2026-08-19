# 2026-08-06 · Unlock the production Control root

- **Owner:** prod rollout coordinator
- **Source:** this PR · Connector Authority foundation [#3227](https://github.com/layervai/nhp/issues/3227) · CLI release trust [qurl-integrations#1227](https://github.com/layervai/qurl-integrations/pull/1227)

Production Control has never been applied — `nhp/prod/control/terraform.tfstate`
does not exist. This PR removes the source-level validation locks that made a
non-dark production plan fail at plan time, and pins the reviewed production
values in their place. It applies nothing on its own; the bootstrap below is the
rollout.

Ordering is load-bearing in two places, both easy to get wrong:

- The catalog row advertises **UDP 443**. Production's public UDP listener does
  not reach that shape until #3649's apply moves it 62206 -> 443. Materializing
  the catalog first places agents on a port with no listener.
- The Authority runtime contract carries an **image digest that does not exist
  yet**. The foundation apply creates the production ECR repository and the
  publisher role; only then can `publish-hub-image.yml` run for
  `target_environment=production`; only then is there a digest for the runtime
  apply to consume.
- Native enrollment has a three-part trust/serving handoff after Control is
  live: an explicit `hub.nhp.layerv.ai` alias must target Control's Hub NLB,
  the official CLI release must embed the Hub (not cell) public key, and cell0's
  server fleet must receive Control's selected four-operation Authority alias
  graph. Omitting any one produces a route that resolves but cannot enroll.

- [ ] Pre-rollout: dispatch `control-prod-update.yml` from the exact reviewed
      `main` commit with `operation=plan-only`, both Hub gates false, and the
      exact confirmation. Review the first-apply plan and then use a fresh
      `plan-and-apply` dispatch under the `production` environment approval;
      its saved-plan byte comparison is the only production Control apply path.
      The `hub-publish-production` environment already exists, while the
      `layerv-nhp-prod-control-hub-publisher` role is created by this foundation
      apply.
- [ ] Pre-rollout: confirm #3649 has applied in production and exactly one
      public UDP listener per cell answers on 443, before the catalog
      materializes. The row's `nhp_host` (`cell0.nhp.layerv.ai`) already
      resolves to the production server NLB.
- [ ] Pre-rollout: re-read `layerv-nhp-prod-server`'s `publicKey` field and
      confirm it still equals the `server_public_key_b64` pinned in
      `terraform/control/environments/prod/variables.tf`. This is the
      SERVER-IDENTITY key, not the shared AC registration key; conflating them
      silently fails every agent knock HMAC validation.
- [ ] Rollout (foundation): apply the production Control root with the runtime
      gates at their committed defaults — `authority_runtime_functions_enabled`,
      `hub_edge_enabled`, `hub_worker_enabled` all false and
      `authority_runtime_contract` null. This creates the VPC (`10.202.0.0/16`),
      Control tables, KMS keys, ECR repositories, and the publisher role, and no
      Lambda, alias, or public listener.
- [ ] Rollout (publish): dispatch `publish-hub-image.yml` with
      `target_environment=production`, approve only `hub-publish-production`,
      and record the exact source SHA, run, attempt, and manifest digest.
      Publish the connector-authority image through its own governed publisher
      the same way.
- [ ] Rollout (runtime): supply the contract and gates through the reviewed
      production dispatch. **Expect two applies** — the first stages aliases and
      fails on the `foundation_contract` precondition; a re-plan and re-apply
      closes it. That is the known behaviour of a same-color authority image
      roll, not a fault to debug mid-window.
- [ ] Rollout (Hub DNS): in the management account's `layerv.ai` Route 53 zone,
      create an explicit `hub.nhp.layerv.ai` A-alias from the production Control
      outputs `hub_nlb_dns_name` and `hub_nlb_zone_id`. Do not accept wildcard
      resolution as proof: before this rollout the wildcard targets the existing
      access-control NLB, which is not the Hub. Read back the exact alias and
      verify the Hub target group is healthy on UDP 443 -> worker 62206.
- [ ] Cross-repo (CLI trust): after the worker keygen has replaced
      `pending-keygen`, read `/prod/nhp/control/hub/identity/public-key`, validate
      it as canonical padded base64 for a usable 32-byte X25519 key, and compute
      SHA-256 over the decoded bytes (not the base64 text). Commit that fingerprint
      in qurl-integrations, set the public repository variable
      `QURL_CONNECTOR_HUB_SERVER_PUBLIC_KEY_B64` to the exact parameter value, and
      require its release verifier to pass before publishing an official CLI.
      Never substitute cell0's `server_public_key_b64`; that key authenticates
      the assignment destination, not the Hub.
- [ ] Rollout (cell0 Authority handoff): only after Control publishes a complete
      same-color `authority_cell_alias_targets["cell0"]`, remove the variable's
      validation source lock and change
      `connector_authority_cell_from_control_enabled` to `true` together in a
      reviewed production-root PR. Require the saved plan to create the Lambda
      VPC endpoint and least-privilege caller policy and to revise, not replace,
      the server launch template; then canary one server and roll the ASG so the
      `NHP_CONNECTOR_REGISTRATION_*` values are actually present at boot.
- [ ] Post-rollout: verify the catalog row materialized exactly as pinned via a
      strongly consistent read, that `REGISTRY/CELL#cell0` reports
      `general_assignable=true` (production has one cell; a non-assignable cell0
      strands every weight-placed agent), and that placement issues and
      activates against it.
- [ ] Post-rollout (customer journey): with an official CLI built from the
      reviewed Hub fingerprint and no `QURL_CONNECTOR_HUB_*` overrides, publish a
      loopback HTTP service, wait for the serving signal, resolve its CRID through
      the sandbox-independent production API path, and record successful traffic
      plus Hub/Authority/cell0 evidence for that same connector run.
- [ ] Post-rollout: confirm every Authority alarm routes to
      `layerv-nhp-prod-cell0-alerts`. Alarm state is not evidence on a fresh
      path — every Authority alarm uses `treat_missing_data = notBreaching`, so
      a wrong dimension set presents as a permanently green `OK`. Fire one
      synthetic failure and record the page receipt.
- [ ] Rollback: before publication, remove the foundation with a reviewed saved
      plan. After publication, preserve every immutable source-SHA image and the
      digest pin as evidence; close the runtime by returning the gates to their
      committed-closed defaults rather than destroying artifacts.
- [ ] Rollback (native enrollment): before an official CLI release, remove the
      explicit Hub alias and return the Control/cell handoff gates to dark with
      reviewed saved plans. After a pinned CLI is released, preserve the Hub
      identity and recover its endpoint in place—falling back to the wildcard AC
      NLB or rotating the key strands installed clients and is not a rollback.
