# 2026-08-06 · Unlock the production Control root

- **Owner:** prod rollout coordinator
- **Source:** this PR · Connector Authority foundation [#3227](https://github.com/layervai/nhp/issues/3227)

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

- [ ] Pre-rollout (**blocking — no production Control apply path exists**):
      `control-sandbox-update.yml` is sandbox-only (1103 lines, 58 sandbox
      bindings) and there is no production counterpart. Land a reviewed
      production Control workflow with prod OIDC, the `production` environment
      approval, and the same saved-plan/byte-compare contract before any
      production Control plan runs. The `hub-publish-production` GitHub
      environment already exists with protection rules; the
      `layerv-nhp-prod-control-hub-publisher` role does not, because the
      foundation apply creates it.
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
- [ ] Post-rollout: verify the catalog row materialized exactly as pinned via a
      strongly consistent read, that `REGISTRY/CELL#cell0` reports
      `general_assignable=true` (production has one cell; a non-assignable cell0
      strands every weight-placed agent), and that placement issues and
      activates against it.
- [ ] Post-rollout: confirm every Authority alarm routes to
      `layerv-nhp-prod-cell0-alerts`. Alarm state is not evidence on a fresh
      path — every Authority alarm uses `treat_missing_data = notBreaching`, so
      a wrong dimension set presents as a permanently green `OK`. Fire one
      synthetic failure and record the page receipt.
- [ ] Rollback: before publication, remove the foundation with a reviewed saved
      plan. After publication, preserve every immutable source-SHA image and the
      digest pin as evidence; close the runtime by returning the gates to their
      committed-closed defaults rather than destroying artifacts.
