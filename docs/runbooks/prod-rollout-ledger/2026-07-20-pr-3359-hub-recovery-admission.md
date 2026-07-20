# 2026-07-20 · PR #3359 · Compose dark Hub recovery admission

- **Owner:** prod rollout coordinator
- **Source:** [#3359](https://github.com/layervai/nhp/pull/3359)

Adds the assignment-only `nhp-hubd` process composition and wires it to admit
`ModeRecover` through the closed `admissibleMode` gate, calling the general
recovery-capable `connectorauthority.HubClient.IssueCredentialRecovery` via a
third `:active` alias. The Hub reads that alias from a new `hub.toml` field
`issue_credential_recovery_alias_arn` (Go `IssueCredentialRecoveryAliasARN`),
validated alongside issue/refresh by `ValidateHubTargets`. Shipped with a
placeholder alias that **fails closed** — recovery is inert until the real
`:active` alias exists and the config value is provisioned.

- [ ] Rollout (prerequisite): confirm the `issue_credential_recovery` Lambda
      `:active` alias exists in the target environment (produced by the
      Connector Authority runtime / qurl-service producers) **before** setting
      the `hub.toml` value — the Hub validates all three `:active` aliases at
      startup and fails closed on an empty/malformed recovery alias.
- [ ] Rollout: set `issue_credential_recovery_alias_arn` in the prod
      `nhp-hubd` config to the provisioned `:active` alias ARN (replacing the
      shipped placeholder). Do NOT enable recovery admission before the alias
      resolves.
- [ ] Post-rollout (fail-closed proof): with the placeholder/unprovisioned
      alias, confirm `nhp-hubd` refuses to start (startup validation), and with
      the real alias confirm a recovery LST is admitted (gate allows
      `ModeRecover`) and routes to `IssueCredentialRecovery` exactly once, with
      issue/refresh unaffected.
- [ ] Post-rollout (metrics export): the composed hub now meters the worker via
      the closed nonblocking `workerMetrics` observer, but counts are exposed
      only via snapshot accessors — wire them to the CloudWatch publisher
      (namespace/dimensions/checkpoint + lifecycle) in the follow-up before
      dashboards/alarms depend on them.
- [ ] Rollback: unset/placeholder `issue_credential_recovery_alias_arn` (Hub
      fails closed again) or revert the PR; no data migration or state refresh.
- [ ] Follow-ups: CloudWatch export of `workerMetrics` counters; delete this
      ledger entry once the prod alias is provisioned and the fail-closed +
      admit proofs are recorded.
