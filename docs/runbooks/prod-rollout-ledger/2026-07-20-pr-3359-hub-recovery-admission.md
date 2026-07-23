# 2026-07-20 · PR #3359 · Compose dark Hub recovery admission

- **Owner:** prod rollout coordinator
- **Source:** [#3359](https://github.com/layervai/nhp/pull/3359),
  observability/resilience follow-up [#3370](https://github.com/layervai/nhp/pull/3370)

Adds the assignment-only `nhp-hubd` process composition and wires it to admit
`ModeRecover` through the closed `admissibleMode` gate, calling the general
recovery-capable `connectorauthority.HubClient.IssueCredentialRecovery` via a
third exact operation-specific alias. The Hub reads that alias from a new `hub.toml` field
`issue_credential_recovery_alias_arn` (Go `IssueCredentialRecoveryAliasARN`),
validated alongside issue/refresh by `ValidateHubTargets`. Shipped with a
placeholder alias that **fails closed** — recovery is inert until the real
`layerv-nhp-<env>-ca-icr:{blue|green}` alias exists, all three Hub targets use
the same IaC-selected color, and the config value is provisioned.

- [ ] Rollout (prerequisite): confirm the `issue_credential_recovery` Lambda
      alias exists at the selected `blue` or `green` qualifier in the target
      environment (produced by the
      Connector Authority runtime / qurl-service producers) **before** setting
      the `hub.toml` value — the Hub validates the exact `ca-ia`, `ca-ra`, and
      `ca-icr` physical names and their one common color before AWS loading, and
      fails closed on an empty, malformed, or mixed-color graph.
- [ ] Rollout: set `issue_credential_recovery_alias_arn` in the prod
      `nhp-hubd` config to the provisioned selected-color alias ARN (replacing
      the shipped placeholder). Do NOT enable recovery admission before that
      exact alias resolves.
- [ ] Post-rollout (fail-closed proof): with the placeholder/unprovisioned
      alias, confirm `nhp-hubd` refuses to start (startup validation), and with
      the real alias confirm a recovery LST is admitted (gate allows
      `ModeRecover`) and routes to `IssueCredentialRecovery` exactly once, with
      issue/refresh unaffected.
- [ ] Pre-rollout (monitoring path): grant the Hub worker role only
      `cloudwatch:PutMetricData` for the `LayerV/NHP` namespace and prove its
      isolated subnet reaches the private CloudWatch `monitoring` endpoint. The
      source exporter uses the exact `Environment` base dimension and performs
      no public network or HTTP application request.
- [ ] Post-rollout (metrics proof): send one sandbox challenge and one valid
      assignment, then prove `HubWorkerOutcome`, `HubHandlerClassification`,
      and `HubChallengeObservation` arrive under the expected `Environment`.
      Prove the failure-path metrics (`HubUnknownLabel`, queue/replay-capacity
      outcomes, and `HubHealthAcceptRetry`) are selectable by the dashboards and
      alarms before activation; do not manufacture a production failure.
- [ ] Post-rollout (health resilience): in the sandbox worker harness, inject a
      temporary TCP health-listener `net.Error` and prove the process remains
      serving UDP while `HubHealthAcceptRetry` increments; a permanent listener
      error must still stop the process.
- [ ] Rollback: unset/placeholder `issue_credential_recovery_alias_arn` (Hub
      fails closed again) or revert the PR; no data migration or state refresh.
- [ ] Follow-ups: delete this ledger entry once the prod alias, private
      monitoring path, fail-closed/admit proof, metric visibility, and health
      resilience proof are all recorded.
