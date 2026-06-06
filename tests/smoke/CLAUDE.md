# tests/smoke — Local Guidance

## Prod Rollout Task Ledger

Smoke-suite changes that add/remove required prod verification, alter
deploy-mode mapping, add SSM probes, or create a new release gate often create
prod rollout tasks. When they do, update
[`../../docs/runbooks/prod-rollout-task-ledger.md`](../../docs/runbooks/prod-rollout-task-ledger.md)
by adding an entry following its PR Update Rule before merge.

During review, confirm either the task ledger was updated or the PR has no
pre-rollout, rollout, or post-rollout tasks. Do not add entries just to
describe behavior changes.

## Smoke Test Suite

Location: `tests/smoke/` (own Go module, build tag `smoke`).

The smoke suite runs against the **deployed** sandbox or prod
environment after a deploy completes. It fences NHP's own contract —
every guarantee the server and AC make to their consumers (QURL
plugin, Traefik plugin, the NHP wire protocol, the blue/green deploy
workflow). Unlike unit/local/integration/e2e tests, smoke exercises
the actual binary that is running in production.

### When to run

- CI: `.github/workflows/build-and-push.yml` runs it against sandbox
  after `deploy-sandbox-validate`. `.github/workflows/promote-to-prod.yml`
  runs it against prod alongside `qurl-smoke-tests`. Both paths
  currently run in report-only mode (burn-in).
- Manual: `gh workflow run nhp-smoke-tests.yml --ref <branch> -f environment=sandbox -f tier=tier1 -f allow_ssm_probes=true`
- Local: `make test-smoke-sandbox` (reads AWS credentials from the
  `layerv` profile and fetches Auth0 from Secrets Manager).

### Tiers

Tests are organized by file-name prefix so `go test` runs them in a
deterministic order:

| Prefix | Tier | Purpose |
|---|---|---|
| `01_`–`09_` | Tier 1 | Regression guards for fenced bug classes |
| `10_`–`19_` | Tier 2 | Consumer contract (guarantees NHP makes) |
| `20_`–`29_` | Tier 3 | NHP capability coverage + informational telemetry |

PR1 ships Tier 1 only. PR2 adds Tier 2. PR3 adds Tier 3 + flips
`continue-on-error` to false in the CI wiring so smoke becomes a
required check.

**Env-keyed feature gating in the smoke suite is currently a
multi-place coordination** — see #1640. Today five sites must update
in lockstep when adding a new env that participates in the qurl-
service internal-ALB rollout:

1. `.github/workflows/nhp-smoke-tests.yml` — `||` chain on
   `NHP_SMOKE_QURL_INTERNAL_ALB_ENABLED`.
2. `tests/smoke/dns.go::deriveEndpoints` — internal hostname mapping.
3. The env's tfvars — `qurl_internal_service_domain`.
4. `tests/smoke/09_public_alb_internal_lockdown_test.go` —
   `httpListenerOptOutEnvs` map (env that disables the public HTTP
   listener opts out of the HTTP-redirect fence).
5. `tests/smoke/17_qurl_router_authz_gate_test.go` —
   `qurlSiteAuthzOptOutEnvs` map (env that disables the L7 authz
   gate on `*.qurl.site` opts out of the silentDrop fence). Added
   in #1984.

#1640 tracks moving all five onto SSM-sourced reads at `TestMain`,
collapsing the coordination to a single Terraform-owned parameter
per gate. Until that lands, adding a new env to the suite is a
five-place edit.

`TestMain` also resolves the #1645 lockdown-body fence's expected
value from the Terraform-owned SSM parameter
`/{env}/nhp/qurl/internal-lockdown-body` (see
`aws_helpers.go::resolvePublicALBLockdownExpectedBody`). This is **not**
one of the five env-gating points above — it's a body-shape source read
only by `09_public_alb_internal_lockdown_test.go`, and a missing/parse-fail
reds just those fences (scoped via `requirePublicALBLockdownExpectedBody`,
not a suite abort). It already follows the #1640 shape (SSM-sourced read at
`TestMain`), so #1640's consolidation needn't touch it.

The `scripts/check-smoke-tier-filter-coverage.sh::tier3_no_ssm_expected_omissions`
list is a sixth env-independent maintenance list — it documents
which Test prefixes are SSM-required and so legitimately omitted
from the tier3-no-ssm RUN_FILTER. Update it when a test gains or
loses a hard SSM dependency.

### Deploy-mode tier mapping

NHP runs two deployment regimes side-by-side. The runtime source of
truth is the SSM parameter `/{env}/nhp/deploy/mode` (Terraform-owned,
see `terraform/main.tf::aws_ssm_parameter.deploy_mode`); the table
below is just the current tfvars snapshot — flipping any env's
toggles updates SSM on the next `terraform apply` and smoke adapts
automatically. The TF preconditions on `deploy_mode` reject
half-flips (e.g., `enable_blue_green=true, enable_ac_blue_green=false`)
at plan time so smoke's mode-keyed assertions can't silently
mis-fence.

| Environment | `enable_blue_green` | `enable_canary_deployment` | Mode (today) |
|---|---|---|---|
| sandbox | `true` | `false` | `blue_green` |
| prod | `false` | `true` | `canary` |

The smoke suite reads the SSM key once in `TestMain` and uses it to
route mode-specific tests:

- `skipIfNotBlueGreen(t)` — skip cleanly on canary envs. Used by
  `TestBlueGreen_*` tests that fence active/inactive ASG color flips,
  color-coded TG ARNs, and listener default-action switching.
- `skipIfNotCanary(t)` — skip cleanly on blue/green envs. Used by
  `TestCanary_*` tests that fence the canary state machine's
  post-deploy invariants (state == idle, state-machine ARN exists).

The `requireActive*ASG` helpers are deploy-mode-aware: in blue/green
they resolve to the active-color ASG via SSM; in canary they resolve
to the single ASG name. Tests that just want "the ASG currently
serving traffic" can call these without caring about the mode.

When adding new tests:
- A bug class in blue/green-only state goes in a `TestBlueGreen_*`
  test gated by `skipIfNotBlueGreen`.
- A bug class in canary-only state goes in a `TestCanary_*` test
  gated by `skipIfNotCanary`.
- Mode-agnostic invariants (listener health, deployed-commit SSM,
  AC EIPs are present) skip neither and use `requireActive*ASG`
  to find the serving ASG.

Greenfield envs must explicitly set exactly one of
`enable_blue_green` (with matching `enable_ac_blue_green`) or
`enable_canary_deployment` in tfvars — both default to `false` and
the precondition on `aws_ssm_parameter.deploy_mode` will reject the
first plan otherwise. The same precondition asserts AC and server
blue/green flags agree, so smoke's mode-keyed assertions stay valid.

### Maintenance rules (enforced at review)

1. **One file per NHP capability.** File name = capability in
   snake_case + `_test.go`. New capability ⇒ new file; retired
   capability ⇒ deleted file. If deleting the file would orphan
   assertions about other capabilities, the file is too broad and
   needs to split.
2. **Every test name references a capability or a bug class.**
   `TestHealth_KnockReadyReflectsACPeerCount` passes.
   `TestHealth_Works` fails review.
3. **Every Tier 1 test has a Go comment tagging the PR whose
   regression it fences.** Format: `// Regression fence for PR #1005
   (knock-ready gate used docker exec wget).`
4. **Every Tier 3 timing test has an SLO it fences.** No SLO
   documented in this file or code comments, no timing test.
5. **Deletion is a valid PR.** When a bug class is structurally
   eliminated, the Tier 1 test is **deleted** — not updated to
   point at a new class. The new mechanism gets its own test.
6. **CODEOWNERS.** Every PR that adds or changes a smoke test
   requires sign-off from `justin@layerv.ai` (see
   `.github/CODEOWNERS`).
7. **Banned file names**: `coverage_test.go`, `advanced_test.go`,
   `features_test.go`. These give no information. If the right file
   name isn't obvious, the capability doesn't exist yet.
8. **SSM probes are named helpers.** No `runCommand(cmd, args)` API.
   Every new probe is a reviewed function in `ssm_probe.go` with the
   command baked in as a Go constant. The reject-list in
   `ssm_probe.go` is defense in depth — it must never be the only
   thing catching a bad command.
9. **When shipping a new NHP capability, the same PR ships its
   Tier 2 contract test.**
10. **No test-only endpoints in production binaries.** If a contract
    can't be tested from smoke without test-mode code, it's an
    integration test, not a smoke test.
11. **30-day SSM burn-in.** Prod starts with `allow_ssm_probes: false`
    until the scheduled unlock workflow confirms 30 days of green
    sandbox runs.

### Shipping a new NHP capability

If you add a new NHP capability (endpoint, protocol message, deploy
gate, etc.), the PR that ships it should also:

1. Add a new `XX_<capability>_test.go` file under `tests/smoke/`.
2. Pick the appropriate tier:
   - Tier 1 if it fences a specific bug class fresh from a fixed PR.
   - Tier 2 if it's a consumer contract clause.
   - Tier 3 if it's capability observation or timing.
3. Cross-reference the PR number in Go comments (`// Regression
   fence for PR #NNNN` or `// Capability added in PR #NNNN`).
4. If the test needs SSM, add the probe as a named helper in
   `ssm_probe.go` with the command as a Go constant. Get review
   from `justin@layerv.ai`.
