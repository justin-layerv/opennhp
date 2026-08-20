# tests/smoke — Local Guidance

## Prod Rollout Ledger

Smoke-suite changes that add/remove required prod verification, alter
deploy-mode mapping, add SSM probes, or create a new release gate often create
prod rollout tasks. When they do, add a succinct entry file under
[`../../docs/runbooks/prod-rollout-ledger/`](../../docs/runbooks/prod-rollout-ledger/)
before merge (delete it once its tasks are done).

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

The suite has ONE entrypoint, `scripts/run-smoke.sh`
(`TARGET=local|sandbox|prod`), shared by all three contexts. It owns the
tier → `RUN_FILTER` mapping (fenced by
`scripts/check-smoke-tier-filter-coverage.sh`, which parses the script) and
the env-derived flags (e.g. `NHP_SMOKE_QURL_INTERNAL_ALB_ENABLED`). It does
**not** fetch Auth0 — the `::add-mask::` masking is GitHub-Actions-only, so
each caller fetches and passes the creds in.

- **Local pre-PR (self-contained, no AWS/Auth0):** `make test-smoke-local`
  brings up nhp-server + dynamodb-local (`tests/smoke/local-stack/`) via
  docker compose and runs the wire-contract `local` tier against the
  freshly-built server binary. `make smoke-build` is the credential-free
  compile + vet + tier-fence gate.
- **PR CI:** `.github/workflows/nhp-smoke-pr.yml` runs `smoke-build` and the
  `smoke-local` stack on PRs touching the server or the smoke suite. No
  secrets — safe for forks. This is the only smoke path that exercises a
  PR's OWN code (the deployed-env paths below test already-deployed binaries).
- **Post-deploy CI:** `.github/workflows/build-and-push.yml` runs it against
  sandbox after `deploy-sandbox-validate`;
  `.github/workflows/promote-to-prod.yml` runs it against prod alongside
  `qurl-smoke-tests`. Both call the reusable `nhp-smoke-tests.yml`, which now
  invokes `run-smoke.sh`. Both run in report-only mode (burn-in).
- **Manual:** `gh workflow run nhp-smoke-tests.yml --ref <branch> -f environment=sandbox -f tier=tier1 -f allow_ssm_probes=true`
- **Deployed sandbox/prod from a laptop:** `make test-smoke-sandbox` /
  `make test-smoke-prod` (read the AWS profile; no Auth0 — the qURL-minting
  tests that needed it were moved out of nhp).

### Local target (`TARGET=local` / `NHP_ENVIRONMENT=local`)

The local stack (`tests/smoke/local-stack/`, brought up by
`scripts/smoke-local-stack.sh`) runs the real **nhp-server + nhp-ac** binaries
in their cloud-mode DynamoDB path against `amazon/dynamodb-local` (etcd is
being retired; do not add an etcd path). The AC registers with the server over
NHP_AOL using a license the stack script seeds into the `nhp-licenses` table —
cloud mode validates the AC via a bcrypt license check, NOT static `ac.toml`
(permit mode accepts the unbound license), so `/health/knock-ready` reflects a
live AC peer.

If `Smoke (local stack)` goes red on an unrelated PR, suspect the AC's
iptables/ipset firewall init first: the AC container runs `ipset` under
`NET_ADMIN` and needs the runner's `ip_set` kernel module; if registration
fails, knock-ready only times out at the 90s `wait_for` ceiling. The bring-up
script dumps `compose logs nhp-server nhp-ac` on that timeout — read those
(ipset errors) before re-diagnosing.

The curated `local` tier runs the non-qURL wire contract
(`HealthLive|HealthReady|HealthStartup|HealthKnockReady|Plugins|Timing`) plus
the offline `ResolveV2` SDK rejection and `QurlLinkFrontend` committed-template
render fences. The remote qurl.link checks under the latter prefix skip locally;
only source/render checks execute.
It exercises **no qURL resolve/handler path** — under `Plugins` only the
dispatcher 404 (`TestPlugins_UnknownASPIDReturns404`) runs locally; the
branded-403 qURL path is `requireRemote`. So the local signal is: server+AC
boot, AC registers via the seeded license, knock-ready reflects a live peer,
and health/timing respond.
Everything else is remote-only and **skips cleanly** under
`NHP_ENVIRONMENT=local` — so `go test -tags=smoke ./...` against the local
stack has zero failures (only the local-runnable subset executes; the rest
skip):
- qURL/TLS-dependent contract tests that REMAIN in nhp — the qurl-plugin
  rejection path (10_resolve bad-token→403), qurl-browser-timings,
  qurl-link-frontend, protocol-surface (real TLS cert), internal-api
  source-IP — skip via `requireRemote(t)` at the top of the test. (The
  qURL-MINTING tests — happy-path resolve, accept-negotiation,
  qurl-router-authz-gate, and the real-resolve knock-ready lie detector — were
  removed from nhp; see the qURL-ownership note below for where those signals
  moved.)
- AWS-infra fences (blue/green, canary, EIP, alarms, CW logs, SSM runbook,
  custom-domain, Docker image) skip via `requireRemote` (in the central
  `getSSMParameter` / `requireCWLogs` / `requireActiveColor` /
  `requireServingASG` helpers, or per-test) / `skipIfNot{BlueGreen,Canary}`
  (DeployMode is empty under local) / `skipIfNoSSMProbes` (probes off).

Keys + license live in `tests/smoke/local-stack/`: the server keypair
(`server/etc/config.toml` private ↔ the AC's `ServerPubKeyBase64`) was
generated with `nhp-serverd keygen` (curve25519); the license key and its
sha256/bcrypt hashes are constants in `scripts/smoke-local-stack.sh` with
inline regen instructions. None are production secrets.

To add a test to the local tier: make it pass against the localhost stack
(gate any AWS/qURL dependency with `requireRemote`), then add its
`Test<Prefix>_` token to the `local` case in `scripts/run-smoke.sh`. The
coverage checker treats `local` as a curated allow-list (like `all`): it
validates the tokens are real but does not require every test to appear.

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
required check. When promoting `nhp-smoke-pr.yml` to a required check,
account for its `paths:` filter: a required check that never triggers on a
PR outside those paths leaves the PR pending forever — gate the requirement
on the same paths (or drop the filter) so it always reports.

**Env-keyed feature gating in the smoke suite is currently a
multi-place coordination** — see #1640. Today four sites must update
in lockstep when adding a new env that participates in the qurl-
service internal-ALB rollout:

1. `scripts/run-smoke.sh` — the per-target
   `NHP_SMOKE_QURL_INTERNAL_ALB_ENABLED` derivation (moved here from
   nhp-smoke-tests.yml's `||` chain when the entrypoint was unified).
2. `tests/smoke/dns.go::deriveEndpoints` — internal hostname mapping.
3. The env's tfvars — `qurl_internal_service_domain`.
4. `tests/smoke/09_public_alb_internal_lockdown_test.go` —
   `httpListenerOptOutEnvs` map (env that disables the public HTTP
   listener opts out of the HTTP-redirect fence).

(The former fifth site — `17_qurl_router_authz_gate_test.go`'s
`qurlSiteAuthzOptOutEnvs` map — is gone: that qURL-minting test was
removed when qURL smoke moved to qurl-service.)

#1640 tracks moving all four onto SSM-sourced reads at `TestMain`,
collapsing the coordination to a single Terraform-owned parameter
per gate. Until that lands, adding a new env to the suite is a
four-place edit.

`TestMain` also resolves the #1645 lockdown-body fence's expected
value from the Terraform-owned SSM parameter
`/{env}/nhp/qurl/internal-lockdown-body` (see
`aws_helpers.go::resolvePublicALBLockdownExpectedBody`). This is **not**
one of the five env-gating points above — it's a body-shape source read
only by `09_public_alb_internal_lockdown_test.go`, and a missing/parse-fail
reds just those fences (scoped via `requirePublicALBLockdownExpectedBody`,
not a suite abort). It already follows the #1640 shape (SSM-sourced read at
`TestMain`), so #1640's consolidation needn't touch it.

### Resolve-endpoint topology gate (JS-agent + relay)

Envs that enable the browser JS-agent + NHP-Relay topology
(`qurl_link_js_agent_enabled = true`, sandbox today) take `nhp-server`
private: Terraform's `qurl_resolve_endpoint_enabled = deploy_qurl_link &&
!qurl_link_js_agent_enabled` tears down the public `resolve.qurl.link`
NLB/HTTPS surface that hosted `/health/*`, `/plugins/*`, the qURL
token-resolution path, the `resolve-origin` record, and the server's
blue/green HTTPS listener (and its `https-listener-arn` SSM param). The
smoke mirror is `derivedEndpoints.ResolveEndpointEnabled`
(`dns.go::deriveEndpoints`), and tests fencing that surface gate on
`skipIfResolveEndpointDisabled(t)` — they skip in JS-agent envs and run
where the surface is live (prod, and the localhost stack). `01_health`,
`09_resolve_origin_idle_timeout`, `10_resolve` (the v1 server-403 tests),
`12_qurl_browser_timings`, `13_plugins`, `14_internal_api`, `24_timing`
all carry the gate; `04_blue_green` drops its `server/https` listener check
on this gate.

**UDP 62206 on the assigned cell NHP NLB is a public invariant.** Upcoming
native UDP SDKs bypass the HTTPS relay and connect directly to their assigned
cell, so every blue/green environment retains the public server NLB, its sole
UDP 62206 listener, and the `udp-listener-arn` / `{color}-udp-tg-arn` SSM
parameters. The relay separately reaches the same cell through the internal
listener tracked by `internal-udp-listener-arn` and
`{color}-internal-udp-tg-arn`; `04_blue_green` asserts both active-color
contracts. The retired `take-server-private` SSM cutover marker has no supported
consumer and is removed by Terraform. `04_blue_green` unconditionally asserts
the public listener and active target group. This UDP invariant is independent
of the legacy HTTPS resolve surface above, which may still be disabled in
JS-agent environments.

`ResolveEndpointEnabled` MUST stay the inverse of
`qurlLinkJSAgentEnabledEnvs` (the `16_qurl_link_frontend_test.go` mirror of
the same tfvar). `dns_test.go::TestDeriveEndpoints_ResolveEndpointTracksJSAgent`
fences the two against drift, so adding a new JS-agent env is a both-places
edit. The TLS-surface fence (`21_protocol_surface`) does NOT skip — it
**re-homes** to the relay ALB via `nhpIngressTLSURL()` / `RelayBaseURL`
(`relay.qurl.link.<env>`); the relay ships dark and 404s every route, so its
TLS termination is the only externally-assertable relay surface. The v2
keyed-identity resolve-REJECTION contract moved client-side into the
`github.com/layervai/qurl-go` SDK — `10_resolve`'s
`TestResolveV2_SDKRejectsBadLinks` fences it offline (no deployed infra, no
minting) and runs in every env. New resolve work uses the SDK, not the dead
HTTP endpoint.

**Server and AC flip blue/green independently.** Each component has its own
`/{env}/nhp/{server,ac}/active-color` SSM param and its own ASG/TG set; a
per-component deploy can leave them on different colors (observed:
server=blue while the AC rolled to green). Every blue/green resolution is
therefore **per-component** — never reuse one component's color for the
other's resources:

- `requireActiveColorForComponent(t, component)` / `inactiveColorForComponent(t, component)`
  read the named component's own active/standby color.
- `requireActiveColor(t)` / `requireActiveACColor(t)` are the server / AC
  convenience wrappers over the former.
- `requireServingASG(t, component)` (behind `requireActiveServerASG` /
  `requireActiveACASG`) and the `04_blue_green` listener + inactive-ASG fences
  all route the component through these, so `02_ac_ebpf_objects` /
  `05_ac_eip_pool` resolve the AC's serving fleet even when the colors diverge.

The `scripts/check-smoke-tier-filter-coverage.sh::tier3_no_ssm_expected_omissions`
list is a sixth env-independent maintenance list — it documents
which Test prefixes are SSM-required and so legitimately omitted
from the tier3-no-ssm RUN_FILTER. Update it when a test gains or
loses a hard SSM dependency.

The qURL resolve/minting smoke tests (formerly the `10_` happy-path,
`15_`, and `17_`) used to exercise the qURL resolve path, which opens the
AC `defaultset` pinhole for the smoke runner's source IP for the env's
OpenTime window. Those tests were removed (qURL minting is a qurl-service
concern), so **no smoke test opens that pinhole today** — the old caveat
about a later `18_+` test inheriting a still-open `*.qurl.site:443`
pinhole and false-passing no longer applies. `10_resolve_test.go` now
exercises only the bad-token→403 rejection path, which mints nothing.

The deleted HTTP-era coverage is no longer an unowned gap:
[qurl-service#1018](https://github.com/layervai/qurl-service/pull/1018)
re-homed the deployed `/plugins/qurl` response shape (302, cookie domain,
`Accept` negotiation, and CORS), the qurl-router silent-drop gate, and the
real-resolve knock-ready "lie detector". qURL v2 live resolve coverage is
being restored in qurl-service via `EnterPortal`; the remaining cutover work is
tracked by
[qurl-service#1047](https://github.com/layervai/qurl-service/issues/1047).
The removed `TestTiming_ResolveMax` latency/SLO signal remains a separate
decision item in [nhp#2799](https://github.com/layervai/nhp/issues/2799).

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
