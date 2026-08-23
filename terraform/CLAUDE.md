# terraform — Local Guidance

## Prod Rollout Ledger

Terraform, workflow, or user-data changes often create concrete prod rollout
tasks such as config writes, deploy ordering, ASG refreshes, rollback steps, or
post-rollout verification. When they do, add a succinct entry file under
[`../docs/runbooks/prod-rollout-ledger/`](../docs/runbooks/prod-rollout-ledger/)
before merge (delete it once its tasks are done).

During review, confirm either the task ledger was updated or the PR has no
pre-rollout, rollout, or post-rollout tasks. Do not add entries just to
describe behavior changes.

## PR-Time Terraform Plan Security

`terraform-plan-pr.yml` is an explicit, same-repo exception to the #1121
"no PR-time AWS credentials" posture. The plan role is non-mutating and
sandbox-only, but it can still read sandbox state, SSM values including
SecureStrings, Secrets Manager values, and KMS-decrypted material needed for
refresh. The role uses a dedicated plan-read managed policy rather than the
normal CI `terraform_read` policy so future apply-role read expansions do not
implicitly widen the PR identity; SSM value reads are scoped to NHP environment
paths, the three Auth0 public SPA-output parameters (`api-audience`, `domain`,
`spa-client-id`), the shared registration public-key path, and the public
Canonical AMI path. `ssm:GetDocument` is scoped to NHP and traefik-plugins
sandbox documents. S3 object reads are scoped to Terraform state plus
NHP-managed/plugin bucket patterns, SQS reads are limited to queue attributes,
queue URLs, and queue tags on `layerv-nhp-*` queues, ElastiCache reads are
`Describe*`/`List*`, and API Gateway reads use `apigateway:GET` and are treated
as value-bearing because API Gateway can return plaintext API key values. KMS
decrypt is constrained to the Terraform state alias plus NHP key aliases with
`kms:ResourceAliases`. The sole non-read-verb exception is
`lambda:InvokeFunction` on the exact `${name_prefix}-relay-status:$LATEST`
qualified function ARN. The invocation data source pins `$LATEST` explicitly;
the unqualified function ARN does not authorize that qualified request. That
function has a distinct handler and execution role which can only read the
relay secret and public-key parameter, aside from writing its own scoped log
stream; the multi-action identity/keygen Lambda is not invokable by the PR role.
**The Auth0 exposure that used to dominate this section is gone (#3284).** The
workflow no longer fetches an Auth0 Management API token, no longer receives the
long-lived Auth0 client secret, and no longer needs the base-commit
`terraform.tfvars` copy that pinned the `auth0_domain` the client-secret POST
was sent to. Terraform manages no Auth0 resource at all — see
[`modules/auth0/removed.tf`](modules/auth0/removed.tf). This mattered because
the credential in question was not read-only: the `Terraform` M2M held 37
Management API scopes (audited 2026-07-26) including `create:connections`,
`update:connections`, `create`/`update`/`delete:clients`, `update:branding`,
`create:actions`, and `read:client_keys` — enough to read every client secret in
the shared tenant, prod included, from a PR-head plan. The sign-off this section
used to demand for that grant is therefore moot; **do not reintroduce an Auth0
provider or credential into any Terraform path without re-opening it.**
`tests/scripts/test_auth0_not_terraform_managed.py` fails CI if that is
attempted.

The remaining PR-time exposure is the sandbox read role, so the rollout sign-off
must still confirm that PR-head code execution with it is accepted, including
plan-time exfil paths such as `data.http`, the `external` provider, and provider
endpoint overrides. The workflow restores its helper action/script paths from
the trusted base commit, but Terraform HCL and tfvars still execute from the PR
head during plan.
AWS IAM cannot evaluate GitHub `workflow_ref`/`job_workflow_ref` custom claims,
so the IAM trust is repo-wide `pull_request` and the fork/secret gates are
workflow-level controls. Before making `Terraform Plan (PR)` required, confirm
the PR #2464 rollout-ledger security sign-off accepts that push access to
`layervai/nhp` is inside this sandbox-secret-read trust boundary; otherwise
replace the gate with an environment-approval, trusted-author, or narrower-policy
design first. A GitHub Environment is the standard tighter OIDC path because it
changes the AWS-matchable `sub` to `repo:ORG/REPO:environment:NAME`. Prod-only
Terraform PRs should skip the sandbox plan and rely on prod validation rather
than being blocked by unrelated sandbox state.

## Auth0 Is Not Terraform-Managed (#3284)

**Terraform does not manage the Auth0 tenant. Do not add it back.** Clients,
connections, the API/resource server, roles, the post-login Action, branding,
attack protection, and email provider/templates are all owned in the Auth0
dashboard. `modules/auth0/` is now an AWS-only module: Secrets Manager
containers, SSM parameters, the SES IAM user, and the (disabled) rotation
Lambda. It takes Auth0 client IDs as tfvars inputs — those are public
identifiers, already published as plaintext SSM parameters and shipped to
browsers as `NEXT_PUBLIC_AUTH0_CLIENT_ID`. Client **secrets** are never
Terraform inputs; an operator writes them straight into Secrets Manager with
`aws secretsmanager put-secret-value`.

Three reasons this is a boundary and not a preference:

- **A tenant-write credential in PR-time code execution.** See the PR-Time
  Terraform Plan Security section above. Retiring the provider deleted that
  exposure rather than documenting an acceptance for it.
- **Terraform could never own the tenant completely.** Writing a connection's
  `options` needs `update:connections_options`, which the CI M2M does not hold.
  The #2305 attempt left read-after-create drift that failed *every* subsequent
  apply — including changes unrelated to Auth0 — until it was un-managed.
  Partial ownership of a shared tenant is a standing outage risk on unrelated
  work.
- **The provider cannot read back what it writes.** Without `read:client_keys`
  it returns an empty `client_secret`, which is why every credential secret in
  the module carried `ignore_changes` plus an operator `put-secret-value` step
  long before this change.

`tests/scripts/test_auth0_not_terraform_managed.py` fails CI on any new
`auth0_*` resource or data source, on a real credential reappearing in the
provider config, and on `TF_VAR_auth0_*` returning to a workflow.

The `provider "auth0"` stub in `environments/*/backend.tf` and
`modules/auth0/removed.tf` are transitional: Terraform requires an explicit
provider configuration to decode state entries even for a forget-only plan, so
they must outlive the apply that forgets those entries. Delete both — plus the
`auth0` entry in `required_providers` — once `terraform state list | grep
auth0_` is empty in **both** environments.

## GitHub Actions Apply-Role IAM Quotas

The shared `modules/ecr` GitHub Actions apply role currently declares a
worst-case 9 of AWS's default 10 managed-policy attachments. The IAM coverage
lint counts all conditional bindings as enabled and fails above
`GITHUB_ACTIONS_MANAGED_POLICY_ATTACHMENT_LIMIT`; this conservative union is
deliberate because the module serves every environment. Filling slot 10
exhausts the default runway. Before adding any subsequent managed-policy
attachment, either consolidate existing grants or raise the IAM quota in every
environment account and update the lint limit in the same change. Do not bump
the code constant based on only one account's quota.

## State Drift Protection for CI/CD-Managed Values

Some SSM parameters are created by Terraform but updated by CI/CD (e.g., image tags, blue/green deployment state). These use `lifecycle { ignore_changes = [value] }` to prevent Terraform from overwriting CI/CD updates:

```hcl
resource "aws_ssm_parameter" "image_tag" {
  name  = "/${var.environment}/nhp/server/image-tag"
  value = var.image_tag  # Initial value from Terraform

  lifecycle {
    ignore_changes = [value]  # CI/CD updates this
  }
}
```

Parameters using this pattern:
- `/${env}/nhp/server/image-tag` - Docker image tag (CI updates on deploy)
- `/${env}/nhp/server/green-image-tag` - Green ASG image tag (blue/green)
- `/${env}/nhp/server/active-color` - Current active deployment color
- `/${env}/nhp/server/last-switch-timestamp` - Deployment audit trail
- `/${env}/nhp/ac/image-tag` - AC Docker image tag
- Auth0 backend credentials secret version - Auth0 provider returns empty `client_secret`
- Dev portal management credentials secret version - same Auth0 provider limitation

**Relay DMZ Terraform contract.** Before changing `modules/relay`, the root
relay control-plane resources, relay networking, endpoint policies, IAM, or
telemetry, inspect and update
[`../.github/scripts/check-relay-dmz-plan.py`](../.github/scripts/check-relay-dmz-plan.py)
and its mutation tests in the same PR. The canonical checker enforces the
HTTPS-only relay contract and is active against the sandbox plan; partial
contract overrides are intentionally rejected.

GuardDuty Runtime Monitoring remains part of this fail-closed boundary while
relay replacement requires healthy runtime coverage. Any intentional change to
its agent-management configuration must use a newly reviewed migration path.
After an AWS provider bump, re-run live targeted plans in sandbox and prod and
confirm `aws_guardduty_detector_feature.runtime_monitoring` is a no-op; provider
issue [hashicorp/terraform-provider-aws#36400](https://github.com/hashicorp/terraform-provider-aws/issues/36400)
makes the returned block order version-sensitive. Reconsider this classification
only if relay replacement no longer depends on the GuardDuty functional-boundary
check.

**Relay active-color routing guardrail (#2658).** Blue/green server colors are
deploy slots inside one relay cell, not separate relay cells. Do not create
blue/green `serverId` values or color-specific qURL bootstrap server keys as an
incidental Terraform target-group/listener detail. The accepted model keeps one
cell-level server identity and makes the relay target source active-color-aware
behind that stable identity; see
[`../docs/design/RELAY_ACTIVE_CELL_ROUTING.md`](../docs/design/RELAY_ACTIVE_CELL_ROUTING.md).

**ASG capacity is co-owned with CI/CD.** The blue/green fleets use
`lifecycle.ignore_changes` for deployment-owned capacity for
the same reason as the SSM params above — CI/CD scales them during
blue/green flips and canary rollouts, and the next `terraform apply`
must not revert that. Operator-side `aws autoscaling
update-auto-scaling-group` against these ASGs sticks until something
else flips it (no plan-time revert):

- `aws_autoscaling_group.server` (`modules/server/main.tf`)
- `aws_autoscaling_group.ac` (`modules/ac/main.tf`)
- `aws_autoscaling_group.frps` blue + green (`modules/qurl-reverse-tunnel-server/main.tf`, `blue_green.tf`)

The NHP server and AC blue + green ASGs additionally ignore `max_size` and
`suspended_processes`. The durable-profile cut retires a legacy color at
min=max=desired=0 with scaling suspended; Terraform must not silently make it
launchable again. Blue/green owns the exact-image/profile write, capacity
restore, process resume, refresh, and health proof. This does not apply to the
FRPS ASGs.

This is a permanent ownership boundary, not a cell1-only exception. A
2026-07-25 read-only production check found `layerv-nhp-prod-server` at
min/max/desired `3/10/3` with `SuspendedProcesses=[]`, so enabling the lifecycle
rule does not preserve any pre-existing production suspension. Future
operator-, deploy-, or incident-created suspensions remain externally owned
until that same workflow explicitly resumes them and verifies the readback.
That workflow ownership is the detection and cleanup boundary; do not add a
second speculative alarm in an unrelated migration PR without first defining
which existing deploy/incident control owns and consumes it.

The compute module's public and enabled internal server NLBs also replace when
the server security group's `vpc_id` changes. The attribute-specific trigger is
plan-neutral while the VPC is stable and deliberately does not cascade an
unrelated SG name/description replacement into NLB downtime. For a VPC move,
the same-VPC NLBs must replace because an NLB cannot move between VPCs. Their
static names require destroy-before-create, so such a future production move is
necessarily an attended downtime operation rather than an ordinary apply.

FRPS ASGs also self-refresh on launch-template version changes. NHP-only
changes that alter qurl-reverse-tunnel-server user_data/env wiring will roll
the tunnel fleet without waiting for a qurl-reverse-tunnel-server image
publish.

For the NHP server/AC blue-green fleets, `max_size` is deployment-owned for the
same one-way-cut safety reason as min/desired. Other ASGs retain their existing
Terraform-owned caps.

**qurl-reverse-tunnel-server NHP validator origin.** Keep
`local.nhp_server_internal_url` on the VPC-internal Cloud Map origin
(`http://server.<namespace>:8888`) for qurl-service headless resolve and
qurl-reverse-tunnel-server knock-token validation. nhp-server's internal
token-validation handler relies on the request source IP being private; a
public resolve edge, public ALB, or re-terminating proxy can turn the same
request into a non-private-source 4xx even when DNS and TLS look healthy.
HMAC protects request integrity, not confidentiality: the knock token is still
plaintext on the wire, so keep this path inside one trusted VPC/private-DNS
boundary and revisit before using VPC peering, Transit Gateway, cross-account
services, or any appliance that mirrors/logs traffic. The Terraform validation
accepts any `*.internal` host with a valid port rather than only
`server.nhp.<env>.internal`; that preserves nonstandard module uses, but a typo
can still pass validation and fail later at DNS/runtime.

**Keep the public and private UDP server paths distinct.** The HTTP
token-validation path above (`local.nhp_server_internal_url`,
`server.<namespace>:8888`) stays on Cloud Map. Upcoming UDP SDKs use
`module.compute.nlb_dns_name`, the assigned cell's public server NLB, whose only
UDP listener is 443, which forwards to the server's UDP 62206 target group.
Browser relay traffic uses
`module.compute.internal_nlb_dns_name` on private UDP 62206. The relay does not
own a public UDP NLB or listener; do not add a relay-native cutover flag or
repoint SDK DNS to the relay. The internal NLB runs `preserve_client_ip=true`,
so the server replies to the relay/AC from its instance IP, not the NLB IP.

**Static name + `create_before_destroy` invariant.** Every ASG in
this repo (the three listed above plus their `blue_green.tf` green
counterparts) uses a static `name = "${var.name_prefix}-..."` AND
sets `lifecycle.create_before_destroy = true`. The combination is
intentional but structurally fragile: under plan/apply, a tainted
ASG cannot replace cleanly — the CBD create-first step collides
with the existing AWS resource's static name (`AlreadyExists`) and
CBD blocks the destroy-first ordering that would otherwise succeed.

The build-and-push workflow's `Handle ASG Attachment Migrations
and Taint Recovery` step detects tainted ASGs in the plan
and runs `terraform untaint` to recover the in-place
reconciliation path. **If you introduce a new ASG that uses
`name_prefix` instead of a static `name`, untaint is the WRONG
recovery** — a `name_prefix` ASG can actually replace under CBD,
and the workflow handler would mask a legitimate replacement need.
Either keep new ASGs on the static-name + CBD pattern, or update
the workflow handler to exclude `name_prefix`-based ASGs from the
auto-untaint sweep.

**State-loss recovery is out of scope of this handler.** If a
future failure pattern leaves an ASG present in AWS but absent
from state (no tainted marker — a true state/AWS divergence rather
than a partial-create), the handler does not fire and `import {}`
in `terraform/environments/<env>/imports.tf` is the correct tool.
Don't extend the taint-recovery handler to cover this case.

**Sandbox-only — prod recovery is operator-driven.** The handler
lives on the sandbox leg of `build-and-push.yml`; there is no
equivalent in `promote-to-prod.yml`. If a prod apply ever hits a
partial-create on a CBD static-named ASG (sandbox is the
absorbing layer for this failure mode, so it shouldn't), the
on-call operator runs `terraform untaint` manually with the
relevant approvals — auto-untaint under prod's approval-gated
flow would skip review of the in-place reconciliation diff.

**Re-validate after Terraform version bumps.** Both the
attachment-migration grep (`aws_autoscaling_attachment\.[^ ]+ will
be destroyed`) and the taint-recovery grep
(`aws_autoscaling_group\.[^ ]+ is tainted, so must be replaced`)
are string matches against `terraform plan` / `terraform show`
output. The wording is unstable across Terraform versions; the
handler silently no-ops if either phrase changes. Re-run the
sandbox apply against a known-good migration / known-tainted ASG
after any TF version bump that touches plan rendering, and tighten
or update the regex if the format drifted.

## IAM eventual-consistency shim pattern

When the same `terraform apply` both grants a new permission to a CI
role's policy AND creates a resource that needs that permission, the
IAM authorization evaluator can lag long enough for the fresh resource
to hit AccessDenied (including an observed ~2m resource-prefix case).
The shim is a `time_sleep` keyed
on a policy fingerprint; the consumer adds `depends_on` on the
sleep. Existing instances of the pattern:

- `time_sleep.apigateway_logging_propagation` (10s; APIGW async
  CloudWatch role check, bounded). Trigger source: a *resource
  dependency* (`depends_on = [aws_api_gateway_account.this]`).
- `time_sleep.qurl_link_static_iam_propagation` (60s; IAM
  evaluator propagation, action-list edits on an already-scoped
  policy). Trigger source: a *content dependency* (sha256 of the
  policy doc + the policy ARN).
- `time_sleep.bootstrap_alb_iam_propagation` (180s; shared by the
  bootstrap-alb resource-prefix grants and the status-page bucket
  notification action grant). The duration comes from a freshly-scoped
  *resource-prefix* grant — see nhp #2072 / run 26251713769 for the
  60s-isn't-enough evidence. Trigger source: same shape as qurl_link_static.
- `time_sleep.agent_otp_ses_iam_propagation` (180s; first-ever
  role-to-policy attachment, with no prior evaluator entry to update).
  Resource=`"*"` does not reduce this first-attachment propagation risk.

Pick by what you're racing: a resource creation → resource-dep
trigger; an in-place policy doc edit → content-hash trigger.

To add a shim for another CI policy when it next trips: expose
`<policy>_policy_doc_hash` AND `<policy>_policy_arn` as outputs
from whichever module owns the policy (today: `modules/ecr/`;
after #1812: `modules/ci-policies/`) computed as
`sha256(aws_iam_policy.<policy>.policy)` and
`aws_iam_policy.<policy>.arn`. Add a `time_sleep` keyed on both
in `terraform/main.tf`, gated on the OR of every consumer's
condition (so envs without consumers don't pay the wait), and add
`depends_on` on each consumer needing the freshly granted perm.
Pick a `create_duration` by what the policy edit looks like, not a
single floor: 10s for APIGW's bounded async check; 60s for an
action-list edit on an already-scoped policy (qurl_link_static
shape); 180s for a freshly-scoped resource-prefix grant where the
evaluator must propagate a new bucket/ARN target through its
caches (bootstrap_alb shape, evidence from nhp #2072 / run
26251713769 — the 60s shim let the sibling lifecycle resource
exhaust SDK retries before propagation cleared); and 180s for a
brand-new role-to-policy attachment even when its resource scope is
`"*"` (agent_otp_ses shape).

The two triggers cover different races: the doc hash catches
in-place perm edits (the common case); the ARN rotates on a
rename-via-`name`. Note `policy_arn` does NOT cover `terraform
taint` of a same-name policy — IAM policy ARNs are deterministic
from `arn:aws:iam::ACCT:policy/NAME`, so a taint+recreate reads
back an identical string and `triggers` compares strings, not
resource identities. For the taint case, also taint the
`time_sleep` so the wait re-fires.

For a brand-new-attachment shim, retain the policy document hash even
though later action-list edits will conservatively repay 180s: newly
added actions can be consumed by the same apply and still need an
ordering gate. The rare extra two minutes is preferable to leaving
those later edits exposed to an IAM propagation race.

`depends_on` defends create + replace paths only. For an in-place
update on an existing resource that exercises a freshly granted
perm, the right escape hatch depends on the resource's replacement
cost:

- **Cheap to recreate** (most resources): `replace_triggered_by =
  [time_sleep.<policy>_iam_propagation]` on the consumer's
  `lifecycle` forces it to recreate when the policy doc changes,
  paying the 60s on the recreate path.

  ```hcl
  resource "aws_some_cheap_resource" "example" {
    # ...config that exercises a newly granted perm...

    lifecycle {
      replace_triggered_by = [time_sleep.qurl_link_static_iam_propagation[0]]
    }
  }
  ```

- **Expensive to recreate** (CF distribution: 15–30 min global
  propagation; ECS service: traffic disruption): DO NOT use
  `replace_triggered_by`. Either split the perm-grant apply from
  the consumer-config apply (two-phase), or manually `terraform
  taint` the consumer once after the perm lands. Both pay the 60s
  exactly once instead of on every policy edit.

Greenfield envs aren't covered by the existing shim's consumer
set — all CF resources consuming the policy need their own
`depends_on` on first apply (tracked in #1813).

## Tag-Scoped IAM Over Replacement-Prone ARNs

For static-name resources that are ForceNew under configuration changes, avoid
IAM policies that enumerate concrete resource ARNs when the consuming role is
attached to a `create_before_destroy` ASG. That dependency can propagate CBD
into resources that cannot be create-before-destroyed because their names are
globally unique inside the AWS namespace. The qurl-reverse-tunnel-server Cloud
Map services use tag-scoped Register/Deregister grants for this reason.

When using this pattern, build the Cloud Map service tags and the IAM condition
from the same local, then add a plan-time precondition that verifies the tags
the IAM condition depends on are present and non-empty. Otherwise the failure
moves to instance boot as AccessDenied. Do not mutate these Cloud Map service
tags out-of-band; IAM evaluates the tags recorded on the service at
Register/Deregister time, so console/CLI tag drift can block registrations
until the next apply rehydrates the tag set. The (`Environment`, `Service`) tag
pair is now an IAM trust boundary; do not reuse it on unrelated Cloud Map
services.

## AC Plugin Source-of-Truth Invariant

The Traefik plugins on AC instances are pulled from
`s3://layerv-nhp-{env}-plugins/traefik/<plugin>/latest/` at boot via
`terraform/modules/ac/user_data.sh.tpl`. Three independent files must
agree on the plugin list, or AC instances cycled by a canary boot
into a degraded state:

1. `terraform/environments/{env}/terraform.tfvars` — `traefik_plugins`
   map. The `version = "latest"` entries here drive what `plugin_key`
   resolves to in `terraform/modules/plugins/main.tf` (it's literal
   string concat: `traefik/${k}/${v.version}/`).
2. `.github/workflows/promote-to-prod.yml` — `TRAEFIK_PLUGIN_SPARSE_PATHS`
   env on the `deploy-traefik-plugins` job. Drives both the
   cross-repo sparse-checkout filter and the upload loop.
3. `layervai/traefik-plugins` — must contain a directory at
   `plugins-local/src/<plugin>/` for every entry in the lists above.

The dangerous direction is **tfvars has plugin X, sparse-paths
doesn't** → AC user_data 404s on boot. The job's preflight catches
this (and missing `version` keys, and non-`"latest"` pins, and
empty plugin directories) — but the structural lint that would
catch it at lint time rather than at deploy time is tracked in
issue #1750. Until that lands, the preflight is the only fence.

The reverse direction (**sparse-paths has plugin Y, tfvars
doesn't**) is **benign**: the workflow uploads to an S3 key AC
never reads, wasting bandwidth but breaking nothing. Don't add a
defensive lint that flags it — that direction has no failure mode.

When the sandbox mirror in #1753 lands, this list grows from
three files to five (sandbox tfvars + `build-and-push.yml`'s
deploy-traefik-plugins-sandbox env). Update this doc in the same
PR so future maintainers don't encode a stale 3-file invariant.

When adding a new Traefik plugin:

1. Land it in `layervai/traefik-plugins` (its own CI ships it to the
   sandbox plugin bucket via `traefik-plugins/.github/workflows/deploy.yml`).
2. Add the entry to **both** sandbox and prod `terraform.tfvars`
   `traefik_plugins` maps with `version = "latest"`.
3. Add `plugins-local/src/<plugin>` to `TRAEFIK_PLUGIN_SPARSE_PATHS`
   in `promote-to-prod.yml`'s `deploy-traefik-plugins` job.
4. Mirror the same change in `build-and-push.yml` once #1753 (sandbox
   mirror) lands.

If you forget step 2 or step 3, the prod promote's preflight fails
loud with a copy-pasteable resolution.

**Plugin renames** require a paired-PR landing across BOTH repos:
the `layervai/traefik-plugins` PR that renames the directory must
land in the same release window as the `nhp` PR that updates
`TRAEFIK_PLUGIN_SPARSE_PATHS` and the `traefik_plugins` tfvars
keys. The tfvars↔sparse-paths preflight catches additions and
removals (drift in either list) but doesn't notice a *rename* if
both lists are updated in lockstep — the failure mode for a
half-landed rename is the directory-existence guard tripping at
upload time, which is correct fail-loud behavior but is downstream
of where you'd want the catch.

## Metric / Alarm Dim-Set Rules

CloudWatch alarms select their metric stream by **exact** dimension match. A
publisher that emits a partial dim set selects a different (non-existent)
stream and the alarm sits in `INSUFFICIENT_DATA` forever — the operator never
gets paged on a real fault.

AWS-managed metrics can fail the same way when the metric name is not actually
published or enableable for that service. For Auto Scaling group alarms, stay
inside the accepted `enabled_metrics` set; compose missing concepts with metric
math (for example, `GroupDesiredCapacity - GroupInServiceInstances`) instead of
inventing names like `GroupUnHealthyInstanceCount`.

The AC publisher's base dim set is `{Component, Environment, Region}` (see
`endpoints/ac/registration.go::NewACRegistration` and `metrics/publisher.go`).
Every alarm in `terraform/modules/ac/monitoring.tf` that keys on the AC
publisher's metrics MUST list those three dims exactly. Metrics emitted from
user_data scripts via the `aws cloudwatch put-metric-data` CLI (e.g.
`CertSyncFailures`) follow their own dim conventions and are out of scope
for this rule.

- **AWS_REGION is required at AC startup.** `NewACRegistration` returns an
  error when `AWS_REGION` is unset (issue #1659). The AWS SDK can't resolve
  the CloudWatch endpoint without a region, and the alarm dim-set guarantee
  above breaks if Region is missing. The live prod startup path is the
  `nhp-acd.service` systemd unit in `terraform/modules/ac/user_data.sh.tpl`
  — `Environment="AWS_REGION=${region}"` must be on that unit, because
  systemd does **not** inherit env from the boot shell. The AC docker image
  (`docker/Dockerfile.ac.aws`) is built and the binary extracted via
  `docker cp` at boot; the supervisord config inside the image never runs
  in prod, so its env wiring is not load-bearing.

- **New AC alarms must mirror the publisher's dim set.** When adding a new
  Region-keyed alarm, audit the metric's emit path and confirm it lands on
  `IncrCounter` / `IncrCounterWithDims` with the publisher base dims. If a
  metric is only emitted with extra dims (e.g., `ACId`/`ErrorCode` on the
  failure metrics), the alarm cannot match it — the cleanest fix is to
  dual-publish: a base `IncrCounter(name)` for the alarm PLUS the
  `IncrCounterWithDims` breakdown for dashboards (the
  `recordRegistrationSuccess` / `recordRegistrationFailure` /
  `recordServerConnectionFailure` helpers in `endpoints/ac/registration.go`).
  Alternatives: match all extra dims exactly, use a SEARCH expression (what
  the registration-event widgets do), or aggregate via `MetricMath`.

- **The `registration_failure` / `server_connection_failure` partial-set bug
  is fixed** (#968): both now dual-publish a base counter and their alarms key
  on `{Component, Environment, Region}`. The `servers_healthy_low` /
  `registration_stale` / dual-publish block is the correct precedent for new
  Go-side alarms. `disk_usage_high` and `cert_sync_failures` intentionally
  stay at `{Component}` because they are CLI-published from the maintenance
  bash scripts (exempt, per the top of this section). Issue #239 (the original
  tracking issue) is closed; #946 is now scoped to the remaining
  `ServersHealthy` gauge work, not a dimension-schema cleanup.

- **`MetricACConnEviction` baseline shifted at PR #1968.** Pre-#1968 the
  metric fired on *any* FIFO eviction, which included a steady stream
  of legitimate same-pubkey-new-IP arrivals (NAT rebind / EIP swap)
  misclassified as evictions. Post-#1968 it fires *only* on legitimate
  distinct-pubkey overflow. **Any alarm threshold (e.g., #1969) MUST be
  calibrated against the post-#1968 sandbox baseline**, NOT the
  historical CloudWatch values — a threshold tuned against the legacy
  rate would be permanently silent on rates that should page. The
  metric is also not strictly monotonic-on-FIFO: if a future regression
  ever admits partial entries, the helper's nil-skip walk evicts a
  later slot (correct, no DoS) but the metric still fires from the
  switch arm; pair the alarm with an `acConnectionMap` size-churn
  signal for invariant-free visibility (see
  https://github.com/layervai/nhp/issues/1969#issuecomment-4455100642).

- **The Connector Authority publisher's base dim set is
  `{EnvironmentID, AuthorityOperation}` plus `CellID` for cell operations
  only.** Namespace `LayerV/ConnectorAuthority`, emitted as EMF from
  `layervai/qurl-service internal/connectorauthorityruntime/telemetry.go`
  (`authorityTelemetry.emitPoint`). The order is fixed: `EnvironmentID`,
  `AuthorityOperation`, then `CellID` iff `config.go::isCellOperation`, then
  that metric's own dynamic dimensions in **sorted key order**. Three traps:

  1. `AuthorityOperation` carries the **PascalCase qurl-conformance name**
     (`ActivateRegistration`), not the snake_case terraform operation key
     (`activate_registration`). It is the same string the module renders into
     `CONNECTOR_AUTHORITY_OPERATION`, so build alarm dimensions from
     `local.authority_operation_conformance_name` rather than the key — see
     `local.authority_custom_metric_identity_dimensions` in
     `modules/connector-authority-foundation/authority_alarms.tf`.
  2. Some counters carry **no** dynamic dimension at all
     (`adapter_contract_violation`, `adapter_late_result`), so the identity
     prefix alone is the complete emitted set. Adding an `Outcome` there
     selects nothing.
  3. Every emitted metric name must be classified in
     `local.authority_emitted_custom_metrics` as alarmed or explicitly
     unalarmed-with-reason; the module's `foundation_contract` precondition
     rejects a partial or overlapping classification, so a handler that starts
     emitting a new metric cannot land unmonitored.

- **Alarm state is not evidence on a dark path.** Every Authority alarm uses
  `treat_missing_data = "notBreaching"` because AWS/Lambda publishes only for
  periods with invocations and EMF metrics exist only when emitted — so a wrong
  dim set presents as a permanently green `OK`, not as `INSUFFICIENT_DATA`.
  The only proof a new zero-baseline alarm actually selects a live stream is a
  **synthetic failure with a recorded page receipt** (NHP #3455). Do not treat
  a green console as coverage.

- **Compose, don't invent, for AWS-managed namespaces.** The Authority's
  non-provisioned-initialization event has no emitted metric (the handler
  rejects it at init, before telemetry exists), so it is an
  `aws_cloudwatch_composite_alarm` over the two published signals it must
  produce — `ALARM(spillover) AND ALARM(errors)` — rather than a guessed metric
  name. Likewise there is **no `DeadLetterErrors` alarm**: no function in the
  account publishes it, so the async axis is covered by an `AsyncEventsReceived`
  guard (which AWS does publish at `{FunctionName}`) plus a plan-time assertion
  that no Authority function declares a `dead_letter_config`.

## `templatefile()` multi-line vars in bash comments must be escaped

`templatefile()` resolves `${...}` interpolations **before** bash ever
sees the rendered file — bash-comment syntax does not suppress
interpolation. When the interpolated value is a multi-line string, the
TOML/whatever body is injected into the comment block, and lines of
the body that don't start with `#` get bash-executed when the rendered
script runs. Past hit: sandbox server fleet broken when
`${frps_resource_toml_overlay}` (a multi-line TOML render, now retired
with the #1976 cutover) was interpolated unescaped in
`modules/compute/user_data.sh.tpl` bash comments once #2035 made the
overlay non-empty. Surfaced as nhp run 26194839994 (post-#2043
sandbox apply); fixed in PR #2044.

Rule: when adding a `${var}` reference inside a bash comment in any
`*.sh.tpl` rendered via `templatefile()`, **escape with `$$` if the
var can interpolate to a multi-line string** (`$${var}` — Terraform
emits the literal token instead of expanding). Single-value scalars
(ports, hostnames, region names, etc.) don't need escaping — their
single-line render stays inside the comment.

Today's compute and AC templates carry only single-value primitives,
so no per-template fence is wired. The compute fence was retired
alongside the FRPS overlay (#1976). The first time a multi-line var
lands in either `*.sh.tpl`, re-add a `terraform_data` precondition
analogous to the prior `frps_overlay_comment_escape_fence` that
regex-checked the rendered template. Generalization to a single
allowlist-based fence across both templates is tracked in #2045.

## Terraform state backend encryption (SSE-KMS)

The remote-state buckets (`layerv-terraform-state-<acct>`) are bootstrap-layer:
created out-of-band, **unmanaged by any Terraform here**, referenced only by
name in `environments/<env>/backend.tf`. The CI Terraform role has object-only
access to them (no `s3:PutEncryptionConfiguration`, no `kms:EnableKeyRotation`)
— do **not** widen that to manage their encryption from CI. The CMK and any
bucket-default change are operator/admin out-of-band steps. Full procedure:
[`../docs/runbooks/tfstate-kms-migration.md`](../docs/runbooks/tfstate-kms-migration.md).

Two durable invariants that outlive that runbook:

- **`backend "s3"` `encrypt = true` forces AES256 unless `kms_key_id` is set.**
  With `encrypt = true` and no `kms_key_id`, the backend sends an explicit
  `x-amz-server-side-encryption: AES256` header that overrides the bucket
  default. So a bucket-default-only KMS change does **not** encrypt state
  objects — only `kms_key_id` in the backend block does. Editing `backend.tf`
  here is a backend-config change, so CI/local `terraform init` needs
  `-reconfigure` (state does not move → not `-migrate-state`).
- **Never disable or schedule deletion of the state CMK** while any state
  object/version is encrypted with it — that bricks state after the deletion
  window. The key uses a root-delegation policy, so an account admin can always
  recover a locked-out principal by granting `kms:Decrypt`/`kms:GenerateDataKey`.
