# terraform — Local Guidance

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

**ASG capacity is co-owned with CI/CD.** Three ASGs use
`lifecycle { ignore_changes = [desired_capacity, min_size] }` for
the same reason as the SSM params above — CI/CD scales them during
blue/green flips and canary rollouts, and the next `terraform apply`
must not revert that. Operator-side `aws autoscaling
update-auto-scaling-group` against these ASGs sticks until something
else flips it (no plan-time revert):

- `aws_autoscaling_group.server` (`modules/server/main.tf`)
- `aws_autoscaling_group.ac` (`modules/ac/main.tf`)
- `aws_autoscaling_group.frps` blue + green (`modules/qurl-reverse-tunnel-server/main.tf`, `blue_green.tf`)

`max_size` is deliberately NOT in `ignore_changes` so a CI scale-up
that exceeds the static cap fights the rehearsal — the cap is the
safety net.

## IAM eventual-consistency shim pattern

When the same `terraform apply` both grants a new permission to a CI
role's policy AND creates a resource that needs that permission, the
IAM authorization evaluator can lag the API call by up to ~60s and the
fresh resource hits AccessDenied. The shim is a `time_sleep` keyed
on a policy fingerprint; the consumer adds `depends_on` on the
sleep. Existing instances of the pattern:

- `time_sleep.apigateway_logging_propagation` (10s; APIGW async
  CloudWatch role check, bounded). Trigger source: a *resource
  dependency* (`depends_on = [aws_api_gateway_account.this]`).
- `time_sleep.qurl_link_static_iam_propagation` (60s; IAM
  evaluator propagation, no published SLA). Trigger source: a
  *content dependency* (sha256 of the policy doc + the policy ARN).

Pick by what you're racing: a resource creation → resource-dep
trigger; an in-place policy doc edit → content-hash trigger.

To add a shim for another CI policy when it next trips: expose
`<policy>_policy_doc_hash` AND `<policy>_policy_arn` as outputs
from whichever module owns the policy (today: `modules/ecr/`;
after #1812: `modules/ci-policies/`) computed as
`sha256(aws_iam_policy.<policy>.policy)` and
`aws_iam_policy.<policy>.arn`. Add a `time_sleep` keyed on both
in `terraform/main.tf`, gated on the OR of every consumer's
condition (so envs without consumers don't pay the 60s), and add
`depends_on` on each consumer needing the freshly granted perm.
The 10s value is for APIGW only — for IAM-evaluator races use 60s.

The two triggers cover different races: the doc hash catches
in-place perm edits (the common case); the ARN rotates on a
rename-via-`name`. Note `policy_arn` does NOT cover `terraform
taint` of a same-name policy — IAM policy ARNs are deterministic
from `arn:aws:iam::ACCT:policy/NAME`, so a taint+recreate reads
back an identical string and `triggers` compares strings, not
resource identities. For the taint case, also taint the
`time_sleep` so the wait re-fires.

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
  metric is emitted with extra dims (e.g., `ACId` on failure metrics), the
  alarm must either match all dims exactly, use a SEARCH expression (what
  the registration-event widgets do), or aggregate via `MetricMath` to
  collapse the extra dim into a fleet-wide series.

- **Older AC alarms with the partial-set bug** (`registration_failure`,
  `server_connection_failure`) are tracked in issue #239. Don't add new
  alarms in that style; the `servers_healthy_low` / `registration_stale`
  block is the correct precedent.

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
