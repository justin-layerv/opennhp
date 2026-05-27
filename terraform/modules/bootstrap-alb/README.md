# bootstrap-alb — `bootstrap.layerv.{xyz,ai}` ALB + WAF stack

Stands up the public, narrow surface that reverse-tunnel-client
sidecars call as their FIRST contact with LayerV:
`POST /v1/agent/bootstrap`. **Distinct from `api.layerv.ai`** (the
broad qurl-service customer-admin surface) — keeping the surface narrow
simplifies WAF rules and access-log triage. The connector type running
on top of the sidecar (Slack, Discord, etc.) is irrelevant at this
layer; any reverse-tunnel-client uses this surface to register its
public key on cold start.

## What lives in this stack

- ALB + HTTPS:443 listener (TLS terminates here).
- One forwarding listener rule: path `/v1/agent/bootstrap` → qurl-service
  target group. **Default rule** is fixed-response 404 — every other
  path returns 404 at the listener.
- WAFv2 WebACL: AWS-managed `CommonRuleSet`, `AmazonIpReputationList`,
  `AnonymousIpList`, `BotControlRuleSet`, plus a path-scoped per-source-IP
  rate-limit rule (default 200 req / 5min as a defense-in-depth backstop;
  the LOAD-BEARING per-API-key 10/hr lives in qurl-service). See the
  `waf_rate_limit_per_source_ip` variable for the headroom calculation.
- S3 access-log bucket (90d Glacier transition) + separate S3 Athena
  query-results bucket (30d retention).
- ACM cert. **Same-account in sandbox** (`layerv.xyz` zone lives in
  nhp's sandbox account, so cert + validation CNAMEs are module-
  managed via `provision_certificate=true`). **Cross-account in
  prod** (`layerv.ai` zone in `layerv-mgmt`, so the operator
  pre-provisions the cert in nhp's prod account and supplies the
  ARN via `existing_certificate_arn`; validation CNAMEs land in
  `layerv-mgmt` out-of-band).
- Route 53 alias `bootstrap.layerv.{xyz,ai}` → ALB. **Module-managed
  in sandbox** (same-account; `manage_dns_alias=true`).
  **Operator-managed out-of-band in prod** (cross-account zone in
  `layerv-mgmt`).
- CloudWatch alarms: ALB target 5xx, ALB-side 5xx, target health,
  TLS-handshake-failure rate, WAF rate-limit-block rate.
- SNS topic for the alarms (alerts-infra subscribes via cross-account
  Chatbot config — producer keeps SNS, alerts-infra owns chat-platform
  routing). The topic is also consumed by
  `terraform/qurl_service_outcomes.tf` at the nhp root for the
  application-layer bootstrap 401/429 spike alarms (those alarm on
  qurl-service's slog output, so they live at root rather than in this
  module to break a TF dependency cycle with `module.qurl_service`).

## What does NOT live here

- The qurl-service ECS service / task definition / image — owned by
  the nhp-side qurl-service stack. nhp's stack consumes this module's
  `target_group_arn` and `alb_security_group_id` outputs.
- AWS Chatbot / chat-platform alarm-routing config — owned by
  `alerts-infra` (org-wide AWS Chatbot home, per the team's standing
  decision).

## Account topology

This module is an intra-repo module under `nhp`'s root terraform.
Apply happens inside the nhp root state — the account targets below
are the actual AWS accounts the nhp root applies to per environment,
NOT separate states.

| Resource | Sandbox account | Prod account |
|---|---|---|
| Stack apply target (nhp root) | nhp's sandbox AWS account | nhp's prod AWS account |
| ACM cert (must live with the ALB) | same as apply target | same as apply target |
| `layerv.xyz` / `layerv.ai` hosted zone | `767397897469` (= sandbox apply target) | layerv-mgmt (cross-account) |

**Sandbox is same-account for DNS; prod is cross-account.** Cross-
account cert attachment isn't supported by AWS, so the cert MUST live
in the ALB account (= the nhp root's apply target). In sandbox the
parent zone happens to live in that same account, so the module can
provision cert + validation CNAMEs + alias itself
(`provision_certificate=true`, `manage_dns_alias=true`). In prod
the parent zone is in `layerv-mgmt`, so the operator pre-provisions
the cert in nhp's prod account and writes validation CNAMEs + the
A-alias into the `layerv-mgmt` zone out-of-band
(`provision_certificate=false` + `existing_certificate_arn=<ARN>`,
`manage_dns_alias=false`).

## First-apply runbook (operator)

Two paths, one per env:

- **Path 1 — cross-account zone (prod, `layerv.ai`)**: operator
  pre-provisions the ACM cert in nhp's prod account, writes
  validation CNAMEs + A-alias into `layerv-mgmt` out-of-band, then
  lands the cert ARN via `bootstrap_alb_existing_certificate_arn`
  with `provision_certificate=false` + `manage_dns_alias=false`.
  See **Step 0** below.
- **Path 2 — same-account zone (sandbox, `layerv.xyz`)**: module
  provisions cert + validation CNAMEs + A-alias itself via
  `provision_certificate=true` + `manage_dns_alias=true`. The first
  apply is now CI-clean — `aws_route53_record.cert_validation`'s
  `for_each` keys on the static `var.dns_name` rather than ACM's
  apply-time `domain_validation_options`, so no operator pre-seed
  step is required. (Step 0a below is preserved for archival
  reference and marked DEPRECATED — see #2061's "Alternative"
  for the architectural rationale.)

> **`bootstrap_alb_dns_name` is a plan-level break, not an in-place
> update.** The cert's `domain_name`, the validation record's
> for_each key, and the alias record's `name` all derive from
> `var.dns_name`. Renaming the bootstrap surface (e.g.,
> `bootstrap.layerv.xyz` → `bootstrap2.layerv.xyz`) plans as forced
> replacement on every dns-keyed resource — the chain stays clean
> thanks to `create_before_destroy` + `allow_overwrite=true` on the
> validation record + ACM's poll-until-validated semantics, but
> operators should be aware that "rename in tfvars" is not free.

Steps below are numbered for sandbox (Path 2 today). Prod will follow
Path 1; the same step numbers apply but the CI-merge step lands
`existing_certificate_arn` instead of flipping
`provision_certificate=true`.

**Convention:** the shell snippets below use these placeholder vars
which the operator should `export` at the start of a session and
reuse across steps:

- `<NHP_PROFILE>` — the AWS profile pointing at nhp's environment
  account (today `layerv` for sandbox; the prod equivalent for prod).
  Literal angle brackets — sub in the actual profile name.
- `$REGION` — apply target's AWS region (today `us-east-2` in both
  envs; matches `var.aws_region` in `terraform/environments/<env>/`).
- `$ENV` — `sandbox` or `prod`.
- `$TLD` — derived: `xyz` for sandbox, `ai` for prod.
- `$ACCT_ID` — 12-digit AWS account ID for the apply target.
  Resolve with `aws sts get-caller-identity --query Account --output text`
  under the right `AWS_PROFILE`.

The pinned `--region us-east-2` in some snippets reflects today's
single-region posture; a future multi-region rollout would
parameterize those too — flag in the same PR that adds the second
region.

### Step 0 — cross-account cert + DNS

> **Path 1 only.** Sandbox runs Path 2 (same-account zone, module-
> managed cert + alias) and skips this entire step — the module
> provisions the cert via `provision_certificate=true` and the
> first apply is CI-clean. Prod *will* run Path 1 (cross-account
> zone in `layerv-mgmt`) when it flips on (tracked in
> `SLACK_QURL_ROLLOUT.md` §5b); until then prod stays
> `deploy_bootstrap_alb=false` and this step is dormant there.

Run from the AWS profile pointing at nhp's environment account
(today: prod-equivalent — sandbox uses Path 2 and skips this step).
`<NHP_PROFILE>` is a placeholder for the locally-configured profile;
`<MGMT_PROFILE>` is the profile pointing at `layerv-mgmt` (where the
parent zone lives on Path 1); `<PARENT_ZONE_ID>` is the parent zone
ID (`layerv.ai` for prod). `$REGION` / `$ENV` / `$TLD` follow the
placeholder convention above.

```sh
REGION=us-east-2  # today's apply target in both envs
ENV=prod          # Path 1 today only applies to prod
TLD=ai            # prod = layerv.ai

# 1. Request the ACM cert in the ALB account/region.
AWS_PROFILE=<NHP_PROFILE> aws acm request-certificate \
  --region "$REGION" \
  --domain-name "bootstrap.layerv.${TLD}" \
  --validation-method DNS \
  --tags "Key=Project,Value=bootstrap-alb" "Key=Environment,Value=${ENV}" \
  --query CertificateArn --output text
# Save the returned ARN.

# 2. Read DNS-validation CNAMEs.
AWS_PROFILE=<NHP_PROFILE> aws acm describe-certificate \
  --region "$REGION" \
  --certificate-arn <ARN> \
  --query 'Certificate.DomainValidationOptions[].ResourceRecord' \
  --output table

# 3. Write the validation CNAMEs into the parent-zone account
#    (layerv-mgmt for prod's layerv.ai zone).
AWS_PROFILE=<MGMT_PROFILE> aws route53 change-resource-record-sets \
  --hosted-zone-id <PARENT_ZONE_ID> \
  --change-batch <change-batch-from-step-2-output>

# 4. Wait for ISSUED.
AWS_PROFILE=<NHP_PROFILE> aws acm describe-certificate \
  --region "$REGION" --certificate-arn <ARN> \
  --query Certificate.Status --output text

# 5. Land the cert ARN into nhp's env tfvars in a paired PR:
#      terraform/environments/prod/terraform.tfvars
#    Set: deploy_bootstrap_alb                   = true
#         bootstrap_alb_dns_name                 = "bootstrap.layerv.ai"
#         bootstrap_alb_existing_certificate_arn = "<ARN-from-step-1>"
```

### Step 0a — DEPRECATED (cold-start fence removed)

> **As of the fix to `cert_dns.tf` that keys `aws_route53_record.cert_validation`
> on the static `var.dns_name`, this step is no longer required.** Path 2 first
> apply now runs cleanly under CI's auto-approve flow. The historical text
> below is preserved verbatim for archival context and for envs that may have
> been state-rm'd back to a pre-fix snapshot. Don't run a targeted apply by
> default — let CI handle it.
>
> **Off-CI laptop state from prior mitigation attempts:** if you previously
> applied this step locally (state contains `aws_route53_record.cert_validation["_<token>.<domain>"]`
> rather than `["<var.dns_name>"]`), the next CI apply will destroy+create the
> validation CNAME. Benign — `allow_overwrite=true` + `create_before_destroy=true`
> + ACM's poll-until-validated semantics keep the cert in ISSUED through the swap.
> Run `terraform state list | grep cert_validation` against the relevant backend
> if unsure.

<details>
<summary>Historical body (DEPRECATED — collapsed by default; expand only for state-rm'd recovery context)</summary>

**Sandbox runs Path 2 (same-account zone) and is the only env that
hits this fence today — prod stays `deploy_bootstrap_alb=false` for
now and will run Path 1 when it flips on (cross-account zone in
`layerv-mgmt`, skips this step entirely).** The nhp CI flow
(`build-and-push.yml`, `promote-to-prod.yml`) runs `terraform plan
-out=tfplan` followed by `terraform apply -auto-approve tfplan`,
and the *plan step* fails on the `for_each` unknown-keys error, so
the whole CI deploy goes red before apply even runs. The operator
MUST run the targeted apply BEFORE the gate-on tfvars merge to
`main` — locally with the right `AWS_PROFILE`. (There's no
`workflow_dispatch` job that disables `-auto-approve` today; if one
is added later it'd be the alternative path, but the local laptop
apply is the only supported route as of this writing.) If a future
env joins Path 2, the same step applies on its first flip.

The constraint: `aws_route53_record.cert_validation.for_each` keys
on `dvo.resource_record_name`, which Terraform doesn't know until
ACM has actually issued the cert request (apply-time, not plan-time).
The first plan on a greenfield env hits:

```
Error: Invalid for_each argument
  on modules/bootstrap-alb/cert_dns.tf line 115, in resource
  "aws_route53_record" "cert_validation":
  The "for_each" map includes keys derived from resource attributes
  that cannot be determined until apply...
```

Operator workaround — must be run from a context that bypasses CI's
auto-approve flow. Today the only supported path is the operator's
local laptop apply (a `workflow_dispatch` variant that disables
`-auto-approve` doesn't exist yet — would be a separate follow-up).

**Pre-flight before the targeted apply.**

1. **Rebase the PR branch against `main`.** Without the rebase, the
   un-targeted `terraform apply` in step 2 below plans the bootstrap-
   alb resources *plus* any unrelated drift the branch is behind on —
   making the plan output harder to eyeball-review at the moment it
   matters most.
2. **Post in `#deploys`** before starting so nobody else lands to
   `main` mid-flight. See the tight-window note in Step 1 for what
   happens if they do (fail-loud but messy).
3. **Confirm the parent zone ID** matches what's in the tfvars
   block. `aws route53 list-hosted-zones --profile=<NHP_PROFILE>
   --query 'HostedZones[?Name==\`layerv.{xyz,ai}.\`].[Id,Name]'
   --output table` — defends against a typoed zone ID that the
   dot-boundary precondition can't catch (correct shape + wrong
   zone would hang ACM validation ~75min before giving up).

```sh
# 1. Apply the cert request first so domain_validation_options is
#    populated in state.
AWS_PROFILE=<NHP_PROFILE> terraform apply \
  -target='module.bootstrap_alb[0].aws_acm_certificate.this[0]'

# 2. Then a normal apply picks up the now-known validation record
#    names. From here, subsequent CI applies are clean (the keys
#    are known in state). EYEBALL the plan output before approving —
#    the rebase above is what makes that practical.
AWS_PROFILE=<NHP_PROFILE> terraform apply
```

**Interruption recovery during step 2.** If the second apply is
interrupted (Ctrl-C, network drop, laptop sleep) *after*
`aws_route53_record.cert_validation` writes its CNAMEs but *before*
`aws_acm_certificate_validation.this` completes its waiter, the cert
sits in ACM with status `PENDING_VALIDATION` while ACM polls the
just-written CNAMEs. Recovery is just re-running `terraform apply` —
the waiter resource re-attaches to the existing cert and the apply
completes once ACM flips the cert to `ISSUED` (typically <5 min once
CNAMEs are in place; can take up to 75 min if ACM's poll is slow).
The cert resource itself is already in state from step 1's targeted
apply, so there's no risk of duplicate cert requests on re-apply.

The `provision_certificate = false` path (prod's posture once it
flips on, and sandbox's pre-flip posture) doesn't hit this because
`aws_acm_certificate.this` is count-0 and the splat collapses
naturally to an empty for_each — Path 1 envs skip this step entirely.

</details>

### Step 1 — terraform apply

Apply happens via nhp's CI release flow against the nhp root, NOT a
standalone `cd bootstrap-alb` invocation. Once the tfvars from step 0
land, the next `promote-to-prod.yml` / `build-and-push.yml` run picks
up `deploy_bootstrap_alb = true` and `module.bootstrap_alb[0]` enters
the plan. There is no per-module state — the module shares nhp's
root state.

### Step 2 — A-alias write (operator, after first apply)

> **Path 1 only.** Sandbox runs Path 2 (same-account zone) and sets
> `manage_dns_alias=true`, so the module's `aws_route53_record.
> alb_alias` writes the A-alias during Step 1's apply — Step 2 is a
> no-op there. Prod *will* run Path 1 (cross-account zone in
> `layerv-mgmt`) when it flips on (tracked in `SLACK_QURL_ROLLOUT.md`
> §5b); until then prod stays `deploy_bootstrap_alb=false` and this
> step is dormant there.

```sh
# Read the ALB DNS / zone from nhp root's outputs (the module is
# count-gated, so the outputs are non-null only after Step 1's apply
# lands with deploy_bootstrap_alb=true).
ALB_DNS=$(cd terraform && terraform output -raw bootstrap_alb_dns_name)
ALB_ZONE=$(cd terraform && terraform output -raw bootstrap_alb_zone_id)

# Write the A-alias into the parent-zone account. <MGMT_PROFILE>
# points at layerv-mgmt (parent zone for prod's layerv.ai);
# <PARENT_ZONE_ID> is the parent zone ID. Path 1 today only
# applies to prod (TLD=ai); sandbox runs Path 2 and the module
# writes this alias during Step 1's apply.
AWS_PROFILE=<MGMT_PROFILE> aws route53 change-resource-record-sets \
  --hosted-zone-id <PARENT_ZONE_ID> \
  --change-batch '{
    "Changes": [{
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "bootstrap.layerv.ai",
        "Type": "A",
        "AliasTarget": {
          "HostedZoneId": "'"$ALB_ZONE"'",
          "DNSName": "'"$ALB_DNS"'",
          "EvaluateTargetHealth": false
        }
      }
    }]
  }'
```

### Step 3 — verify dark-launch posture (operator, after first apply)

Between this stack's apply and the paired follow-up PR (which
registers qurl-service against the empty TG), the ALB is running but
has **zero healthy targets**. That means:

- **Expected dark-launch state**: `POST /v1/agent/bootstrap` → **503**
  (Service Unavailable; AWS ALB's standard response when no target is
  healthy). This is **not** a deploy failure — it's the correct
  intermediate state until the paired qurl-service ECS registration
  PR lands.
- **Not-expected, real failures**: any non-bootstrap path returning
  anything other than 404; the bootstrap path returning 5xx other
  than 503 (e.g., 502 = listener misconfig, 504 = TG idle-timeout
  mismatch); TLS errors on any path (cert chain doesn't validate).

#### ⚠️ Alarm noise during dark-launch

503s from the bootstrap path during the dark-launch window count as
ELB-side 5xx and WILL trip the `bootstrap-alb-<env>-alb-elb-5xx`
alarm. Any sidecar that starts bootstrapping early — or any scanner
that probes `/v1/agent/bootstrap` during the window — triggers the
page.

The other alarms stay quiet during dark-launch and that's
**intentional, not a misconfiguration**:

- **`alb-unhealthy-hosts`** — `UnHealthyHostCount` is `0` during
  dark-launch (no targets registered → nothing can be unhealthy).
  Alarm stays at `OK`. It flips to `ALARM` only after qurl-service
  ECS registers and a target then becomes unhealthy.
- **`alb-target-5xx`** — no targets registered → no
  `HTTPCode_Target_5XX_Count` published. Alarm stays at
  `INSUFFICIENT_DATA` (`treat_missing_data = notBreaching` so no
  page).
- **`waf-rate-limit-blocks`** — fires only on rate-limit blocks,
  which require sustained probe traffic. Quiet under normal
  dark-launch scanner volume.

Only `alb-elb-5xx` is noisy during the window. Two ways to handle:

1. **Defer alerts-infra routing.** Pass
   `bootstrap_alb_cross_account_subscriber_arns = []` in the sandbox
   tfvars flip PR (Merge plan step 3) so the alerts topic exists but
   no chat-platform subscriber receives the alarm payload until the
   paired data-plane PR lands. Then flip the var to the alerts-infra
   role ARN in a follow-up after the surface goes live.
2. **Acknowledge on alerts-infra side.** Have the alerts-infra
   operator silence the alarm on the chat-platform routing side for
   the duration of the dark-launch window.

Posture #1 is cleaner for prod (zero risk of accidental 3am page);
posture #2 is fine for sandbox.

Operator-checkable signals the stack landed correctly:

```sh
# 0. Alias is live in public DNS (Route 53 ALB alias is fast but
#    not instant; ~30-60s typical after apply). Run BEFORE the
#    cert-chain check below — a stale-DNS curl produces a TLS error
#    that looks identical to a wrong-cert error and sends the
#    operator chasing the wrong root cause.
dig @1.1.1.1 +short bootstrap.layerv.xyz
# Expect: a non-empty A-record (the ALB's public IPs). If empty,
#         wait ~30s and retry; Route 53 propagation isn't done yet.
#         If still empty after ~5 min, the alias didn't write (Path 2
#         module-managed: check `aws_route53_record.alb_alias` is in
#         state; Path 1 operator-managed: re-run Step 2's UPSERT).

# 0a. Cert chain validates against public roots (no -k flag).
#    This is the highest-risk part of first-apply: a wrong cert ARN
#    in tfvars + `provision_certificate=false` plans cleanly and
#    applies cleanly, then fails at first TLS handshake. Catching
#    here costs ~1s; catching at first sidecar bootstrap means the
#    operator chases a connection-refused report from prod.
curl -sI https://bootstrap.layerv.xyz/random | head -1
# Expect: HTTP/2 404 (no `SSL certificate problem` / `unable to verify`
#         errors). If TLS errors print, the ACM cert ARN in tfvars
#         doesn't match `bootstrap.layerv.{xyz,ai}` — fix before
#         continuing.
#
# 0b. Cert SAN covers the served hostname (chain-valid != SAN-correct).
#    A chain-valid cert with the wrong SAN passes 0a's `curl -sI`
#    against public roots — the TLS handshake completes — but the
#    served name doesn't match what the sidecar will request. Path 2
#    (`provision_certificate=true`) precludes this via the dot-boundary
#    precondition on `dns_name`/zone, but a future Path 1 ↔ Path 2
#    migration (e.g., zone moves accounts) could trip it.
echo | openssl s_client -connect bootstrap.layerv.xyz:443 \
  -servername bootstrap.layerv.xyz 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName
# Expect: a `DNS:bootstrap.layerv.xyz` entry. Any other SAN means the
#         listener is serving a cert that doesn't cover this hostname.

# Operator caveat for steps 1-2 while `waf_count_only_rule_groups=[]`
# (dark-launch posture per the module variable doc): commercial-VPN
# egress IPs frequently appear on `AWSManagedRulesAnonymousIpList`,
# and the WAF block surfaces as 403 from the operator's laptop. If
# step 1 or step 2 returns 403, retry from a non-VPN network before
# treating it as a stack issue. (This goes away once the paired
# data-plane PR sets `waf_count_only_rule_groups` per the module
# variable doc — tracked at nhp #1982.)

# 1. Default 404 with the canonical JSON envelope (any non-bootstrap path).
curl -sk -o /dev/null -w "%{http_code}\n" https://bootstrap.layerv.xyz/random
# Expect: 404

# 2. Bootstrap path returns 503 (no healthy targets — expected during
#    the dark-launch window; flips to 200/4xx once qurl-service registers).
curl -sk -o /dev/null -w "%{http_code}\n" https://bootstrap.layerv.xyz/v1/agent/bootstrap
# Expect: 503

# 3. Both ALB-side alarms show INSUFFICIENT_DATA or OK (not stuck unconfigured).
AWS_PROFILE=<NHP_PROFILE> aws cloudwatch describe-alarms \
  --region us-east-2 \
  --alarm-name-prefix bootstrap-alb-sandbox- \
  --query 'MetricAlarms[].[AlarmName,StateValue]' --output table

# 3a. Access-log delivery is wired through BOTH the modern service
#     principal (`logdelivery.elasticloadbalancing.amazonaws.com`) and
#     the legacy regional ELB log-delivery AWS-account principal — the
#     latter is what ELB uses for the synchronous test-write at
#     ALB-create time; the former is what ongoing delivery uses (see
#     `access_logs.tf` policy-doc header). Failure mode for ONGOING
#     delivery is silent — no error surfaces, logs just never land —
#     so verify explicitly after ~5–10 min. Probe traffic from earlier
#     curls should appear here.
ACCT_ID=$(AWS_PROFILE=<NHP_PROFILE> aws sts get-caller-identity --query Account --output text)
AWS_PROFILE=<NHP_PROFILE> aws s3 ls \
  "s3://bootstrap-alb-alb-logs-${ENV}-${ACCT_ID}/AWSLogs/${ACCT_ID}/elasticloadbalancing/${REGION}/" \
  --recursive | tail -5
# Expect: at least one object under today's date. If empty after
#         10+ min of generated probe traffic, the modern service
#         principal isn't accepted by ELB log-delivery in this
#         region — confirm the legacy statement is still in place
#         (it should be; both principals are permanently load-bearing
#         post run 26259811292).

# 4. WAF WebACL is associated to the ALB.
ALB_ARN=$(cd terraform && terraform output -raw bootstrap_alb_arn)
AWS_PROFILE=<NHP_PROFILE> aws wafv2 get-web-acl-for-resource \
  --region "$REGION" --resource-arn "$ALB_ARN" \
  --query 'WebACL.Name' --output text
# Expect: bootstrap-alb-sandbox

# 5. Path-pattern is case-sensitive (proves the case-sensitivity
#    invariant alb.tf:bootstrap listener-rule depends on).
curl -sk -o /dev/null -w "%{http_code}\n" https://bootstrap.layerv.xyz/V1/agent/bootstrap
# Expect: 404 (NOT 503 — the rule's path-pattern is exact-case,
#         mixed-case falls through to the default 404).

# 5a. Method-restriction: only POST forwards (proves the
#     http_request_method condition on the listener rule).
curl -sk -o /dev/null -w "%{http_code}\n" -X GET https://bootstrap.layerv.xyz/v1/agent/bootstrap
# Expect: 404 (NOT 503 — GET falls through to the default 404 even
#         though the path matches; only POST forwards to qurl-service).

# 6. Access log records the AWS-injected XFF rightmost entry, not
#    the forged leftmost (proves the audit-writer contract — the
#    qurl-service writer must take the rightmost entry; see
#    alb.tf:xff_header_processing_mode for the contract).
curl -sk -o /dev/null \
  -H "X-Forwarded-For: 10.0.0.99" \
  https://bootstrap.layerv.xyz/v1/agent/bootstrap
# Wait ~5 min for ALB to flush the access log, then read it from S3
# and confirm the request line contains BOTH the forged 10.0.0.99
# AND the real client IP at the rightmost position.

# 7. Email SNS subscriptions are CONFIRMED (only relevant when
#    `var.alarm_email_subscriptions` is non-empty). Email
#    subscriptions land in `PendingConfirmation` after apply — each
#    recipient must click the AWS-sent confirmation link before
#    alarms deliver to that address.
TOPIC_ARN=$(cd terraform && terraform output -raw bootstrap_alb_alerts_topic_arn)
AWS_PROFILE=<NHP_PROFILE> aws sns list-subscriptions-by-topic \
  --region "$REGION" \
  --topic-arn "$TOPIC_ARN" \
  --query 'Subscriptions[?Protocol==`email`].[Endpoint,SubscriptionArn]' --output table
# Any SubscriptionArn that reads `PendingConfirmation` means the
# recipient hasn't clicked the link yet — chase them down before
# trusting alarm delivery on that endpoint.
```

If any of these diverge from expected, the qurl-service attachment
follow-up will not land cleanly — fix here before kicking that
rollout.

### Operator note — customer sidecar reports bootstrap 403 from this ALB

(Applies post-apply only — when `deploy_bootstrap_alb = false`, the
ALB and WebACL don't exist and this section is moot.)

If a customer reports `POST /v1/agent/bootstrap` returning 403,
**check WAF sampled-requests before debugging app-side.** Look-first
check: is `bootstrap-alb-<env>-waf-rate-limit-blocks` alarm firing?
If yes, the customer's egress source IP is likely above the
`waf_rate_limit_per_source_ip` threshold (default 200/5min). Large
customer fleets (200+ sidecars behind a single NAT, especially
during a redeploy with TLS-retry storms) can plausibly hit this —
the per-API-key 10/hr limit in qurl-service is the load-bearing
gate, so bumping `bootstrap_alb_waf_rate_limit_per_source_ip` in env
tfvars (above 200, up to module-policy ceiling 1000) is a safe
short-term mitigation. Three common WAF false-positive classes:

1. **`AWSManagedRulesAnonymousIpList`** — blocks known VPN/TOR/
   anonymizer exit IPs. A customer sidecar behind a corporate VPN,
   Tailscale exit node, or some cloud-NAT egress falls into the
   block silently.
2. **`AWSManagedRulesCommonRuleSet` body inspection** — the
   sidecar's bootstrap POST carries a PEM-wrapped public key
   (`-----BEGIN PUBLIC KEY-----`...) whose body content can
   false-positive on CRS's `CrossSiteScripting_BODY` and
   `SQLi_BODY` sub-rules (the PEM payload contains characters
   these rules flag).

In both cases the sidecar sees a 403 with the ALB's `WAF` response
body and no qurl-service log entry exists.

```sh
# Pull the last 100 blocked requests from the WebACL to see which
# rule fired. Filter on the customer's known source IP.
WEB_ACL_ARN=$(cd terraform && terraform output -raw bootstrap_alb_web_acl_arn)
AWS_PROFILE=<NHP_PROFILE> aws wafv2 get-sampled-requests \
  --region us-east-2 \
  --web-acl-arn "$WEB_ACL_ARN" \
  --rule-metric-name AWSManagedRulesAnonymousIpList \
  --scope REGIONAL \
  --time-window "StartTime=$(python3 -c 'import time; print(int(time.time())-3600)'),EndTime=$(python3 -c 'import time; print(int(time.time()))')" \
  --max-items 100
```

If the customer's IP shows up, the WAF rule fired correctly. Two
remediation paths: (a) ask the customer to bootstrap from a non-VPN
egress (preferred — the AnonymousIpList block protects against
genuinely anonymous abuse); (b) if many customers report the same
issue, flip `bootstrap_alb_waf_count_only_rule_groups` to include
`"AWSManagedRulesAnonymousIpList"` in the affected env's tfvars and
watch the sampled-requests for false-positive rate before re-enforcing.

### Step 4 — wire qurl-service (paired follow-up PR)

The qurl-service ECS service registers against this module's
`target_group_arn` output and adds a task-SG ingress rule referencing
its `alb_security_group_id`. That wiring lands in the paired follow-up
PR `feat/bootstrap-alb-attach-qurl-service` (NOT in this PR — this PR
is module-only, default-off). Until the paired PR lands, the ALB
returns 503 on `/v1/agent/bootstrap` (no healthy targets) — that's
the expected dark-launch state during the bootstrap window.

## Teardown / cleanup

A `terraform destroy` (flipping `deploy_bootstrap_alb=false` in
tfvars then re-applying) of this module has two non-obvious gotchas
the operator needs to handle manually:

### 1. Access-log bucket has TWO destroy fences

`aws_s3_bucket.alb_access_logs` carries BOTH:

1. `force_destroy = false` — destroy fails with `BucketNotEmpty`
   unless the bucket is manually emptied first.
2. `lifecycle.prevent_destroy = true` — destroy fails even when the
   bucket IS empty (catches the "operator empties it manually then
   runs destroy" case).

Both fences are deliberate (bootstrap forensics are irrecoverable;
see `access_logs.tf`). A genuine sandbox teardown requires a
one-commit PR that flips BOTH:

```sh
# In modules/bootstrap-alb/access_logs.tf:
#   1. force_destroy = false  →  force_destroy = true
#   2. comment out the `lifecycle { prevent_destroy = true }` block
# Apply, destroy, then revert in a follow-up commit.
AWS_PROFILE=<NHP_PROFILE> terraform apply
AWS_PROFILE=<NHP_PROFILE> terraform destroy \
  -target='module.bootstrap_alb[0]'
```

Prod should NEVER reach this path under normal operations.

### 2. Orphaned ACM cert (`provision_certificate = false` paths)

When `provision_certificate = false` (prod's posture once it flips
on; sandbox runs `provision_certificate = true`), the ACM cert is
operator-pre-provisioned outside the stack — so `terraform destroy`
of the module leaves the cert orphaned in ACM.
ACM does NOT auto-clean unused certs and they sit around forever
otherwise. After destroying the module, run:

```sh
AWS_PROFILE=<NHP_PROFILE> aws acm delete-certificate \
  --region us-east-2 \
  --certificate-arn <ARN-from-tfvars>
```

`provision_certificate = true` paths are self-cleaning — the cert is
managed inside this stack's state and gets destroyed with the rest of
the module.

**Inverse foot-gun (Path 2 → Path 1 migration)**: if a Path 2 env
ever migrates to Path 1 (e.g., the parent zone moves to a different
account), flipping `provision_certificate = true → false` without
first running `terraform state rm module.bootstrap_alb[0].aws_acm_
certificate.this[0]` orphans the previously module-managed cert in
ACM the same way the Path 1 destroy does. The symmetric mitigation
applies — `aws acm delete-certificate` after the flip, using the ARN
captured from `terraform state show` before the state-rm. Hypothetical
today (no Path 2 → Path 1 migration in flight); listed here so the
operator finds it in the right place if it ever happens.

## Module outputs (intra-repo)

This is an intra-repo module — outputs flow via direct module
references (`module.bootstrap_alb[0].<name>`) from nhp's root, NOT
via `terraform_remote_state`. The table below tracks where each
output is consumed.

| Output | Consumer |
|---|---|
| `target_group_arn` | qurl-service ECS service `load_balancer.target_group_arn` (intra-repo, paired follow-up PR) |
| `alb_security_group_id` | qurl-service task SG ingress rule (intra-repo, paired follow-up PR) |
| `alb_dns_name` / `alb_zone_id` | Operator runbook for parent-zone-account A-alias write (re-exported at nhp root as `output.bootstrap_alb_dns_name`) |
| `alerts_topic_arn` | `alerts-infra`'s cross-account AWS Chatbot subscription (consumed cross-repo) |

## Tracked follow-ups

- **WAF logging configuration** ([#1892](https://github.com/layervai/nhp/issues/1892)):
  `aws_wafv2_web_acl_logging_configuration` is out of scope for this
  module. The follow-up will wire logging to CloudWatch Logs (or
  Firehose → S3) so the WAF rules' blocked-request payloads are
  inspectable for incident response.
- **CI policy posture** ([#1891](https://github.com/layervai/nhp/issues/1891)):
  nhp's `aws_iam_role.github_actions` in `terraform/modules/ecr/` is
  not currently tag-scoped on `aws:RequestTag/Project` for ELB/ACM/
  WAF/S3/SNS, so no allowlist widening is required to first-apply
  this module today. If a future PR adds tag-scoping to nhp's CI
  role, the `bootstrap-alb` Project value must be included in the
  allowlist or every `Create*` verb 403s at apply. Linked issue
  enumerates all resource verbs and the tag-scope target for each.
  **Bucket-prefix scoping coupling**: when #1891 lands, the
  bucket-name pattern `bootstrap-alb-alb-logs-*` (with the
  deliberate cosmetic double `alb-` segment) becomes a literal
  IAM policy match. Renaming `local.project` from `bootstrap-alb`
  to anything else after that point requires a paired
  ecr-module CI-role update — preserve the double-`alb-` shape
  in the same PR or every S3 create-bucket verb 403s.
- **Narrow-surface smoke test** ([#1894](https://github.com/layervai/nhp/issues/1894)):
  once `deploy_bootstrap_alb=true` lands and the surface is live, a
  Tier 1 smoke test will fence the narrow-surface invariant (only
  `POST /v1/agent/bootstrap` forwards; method/case/path deviations
  fall through to 404).
- **ALB connection logs** ([#1896](https://github.com/layervai/nhp/issues/1896)):
  the `alb-tls-handshake-failures` alarm fires on
  `ClientTLSNegotiationErrorCount` but the access logs only capture
  successfully-handshaked requests — the failed handshake never
  appears. Follow-up enables `aws_lb.connection_logs` (provider
  5.20+) to give the alarm a forensic-payload source.
- **RequestCount low-watermark alarm** ([#1898](https://github.com/layervai/nhp/issues/1898)):
  today's alarm set is failure-shaped; a silent *drop* in legitimate
  bootstrap traffic (DNS regression, cert chain change) doesn't cross
  any threshold. Follow-up adds a `LessThanThreshold` `RequestCount`
  alarm once ~30d of steady-state baseline is observable.
- **Project-tag inheritance from root** ([#1900](https://github.com/layervai/nhp/issues/1900)):
  the module pins `Project = "bootstrap-alb"` in `local.tags`,
  diverging from nhp root's `Project = "NHP"`. Best landed in the
  same window as #1891 so the CI-role allowlist widening and the
  module-side tag-flow restructure ship together.
- **Pass-through completeness** ([#1905](https://github.com/layervai/nhp/issues/1905)):
  nhp root forwards three of the module's ~10 tunable vars today
  (the dark-launch-critical knobs). Follow-up adds nullable root
  pass-throughs for the rest (alarm thresholds, retention windows,
  email subscriptions) so env-tfvars tuning doesn't require
  module-code edits.
- **terraform test coverage** ([#1906](https://github.com/layervai/nhp/issues/1906)):
  module has zero automated test coverage today; preconditions
  and variable validations are heavily reviewed but unfenced
  against future refactors. Follow-up adds `.tftest.hcl` fences
  for the plan-time invariants (cert XOR, strict bootstrap_path,
  partition mismatch, etc.).
- **S3 server access logging on access-log bucket** ([#1907](https://github.com/layervai/nhp/issues/1907)):
  meta-forensics surface for the access-log bucket itself.
  Compliance-scanner posture (AWS Config
  `s3-bucket-logging-enabled`) flags the missing log-of-the-log
  even though the bucket has strong protections. Best landed
  paired with #1892 (WAF logging) — both add forensic surfaces.
- **HSTS response header** ([#1904](https://github.com/layervai/nhp/issues/1904)):
  ALB's default 404 (and forwarded responses) currently carry no
  `Strict-Transport-Security` header. Threat model excludes
  browser clients today, but defense-in-depth + compliance-scanner
  hygiene. Best landed paired with #1892 (WAF logging) since both
  touch the WebACL configuration.
- **Annual access-log cost review** ([#1902](https://github.com/layervai/nhp/issues/1902)):
  no expiration on the access-log bucket today (forensics-favors-
  retention argument holds at low traffic volume). Annual revisit
  signal so the retention posture doesn't silently cover 100x
  volume growth.
- **IPv6 / dualstack** ([#1901](https://github.com/layervai/nhp/issues/1901)):
  ALB ships IPv4-only today. Customer sidecars in IPv6-only
  networks (some k8s clusters, AWS dualstack-without-public-IPv4
  cost-optimized setups, HE tunnels) currently fail at TCP-level
  with no signal. Follow-up wires IPv6 CIDR blocks into the
  networking module's public subnets AND flips this ALB to
  `dualstack` + paired SG ingress rule.
- **Unhealthy-hosts threshold revisit** ([#1899](https://github.com/layervai/nhp/issues/1899)):
  the default `alb_unhealthy_hosts_threshold = 0` is aggressive once
  qurl-service registers N ≥ 2 tasks — any rolling-deploy blip pages.
  Paired `feat/bootstrap-alb-attach-qurl-service` PR sets the per-env
  threshold based on the qurl-service ECS desired_count.
- **Deploy path**: this module lives inside nhp's root state, applied
  by the standard nhp CI workflows (`build-and-push.yml` for sandbox,
  `promote-to-prod.yml` for prod). No separate workflow exists or is
  planned for it; first-apply is "flip `deploy_bootstrap_alb=true` in
  env tfvars, merge, CI applies."
