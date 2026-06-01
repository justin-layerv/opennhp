# Per-env values land in `{sandbox,prod}.tfvars`. The deploy workflow
# loads them via `-var-file=<env>.tfvars`. Defaults live here ONLY for
# values that are env-invariant (e.g. WAF managed-rule list, rate-limit
# threshold) — env-varying values (DNS name, account ID, cert arn) are
# committed per-env in tfvars so reviewers can see the sandbox ↔ prod
# distinction at every diff.

variable "environment" {
  description = "Deployment environment. Drives ALB deletion protection (`alb.tf`) and DNS hostname (sandbox: `bootstrap.layerv.xyz`, prod: `bootstrap.layerv.ai`). S3 `force_destroy` is hard-coded per-bucket (access-log bucket: false in BOTH envs because forensics are irrecoverable; Athena results: true in BOTH envs because they're cheap-rebuild). Values are nhp's canonical `sandbox` / `prod` — NOT `production`."
  type        = string

  validation {
    condition     = contains(["sandbox", "prod"], var.environment)
    error_message = "environment must be `sandbox` or `prod` (nhp convention)."
  }
}

variable "account_id" {
  description = "AWS account ID for this env. Used ONLY where the value lands in a resource's identity attribute (today: `aws_s3_bucket.{alb_access_logs,athena_query_results}.bucket` names via the `<project>-<role>-<env>-<account>` shape). Passed in from root rather than read from the in-module `data.aws_caller_identity.current` because the module's call site carries `depends_on = [time_sleep.bootstrap_alb_iam_propagation]` (root `terraform/main.tf`) — module-level depends_on propagates pending-change status to every in-module data source, deferring `account_id` to apply, which in turn promotes the bucket-name attribute to `(known after apply)` and forces replacement of buckets fenced by `lifecycle.prevent_destroy`. Evidence: nhp run 26258687592 (the post-#2072 main apply that tripped this on the partial-create state). Non-identity references (IAM policy doc ARNs, `aws:SourceAccount` conditions) keep using the in-module `data.aws_caller_identity.current` — those land in `policy = jsonencode(...)` and update in-place, where the deferred read is harmless."
  type        = string

  validation {
    # 12-digit AWS account ID. Catches garbage like a trailing space or a literal `default` at plan rather than surfacing as a malformed-ARN mid-apply.
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

# ── Networking inputs (passed from nhp root) ──
#
# Networking is passed in directly from nhp's root
# (`module.networking.{vpc_id,public_subnet_ids,vpc_cidr}`) since the
# bootstrap ALB lives intra-repo with the qurl-service ECS service it
# forwards to — no `terraform_remote_state` indirection.

variable "vpc_id" {
  description = "VPC ID where the ALB is provisioned. Pass `module.networking.vpc_id` from nhp's root."
  type        = string

  validation {
    # `vpc-<8|17 hex>` shape. AWS launched 17-char VPC IDs in 2018;
    # legacy 8-char IDs still exist in old accounts. The tighter
    # shape catches garbage like `vpc-x` at plan rather than
    # surfacing as a generic `InvalidVpcID.NotFound` mid-apply.
    condition     = can(regex("^vpc-[0-9a-f]{8}([0-9a-f]{9})?$", var.vpc_id))
    error_message = "vpc_id must be a `vpc-<8-hex>` (legacy) or `vpc-<17-hex>` (modern) identifier."
  }
}

variable "public_subnet_ids" {
  description = "Public subnet IDs the ALB attaches to. Pass `module.networking.public_subnet_ids` from nhp's root. Minimum 2 subnets in distinct AZs (ALB requirement)."
  type        = list(string)

  validation {
    condition     = length(var.public_subnet_ids) >= 2
    error_message = "public_subnet_ids must include at least 2 subnets (ALB requirement: distinct AZs)."
  }
}

variable "vpc_cidr_block" {
  description = "CIDR block of `var.vpc_id`. Used by the ALB → target SG rule that allows ingress on `var.target_port` from inside the VPC. Pass `module.networking.vpc_cidr` from nhp's root."
  type        = string

  validation {
    # `cidrhost()` is Terraform's own CIDR parser — rejects out-of-range
    # octets (`999.999.999.999/24`) and bad prefix lengths (`/99`) that
    # a permissive regex would silently accept.
    condition     = can(cidrhost(var.vpc_cidr_block, 0))
    error_message = "vpc_cidr_block must be valid CIDR notation (e.g. `10.0.0.0/16`)."
  }
}

# ── DNS + cert ──

variable "dns_name" {
  description = "Public DNS name fronting the ALB. Sandbox: `bootstrap.layerv.xyz`. Prod: `bootstrap.layerv.ai`. Customer reverse-tunnel-client sidecars hit `https://{dns_name}/v1/agent/bootstrap` for first-contact bootstrap."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", var.dns_name))
    error_message = "dns_name must be a valid lowercase FQDN."
  }
}

variable "route53_zone_id" {
  description = "Hosted zone ID for the parent of `dns_name`. Required when `provision_certificate=true` (ACM DNS-validation CNAMEs) or `manage_dns_alias=true` (alias record). Empty string when both are false (cross-account prod where DNS is operator-managed in the prod-mgmt account)."
  type        = string
  default     = ""

  validation {
    condition     = var.route53_zone_id == "" || can(regex("^Z[A-Z0-9]{8,}$", var.route53_zone_id))
    error_message = "route53_zone_id must be a Route53 zone ID (uppercase, starting with Z) or empty string."
  }
}

variable "route53_record_change_iam_propagation_triggers" {
  description = "Optional trigger map for waiting on Terraform CI Route53 record-change IAM propagation before same-account bootstrap DNS writes."
  type        = map(string)
  default     = {}
}

variable "route53_record_change_iam_propagation_duration" {
  description = "Duration to wait for Terraform CI Route53 record-change IAM propagation before same-account bootstrap DNS writes."
  type        = string
  default     = "60s"
}

variable "manage_dns_alias" {
  description = "Whether this stack writes the A-alias from `dns_name` to the ALB. True when the parent zone is in the same account as this ALB; false when the zone is cross-account and the operator writes the alias out-of-band. Sandbox: true (`layerv.xyz` zone in account 767397897469, same as the ALB). Prod: false (`layerv.ai` zone in `layerv-mgmt`, cross-account). See README's runbook for the operator path."
  type        = bool
  default     = false
}

variable "provision_certificate" {
  description = "Whether this stack provisions+validates an ACM cert for `dns_name`. True only when the parent zone is in the same account as this ALB (DNS validation needs to write CNAMEs into that zone). Sandbox: true (same-account `layerv.xyz`). Prod: false (cross-account `layerv.ai`; the operator pre-provisions the cert and supplies the ARN via `existing_certificate_arn`)."
  type        = bool
  default     = false
}

variable "existing_certificate_arn" {
  description = "ACM cert ARN to attach when `provision_certificate=false`. Empty during the first-apply bootstrap window; populated after the operator pre-provisions the cert in this account (see README). The listener-side precondition rejects the misconfigured combo (provision=false + arn empty) before plan finishes."
  type        = string
  default     = ""

  validation {
    # Match the eight real AWS partitions verbatim (aws, aws-us-gov,
    # aws-cn, aws-iso, aws-iso-b, aws-iso-c, aws-iso-e, aws-iso-f).
    # 36-char UUID after `certificate/` is the canonical shape; the validation
    # surfaces typo-shape errors at plan instead of as a deferred
    # apply failure. This check is syntactic only — the listener-side
    # precondition in `alb.tf` strict-matches the apply-target
    # partition+region via `data.aws_partition.current.partition`, so
    # a cross-partition paste here still fails plan at the precondition
    # layer.
    condition     = var.existing_certificate_arn == "" || can(regex("^arn:(aws|aws-us-gov|aws-cn|aws-iso|aws-iso-b|aws-iso-c|aws-iso-e|aws-iso-f):acm:[a-z0-9-]+:[0-9]{12}:certificate/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", var.existing_certificate_arn))
    error_message = "existing_certificate_arn must be empty or a valid ACM ARN: `arn:(aws|aws-us-gov|aws-cn|aws-iso|aws-iso-b|aws-iso-c|aws-iso-e|aws-iso-f):acm:<region>:<12-digit-account>:certificate/<canonical 8-4-4-4-12 UUID>`."
  }
}

# ── Listener routing ──

variable "bootstrap_path" {
  description = "Path that gets forwarded to qurl-service. Pinned to `/v1/agent/bootstrap` per the qurl-service OpenAPI spec. Anything else returns 404 at the listener — keeping the surface narrow simplifies WAF rules and access-log triage. Kept as a variable (rather than hardcoded) for module-test affordance, but the validation rejects any override: the WAF scope-down, listener rule, host-header restriction, fixed-response body, and OpenAPI contract all reference this value, and a coherent-but-wrong override (e.g. `/v2/agent/bootstrap`) would silently couple to a path the qurl-service handler doesn't serve."
  type        = string
  default     = "/v1/agent/bootstrap"

  validation {
    # Strict pin to the canonical value. The variable's `default`
    # is the only allowed input — any override would diverge from
    # the OpenAPI contract on qurl-service's side. If a future
    # protocol revision needs `/v2/agent/bootstrap` or similar,
    # update both this validation AND the qurl-service handler in
    # lockstep. The previous regex-shape validation accepted any
    # path-pattern-shaped string, which let an operator silently
    # set `bootstrap_path = "/v2/agent/bootstrap"` and get a
    # WAF/listener/404-body trio that all agreed on a path the
    # handler doesn't serve — coherent but wrong.
    condition     = var.bootstrap_path == "/v1/agent/bootstrap"
    error_message = "bootstrap_path is pinned to `/v1/agent/bootstrap` (the OpenAPI contract). Update both this validation AND the qurl-service handler in lockstep for any future protocol-version change."
  }
}

variable "target_port" {
  description = "TCP port the qurl-service ECS task listens on. ALB target group registers tasks on this port; the qurl-service task SG must allow ingress from this stack's ALB SG on this port. Default 8080 matches qurl-service's `var.container_port` default (`terraform/modules/qurl-service/variables.tf`); if a caller overrides `container_port` over there, this `target_port` MUST be overridden to match — TF won't catch the mismatch at plan time and the target group will silently health-check the wrong port."
  type        = number
  default     = 8080

  validation {
    condition     = var.target_port > 0 && var.target_port < 65536
    error_message = "target_port must be a valid TCP port (1–65535)."
  }
}

variable "health_check_path" {
  description = "HTTP path the ALB target group hits for health checks. qurl-service exposes split liveness/readiness endpoints (`/health/live` for ECS container health, `/health/ready` for ALB target groups — see `terraform/modules/qurl-service/main.tf`). `/health/ready` is the correct default for an ALB TG: it returns 200 when all dependencies (DynamoDB, Redis, etc.) are reachable, 503 when a critical dependency is down. Setting this to `/health/live` would mask a degraded dependency from the ALB. **Trade-off**: with `unhealthy_threshold = 2` and `interval = 15s` (see `aws_lb_target_group.qurl_service.health_check`), a flaky upstream dependency translates into ~30s of host flapping (mark-unhealthy → recovery → next failure → mark-unhealthy again). If the qurl-service dependency layer is observably flaky, raise the unhealthy_threshold above 2 in tandem with the dependency-layer's own retry posture — masking the flap by widening the threshold without fixing the dependency just delays the signal."
  type        = string
  default     = "/health/ready"

  validation {
    condition     = can(regex("^/[A-Za-z0-9._/-]*$", var.health_check_path))
    error_message = "health_check_path must start with `/` and contain only `[A-Za-z0-9._/-]` (no query string or fragment)."
  }
}

# ── WAF ──

variable "waf_managed_rule_groups" {
  description = "AWS-managed rule groups to enable on the WebACL, by full canonical name. **AWS-vendor only** — `waf.tf` hard-codes `vendor_name = \"AWS\"` and the entries are validated to start with `AWSManagedRules`. Third-party managed groups (Fastly, F5, Imperva, etc.) are NOT supported via this variable; they would require module changes. The bootstrap surface is a public POST endpoint, so the rule list is wide: `CommonRuleSet` (OWASP-core) + `AmazonIpReputationList` (known-bad sources, ~25 WCU) + `AnonymousIpList` (TOR / VPN exit nodes — bootstrap from a TOR exit is high-signal of abuse) + `BotControlRuleSet` (sophisticated probing). NOTE on rule ordering: the path-scoped rate-limit rule runs at priority 0 (before any managed rule), so a sustained probe on `/v1/agent/bootstrap` from a single source IP attributes to `RateLimitPerSourceIP` rather than to the IP-reputation list — see `waf.tf::waf_priority_rate_limit` rationale. AWS naming is inconsistent — most groups end in `RuleSet` but `AmazonIpReputationList` and `AnonymousIpList` do NOT — so the variable contract takes the FULL canonical name; a template like `AWSManagedRules$${name}RuleSet` would silently produce non-existent group names for the reputation lists."
  type        = list(string)
  default = [
    # Listed first in the variable for readability — but priority is
    # set per-name in `local.waf_managed_rule_priorities` (waf.tf),
    # NOT by list index, so reordering this list is a no-op at the
    # rule layer. IP-reputation is cheap (~25 WCU) and short-circuits
    # known-bad sources before the heavier managed rule groups
    # (CommonRuleSet, BotControlRuleSet) evaluate — but the path-
    # scoped rate-limit rule (priority 0) runs ahead of all managed
    # rules.
    "AWSManagedRulesAmazonIpReputationList",
    "AWSManagedRulesAnonymousIpList",
    "AWSManagedRulesCommonRuleSet",
    "AWSManagedRulesBotControlRuleSet",
  ]

  validation {
    # AWS WAFv2 hard cap is 10 managed rule groups per WebACL; default
    # of 4 leaves headroom but a typo-driven cap-exceedance fails apply
    # with `WAFInvalidParameterException`. Surface at plan instead.
    condition     = length(var.waf_managed_rule_groups) <= 10
    error_message = "At most 10 managed rule groups (WAF WebACL has a 10-rule capacity hard limit beyond which WCU exhaustion becomes likely)."
  }

  validation {
    # The for_each in waf.tf keys on the rule-group name; duplicates
    # would silently dedupe (same key twice). Surface the typo here.
    condition     = length(var.waf_managed_rule_groups) == length(toset(var.waf_managed_rule_groups))
    error_message = "waf_managed_rule_groups must not contain duplicate entries."
  }

  validation {
    # Catch the obvious typo class (missing `AWSManagedRules` prefix
    # entirely). Doesn't validate that the rule-group name is a real
    # AWS-published group — apply will surface `WAFInvalidParameterException`
    # if not — but at least flags the most common shape error at plan.
    condition     = alltrue([for n in var.waf_managed_rule_groups : startswith(n, "AWSManagedRules")])
    error_message = "Each entry must be the full canonical AWS-managed rule-group name starting with `AWSManagedRules`."
  }

  validation {
    # Every entry must have a priority assignment in waf.tf's static
    # `local.waf_managed_rule_priorities` map. Pinning priorities to
    # NAMES (vs deriving from list index) keeps `terraform plan` quiet
    # on a list reorder. Trade-off: adding a new managed rule group
    # requires editing TWO places — this allowlist AND the priority
    # map.
    #
    # **Why not collapse to one source of truth?** Terraform's variable
    # `validation { condition }` block CANNOT reference locals, data
    # sources, or resources — only the variable itself. The priority
    # map MUST live in waf.tf (it's referenced from a resource), so
    # the validation allowlist can't read `keys(local.waf_managed_rule_priorities)`
    # and must instead inline the same list. The defense-in-depth: if
    # an operator adds an entry to `waf_managed_rule_groups` without
    # extending the priority map, this validation fires at plan with
    # a helpful error message; without it, the `local.waf_managed_rule_priorities[rule.value]`
    # lookup in waf.tf fires `Invalid index` at apply with a generic
    # error.
    condition = alltrue([for n in var.waf_managed_rule_groups : contains([
      "AWSManagedRulesAmazonIpReputationList",
      "AWSManagedRulesAnonymousIpList",
      "AWSManagedRulesCommonRuleSet",
      "AWSManagedRulesBotControlRuleSet",
    ], n)])
    error_message = "Each entry must have a priority assignment in waf.tf's `local.waf_managed_rule_priorities`. Allowed values today: AWSManagedRulesAmazonIpReputationList, AWSManagedRulesAnonymousIpList, AWSManagedRulesCommonRuleSet, AWSManagedRulesBotControlRuleSet. To add a new group, extend BOTH the priority map in waf.tf AND this validation's allowlist."
  }
}

variable "waf_count_only_rule_groups" {
  description = "Managed rule-group names from `waf_managed_rule_groups` to override to `count` action (vs the default `none` action which honors the group's own block/count actions). Use this when bringing a new managed group up: set the group to `count` first, watch the WAF sampled-requests for false-positive rate, then drop the entry to flip to enforcement. **Recommended sandbox first-rollout posture** is BOTH `AWSManagedRulesAnonymousIpList` AND `AWSManagedRulesCommonRuleSet`: (a) customer sidecars behind corporate VPNs / Tailscale exit nodes / some cloud NATs hit AnonymousIpList's block; (b) the sidecar's bootstrap POST carries a PEM-wrapped public key (`-----BEGIN PUBLIC KEY-----`...) whose body content routinely false-positives on CRS's `CrossSiteScripting_BODY` and `SQLi_BODY` sub-rules. Count-only for the first 2–4 weeks of sandbox bootstrap traffic before flipping either to enforce in prod. (For granular control over the CRS sub-rules, a future `rule_action_override` like the existing `SignalNonBrowserUserAgent` one can target the body-inspection rules specifically.)"
  type        = list(string)
  default     = []

  validation {
    # Variable-validation can't reference other variables, so the
    # cross-list check ("every entry must also be in
    # `waf_managed_rule_groups`") lives as a `lifecycle.precondition`
    # block on `aws_wafv2_web_acl.this` in `waf.tf` (search for
    # `length(setsubtract(toset(var.waf_count_only_rule_groups), ...`).
    # That's the only place both variables are in scope. This
    # validation catches only the standalone duplicate-entry typo case.
    condition     = length(var.waf_count_only_rule_groups) == length(toset(var.waf_count_only_rule_groups))
    error_message = "waf_count_only_rule_groups must not contain duplicate entries."
  }
}

variable "waf_rate_limit_per_source_ip" {
  description = "Per-source-IP request rate limit (requests per 5-minute window). Default 200 is a defense-in-depth backstop — the LOAD-BEARING rate limit is per-API-key 10/hr in qurl-service. Headroom calculation: a customer running 50 sidecars behind a single NAT egress at first-bootstrap moment hits ~50/min for a few seconds, then drops to near-zero. A fleet redeploy with TLS-retry storms (each sidecar retries 2-3x while warming up TLS sessions) or replicas >1 per instance pushes that to ~100-150/5min from a single NAT. Default raised from 100 to 200 to keep headroom over the largest plausible legitimate burst while staying well below brute-force-effectiveness threshold against a 10/hr per-API-key limit. False-positives only delay bootstrap retries (per-API-key limit is the real gate), but a delay during a customer fleet redeploy is itself a poor signal. The module-policy floor is 100 — AWS's actual `rate_based_statement.limit` floor is 10, but anything below 100 is below the largest legitimate-burst calculation above and would false-positive a routine fleet redeploy."
  type        = number
  default     = 200

  validation {
    # Module-policy floor of 100 — AWS's actual WAFv2 `rate_based_statement.limit`
    # floor is 10, but values that low would false-positive a routine
    # customer-fleet redeploy (see headroom calc in description). Upper
    # bound is module policy too — anything above 1000 means the rule
    # isn't doing its job as a backstop and the caller probably wants
    # the per-API-key limit at the app layer instead.
    condition     = var.waf_rate_limit_per_source_ip >= 100 && var.waf_rate_limit_per_source_ip <= 1000
    error_message = "waf_rate_limit_per_source_ip must be 100–1000 (module policy; AWS's hard floor is 10 but anything below 100 false-positives routine customer-fleet redeploys; upper bound — the LOAD-BEARING per-API-key limit lives in qurl-service)."
  }
}

variable "waf_blocked_threshold_per_5min" {
  description = "WAF blocked-request alarm trigger (count per 5min). Above this rate signals active reconnaissance or a misconfigured legitimate caller — operator should investigate. Set lower than the typical broad-surface ALB threshold because the bootstrap surface has only one valid path, so WAF blocks here are higher-signal."
  type        = number
  default     = 50

  validation {
    condition     = var.waf_blocked_threshold_per_5min >= 1
    error_message = "waf_blocked_threshold_per_5min must be ≥1. Threshold 0 with GreaterThanThreshold means 'fire on any single block' — almost certainly not what you want."
  }
}

# ── Access logs ──

variable "access_log_glacier_transition_days" {
  description = "Days after which ALB access log objects TRANSITION to Glacier (not expire). The hot tier (S3 Standard) covers the typical incident-investigation window; older logs land in Glacier where retrieval is operator-explicit and cheaper at rest. **Distinct from object expiration**: objects in Glacier remain there indefinitely (no expiration today — bootstrap forensics intent is years-long retention, per `access_logs.tf` header). The 365 ceiling here only bounds when the transition happens, NOT how long objects live; a 365-day transition means objects spend their first year in Standard, then move to Glacier and stay forever."
  type        = number
  default     = 90

  validation {
    # AWS minimum days-in-class before Glacier transition is 30 (anything
    # lower fails apply with `Days for transition cannot be less than 30`).
    # Upper bound at 365 is module policy — anything past a year means
    # the operator is using lifecycle for cold-archive timing, not
    # investigation retention, and should land in a separate bucket
    # with a different shape. This ceiling does NOT cap object
    # lifetime in Glacier (no expiration is configured here).
    condition     = var.access_log_glacier_transition_days >= 30 && var.access_log_glacier_transition_days <= 365
    error_message = "access_log_glacier_transition_days must be 30–365 (AWS lifecycle floor is 30; module-policy ceiling is 365 for the TRANSITION timing — object lifetime in Glacier is unbounded by design)."
  }
}

variable "access_log_athena_query_retention_days" {
  description = "Days the separate Athena query-results bucket retains output. Athena query results are fan-out from the access-log bucket, useful within the post-incident triage window but not load-bearing after."
  type        = number
  default     = 30

  validation {
    condition     = var.access_log_athena_query_retention_days >= 7 && var.access_log_athena_query_retention_days <= 90
    error_message = "access_log_athena_query_retention_days must be 7–90 (anything shorter loses triage utility; anything longer means Athena results aren't actually triage-scoped)."
  }
}

# ── Alarms ──

variable "alb_5xx_threshold_per_minute" {
  description = "ALB-target 5xx alarm trigger threshold (count per minute, evaluated over 5 minutes). Default 5 catches a real qurl-service outage without firing on a single bad request."
  type        = number
  default     = 5

  # See rationale on `alb_elb_5xx_threshold_per_minute`.
  nullable = false

  validation {
    condition     = var.alb_5xx_threshold_per_minute >= 1
    error_message = "alb_5xx_threshold_per_minute must be ≥1. Threshold 0 with GreaterThanThreshold means 'fire on any single 5xx' — almost certainly not what you want."
  }
}

variable "alb_elb_5xx_threshold_per_minute" {
  description = "ALB-side (load-balancer-emitted) 5xx alarm threshold (count per minute, evaluated over 5 minutes). ALB-side 5xx is more diagnostic than target-side (no healthy targets, listener-rule misconfig, ALB throttling). **Default `10` is dark-launch-friendly**: between this stack's first apply and the paired qurl-service ECS-attach PR, the listener returns 503 on every `/v1/agent/bootstrap` probe (TG has no healthy targets — expected state). At 10/min the alarm tolerates moderate scanner / sidecar-early-bootstrap noise during the window without flipping into ALARM. Once the data plane is attached and the surface is live, env tfvars SHOULD override down to `1` — at that point any ALB-side 5xx is the outage signal. See README's 'Step 3 — verify dark-launch posture / Alarm noise during dark-launch' section."
  type        = number
  default     = 10

  # `nullable = false` coerces a caller `null` to this default. The
  # raw-null path fails the validation below with "argument must not
  # be null"; keeping the module as single-source-of-truth requires
  # this coercion, since the caller defaults the passthrough to null.
  nullable = false

  validation {
    condition     = var.alb_elb_5xx_threshold_per_minute >= 1
    error_message = "alb_elb_5xx_threshold_per_minute must be ≥1. Threshold 0 with GreaterThanThreshold means 'fire on any single 5xx' — almost certainly not what you want."
  }
}

variable "alb_unhealthy_hosts_threshold" {
  description = "Threshold for the `alb-unhealthy-hosts` alarm (`UnHealthyHostCount > N`). Default 0 means 'page on any unhealthy host' — qurl-service is the only thing this ALB forwards to, so any unhealthy target IS the outage. Tune up only if the qurl-service ECS service runs N+ tasks and a partial outage tolerates 1+ unhealthy."
  type        = number
  default     = 0

  # See rationale on `alb_elb_5xx_threshold_per_minute`.
  nullable = false

  validation {
    condition     = var.alb_unhealthy_hosts_threshold >= 0
    error_message = "alb_unhealthy_hosts_threshold must be ≥0."
  }
}

variable "alb_tls_handshake_failure_threshold" {
  description = "Per-period threshold for the TLS-handshake-failure alarm (count per minute, evaluated over 5 minutes). Sustained TLS failures signal cert misconfiguration, an in-flight cert rotation that didn't propagate, or an attacker probing for downgrade. Default 10/min filters benign client-version-mismatch noise while catching a real misconfiguration. The ALB metric is `ClientTLSNegotiationErrorCount`; a 0 threshold would fire on every legacy TLS-1.0 client probe. **Tuning note for low-QPS surface**: the bootstrap surface is described as 'sidecars bootstrap once per restart' (likely ~50 req/min steady state). At that volume, 10/min represents a 20% handshake-failure rate, which may be a higher noise floor than this surface warrants. Once the data plane is attached and a real-traffic baseline is observable, consider tuning down to 5/min in env tfvars."
  type        = number
  default     = 10

  # See rationale on `alb_elb_5xx_threshold_per_minute`.
  nullable = false

  validation {
    condition     = var.alb_tls_handshake_failure_threshold >= 1
    error_message = "alb_tls_handshake_failure_threshold must be ≥1. Threshold 0 with GreaterThanThreshold means 'fire on any single TLS error' — legacy clients produce these legitimately."
  }
}

variable "cross_account_subscriber_arns" {
  description = "Cross-account principals that may `sns:Subscribe` to the alerts topic. Today's pattern: alerts-infra (the org-wide AWS Chatbot home) subscribes to this stack's alerts topic from a different AWS account. Without an explicit topic policy granting the alerts-infra IAM principal `sns:Subscribe`, the cross-account subscribe fails with `AuthorizationError` and no chat-platform routing happens — alarms fire silently into the topic. Default empty list ships the topic without a cross-account policy; alerts-infra wiring requires populating this list with the right alerts-infra role ARN. The producer-keeps-SNS pattern (alerts-infra owns chat-platform routing, this stack owns the SNS topic itself) requires the policy on THIS side."
  type        = list(string)
  default     = []

  validation {
    # Accept IAM role, user, OR account-root. `:root` is a valid
    # subscriber-principal shape when the cross-account subscriber
    # service authenticates internally (some SaaS chat-platform
    # integrations subscribe-as-account-root rather than as a
    # dedicated role).
    condition     = alltrue([for a in var.cross_account_subscriber_arns : can(regex("^arn:(aws|aws-us-gov|aws-cn|aws-iso|aws-iso-b|aws-iso-c|aws-iso-e|aws-iso-f):iam::[0-9]{12}:(role/.+|user/.+|root)$", a))])
    error_message = "Each entry must be an IAM role, user, or account-root ARN: arn:<partition>:iam::<account>:role/<name>, arn:<partition>:iam::<account>:user/<name>, or arn:<partition>:iam::<account>:root."
  }
}

variable "alarm_email_subscriptions" {
  description = "Optional email addresses subscribed to the alerts SNS topic. Empty list ships the topic without subscriptions (alerts-infra wires AWS Chatbot via separate cross-account subscription — producer keeps SNS, alerts-infra owns chat-platform routing). **Subscription confirmation required**: after apply, each recipient receives an AWS confirmation email and MUST click the link before alarm notifications deliver — until confirmed, the subscription sits in `PendingConfirmation` state and alarms fire silently to that address. Operator should verify the subscription state with `aws sns list-subscriptions-by-topic` after first apply."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for e in var.alarm_email_subscriptions : can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", e))])
    error_message = "All alarm_email_subscriptions entries must be syntactically valid email addresses."
  }
}
