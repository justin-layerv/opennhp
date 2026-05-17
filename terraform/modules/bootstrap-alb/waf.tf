# WAFv2 WebACL: scoped to the bootstrap ALB.
#
# The bootstrap surface has only one valid path, so the WAF rule set
# can be tight: more managed rule groups (BotControl + AnonymousIp on
# top of the IpReputation + CommonRuleSet baseline), per-source-IP
# rate limit AND path-scoped (the rate-limit aggregator only counts
# requests to `/v1/agent/bootstrap` so health-check / 404-probing
# traffic doesn't burn the budget).
#
# **The LOAD-BEARING bootstrap rate limit is per-API-key 10/hr in
# qurl-service.** This WAF rule is a defense-in-depth backstop — 100
# req / 5min from a single source IP is well above any plausible
# legitimate fleet-bring-up burst, and BELOW the threshold where a
# brute-force attempt against the qurl-service per-key limit becomes
# effective.
#
# ── Maintenance: adding a new managed rule group ──
#
# Three places must agree on the rule-group name (single source of
# truth is structurally impossible — Terraform variable validations
# can't reference locals):
#   1. `var.waf_managed_rule_groups` default list (variables.tf)
#   2. `var.waf_managed_rule_groups` validation allowlist
#      (variables.tf — the third `validation` block)
#   3. `local.waf_managed_rule_priorities` map below
# Drift in any one fails plan with a clear error pointing at the
# right file. The duplication exists because variable-validation
# scope rules prevent a single keys() lookup.
#
# ── Maintenance: WCU budget ──
#
# AWS WAFv2 WebACLs have a 1500 WCU base capacity (above which AWS
# auto-bills additional WCU at $0.20/100 WCU/mo). Current usage of
# the default rule set is approximately:
#   - AWSManagedRulesAmazonIpReputationList  ~25 WCU
#   - AWSManagedRulesAnonymousIpList         ~50 WCU
#   - AWSManagedRulesCommonRuleSet           ~700 WCU
#   - AWSManagedRulesBotControlRuleSet       ~50 WCU
#   - RateLimitPerSourceIP (rate_based)      ~2 WCU
#   - Total                                  ~830 / 1500 base
# A fifth managed group would land in the headroom, but
# `AWSManagedRulesKnownBadInputsRuleSet` (~200 WCU) +
# `AWSManagedRulesSQLiRuleSet` (~200 WCU) together would tip past
# the base capacity. `WAFLimitsExceededException` at apply is not
# a great UX — recompute the budget when adding a group.

locals {
  # Stable ordering for the WAF rule priorities. Lower number = higher
  # priority. The path-scoped rate-limit rule runs FIRST (priority 0)
  # so a sustained-probe stream against `/v1/agent/bootstrap` from a
  # single source IP short-circuits the rest of the rule chain
  # before burning WCU on the managed-rule eval.
  #
  # **Metric-attribution consequence.** When a known-bad IP from
  # `AmazonIpReputationList` (priority 10) hammers
  # `/v1/agent/bootstrap`, the request gets blocked by the rate-limit
  # rule BEFORE the IP-reputation rule sees it. The WAF metric stream
  # attribution lands on `RateLimitPerSourceIP` (which IS alarmed at
  # `var.waf_blocked_threshold_per_5min`), NOT on
  # `AWSManagedRulesAmazonIpReputationList` (which is unalarmed by
  # design — managed-rule blocks are routine internet noise; the
  # rate-limit signal is the operator-actionable one). This is
  # intentional: a known-bad IP getting both "is in IP-rep list" AND
  # "is hammering us" telemetered as the latter is correct prioritization.
  #
  # If a future caller wants known-bad-IP attribution before
  # rate-limiting (e.g., to tune WAF rule effectiveness), reorder
  # priorities so `AmazonIpReputationList` (10) drops below
  # `waf_priority_rate_limit` (0). Cost: a probing-IP scanner from a
  # known-bad source would consume IP-rep WCU per probe instead of
  # being short-circuited.
  waf_priority_rate_limit = 0

  # Rule names referenced by alarm dimensions in observability.tf —
  # extracting to a local makes the cross-file coupling explicit so a
  # rename can't silently put the alarm into INSUFFICIENT_DATA.
  waf_rule_rate_limit = "RateLimitPerSourceIP"

  # Static priority map for managed rule groups, keyed by canonical
  # AWS-managed rule-group name. Pinning priorities to NAMES — rather
  # than deriving them from `var.waf_managed_rule_groups` index — means
  # re-ordering the variable doesn't trigger a noisy priority diff on
  # every entry. The for_each in the dynamic-rule body is keyed by
  # name too, so the rules don't destroy-create; this fixes the *
  # priority * value so the diff is silent on reorder.
  #
  # Spacing of 10 (not 1) leaves headroom for a future rule group
  # that needs to slot between two existing priorities without
  # renumbering — e.g. inserting `KnownBadInputsRuleSet` between
  # IP-rep (10) and AnonymousIpList (20) at priority 15. Without
  # headroom, the renumber would cascade and produce a noisy diff.
  #
  # When adding a new managed rule group to `var.waf_managed_rule_groups`,
  # also add an entry here. The validation on the variable enforces that
  # the lists agree (every variable entry must have a priority).
  waf_managed_rule_priorities = {
    "AWSManagedRulesAmazonIpReputationList" = 10
    "AWSManagedRulesAnonymousIpList"        = 20
    "AWSManagedRulesCommonRuleSet"          = 30
    "AWSManagedRulesBotControlRuleSet"      = 40
  }
}

resource "aws_wafv2_web_acl" "this" {
  name        = local.alb_name
  description = "WAF for ${local.project} ${var.environment} — narrow public bootstrap surface"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # Path-scoped per-source-IP rate-limit rule. Aggregates over a 5-min
  # sliding window, but ONLY counts requests to the bootstrap path —
  # 404-probing traffic and ALB health checks (when target group is
  # populated) don't burn the budget.
  #
  # `scope_down_statement` filters the aggregator BEFORE the rate-
  # based eval, which means a sustained 10000 req/min stream of probes
  # to `/random` doesn't deny legitimate bootstrap calls from the same
  # source IP. The 404 fixed-response on probes already discourages
  # repeat scanners; the rate-limit rule's job is specifically to slow
  # down brute-force attempts against the bootstrap endpoint.
  #
  # `aggregate_key_type = "IP"` — geographic-key aggregation (per-country
  # rate limit) was considered but the bootstrap surface receives
  # legitimate traffic from every country a customer has a sidecar
  # in, so a single hot region (US-East, EU-West) would routinely
  # trip a per-country threshold. Per-source-IP is the correct
  # granularity; geographic blocking, if needed, lands as a separate
  # `geo_match_statement`-based rule (out of scope here — start
  # without it and add only with evidence of region-clustered abuse).
  rule {
    name     = local.waf_rule_rate_limit
    priority = local.waf_priority_rate_limit

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.waf_rate_limit_per_source_ip
        aggregate_key_type = "IP"
        # Pin to 300s explicitly. AWS WAFv2 supports 60/120/300/600;
        # the AWS-side default is 300 today, but pinning here keeps
        # the rule's window in sync with the rate-limit variable's
        # documented "per-5-minute-window" semantics regardless of
        # any future AWS default change.
        evaluation_window_sec = 300

        # Path-scoped: only count requests to the bootstrap path.
        # `EXACTLY` matches `var.bootstrap_path` verbatim — health-
        # check probes (different path) and the 404 fixed-response
        # path (everything else) are excluded from the aggregator.
        scope_down_statement {
          byte_match_statement {
            search_string         = var.bootstrap_path
            positional_constraint = "EXACTLY"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "NONE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      # **Load-bearing**: AWS WAFv2 publishes `BlockedRequests` with
      # the `Rule` dimension keyed on `visibility_config.metric_name`
      # — NOT on `rule.name`. The CloudWatch alarm in
      # `observability.tf::waf_rate_limit_blocks` dimensions the
      # stream by `Rule = local.waf_rule_rate_limit`; to match, the
      # `metric_name` here MUST equal `local.waf_rule_rate_limit`.
      # Diverging puts the alarm in `INSUFFICIENT_DATA` forever
      # (the exact failure mode terraform/CLAUDE.md's "Metric / Alarm
      # Dim-Set Rules" section warns against).
      metric_name              = local.waf_rule_rate_limit
      sampled_requests_enabled = true
    }
  }

  # AWS-managed rule groups. `for_each` keys on the rule-group name
  # itself (not a numeric index) so reordering or inserting an entry
  # in `var.waf_managed_rule_groups` doesn't churn unrelated rules
  # through destroy/create.
  #
  # `BotControlRuleSet` deserves a callout — it has TWO cost
  # components:
  #   - **Fixed monthly floor**: ~$10/mo per WebACL for Common
  #     protection level (the AWS published price for the
  #     `AWSManagedRulesBotControlRuleSet` group with Common targeted
  #     protection). On a low-QPS surface like bootstrap, this floor
  #     dominates the bill, so it's NOT negligible.
  #   - **Per-request CMV** (Common Model Verification): ~$1/1M
  #     requests on top of the floor, only when the `TGT_*` labels
  #     fire.
  # The bootstrap surface is low-QPS (sidecars bootstrap once per
  # restart, then knock from there), so the per-request cost is
  # bounded but the fixed floor still applies. If/when bootstrap
  # traffic patterns warrant cost optimization, downgrade to
  # `AWSManagedRulesBotControlCommonRuleSet` (paid) → drop the group
  # entirely + add a custom `bot:` label rule, in that order.
  #
  # **Sandbox/prod parity is deliberate.** ~$10/mo × 2 envs ≈ $20/mo
  # total is acceptable for the detection-value of running the same
  # rule set in both envs — a probing pattern that would trip
  # BotControl in prod can be observed and tuned against in sandbox
  # first. If a future cost review wants to drop BotControl in
  # sandbox only, the cleanest shape is a `var.waf_managed_rule_groups`
  # override in sandbox tfvars (the variable is already a list, no
  # module change required).
  dynamic "rule" {
    for_each = toset(var.waf_managed_rule_groups)

    content {
      name     = rule.value
      priority = local.waf_managed_rule_priorities[rule.value]

      # `override_action`: `none {}` honors the managed group's own
      # rule actions (block/allow/count). Operator can flip an
      # individual group to `count {}` via `var.waf_count_only_rule_groups`
      # — useful for a managed-group rollout (turn on, observe sampled-
      # requests, then drop from the count-only list to enforce). The
      # default empty list means every group enforces from day one.
      #
      # `AWSManagedRulesAnonymousIpList` is the most common candidate
      # for count-only first: customer sidecars behind corporate
      # VPNs / Tailscale exit nodes / some cloud NATs hit this group's
      # IP-list block and bootstrap silently fails with a 403 from the
      # ALB. Sandbox first-rollout posture: pass
      # `waf_count_only_rule_groups = ["AWSManagedRulesAnonymousIpList"]`
      # and watch the sampled-requests for 2–4 weeks before enforcing.
      # **Two dynamic blocks with inverted guards = ternary over
      # nested-block-type.** Exactly one emits per rule. The
      # `count {}` vs `none {}` blocks are different nested-block
      # types (not different attribute values on one type), so a
      # single `dynamic` with a ternary inside doesn't work —
      # `dynamic` is the only conditional-block primitive in
      # Terraform HCL.
      dynamic "override_action" {
        for_each = contains(var.waf_count_only_rule_groups, rule.value) ? [1] : []
        content {
          count {}
        }
      }
      dynamic "override_action" {
        for_each = contains(var.waf_count_only_rule_groups, rule.value) ? [] : [1]
        content {
          none {}
        }
      }

      statement {
        managed_rule_group_statement {
          name        = rule.value
          vendor_name = "AWS"

          # Pin BotControl to the `COMMON` inspection level explicitly
          # rather than relying on the AWS-side default. COMMON is
          # today's default and matches the cost commentary in this
          # file's header (~$10/mo fixed floor + ~$1/1M requests),
          # but if AWS ever flipped the default to TARGETED, the bill
          # would silently jump ~10x. Pinning here surfaces a
          # `terraform plan` diff if AWS rev's the default.
          #
          # Only BotControl supports `managed_rule_group_configs`;
          # other groups in `var.waf_managed_rule_groups` don't need
          # this block, so the dynamic-with-for_each emits the
          # `managed_rule_group_configs` block exactly when
          # `rule.value` is the BotControl name.
          dynamic "managed_rule_group_configs" {
            for_each = rule.value == "AWSManagedRulesBotControlRuleSet" ? [1] : []
            content {
              aws_managed_rules_bot_control_rule_set {
                inspection_level = "COMMON"
              }
            }
          }

          # **`SignalNonBrowserUserAgent` rule_action_override.** AWS
          # BotControl's COMMON-level set includes
          # `SignalNonBrowserUserAgent` which BLOCKS-by-default any
          # request whose User-Agent doesn't match a known browser
          # UA pattern. The reverse-tunnel-client sidecar is a
          # non-browser Go HTTP client emitting
          # `POST /v1/agent/bootstrap` — without this override, every
          # legitimate bootstrap call gets WAF-blocked at the first
          # COMMON-level eval and a customer sees a silent 403 with
          # no qurl-service log entry.
          #
          # Overriding to `Count` (not `Allow`) keeps the rule
          # observable in WAF sampled-requests for tuning while
          # disabling the block. The granular per-rule override is
          # cleaner than dropping the whole BotControl group into
          # `var.waf_count_only_rule_groups` — keeps every OTHER
          # BotControl rule enforcing.
          #
          # Gate this also on BotControl NOT being in
          # `waf_count_only_rule_groups`. When the whole group is
          # already overridden to `count` at the group level (via
          # the `override_action` dynamic above), emitting the
          # rule-level override is functionally redundant (both
          # resolve to count) and AWS may reject the parallel
          # configuration or emit a noisy plan diff. The
          # group-level `count` already neutralizes the
          # non-browser-block, so no defense lost.
          dynamic "rule_action_override" {
            for_each = (
              rule.value == "AWSManagedRulesBotControlRuleSet" &&
              !contains(var.waf_count_only_rule_groups, rule.value)
            ) ? [1] : []
            content {
              name = "SignalNonBrowserUserAgent"
              action_to_use {
                count {}
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        # `metric_name = rule.value` (the canonical AWS-published
        # group name). AWS WAFv2 publishes `BlockedRequests` with
        # the `Rule` dimension keyed on `visibility_config.metric_name`
        # — so pinning this to the canonical name means any future
        # alarm wired against a managed-group's blocked-rate can
        # use `Rule = "AWSManagedRules<Group>"` directly without
        # a separate metric-name mapping. Same shape as
        # `rate_limit` above. Trade-off: CloudWatch dashboard
        # readability is slightly worse (longer prefix), but the
        # alarm-correctness invariant outweighs that.
        metric_name              = rule.value
        sampled_requests_enabled = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    # WebACL-level metric name. `_` separator (vs the `-` in
    # `local.alb_name`) reads cleaner in CloudWatch metric paths.
    #
    # **Dim-set note**: AWS WAFv2 publishes the `WebACL` dimension
    # of `BlockedRequests` keyed on the WebACL's `name` attribute
    # (with dashes), NOT this `metric_name`. Today's alarm at
    # `observability.tf::waf_rate_limit_blocks` dims on
    # `WebACL = aws_wafv2_web_acl.this.name` (dashes), so it
    # works. A future WebACL-aggregate alarm wired against
    # `BlockedRequests` WITHOUT a `Rule` dim would also use the
    # `.name` attribute, not this `_webacl`-suffixed string.
    # This metric_name only surfaces in CloudWatch metric search
    # / dashboard listings, not in alarm dim-sets.
    metric_name              = "${replace(local.alb_name, "-", "_")}_webacl"
    sampled_requests_enabled = true
  }

  tags = merge(local.tags, { Name = local.alb_name })

  # Cross-list check: every entry in `var.waf_count_only_rule_groups`
  # MUST appear in `var.waf_managed_rule_groups`. Without this guard,
  # the `contains(...)` check at the dynamic-`override_action` site
  # silently returns `false` for a typo'd entry (e.g.,
  # `AWSManagedRulesAnonymousIPList` with capital `IP` instead of
  # `Ip`) — the operator believes they've flipped a group to count-
  # only, but enforcement is still on. The precondition turns the
  # silent-no-op into a plan-time error pointing at the right var.
  lifecycle {
    precondition {
      condition     = length(setsubtract(toset(var.waf_count_only_rule_groups), toset(var.waf_managed_rule_groups))) == 0
      error_message = "Every entry in waf_count_only_rule_groups must also appear in waf_managed_rule_groups. Entries missing from waf_managed_rule_groups (likely typos): ${jsonencode(setsubtract(toset(var.waf_count_only_rule_groups), toset(var.waf_managed_rule_groups)))}."
    }
  }
}

resource "aws_wafv2_web_acl_association" "this" {
  resource_arn = aws_lb.this.arn
  web_acl_arn  = aws_wafv2_web_acl.this.arn

  # Explicit dependency on the listener so the WAF association
  # graph is unambiguous: Terraform's implicit dep via
  # `aws_lb.this.arn` would create the association as soon as
  # the ALB exists, even before `aws_lb_listener.https` lands —
  # producing a brief mid-apply window where the ALB carries
  # WAF but no listener. Not a security issue, but it complicates
  # first-apply traces and races against the planned WAF logging
  # configuration in #1892.
  depends_on = [aws_lb_listener.https]
}
