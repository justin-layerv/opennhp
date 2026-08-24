# ============================================================================
# Internet-facing ALB edge for the relay. Client TLS terminates here, then the
# ALB re-encrypts to the relay backend over HTTPS. The relay trusts
# X-Forwarded-For (source_addr_mode=trusted_header) only because the ALB appends
# the client IP and is the relay's sole browser ingress path. Mirrors
# modules/bootstrap-alb, trimmed for a single backend service. Access logging,
# retention, and Athena query support are provisioned with this edge.
# ============================================================================

locals {
  alb_name             = "${var.name_prefix}-relay" # ≤32 chars: layerv-nhp-sandbox-relay = 24
  relay_tg_name        = "${local.alb_name}-tg-tls"
  relay_tg_name_prefix = "rlytls"
}

# ── ALB security group ──
# Strip AWS's auto-created 0.0.0.0/0 egress on first apply (ingress=[]/egress=[]
# + ignore_changes), then attach scoped standalone rules. Same first-apply-vs-
# refresh trap fix as bootstrap-alb. Security group descriptions are ForceNew;
# ignore that wording-only drift so TLS-backend migrations do not try to destroy
# the static-named live ALB SG while ALB ENIs still depend on it. Existing SGs
# may keep older description text in AWS; the HCL description is authoritative
# for new environments only. The relay node SG mirrors this description freeze in
# compute.tf for the same ForceNew/deposed-SG reason.
resource "aws_security_group" "alb" {
  name        = "${local.alb_name}-alb"
  description = "Relay ALB: ingress 443 from internet; egress to relay nodes on the HTTPS backend port."
  vpc_id      = var.vpc_id

  ingress = []
  egress  = []

  tags = merge(local.tags, { Name = "${local.alb_name}-alb" })

  lifecycle {
    ignore_changes = [description, ingress, egress]
  }
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from internet (browser relay POSTs)"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"

  tags = merge(local.tags, { Name = "${local.alb_name}-ingress-https" })
}

# Egress to the relay nodes on the HTTPS backend port — referenced by SG ID (tight;
# same-module, no cross-stack coupling). The relay SG's symmetric ingress
# (compute.tf::relay_http_from_alb) is the load-bearing fence.
resource "aws_vpc_security_group_egress_rule" "alb_to_relay" {
  security_group_id            = aws_security_group.alb.id
  description                  = "Forward to relay nodes on the HTTPS backend port"
  referenced_security_group_id = aws_security_group.relay.id
  from_port                    = var.listen_port
  to_port                      = var.listen_port
  ip_protocol                  = "tcp"

  tags = merge(local.tags, { Name = "${local.alb_name}-egress-relay" })
}

# ── ALB ──
resource "aws_lb" "relay" {
  name               = local.alb_name
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids
  ip_address_type    = "ipv4"

  # Relay POSTs are short request/ACK round-trips (≤~5s server-ACK wait); 30s
  # idle is ample.
  idle_timeout               = 30
  drop_invalid_header_fields = true
  desync_mitigation_mode     = "defensive"

  # `append`: the ALB appends the observed client IP to the END of
  # X-Forwarded-For. The relay's deriveSourceAddr reads X-Forwarded-For for the
  # AC-pinhole client IP and deliberately takes the RIGHTMOST entry, because
  # entries to the left can be caller supplied while the rightmost entry is the
  # ALB-observed client IP. drop_invalid_header_fields above strips
  # control-char/RFC-7230-violating XFF before append, closing the smuggled-XFF
  # class.
  xff_header_processing_mode = "append"
  enable_xff_client_port     = false
  enable_waf_fail_open       = false

  enable_deletion_protection = local.is_prod

  # Per-request access logs to the dedicated S3 bucket (#2623) — forensics for the
  # internet-facing knock surface, which can't be backfilled once #6 routes real
  # traffic. No `prefix`: the bucket policy's `AWSLogs/<acct>/*` resource matches
  # the default empty-prefix key shape; setting a prefix without widening the
  # policy Resource in lockstep would break delivery with AccessDenied.
  access_logs {
    bucket  = aws_s3_bucket.alb_access_logs.bucket
    enabled = true
  }

  tags = merge(local.tags, { Name = local.alb_name })

  lifecycle {
    # The AWS provider models subnet changes as in-place, but SetSubnets cannot
    # move an ALB across VPCs. The ALB SG is necessarily replaced when vpc_id
    # changes, so use that replacement as the explicit cross-VPC trigger. Keep
    # destroy-before-create: the ALB has a static remote name and sandbox outage
    # is accepted; create_before_destroy would collide with the existing name.
    replace_triggered_by = [aws_security_group.alb.id]
  }

  # The bucket policy (legacy + modern delivery principals) must exist before the
  # enable test-write ModifyLoadBalancerAttributes runs, or it AccessDenies.
  depends_on = [
    aws_s3_bucket_policy.alb_access_logs,
    terraform_data.network_ready,
  ]
}

# ── Target group → relay nodes ──
resource "aws_lb_target_group" "relay" {
  # create_before_destroy is required for this HTTP->HTTPS target-group
  # replacement because the current TG is still attached to the listener/ASG
  # while Terraform creates the successor. Use AWS's random suffix so future
  # forced replacements do not trip DuplicateTargetGroupName on a deterministic
  # name (see bootstrap-alb's opposite no-CBD rationale).
  name_prefix = local.relay_tg_name_prefix
  port        = var.listen_port
  protocol    = "HTTPS"
  target_type = "instance"
  vpc_id      = var.vpc_id

  deregistration_delay = 30

  # Backend TLS is an encryption control, not target identity validation: ALB
  # does not validate target certificates, so the relay uses a per-instance
  # self-signed cert generated by user_data. The ALB-only SG path is still the
  # authenticated ingress boundary.
  # https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html
  #
  # /health/live is the relay's process-up liveness probe (GET → 200). It does
  # NOT check server reachability, which is correct: a dark relay (server hasn't
  # registered it) is still correctly forwarding — keeping it in rotation is
  # right, the forward failure surfaces as a 504 to the browser, not an unhealthy
  # target.
  health_check {
    enabled             = true
    path                = "/health/live"
    protocol            = "HTTPS"
    port                = "traffic-port"
    matcher             = "200"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }

  tags = merge(local.tags, { Name = local.relay_tg_name })

  lifecycle {
    create_before_destroy = true

    precondition {
      condition     = length(local.relay_tg_name_prefix) <= 6
      error_message = "Relay target group name_prefix '${local.relay_tg_name_prefix}' exceeds AWS's 6-character name_prefix limit."
    }
  }
}

# ── HTTPS listener ──
# Narrow surface (mirrors bootstrap-alb's "narrowness invariant"): the default
# action is a fixed-response 404, and ONLY `POST /relay/*` is forwarded to the
# backend (the rule below). Scanner noise / volumetric L7 floods on any other
# path are answered AT THE ALB and never reach the fleet — and the forwarded set
# stays aligned with the WAF per-source-IP rate-limit's `/relay/` scope-down. The
# TG health check hits the target's `/health/live` directly (ALB→target on the
# listen port), NOT through this listener, so it needs no rule here. No port-80
# companion — browsers reach the relay over HTTPS only.
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.relay.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "application/json"
      message_body = jsonencode({
        error   = "not_found"
        message = "This endpoint serves only POST /relay/{serverId}."
      })
      status_code = "404"
    }
  }

  lifecycle {
    precondition {
      condition     = var.certificate_arn != ""
      error_message = "certificate_arn must identify the root-owned regional ACM certificate."
    }
  }

  tags = merge(local.tags, { Name = "${local.alb_name}-https" })
}

# The ONLY forwarding rule: POST and OPTIONS on /relay/* → relay TG. Everything
# else hits the listener's fixed-response 404 and never reaches the fleet. Keep
# `/relay/*` in lockstep with the WAF rate-limit scope-down (STARTS_WITH /relay/)
# below — both must describe the same forwarded set.
# CORS (#2631): the qURL knock portal (qurl.link) and the relay are different
# origins, and the js-agent POSTs an application/octet-stream body, so the browser
# fires an OPTIONS preflight first. OPTIONS is forwarded here PAIRED WITH the relay
# daemon's CORS headers (handleRelay answers OPTIONS with 204 + the echoed allowed
# origin). The two MUST land together — forwarding OPTIONS while the daemon lacks
# CORS handling is no better than the 404. The allowlist is the knock portal only
# (the resource domains *.qurl.site / custom whitelabel are the data plane —
# direct connect through the AC, never the relay; see endpoints/relay/cors.go). The
# WAF rate rule counts OPTIONS too; the daemon sets Access-Control-Max-Age so the
# browser caches the preflight rather than re-sending it per knock.
resource "aws_lb_listener_rule" "relay" {
  listener_arn = aws_lb_listener.https.arn
  # Priority 1 is the dormant matched-cohort fixed-response gate when the
  # additive canary authority is enabled.
  priority = var.enable_matched_cohort_canary ? 2 : 1

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.relay.arn
  }

  condition {
    path_pattern {
      values = ["/relay/*"]
    }
  }

  condition {
    http_request_method {
      # POST = the knock; OPTIONS = the CORS preflight the browser sends first.
      values = ["POST", "OPTIONS"]
    }
  }

  tags = merge(local.tags, { Name = "${local.alb_name}-relay-rule" })
}

# ── WAF ──
locals {
  waf_priority_rate_limit = 0
  waf_rule_rate_limit     = "RateLimitPerSourceIP"

  # Priorities keyed by canonical AWS group name (not list index), so reordering
  # the variable doesn't churn rules. Spacing of 10 leaves insert headroom.
  waf_managed_rule_priorities = {
    "AWSManagedRulesAmazonIpReputationList" = 10
    "AWSManagedRulesAnonymousIpList"        = 20
    "AWSManagedRulesCommonRuleSet"          = 30
    "AWSManagedRulesBotControlRuleSet"      = 40
  }
}

resource "aws_wafv2_web_acl" "relay" {
  name        = local.alb_name
  description = "WAF for ${var.name_prefix} relay - browser-facing relay surface"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # Path-scoped per-source-IP rate limit (the load-bearing relay DoS control).
  # scope_down STARTS_WITH /relay/ — the serverId path segment varies, so an
  # EXACTLY match (bootstrap-alb's shape) won't work. Health-check probes
  # (/health/live) and 404 noise don't burn the budget.
  rule {
    name     = local.waf_rule_rate_limit
    priority = local.waf_priority_rate_limit

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit                 = var.waf_rate_limit_per_source_ip
        aggregate_key_type    = "IP"
        evaluation_window_sec = 300

        scope_down_statement {
          byte_match_statement {
            search_string         = "/relay/"
            positional_constraint = "STARTS_WITH"
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
      metric_name                = local.waf_rule_rate_limit
      sampled_requests_enabled   = true
    }
  }

  # AWS-managed groups. for_each keyed on the group name. override_action
  # count{} when listed in waf_count_only_rule_groups (observe-only — e.g.
  # CommonRuleSet by default, whose body rules false-positive the binary NHP
  # POST body), else none{} (enforce the group's own actions).
  dynamic "rule" {
    for_each = toset(var.waf_managed_rule_groups)

    content {
      name     = rule.value
      priority = local.waf_managed_rule_priorities[rule.value]

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
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.value
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${replace(local.alb_name, "-", "_")}_webacl"
    sampled_requests_enabled   = true
  }

  tags = merge(local.tags, { Name = local.alb_name })

  lifecycle {
    precondition {
      condition     = length(setsubtract(toset(var.waf_count_only_rule_groups), toset(var.waf_managed_rule_groups))) == 0
      error_message = "Every waf_count_only_rule_groups entry must also appear in waf_managed_rule_groups. Stray entries (likely typos): ${jsonencode(setsubtract(toset(var.waf_count_only_rule_groups), toset(var.waf_managed_rule_groups)))}."
    }
  }
}

resource "aws_wafv2_web_acl_association" "relay" {
  resource_arn = aws_lb.relay.arn
  web_acl_arn  = aws_wafv2_web_acl.relay.arn

  depends_on = [aws_lb_listener.https]
}
