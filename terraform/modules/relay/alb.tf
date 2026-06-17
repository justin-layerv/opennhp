# ============================================================================
# Internet-facing ALB edge for the relay. TLS terminates here; the relay binds
# plaintext HTTP behind it and trusts X-Forwarded-For (source_addr_mode=
# trusted_header). Mirrors modules/bootstrap-alb, trimmed for a single backend
# service. NOTE: access logs / Athena are intentionally deferred for the dark
# launch (tracked issue; a #6 blocker — forensics can't be backfilled once real
# browser traffic flows).
# ============================================================================

locals {
  alb_name = "${var.name_prefix}-relay" # ≤32 chars: layerv-nhp-sandbox-relay = 24
}

# ── ALB security group ──
# Strip AWS's auto-created 0.0.0.0/0 egress on first apply (ingress=[]/egress=[]
# + ignore_changes), then attach scoped standalone rules. Same first-apply-vs-
# refresh trap fix as bootstrap-alb.
resource "aws_security_group" "alb" {
  name        = "${local.alb_name}-alb"
  description = "Relay ALB: ingress 443 from internet; egress to relay nodes on the HTTP port."
  vpc_id      = var.vpc_id

  ingress = []
  egress  = []

  tags = merge(local.tags, { Name = "${local.alb_name}-alb" })

  lifecycle {
    ignore_changes = [ingress, egress]
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

# Egress to the relay nodes on the HTTP port — referenced by SG ID (tight;
# same-module, no cross-stack coupling). The relay SG's symmetric ingress
# (compute.tf::relay_http_from_alb) is the load-bearing fence.
resource "aws_vpc_security_group_egress_rule" "alb_to_relay" {
  security_group_id            = aws_security_group.alb.id
  description                  = "Forward to relay nodes on the HTTP port"
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
  # AC-pinhole client IP. SECURITY: a multi-entry XFF (upstream proxy present)
  # currently fails the relay's bare ParseIP and fail-safes to the ALB IP — the
  # rightmost-entry parse fix is tracked as a #6 blocker (relay-code, not TF).
  # drop_invalid_header_fields above strips control-char/RFC-7230-violating XFF
  # before append, closing the smuggled-XFF class.
  xff_header_processing_mode = "append"

  enable_deletion_protection = local.is_prod

  tags = merge(local.tags, { Name = local.alb_name })
}

# ── Target group → relay nodes ──
resource "aws_lb_target_group" "relay" {
  name        = "${local.alb_name}-tg" # ≤32: layerv-nhp-sandbox-relay-tg = 27
  port        = var.listen_port
  protocol    = "HTTP"
  target_type = "instance"
  vpc_id      = var.vpc_id

  deregistration_delay = 30

  # /health/live is the relay's process-up liveness probe (GET → 200). It does
  # NOT check server reachability, which is correct: a dark relay (server hasn't
  # registered it) is still correctly forwarding — keeping it in rotation is
  # right, the forward failure surfaces as a 504 to the browser, not an unhealthy
  # target.
  health_check {
    enabled             = true
    path                = "/health/live"
    protocol            = "HTTP"
    port                = "traffic-port"
    matcher             = "200"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }

  tags = merge(local.tags, { Name = "${local.alb_name}-tg" })
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
  certificate_arn   = local.effective_certificate_arn

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
      condition     = var.provision_certificate || var.existing_certificate_arn != ""
      error_message = "Either provision_certificate=true (module provisions the ACM cert) or supply existing_certificate_arn."
    }

    precondition {
      condition     = !var.provision_certificate || var.existing_certificate_arn == ""
      error_message = "provision_certificate=true and existing_certificate_arn must not both be set — pick one."
    }

    precondition {
      condition     = local.effective_certificate_arn != null && local.effective_certificate_arn != ""
      error_message = "local.effective_certificate_arn resolved to null/empty: provision_certificate=false AND existing_certificate_arn empty. Set one."
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
  priority     = 1

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
