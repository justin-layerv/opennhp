# =============================================================================
# Blue/Green Deployment Infrastructure for qurl-reverse-tunnel-server
# =============================================================================
# Mirrors `modules/ac/blue_green.tf` but adapted to the qurl-reverse-tunnel-server topology:
# routing happens through Cloud Map (per-AZ services) rather than an NLB
# listener default-action. The "blue/green flip" therefore writes the
# active color into SSM and CI rewrites `frps_addr` upstream in qurl-service
# to point at the active-color per-AZ services.
#
# All resources here are gated on `var.enable_blue_green`. Default false
# keeps the module a no-op for current deploys.
#
# Architecture:
#   - Blue ASG  = the existing `aws_autoscaling_group.frps` in main.tf
#   - Green ASG = `aws_autoscaling_group.frps_green` here, sized by
#                 `var.green_standby_capacity_per_az` × length(suffixes)
#                 with min/max tracking the same per-AZ knobs once
#                 enabled (so a CI scale-up doesn't get scaled back).
#   - Per-AZ Cloud Map services for each color:
#       blue:  `frps-${suffix}.${namespace}` (existing, unchanged)
#       green: `frps-green-${suffix}.${namespace}` (new)
#     The blue services keep their historical name so frpc / qurl-router
#     resolution against the API-supplied `frps_addr` continues to work
#     for the active-blue case without a coordinated rename across
#     qurl-service. CI flips the active color by rewriting `frps_addr`
#     in the QURL API.
#   - SSM parameters expose ASG names + active-color marker for CI.
#
# Mutual exclusion with canary: a precondition at the root rejects
# `enable_blue_green = true` paired with a canary-deployment instantiation
# for qurl-reverse-tunnel-server. The two regimes own the same `desired_capacity` field.

# =============================================================================
# Locals (effective green-side sizing)
# =============================================================================

locals {
  # Green ASG sizing. Tracks the per-AZ knobs when blue/green is enabled
  # so a CI-driven flip doesn't fight Terraform on the next plan. When
  # disabled, these locals are computed but unreferenced — count = 0
  # collapses every green resource to empty.
  #
  # Resolution rule for green_standby_capacity_per_az:
  #   - explicit value (>= 0): use as-is (caller knows what they want)
  #   - null + min_size_per_az set: track min_size_per_az (so green is
  #     full-warm and min ≤ desired ≤ max holds automatically)
  #   - null + no per-AZ form: 1 (the historical default — warm standby
  #     when blue/green is enabled on a 1/AZ deploy)
  # This is what the variable's `default = null` resolves to; the
  # explicit numeric form still works for cold standby (= 0) etc.
  effective_green_standby_per_az = (
    var.green_standby_capacity_per_az != null
    ? var.green_standby_capacity_per_az
    : (var.min_size_per_az != null ? var.min_size_per_az : 1)
  )

  # green_min_size tracks the resolved standby so cold standby
  # (`green_standby_capacity_per_az = 0`) on per-AZ form actually
  # works (min = 0 ≤ desired = 0 ≤ max). When the operator wants
  # warm standby, `green_standby_capacity_per_az = null` resolves to
  # `min_size_per_az` via `effective_green_standby_per_az`, so warm
  # standby still gets `green_min == green_desired == per_az *
  # az_count` without the operator having to keep two knobs in
  # lockstep. The "CI-driven scale-up not immediately reverted"
  # property is preserved by `lifecycle.ignore_changes =
  # [desired_capacity, min_size]` on the green ASG itself, not by
  # the min-size floor.
  # green_standby_desired uses the same resolved standby.
  # green_max_size uses the same effective max as the blue ASG —
  # when the per-AZ form is set, the legacy-fallback inside
  # `local.effective_max_size` still produces `max_size_per_az *
  # az_count`, so a single reference suffices.
  green_min_size        = local.effective_green_standby_per_az * local.az_count
  green_max_size        = local.effective_max_size
  green_standby_desired = local.effective_green_standby_per_az * local.az_count
}

# =============================================================================
# SSM Parameters for Blue/Green State
# =============================================================================
# These six keys (active-color, green-image-tag, last-switch-timestamp,
# blue-asg-name, green-asg-name, color-cloudmap-service-ids) remain at
# `/<env>/nhp/frps/...` for now. The image-tag and asg-name SSM keys
# moved to the canonical `/<env>/nhp/reverse-tunnel-server/*` path in
# #1668 phase 1 (see ssm.tf).
#
# Why deferred: the blue/green keys are pure-Terraform-owned and have no
# in-codebase reader today (the canary-deployment Lambda gets its SSM
# paths via env vars, not hardcoded prefixes; smoke tests read only
# `/<env>/nhp/{server,ac}/*`; qurl-service has no `/<env>/nhp/frps/*`
# references at the time of writing). They could be migrated in this PR
# without breaking anything — but that's also why deferring is cheap:
# moving them is a literal HCL string edit with no force-new state
# concern (none of these have AWS-side state in any deployed env yet).
# Phase 1's scope is intentionally narrow to the rts CI Docker Publish
# unblocker; the follow-up PR that migrates these keys also flips the
# `Component = "frps"` tags here and in ssm.tf in lockstep with a
# CloudWatch dashboard / log query audit (see #1668 acceptance).
#
# All "value" fields that CI mutates carry `ignore_changes = [value]` so
# a Terraform plan after a CI flip doesn't try to revert it.

resource "aws_ssm_parameter" "active_color" {
  count = var.enable_blue_green ? 1 : 0

  name        = "/${var.environment}/nhp/frps/active-color"
  description = "Currently active qurl-reverse-tunnel-server deployment color (blue or green). CI rewrites this during blue/green flip; downstream readers (qurl-service tunnel-addr emitter) consult it to decide which per-AZ Cloud Map services to publish in `frps_addr`."
  type        = "String"
  value       = "blue" # Initial state — blue is active

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-frps-ssm-active-color"
    Component = "frps"
  })

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "green_image_tag" {
  count = var.enable_blue_green ? 1 : 0

  name        = "/${var.environment}/nhp/frps/green-image-tag"
  description = "qurl-reverse-tunnel-server Docker image tag for the green ASG. CI/CD updates between releases without a Terraform apply."
  type        = "String"
  value       = var.image_tag # Initial value from Terraform

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-frps-ssm-green-image-tag"
    Component = "frps"
  })

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "last_switch_timestamp" {
  count = var.enable_blue_green ? 1 : 0

  name        = "/${var.environment}/nhp/frps/last-switch-timestamp"
  description = "Timestamp of last qurl-reverse-tunnel-server blue/green traffic switch (ISO 8601). CI updates after a successful flip; \"never\" until then."
  type        = "String"
  value       = "never"

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-frps-ssm-last-switch"
    Component = "frps"
  })

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "blue_asg_name" {
  count = var.enable_blue_green ? 1 : 0

  name        = "/${var.environment}/nhp/frps/blue-asg-name"
  description = "qurl-reverse-tunnel-server Blue Auto Scaling Group name. Symmetric with green-asg-name; CI uses both for instance refresh during a flip."
  type        = "String"
  value       = aws_autoscaling_group.frps.name

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-frps-ssm-blue-asg-name"
    Component = "frps"
  })
}

resource "aws_ssm_parameter" "green_asg_name" {
  count = var.enable_blue_green ? 1 : 0

  name        = "/${var.environment}/nhp/frps/green-asg-name"
  description = "qurl-reverse-tunnel-server Green Auto Scaling Group name. Used by CI/CD to drive instance refresh on the standby color."
  type        = "String"
  value       = aws_autoscaling_group.frps_green[0].name

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-frps-ssm-green-asg-name"
    Component = "frps"
  })
}

# Per-color, per-AZ Cloud Map service IDs — flat keys (e.g.
# `blue-a`, `green-a`) so a single SSM parameter holds the whole map
# CI/CD needs to walk during a flip. Stored as JSON because SSM
# `String` values can't natively encode a map; downstream readers
# `jq` it.
#
# CONTRACT WITH CI/CD: the JSON key shape `{color}-{az_suffix}` (e.g.
# `"blue-a"`) is part of the public interface of this SSM parameter.
# The blue/green flip workflow's jq path (`.[$color + "-" + $suffix]`)
# depends on this exact format. Renaming or restructuring the keys
# (e.g., to a nested `{blue: {a: ...}, green: {...}}` shape) is a
# breaking change that requires a coordinated CI script update.
#
# Type `String` (not `SecureString`): Cloud Map service IDs aren't
# secrets — `aws servicediscovery list-services` returns the same
# IDs to anyone with the API call. Storing as `String` avoids a
# circular dependency on `var.logs_kms_key_arn` (which is optional;
# `null` would force `SecureString` to fall back to the AWS-managed
# default key).
resource "aws_ssm_parameter" "color_cloudmap_service_ids" {
  count = var.enable_blue_green ? 1 : 0

  name        = "/${var.environment}/nhp/frps/color-cloudmap-service-ids"
  description = "JSON map of {color}-{az_suffix} → Cloud Map service ID for the per-color, per-AZ qurl-reverse-tunnel-server services. Used by CI/CD during blue/green flips to enumerate the side that needs registrations updated."
  type        = "String"

  value = jsonencode(merge(
    { for s, svc in aws_service_discovery_service.frps_per_az : "blue-${s}" => svc.id },
    { for s, svc in aws_service_discovery_service.frps_per_az_green : "green-${s}" => svc.id },
  ))

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-frps-ssm-color-cloudmap-ids"
    Component = "frps"
  })
}

# =============================================================================
# Green Cloud Map Services (per-AZ)
# =============================================================================
# Parallel set: `frps-green-${suffix}.${namespace}`. Same routing policy
# and health-check posture as the blue services — CI flips traffic by
# rewriting the upstream `frps_addr` to point here, not by changing
# routing semantics.

resource "aws_service_discovery_service" "frps_per_az_green" {
  for_each = var.enable_blue_green ? toset(var.frps_az_suffixes) : toset([])

  name        = "frps-green-${each.key}"
  description = "qurl-reverse-tunnel-server (green) — AZ suffix '${each.key}'"

  dns_config {
    namespace_id = var.namespace_id

    dns_records {
      ttl  = 30
      type = "A"
    }

    routing_policy = var.cloud_map_routing_policy
  }

  # `health_check_custom_config` deliberately omitted — see the matching
  # comment on the blue per-AZ services in `main.tf`.

  tags = merge(local.frps_cloudmap_service_tags, {
    Name        = "${var.name_prefix}-frps-green-${each.key}"
    Component   = "frps"
    DeployColor = "green"
  })
}

# =============================================================================
# Green Auto Scaling Group
# =============================================================================
# Shares the launch template with blue; only the SSM image-tag parameter
# (read by user_data via the `ImageTagSSMParam` ASG tag) and the
# `DeployColor` tag differ.

resource "aws_autoscaling_group" "frps_green" {
  count = var.enable_blue_green ? 1 : 0

  name                = "${var.name_prefix}-frps-green"
  vpc_zone_identifier = var.private_subnet_ids
  min_size            = local.green_min_size
  max_size            = local.green_max_size
  desired_capacity    = local.green_standby_desired

  launch_template {
    id      = aws_launch_template.frps.id
    version = aws_launch_template.frps.latest_version
  }

  # Same EC2-health-only refresh gate as blue; see the blue ASG comment for
  # the #1089 custom-health follow-up and why instance_warmup remains
  # load-bearing here. Keep health_check_grace_period and instance_warmup in
  # lockstep unless the bootstrap/readiness budget is re-evaluated.
  health_check_type         = "EC2"
  health_check_grace_period = 180

  enabled_metrics = local.asg_enabled_metrics

  # Mirror the blue ASG launch-template refresh posture. Green is the
  # pre-warmed candidate during blue/green rollouts; if a Terraform-only
  # launch-template change updates user_data or env wiring, the standby color
  # must not sit on stale bootstrap state until the next image publish. Keep
  # the same "launch-template only, no tag trigger" contract documented on the
  # blue ASG. Because blue and green share the launch template, a template-only
  # apply refreshes both colors; green is unrouted in standby, but it is not a
  # guaranteed-known-good rollback color while both refreshes are in flight.
  # auto_rollback only catches EC2-health failures until #1089 adds the
  # stricter FRPS readiness gate, and operators should still expect the extra
  # temporary +1 surge on each warm color.
  instance_refresh {
    strategy = "Rolling"

    preferences {
      instance_warmup        = 180
      min_healthy_percentage = 100
      max_healthy_percentage = 200
      auto_rollback          = true
      skip_matching          = true
    }
  }

  tag {
    key                 = "Name"
    value               = "${var.name_prefix}-frps-green"
    propagate_at_launch = true
  }

  tag {
    key                 = "Component"
    value               = "frps"
    propagate_at_launch = true
  }

  # user_data reads this tag at boot to choose the green-color SSM
  # image-tag parameter and the green per-AZ Cloud Map service.
  tag {
    key                 = "DeployColor"
    value               = "green"
    propagate_at_launch = true
  }

  tag {
    key                 = "ImageTagSSMParam"
    value               = aws_ssm_parameter.green_image_tag[0].name
    propagate_at_launch = true
  }

  dynamic "tag" {
    for_each = var.tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }

  lifecycle {
    create_before_destroy = true
    # CI/CD manages capacity during blue/green switches; ignore
    # `desired_capacity`/`min_size` here so a Terraform plan after
    # a flip doesn't try to revert it.
    #
    # `max_size` is deliberately NOT in ignore_changes (matches the AC
    # green ASG pattern in modules/ac/blue_green.tf::ac_green). The
    # fixed-size fleet design (resolved min == max == desired) means
    # Terraform's max stays in lockstep with the per-AZ knobs; a CI
    # scale-up on the green side would push `desired_capacity` (which
    # IS ignored) but never max. If a future autoscaling-on-green-side
    # rehearsal pushes desired above the static max, the cap will
    # fight the rehearsal — that's actually the desired safety net,
    # not a bug.
    #
    # Single-source-of-truth posture: only the SIZING precondition
    # below lives on the green ASG. Every other ASG-level invariant
    # (qurl_api_url ↔ token, tunnel-auth ↔ token, IMDSv2 hop-count,
    # etc.) lives on the blue ASG (`aws_autoscaling_group.frps`)
    # because both ASGs share a launch template and the LT-level
    # contracts are checked once at the LT-attached blue resource. A
    # future change that moves any of those invariants out of the
    # blue resource MUST mirror them here too — otherwise the green
    # ASG passes a fence the blue ASG enforces.
    ignore_changes = [desired_capacity, min_size]

    precondition {
      # green_min_size <= green_standby_desired <= green_max_size on
      # the resolved values, mirroring the blue-side fence in
      # main.tf::aws_autoscaling_group.frps. With `green_min_size ==
      # green_standby_desired` holding by construction (both resolve
      # to `effective_green_standby_per_az * az_count`), the chain
      # reduces to a `desired <= max` check. The fence stays in place
      # so the constraint is auditable at the alarm site even if a
      # future refactor decouples min from standby.
      condition     = local.green_min_size <= local.green_standby_desired && local.green_standby_desired <= local.green_max_size
      error_message = "Green ASG sizing must satisfy min <= desired <= max. Resolved: min=${local.green_min_size}, desired=${local.green_standby_desired}, max=${local.green_max_size}. With the resolved standby tracking the green-min by construction, this only fires when `green_standby_capacity_per_az > effective_max_size / az_count`. Lower `green_standby_capacity_per_az` or raise `max_size_per_az`."
    }
  }
}

# =============================================================================
# Green Launch-Readiness Hook
# =============================================================================
# EC2_INSTANCE_LAUNCHING readiness hook for the green frps ASG
# (qurl-reverse-tunnel-server#195). Same self-completed launch gate as the blue
# `aws_autoscaling_lifecycle_hook.frps_launch` in main.tf; count-gated on
# enable_blue_green so it exists exactly when the green ASG does. The same hook
# name as blue is intentional — hook names are scoped per Auto Scaling group, and
# single-sourcing via `local.frps_launch_lifecycle_hook_name` keeps user_data's
# `complete-lifecycle-action --lifecycle-hook-name` correct for both colors.
resource "aws_autoscaling_lifecycle_hook" "frps_launch_green" {
  count = var.enable_blue_green ? 1 : 0

  name                   = local.frps_launch_lifecycle_hook_name
  autoscaling_group_name = aws_autoscaling_group.frps_green[0].name
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_LAUNCHING"
  default_result         = var.frps_launch_readiness_default_result
  heartbeat_timeout      = var.frps_launch_readiness_heartbeat_timeout
}

# =============================================================================
# CloudWatch Alarms — Green Standby Health
# =============================================================================
# Mirrors the AC green-side alarms. We only emit the ASG-shape capacity
# deficit alarm; qurl-reverse-tunnel-server has no NLB, so the AC target-group
# health alarm has no analog here.
#
# Coverage gap (tracked in #1755): the empty-AZ watchdog (#1542)
# currently iterates only `frps-${suffix}.${namespace}` (blue)
# services — not the green `frps-green-${suffix}.${namespace}` set
# added here. When blue/green is enabled with a warm-standby green
# fleet, an "empty green AZ" failure during a flip would not page
# until either traffic shifts to green (at which point the existing
# per-AZ Cloud Map alarms fire because they're now in-band) or this
# alarm fires on a sustained ASG capacity deficit. The standby-side alarm
# here is the bridge until #1755 extends the watchdog to walk both
# colors.

# Asymmetric responsiveness vs. the canary's `canary_asg_unhealthy`
# alarm (`modules/canary-deployment/alarms.tf` -- 60s periods for
# instance-warmup + one extra period). The green standby has no live
# traffic, so paging on the canary cadence would surface a same-fault-
# class transient that the standby can absorb silently. The 10-min
# window (2 x 300s) trades a slower page for fewer false alarms during
# deploy churn (instance refreshes, AMI rolls). The input stats are
# intentionally asymmetric: `desired` Minimum and `in_service` Maximum
# only declare a deficit when capacity stayed short across the period.
# Revisit after the first sandbox green refresh; lengthen the window only
# if this still pages on healthy refresh noise.
# A sustained green-side fault still pages within the same eval
# window the empty-AZ watchdog (#1542) uses, so an "unrecoverable
# green fleet during a blue→green flip rehearsal" surfaces on both
# detection layers in the same 10-15 min window.
#
# Gate this SNS-routed alarm count on the static enable_sns_alerts flag, not
# on alarm_sns_topic_arn. The ARN is computed by the root monitoring module.
resource "aws_cloudwatch_metric_alarm" "frps_green_asg_unhealthy" {
  count = var.enable_blue_green && var.enable_cloudwatch_alarms && var.enable_sns_alerts ? 1 : 0

  alarm_name          = "${var.name_prefix}-frps-green-asg-unhealthy"
  alarm_description   = "qurl-reverse-tunnel-server Green ASG has sustained capacity deficit — may affect rollback capability during a blue/green flip."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  threshold           = 0
  # Belt-and-suspenders for whole-expression no-data states; the FILLs
  # make normal partial input gaps explicit.
  treat_missing_data = "notBreaching"

  metric_query {
    id = "capacity_deficit"
    # FILL bias is intentional for one-sided gaps: missing desired is treated
    # as "nothing wanted"; missing in-service with desired present should read
    # as a full deficit. The rollout ledger verifies CloudWatch's fresh-series
    # and one-input-missing behavior after apply.
    expression  = "FILL(desired, 0) - FILL(in_service, 0)"
    label       = "ASG desired capacity minus in-service instances"
    return_data = true
  }

  metric_query {
    id = "desired"
    metric {
      metric_name = "GroupDesiredCapacity"
      namespace   = "AWS/AutoScaling"
      period      = 300
      stat        = "Minimum"
      dimensions = {
        AutoScalingGroupName = aws_autoscaling_group.frps_green[0].name
      }
    }
  }

  metric_query {
    id = "in_service"
    metric {
      metric_name = "GroupInServiceInstances"
      namespace   = "AWS/AutoScaling"
      period      = 300
      stat        = "Maximum"
      dimensions = {
        AutoScalingGroupName = aws_autoscaling_group.frps_green[0].name
      }
    }
  }

  alarm_actions = [var.alarm_sns_topic_arn]
  ok_actions    = [var.alarm_sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-frps-green-asg-unhealthy-alarm"
    Component = "frps"
  })
}
