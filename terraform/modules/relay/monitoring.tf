# ============================================================================
# CloudWatch alarms for the relay fleet (#2630, part of #2208).
#
# The relay is the only internet-facing surface and ships DARK until #6 (real
# browser traffic) — but a SYSTEMIC boot failure (e.g. the relay image tag
# missing in ECR) fails /health/live on every instance, ELB health replaces them
# all, and you get a fleet-wide boot-loop with ZERO healthy targets. With
# health_check_type=ELB (#2625) the ASG auto-replaces a single wedged instance,
# so these alarms are no longer the only recovery path — but they are the only
# VISIBILITY into replacements/boot-failures and the only backstop for the
# abnormal fleet-wide case. #2630 promoted them to a hard pre-#6 gate.
#
# DIM-SET CORRECTNESS (terraform/CLAUDE.md "Metric / Alarm Dim-Set Rules"):
# a CloudWatch alarm selects its metric stream by EXACT dimension match; a
# wrong/partial dim set sits in INSUFFICIENT_DATA forever and never pages. Each
# alarm below pins exactly the dim set its publisher emits — see the per-alarm
# notes. `terraform validate` is a syntax/type check only and CANNOT catch a
# wrong dim set; correctness rests on matching the emit sites:
#   - BootstrapFailure: user_data.sh.tpl (aws cloudwatch put-metric-data)
#   - UnHealthyHostCount / HealthyHostCount: AWS/ApplicationELB (TG + LB ARN suffixes)
#   - GroupInServiceInstances: AWS/AutoScaling (the ASG's enabled_metrics)
#   - RelayShed: endpoints/relay/relay.go (the relay's endpoints/metrics publisher, #2649)
#
# Action routing mirrors modules/ac: a single optional SNS topic ARN threaded in
# from the root (module.monitoring.sns_topic_arn), with the same
# `!= "" ? [..] : []` guard so an empty ARN leaves the alarm action-less rather
# than failing apply. All module-internal resources, count-gated at the root by
# deploy_relay (module "relay" count) — no per-resource count needed here.
# ============================================================================

locals {
  relay_alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
}

# ── 1. Target group: unhealthy hosts (the silent-degrade gap #2630 opens with) ──
#
# A wedged relay container fails the TG /health/live probe while EC2 status
# checks still pass. Under health_check_type=ELB the ASG replaces it, but at the
# one-per-AZ baseline that still drops an AZ's capacity for the replacement
# window — and a fleet-wide boot-loop (systemic bad image) leaves the TG with
# zero healthy targets. Page on ANY unhealthy target.
#
# DIM SET — AWS/ApplicationELB {LoadBalancer, TargetGroup}, NO Region:
# AWS-native ALB metrics are region-implicit (the stream lives in the ALB's
# region), so a Region dim does NOT apply here — the {Component, Environment,
# Region} convention in terraform/CLAUDE.md is specific to the AC Go publisher's
# IncrCounter emit, not AWS-managed namespaces. Pinning BOTH LoadBalancer and
# TargetGroup (not LoadBalancer alone, which aggregates across all TGs) keeps the
# signal scoped to the relay TG even if a second TG is ever attached. Mirrors
# modules/bootstrap-alb/observability.tf::alb_unhealthy_hosts' any-unhealthy
# detector shape while keeping relay's threshold fixed at 0 until #2644 tuning.
#
# GreaterThanThreshold + threshold=0 reads as "fire on count > 0" (i.e. >= 1
# unhealthy host). 2-of-2 over 1-minute windows absorbs a transient systemd
# restart / single-instance refresh drain blip (the TG's own unhealthy_threshold
# is 2 x 15s) without a spurious page; wall-clock to ALARM is ~2-3 min including
# CloudWatch evaluation latency. notBreaching: a no-traffic dark relay still
# emits this gauge (the TG health-checks targets continuously), but keep the
# absence-of-data window green to be safe.
resource "aws_cloudwatch_metric_alarm" "relay_tg_unhealthy_hosts" {
  alarm_name          = "${var.name_prefix}-relay-tg-unhealthy-hosts"
  alarm_description   = "Relay target group has had >=1 unhealthy target across 2 consecutive 1-minute windows. A wedged container fails /health/live while EC2 status checks pass; at one-per-AZ baseline this drops an AZ's capacity, and a systemic bad-image boot-loop leaves zero healthy targets. Investigate the relay container (docker logs / awslogs stream <instance>/relay) and the SSM relay image-tag."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  metric_name         = "UnHealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = aws_lb.relay.arn_suffix
    TargetGroup  = aws_lb_target_group.relay.arn_suffix
  }

  alarm_actions = local.relay_alarm_actions
  ok_actions    = local.relay_alarm_actions

  tags = merge(local.tags, {
    Name  = "${var.name_prefix}-relay-tg-unhealthy-hosts"
    Issue = "2630"
  })
}

# ── 2. Target group: zero healthy targets (the direct fleet-outage signal) ──
#
# UnHealthyHostCount catches registered targets that are failing health checks.
# It does NOT directly catch the terminate -> replacement-not-attached-yet window
# of a systemic boot-loop, where there can be zero registered healthy targets and
# UnHealthyHostCount can read as 0/no-data. HealthyHostCount < 1 is the direct
# "nobody can serve relay traffic" signal #2630 promoted to a hard pre-#6 gate.
#
# DIM SET — same AWS/ApplicationELB {LoadBalancer, TargetGroup}, NO Region shape
# as relay_tg_unhealthy_hosts above. Pinning both dims keeps the alarm scoped to
# this target group instead of the whole relay ALB.
#
# LessThanThreshold + threshold=1 reads as "fire on zero healthy targets". 2-of-2
# over 1-minute windows avoids a single sparse datapoint flap while still paging
# much faster than the 2x5-min ASG capacity backstop. breaching: when every
# target is deregistered, ELB can stop publishing HealthyHostCount entirely
# rather than emitting 0. Missing data is therefore part of the outage signal.
resource "aws_cloudwatch_metric_alarm" "relay_tg_zero_healthy_targets" {
  alarm_name          = "${var.name_prefix}-relay-tg-zero-healthy-targets"
  alarm_description   = "Relay target group had zero healthy targets across 2 consecutive 1-minute windows. This is the direct fleet-outage signal for systemic boot-loops, missing registrations, or target attach churn that leaves no relay able to serve traffic. Check ALB target health, ASG activity history, relay container logs, and per-instance user-data.log."
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  metric_name         = "HealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Minimum"
  threshold           = 1
  treat_missing_data  = "breaching"

  dimensions = {
    LoadBalancer = aws_lb.relay.arn_suffix
    TargetGroup  = aws_lb_target_group.relay.arn_suffix
  }

  alarm_actions = local.relay_alarm_actions
  ok_actions    = local.relay_alarm_actions

  tags = merge(local.tags, {
    Name  = "${var.name_prefix}-relay-tg-zero-healthy-targets"
    Issue = "2630"
  })
}

# ── 3. Boot failure (the boot-loop backstop #2630 promoted to a hard gate) ──
#
# user_data.sh.tpl emits a LayerV/NHP "BootstrapFailure" metric (value=1) on
# every fatal boot path (IMDS empty, SSM image-tag fetch/validate fail, ECR pull
# fail, Secrets Manager fetch/extract fail, or the ERR trap). A single emission
# means an instance failed to boot the relay daemon; sustained emissions mean a
# boot-loop. With health_check_type=ELB a systemic failure replaces the whole
# fleet silently — this metric is the ONLY signal that the replacements are boot
# FAILURES, not healthy rolls. Page on any single event.
#
# DIM SET — {Component="relay", Environment=<env>}, NO Region: this is a
# CLI-published metric (aws cloudwatch put-metric-data at user_data.sh.tpl:20),
# whose dims are EXACTLY `Component=relay,Environment=${environment}`. Per
# terraform/CLAUDE.md, CLI-published metrics carry their own dim conventions and
# are exempt from the Go-publisher {Component, Environment, Region} rule — match
# the emit site literally. A Region dim here would select a non-existent stream
# and the alarm would never fire. (Same shape as modules/ac's EIP user_data
# metrics, which carry {Component, Environment}.)
#
# Single-event detector (threshold=0, datapoints_to_alarm=1 over a 5-min
# lookback), NOT a consecutive-window rate alarm — boot failures are discrete and
# rare, and prod knock traffic is sparse, so the first failure must page (repo
# memory: tune sparse-fleet alarms as single-event detectors). CloudWatch only
# sends another ALARM notification after an OK->ALARM transition; a continuing
# boot loop stays ALARM and relies on the TG/capacity alarms as backstops.
# evaluation_periods is 1 (the lookback) with datapoints_to_alarm=1.
# notBreaching: the metric is only emitted by an instance that actually attempted
# (and failed) a boot, so quiet periods are genuinely failure-free.
resource "aws_cloudwatch_metric_alarm" "relay_bootstrap_failure" {
  alarm_name          = "${var.name_prefix}-relay-bootstrap-failure"
  alarm_description   = "A relay instance emitted BootstrapFailure (user_data boot failure: IMDS / SSM image-tag / ECR pull / Secrets Manager / unexpected error). The first event transitions the alarm to ALARM; with health_check_type=ELB a systemic failure replaces the whole fleet silently, so this is the only signal the replacements are boot failures, not healthy rolls. Check the instance's user-data.log (BOOTSTRAP FAILED: <reason>) and the relay image tag in ECR/SSM."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  metric_name         = "BootstrapFailure"
  namespace           = "LayerV/NHP"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    Component   = "relay"
    Environment = var.environment
  }

  alarm_actions = local.relay_alarm_actions
  # No OK notification: returning to OK means no new failures arrived in the
  # lookback window, not that the failed instance recovered.
  ok_actions = []

  tags = merge(local.tags, {
    Name  = "${var.name_prefix}-relay-bootstrap-failure"
    Issue = "2630"
  })
}

# ── 4. ASG capacity below baseline ──
#
# The relay baseline is local.relay_min_capacity, which defaults to
# length(private_subnet_ids). In today's networking layout that is one private
# subnet per AZ, so the default places one relay in each AZ for AZ-redundant HA
# on the only internet-facing surface. If in-service capacity stays below that
# baseline, the fleet has lost baseline coverage (boot-loop replacements not
# catching up, or a stuck refresh) and is no longer AZ-redundant.
#
# DIM SET — AWS/AutoScaling {AutoScalingGroupName}, NO Region: GroupInServiceInstances
# is one of the ASG's enabled_metrics (compute.tf), published in AWS/AutoScaling
# keyed only by the ASG name (region-implicit, like the ALB metrics above).
#
# SHAPE — single real metric (GroupInServiceInstances < relay_min_capacity), NOT
# metric math: deliberately avoids the FILL(desired,0)-FILL(in_service,0)
# capacity-deficit form modules/ac uses for its blue/green standby. The relay's
# desired_capacity is owned by the target-tracking policy (compute.tf), so a
# `desired - in_service` deficit would false-fire on legitimate scale-OUT lag
# (desired jumps, in-service catches up) — which is NOT a baseline shortfall.
# `GroupInServiceInstances < min_capacity` expresses "below baseline" directly,
# uses no fabricated metric name (terraform/CLAUDE.md forbids inventing
# GroupUnHealthyInstanceCount), and avoids TF metric_math fragility (the repo has
# burned three PRs on it — AC monitoring.tf documents this preference).
#
# LessThanThreshold + statistic=Minimum over 2 x 5-min windows: only declares a
# shortfall when in-service stayed below baseline across the window, riding out a
# normal instance refresh / AMI roll that briefly dips one instance. notBreaching:
# a brief metric gap during a refresh shouldn't page; a real sustained shortfall
# holds the Minimum below baseline across both windows.
resource "aws_cloudwatch_metric_alarm" "relay_capacity_below_baseline" {
  alarm_name          = "${var.name_prefix}-relay-capacity-below-baseline"
  alarm_description   = "Relay in-service instances stayed below relay_min_capacity (${local.relay_min_capacity}) across 2 consecutive 5-minute windows. Baseline relay coverage was lost (boot-loop replacements not catching up, or a stuck instance refresh) and the fleet is no longer AZ-redundant. Check the ASG activity history and per-instance user-data.log."
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  metric_name         = "GroupInServiceInstances"
  namespace           = "AWS/AutoScaling"
  period              = 300
  statistic           = "Minimum"
  threshold           = local.relay_min_capacity
  treat_missing_data  = "notBreaching"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.relay.name
  }

  alarm_actions = local.relay_alarm_actions
  ok_actions    = local.relay_alarm_actions

  tags = merge(local.tags, {
    Name  = "${var.name_prefix}-relay-capacity-below-baseline"
    Issue = "2630"
  })
}

# ── 5. Backpressure shedding (the relay-is-shedding incident signal #2649) ──
#
# The relay daemon emits a LayerV/NHP "RelayShed" counter on every backpressure
# 503 (endpoints/relay/relay.go::recordShed, via the same endpoints/metrics
# publisher nhp-server uses). A shed means a cell's in-flight cap
# (maxInFlightPerServer=256) was reached — a real incident signal: the target
# cell is stuck/slow, or the relay is under flood. Until #2649 a shed was only a
# throttled Warning in the relay logs (logShed); this alarm makes it alertable,
# pairing with #2640's relay alarms and #2643's server-side reject alarm.
#
# DIM SET — {Environment=<env>}, NO Region/Cell: this is a GO-published metric
# (PutMetricData via the metrics publisher), NOT a CLI put-metric-data like
# BootstrapFailure above. recordShed DUAL-PUBLISHES — a base counter at the
# publisher's [Environment] dims (matched here) PLUS a per-cell breakdown that
# adds a Cell dim (dashboards/attribution only). The alarm keys on the clean
# [Environment] base because (a) the relay fleet fronts all cells, so there is
# no single Cell value for the process, and (b) CloudWatch metric alarms can't
# aggregate the per-cell streams (no SEARCH on alarms — see modules/compute's
# server_instance_restart note). NO Region dim: the relay publisher's base set is
# [Environment] only (buildRelayMetricDimensions), unlike the AC publisher's
# {Component,Environment,Region} — match the emit site, per terraform/CLAUDE.md.
# `terraform validate` cannot catch a dim-set mismatch; correctness rests on
# matching buildRelayMetricDimensions + recordShed.
#
# Single-event detector (threshold=0, datapoints_to_alarm=1 over a 5-min
# lookback, Sum), NOT a consecutive-window rate alarm — same shape as
# relay_bootstrap_failure above and per the repo's sparse-fleet alarm rule: prod
# knock traffic is sparse (~1-2/hr) and the cap (256) sits orders of magnitude
# above real peak, so a HEALTHY relay never sheds and the FIRST shed must page.
# notBreaching: the counter is only emitted on an actual shed (it's skipped at 0
# by the publisher's flush), so quiet periods are genuinely shed-free, and a dark
# relay carrying no traffic correctly stays green. No OK notification: returning
# to OK means no new sheds in the lookback, not that the overloaded cell
# recovered — same posture as relay_bootstrap_failure.
#
# GATING — actions only, NOT count: mirrors the four alarms above (and the file
# header) — the alarm always exists when the relay is deployed (module-level
# `count = var.deploy_relay`), and its actions are gated on the static `!= ""`
# ARN guard. Deliberately does NOT gate `count` on the (computed)
# alarm_sns_topic_arn: gating count on a computed value is the greenfield
# "Invalid count argument" trap (#2665). The relay module sidesteps that for all
# its alarms by action-gating instead of count-gating.
resource "aws_cloudwatch_metric_alarm" "relay_shedding" {
  alarm_name          = "${var.name_prefix}-relay-shedding"
  alarm_description   = "The relay shed >=1 request with a backpressure 503 (RelayShed) in the last 5 minutes — a cell's in-flight cap (256) was reached, meaning the target cell is stuck/slow or the relay is under flood. A healthy relay never sheds (sparse knock traffic sits far below the cap), so the first shed pages. Check the relay logs for the throttled 'relay: shed N request(s) to <cell>' Warning and the per-cell RelayShed breakdown, then the target cell's NHP server/AC health and the relay's request volume (WAF / ALB metrics)."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  metric_name         = "RelayShed"
  namespace           = "LayerV/NHP"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    Environment = var.environment
  }

  alarm_actions = local.relay_alarm_actions
  # No OK notification: returning to OK means no new sheds arrived in the
  # lookback window, not that the overloaded cell recovered (same as
  # relay_bootstrap_failure).
  ok_actions = []

  tags = merge(local.tags, {
    Name  = "${var.name_prefix}-relay-shedding"
    Issue = "2649"
  })
}
