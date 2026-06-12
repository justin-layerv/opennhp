# CloudWatch monitoring for AC instances
# Alarms for disk usage, SSM compliance, and EIP pool utilization
# Note: Uses data.aws_region.current from main.tf

# ==================== CloudWatch Alarms ====================

# DELIBERATE `{Component = "AC"}` dim set (do NOT "upgrade" to the
# {Component, Environment, Region} set the Go-published alarms use):
# DiskUsagePercent is published by the user_data bash script
# (terraform/modules/ac/scripts/disk-monitor.sh) via the
# `aws cloudwatch put-metric-data` CLI with `{Component = "AC"}` only —
# the bash path has no Environment/Region dims (terraform/CLAUDE.md
# "Metric / Alarm Dim-Set Rules" exempts CLI-published metrics). The
# script previously also tagged InstanceId, which made this alarm and the
# dashboard widget watch a non-existent {Component=AC} stream — fixed in
# #968 by dropping InstanceId so the fleet aggregates into one stream and
# `statistic = Maximum` pages on the worst instance's disk usage.
resource "aws_cloudwatch_metric_alarm" "disk_usage_high" {
  count = var.enable_ssm_maintenance && var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.name_prefix}-ac-disk-usage-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "DiskUsagePercent"
  namespace           = "LayerV/NHP"
  period              = 900 # 15 minutes
  statistic           = "Maximum"
  threshold           = var.disk_usage_threshold_percent
  alarm_description   = "Disk usage exceeds ${var.disk_usage_threshold_percent}% on AC instances. Metric is fleet-aggregated ({Component=AC}, statistic=Maximum) so it does not name the instance — for per-instance attribution pull the disk-monitor SSM run-command output (it echoes Instance/Disk usage), or query the AC fleet's df via SSM."
  treat_missing_data  = "notBreaching"

  dimensions = {
    Component = "AC"
  }

  # Send to SNS if configured
  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  ok_actions    = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ac-disk-usage-high"
  })
}

# Dim set MUST be the AC publisher base set [Component, Environment, Region]:
# CloudWatch alarms select a stream by exact dimension match. RegistrationFailure
# was historically published ONLY with extra dims (ACId, ErrorCode), so this
# alarm watched a {Component=AC} stream that never existed and sat in permanent
# OK (treat_missing_data=notBreaching) for months. Fixed in #968:
# recordRegistrationFailure (endpoints/ac/registration.go) now dual-publishes an
# unbreakdown base counter at exactly these three dims, while the ErrorCode/ACId
# breakdown stream remains queryable for dashboards.
#
# The base counter this alarm watches counts ONLY page-worthy server-side
# rejections (error response, NHP_AAK ErrCode, Registered=false). Lifecycle and
# transport drops (canceled / timeout / stopped) go to the breakdown stream only
# (recordRegistrationDrop) so the alarm does not false-fire on the failure burst
# every instance refresh / blue/green flip produces. A total "AC can't reach any
# server" outage is covered by registration_stale (absence of RegistrationSuccess)
# and servers_healthy_low, not by this counter. NOTE: this alarm has never fired
# before — its threshold (Sum>5 over one 5-min period) is unvalidated; calibrate
# against the post-#968 sandbox baseline before treating it as load-bearing.
resource "aws_cloudwatch_metric_alarm" "registration_failure" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.name_prefix}-ac-registration-failure"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "RegistrationFailure"
  namespace           = "LayerV/NHP"
  period              = 300 # 5 minutes
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "AC registration failures exceeded 5 in 5 minutes"
  treat_missing_data  = "notBreaching"

  dimensions = {
    Component   = "AC"
    Environment = var.environment
    Region      = data.aws_region.current.id
  }

  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  ok_actions    = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ac-registration-failure"
  })
}

resource "aws_cloudwatch_metric_alarm" "server_connection_failure" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.name_prefix}-ac-server-connection-failure"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "ServerConnectionFailure"
  namespace           = "LayerV/NHP"
  period              = 300 # 5 minutes
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "AC server connection failures exceeded 10 in 10 minutes (2 consecutive periods)"
  treat_missing_data  = "notBreaching"

  # Base dim set — see registration_failure above. recordServerConnectionFailure
  # dual-publishes the unbreakdown base counter at these three dims (#968).
  #
  # Asymmetry vs registration_failure (intentional): this counter has NO
  # lifecycle/transport drop exclusion — every connectToServer failure, incl.
  # classifyError -> "timeout", is alarmable. A sustained inability to reach
  # assigned servers IS the fault this alarm targets, so the exclusion machinery
  # the registration path uses is deliberately absent. Note that means BOTH a
  # server blue/green flip (timeouts to torn-down old-color servers) AND an
  # AC-side instance refresh (in-flight connectToServer calls failing as the AC
  # tears down — their errors are demoted to Debug but still record this metric)
  # feed this counter. The Sum>10-over-2-consecutive-periods threshold (vs
  # registration's Sum>5/1 period) is meant to ride both out. CALIBRATION: this
  # alarm has never fired; confirm neither the first sandbox blue/green flip nor
  # a fleet instance refresh pushes >10 across two 5-min windows before treating
  # it as load-bearing (see #968 ledger entry).
  dimensions = {
    Component   = "AC"
    Environment = var.environment
    Region      = data.aws_region.current.id
  }

  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  ok_actions    = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ac-server-connection-failure"
  })
}

# AOPReplayDetected is emitted by the AC replay-dedupe gate before JSON
# unmarshal / access-control handling. The stream uses the AC publisher base
# dimensions [Component, Environment, Region]; keep this alarm on that exact
# set so it matches the alarmable base counter and leaves any future
# breakdown stream free for dashboards.
resource "aws_cloudwatch_metric_alarm" "aop_replay_detected" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.name_prefix}-ac-aop-replay-detected"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "AOPReplayDetected"
  namespace           = "LayerV/NHP"
  period              = 300
  statistic           = "Sum"
  threshold           = 3
  alarm_description   = "AC dropped at least 3 replayed/duplicate AOP packets within 5 minutes. A single isolated event can follow restart/failover retries; this threshold targets repeated drops that indicate replay attempts or a broken retry path."
  treat_missing_data  = "notBreaching"

  dimensions = {
    Component   = "AC"
    Environment = var.environment
    Region      = data.aws_region.current.id
  }

  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  ok_actions    = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []

  tags = merge(var.tags, {
    Name  = "${var.name_prefix}-ac-aop-replay-detected"
    Issue = "1140"
  })
}

# ==================== UDP Handler Panic Alarm ====================
#
# Pages on any panic recovered by the top-level guard on the AC's UDP
# message-handler goroutines (NHP_AOP / NHP_ARD entry points in
# endpoints/ac/udpac.go::recvMessageRoutine). The guard exists because
# a single panic on a per-packet goroutine would otherwise crash
# nhp-acd, taking down all in-flight knock transactions on the
# instance and triggering an ASG instance refresh. Any non-zero value
# is a page-worthy signal: it indicates a reachable panic site on the
# UDP path that needs a root-cause fix, not a tuning change. See
# nhp#1423.
resource "aws_cloudwatch_metric_alarm" "udp_handler_panic" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.name_prefix}-ac-udp-handler-panic"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "UDPHandlerPanic"
  namespace           = "LayerV/NHP"
  period              = 300 # 5 minutes
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "AC nhp-acd recovered a panic on a UDP message-handler goroutine. Investigate the panic stack in CloudWatch logs and fix the root cause — ack-and-resolve before fixing means the next OK→ALARM transition will page again."
  treat_missing_data  = "notBreaching"

  # Must match the publisher's full base-dim set exactly: CloudWatch
  # alarms select streams by exact dimension match, and a partial set
  # silently lands in INSUFFICIENT_DATA forever. The publisher is
  # guaranteed to emit all three dims because NewACRegistration hard-fails
  # without AWS_REGION (#1659). The registration_failure /
  # server_connection_failure alarms above were fixed to this same set in
  # #968; the only remaining {Component=AC} alarms (disk_usage_high,
  # cert_sync_failures) are bash/CLI-published and intentionally use that
  # narrower set (terraform/CLAUDE.md "Metric / Alarm Dim-Set Rules").
  dimensions = {
    Component   = "AC"
    Environment = var.environment
    Region      = data.aws_region.current.id
  }

  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  ok_actions    = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ac-udp-handler-panic"
  })
}

# ==================== Custom Domain Cert Sync Alarms ====================

resource "aws_cloudwatch_metric_alarm" "cert_sync_failures" {
  count = var.enable_ssm_maintenance && var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.name_prefix}-ac-cert-sync-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "CertSyncFailures"
  namespace           = "LayerV/NHP"
  # DELIBERATE {Component=AC} set (do NOT add Environment/Region):
  # CertSyncFailures is published by custom-domain-cert-sync.sh via the
  # `aws cloudwatch put-metric-data` CLI with {Component=AC} only — the
  # bash path carries no Environment/Region dims and this alarm has always
  # matched it (it was the one of the four #968 audited that was already
  # functional). terraform/CLAUDE.md exempts CLI-published metrics.
  dimensions = {
    Component = "AC"
  }
  period             = 21600 # 6 hours (matches SSM association interval)
  statistic          = "Maximum"
  threshold          = 0
  alarm_description  = "Custom domain cert sync encountered failures on AC instances"
  treat_missing_data = "notBreaching"

  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  ok_actions    = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ac-cert-sync-failures"
  })
}

# ==================== EIP Pool Monitoring ====================
#
# Dimension schema note: every AC alarm now keys on exactly the dim set its
# publisher emits — CloudWatch alarms select a stream by exact dimension match,
# so this is a correctness requirement, not a style choice. The conventions:
#
#   - Go-published metrics (RegistrationFailure, ServerConnectionFailure,
#     RegistrationSuccess, UDPHandlerPanic, ...) carry the publisher base set
#     [Component, Environment, Region] — see endpoints/ac/registration.go
#     ::acBaseDims. Their alarms list all three. (#968 fixed the last two
#     that lagged this convention.)
#   - EIP metrics published from user_data.sh.tpl carry [Component, Environment]
#     (search `MetricName=EIPClaimSuccess`); the EIP alarms below match that.
#   - Pure-CLI metrics from the maintenance bash scripts (DiskUsagePercent,
#     CertSyncFailures) carry [Component] only; their alarms match that
#     (terraform/CLAUDE.md "Metric / Alarm Dim-Set Rules" exempts these).
#
# The split is per-publisher, not arbitrary. Issue #946 tracks the remaining
# registration-health observability work (a ServersHealthy gauge), not a
# dimension-schema unification — there is no unification left to do.

# Alarm: EIP pool utilization exceeds threshold (default 80%) for 15 min.
# Fires when pool usage is SUSTAINED high, warning before exhaustion blocks
# instance launches. Metric is pushed by each instance at boot (user_data)
# AFTER it has already claimed its EIP, so by the time an alert fires the
# instance that triggered it is past the danger window. The signal is for
# capacity planning, not for rescuing the launching instance.
#
# evaluation_periods=3 (15 minutes at period=300) is load-bearing: a
# blue/green deploy with both colours at full capacity briefly pushes
# the pool to 85-92% utilization (see eip.tf: `+1` refresh slack means
# (max*2)/(max*2+1), so 6/7 = 86% in sandbox and 12/13 = 92% in prod).
# That transient lasts 1-2 of these 5-minute windows — not 3
# consecutive ones — so the alarm does not fire during a normal deploy.
# The alarm only fires if utilization stays above 80% for 15 minutes
# straight, which corresponds to a real steady-state capacity shortfall.
resource "aws_cloudwatch_metric_alarm" "eip_pool_utilization_high" {
  count = var.enable_egress_eips && var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.name_prefix}-ac-eip-pool-utilization-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "EIPPoolUtilizationPercent"
  namespace           = "LayerV/NHP"
  period              = 300 # 5 minutes
  statistic           = "Maximum"
  threshold           = var.eip_pool_utilization_threshold_percent
  alarm_description   = "AC EIP pool utilization exceeds ${var.eip_pool_utilization_threshold_percent}%. Pool exhaustion will prevent new instances from launching. Total EIPs allocated: ${local.eip_count}."
  treat_missing_data  = "notBreaching"

  dimensions = {
    Component   = "AC"
    Environment = var.environment
  }

  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  ok_actions    = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ac-eip-pool-utilization-high"
  })
}

# Alarm: EIP claim failure
# Any single failure means the pool is exhausted or there is an AWS API issue.
# This is a critical alarm - the instance will terminate after a 2-minute cooldown.
#
# treat_missing_data = "notBreaching" is correct for a failure counter:
# the metric is only published when an instance attempts a claim, so periods
# with no instance launches genuinely have no failures and should not alarm.
# Switching to "missing" or "breaching" here would page on every quiet hour.
resource "aws_cloudwatch_metric_alarm" "eip_claim_failure" {
  count = var.enable_egress_eips && var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.name_prefix}-ac-eip-claim-failure"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "EIPClaimFailure"
  namespace           = "LayerV/NHP"
  period              = 300 # 5 minutes
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "AC instance failed to claim an EIP from the pool. The instance will terminate. This indicates the EIP pool is exhausted - increase ac_max_capacity or check for leaked EIP associations."
  treat_missing_data  = "notBreaching"

  dimensions = {
    Component   = "AC"
    Environment = var.environment
  }

  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  ok_actions    = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ac-eip-claim-failure"
  })
}

# ==================== AC-to-Server Registration Health (issue #239) ====================

# NOTE on alarm dimensions: the AC publisher (endpoints/ac/registration.go
# NewACRegistration) emits metrics with the *exact* dimension set
# [Component=AC, Environment=<env>, Region=<region>]. CloudWatch alarms must
# match this dimension set EXACTLY — a partial dimension set selects a different
# (non-existent) metric stream and the alarm sits in INSUFFICIENT_DATA forever.
resource "aws_cloudwatch_metric_alarm" "servers_healthy_low" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.name_prefix}-ac-servers-healthy-low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ServersHealthy"
  namespace           = "LayerV/NHP"
  period              = 300
  statistic           = "Minimum"
  threshold           = 2
  alarm_description   = "AC has fewer than 2 healthy server connections for 5 minutes. Target is 3 (one per AZ)."
  treat_missing_data  = "notBreaching"

  dimensions = {
    Component   = "AC"
    Environment = var.environment
    Region      = data.aws_region.current.id
  }

  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  ok_actions    = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ac-servers-healthy-low"
  })
}

resource "aws_cloudwatch_metric_alarm" "registration_stale" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.name_prefix}-ac-registration-stale"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "RegistrationSuccess"
  namespace           = "LayerV/NHP"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "No AC registration success events in 10 minutes. ACs may be unable to reach any server."
  treat_missing_data  = "breaching"

  dimensions = {
    Component   = "AC"
    Environment = var.environment
    Region      = data.aws_region.current.id
  }

  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  ok_actions    = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ac-registration-stale"
  })
}

# L3FlushScheduleWaitTimeout is a cumulative counter (gauge of total wait
# timeouts since AC start) published every 60s by RegisterGaugeFunc. The
# scheduler increments it inside Schedule() when waiting for an in-flight
# Flush exceeds flushCallTimeout + scheduleWaitSlop, which fires the
# force-insert bypass — sustained non-zero readings mean a chronically
# stuck flusher and operators must notice before flipping L3FlushDryRun=false.
#
# Latching is intentional. Because the metric is a cumulative counter
# (not a per-interval event count like RegistrationSuccess above), Maximum
# stays > 0 until the AC process restarts. That keeps the alarm loud until
# an operator follows the runbook and decides whether the cause is a real
# stuck flusher (restart + investigate) or GC-STW noise (widen
# scheduleWaitSlop). DIFF-based metric math would auto-OK and lose the
# acknowledgement requirement — and the repo has burned three PRs on TF
# metric_math fragility (terraform/CLAUDE.md gotcha #1104→#1109), so the
# simpler single-metric shape matches the existing AC alarm precedent.
#
# When the L3 flush scheduler is disabled (default), the gauge closure
# returns 0 unconditionally — the alarm stays in OK on every AC. After
# L3FlushDryRun=false in prod this becomes a paging signal; until then
# it's an operator dashboard item.
#
# treat_missing_data=notBreaching: the gauge is registered unconditionally
# but only emits during the 60s registration loop tick. A boot or short
# registration outage produces a missing-data window we don't want to
# alarm on (false-positive surface unrelated to the flusher's health).
#
# Runbook: docs/runbooks/l3-flush-schedule-wait-timeout.md.
resource "aws_cloudwatch_metric_alarm" "l3_flush_schedule_wait_timeout" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.name_prefix}-ac-l3-flush-schedule-wait-timeout"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "L3FlushScheduleWaitTimeout"
  namespace           = "LayerV/NHP"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  alarm_description   = "Latches until the offending AC instance is replaced (refresh / health-check / restart). AC L3 flush scheduler reported a Schedule() wait timeout (cumulative counter > 0) for 2 consecutive 1-minute windows. Indicates a chronically stuck flusher blocking Schedule() past flushCallTimeout + scheduleWaitSlop. Must clear before flipping L3FlushDryRun=false. See docs/runbooks/l3-flush-schedule-wait-timeout.md."
  treat_missing_data  = "notBreaching"

  dimensions = {
    Component   = "AC"
    Environment = var.environment
    Region      = data.aws_region.current.id
  }

  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  ok_actions    = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ac-l3-flush-schedule-wait-timeout"
  })
}

# ==================== Metric Publisher Failure Alarm ====================
#
# PublisherFailures is a counter the AC's CloudWatch publisher increments once
# per PutMetricData batch that returns an error (endpoints/metrics/publisher.go
# ::flush -> MetricPublisherFailure). It is the meta-alarm from #1707: it pages
# when the publisher itself is partially/intermittently failing to publish —
# throttling, a transient IAM/STS hiccup, one bad batch — a class that was
# otherwise only a log.Warning and silently dropped all metrics.
#
# Coverage boundary (the honest framing #1707 step 3 calls out): this catches
# the case where the client EXISTS but some PutMetricData calls fail. It does
# NOT catch total publisher death — when NewACRegistration/NewPublisher can't
# load AWS config (missing AWS_REGION/creds; the #1659 incident) the publisher
# is nil and emits nothing, so this self-reported counter rides the same dead
# channel. That blackout is caught by the absence-of-metric alarm
# `ac-registration-stale` above (treat_missing_data="breaching" on
# RegistrationSuccess) — the two alarms are complementary, not redundant.
#
# Dim set {Component, Environment, Region} mirrors the AC publisher base dims
# (endpoints/ac/registration.go::acBaseDims) exactly, per the dim-set rule in
# terraform/CLAUDE.md — the `registration_stale` precedent, NOT the partial-set
# `registration_failure` style (#239).
#
# Sensitivity: 2 failing 5-min windows within 15 min (evaluation_periods=3,
# datapoints_to_alarm=2). A single isolated transient PutMetricData throttle is
# absorbed; sustained creds/IAM/throttle degradation pages in <=10 min. Leans
# more sensitive than registration_failure's threshold-5 because a degraded
# observability pipeline is rare-and-serious. notBreaching because the counter
# is sparse (only emitted on a flush that had a failed batch); missing windows
# are healthy, not breaching.
resource "aws_cloudwatch_metric_alarm" "publisher_failures" {
  count = var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.name_prefix}-ac-publisher-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  datapoints_to_alarm = 2
  metric_name         = "PublisherFailures"
  namespace           = "LayerV/NHP"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "AC CloudWatch metric publisher reported PutMetricData batch failures in 2 of the last 3 five-minute windows. Metrics are being partially/intermittently dropped (throttling, IAM/STS, transient AWS). Does NOT cover total publisher death (missing AWS_REGION/creds) — see ac-registration-stale. #1707."
  treat_missing_data  = "notBreaching"

  dimensions = {
    Component   = "AC"
    Environment = var.environment
    Region      = data.aws_region.current.id
  }

  alarm_actions = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []
  ok_actions    = var.alarm_sns_topic_arn != "" ? [var.alarm_sns_topic_arn] : []

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ac-publisher-failures"
  })
}

# ==================== CloudWatch Dashboard ====================

locals {
  # All EIP dashboard widgets. The list is always defined but only included
  # in the dashboard when var.enable_egress_eips is true (see
  # eip_dashboard_widgets below). The two-step definition is required because
  # Terraform's `cond ? a : b` requires both branches to produce the same
  # tuple type/length, and this list is a heterogeneous tuple of 4 widget
  # objects — a for-expression with an `if` clause is the standard workaround.
  # Dashboard layout: the existing dashboard ends at y=9 with a height-2
  # text widget (rows 9 and 10), so the EIP widgets at y=11 are visually
  # contiguous with the previous row — no gap, no overlap. Each EIP row
  # is height=6, so the second row starts at y=17. If you re-order the
  # dashboard, recompute these to match the new previous-widget end.
  eip_widget_definitions = [
    {
      type   = "metric"
      x      = 0
      y      = 11 # immediately below the existing y=9, height=2 text widget
      width  = 12
      height = 6
      properties = {
        title  = "EIP Pool Utilization"
        region = data.aws_region.current.id
        metrics = [
          ["LayerV/NHP", "EIPPoolUtilizationPercent", "Component", "AC", "Environment", var.environment, { "stat" : "Maximum", "label" : "Utilization %" }]
        ]
        view    = "timeSeries"
        stacked = false
        period  = 300
        yAxis = {
          left = {
            min   = 0
            max   = 100
            label = "Percent"
          }
        }
        annotations = {
          horizontal = [
            {
              label = "Warning Threshold"
              value = var.eip_pool_utilization_threshold_percent
              color = "#ff7f0e"
            },
            {
              label = "Pool Exhausted"
              value = 100
              color = "#d62728"
            }
          ]
        }
      }
    },
    {
      type   = "metric"
      x      = 12
      y      = 11
      width  = 12
      height = 6
      properties = {
        title  = "EIP Pool Capacity"
        region = data.aws_region.current.id
        metrics = [
          ["LayerV/NHP", "EIPPoolTotal", "Component", "AC", "Environment", var.environment, { "stat" : "Maximum", "label" : "Total Allocated" }],
          ["LayerV/NHP", "EIPPoolAvailable", "Component", "AC", "Environment", var.environment, { "stat" : "Minimum", "label" : "Available" }]
        ]
        view    = "timeSeries"
        stacked = false
        period  = 300
        yAxis = {
          left = {
            min   = 0
            label = "Count"
          }
        }
      }
    },
    {
      type   = "metric"
      x      = 0
      y      = 17
      width  = 12
      height = 6
      properties = {
        title  = "EIP Claim Results"
        region = data.aws_region.current.id
        metrics = [
          ["LayerV/NHP", "EIPClaimSuccess", "Component", "AC", "Environment", var.environment, { "stat" : "Sum", "label" : "Success" }],
          ["LayerV/NHP", "EIPClaimFailure", "Component", "AC", "Environment", var.environment, { "stat" : "Sum", "label" : "Failure" }]
        ]
        view    = "timeSeries"
        stacked = false
        period  = 300
      }
    },
    {
      type   = "metric"
      x      = 12
      y      = 17
      width  = 12
      height = 6
      properties = {
        title  = "EIP Claim Duration"
        region = data.aws_region.current.id
        metrics = [
          ["LayerV/NHP", "EIPClaimDuration", "Component", "AC", "Environment", var.environment, { "stat" : "Average", "label" : "Average" }],
          ["LayerV/NHP", "EIPClaimDuration", "Component", "AC", "Environment", var.environment, { "stat" : "Maximum", "label" : "Max" }]
        ]
        view    = "timeSeries"
        stacked = false
        period  = 300
        yAxis = {
          left = {
            min   = 0
            label = "Seconds"
          }
        }
      }
    }
  ]

  # Conditionally include the widgets via a for-comprehension. When
  # var.enable_egress_eips is false the comprehension yields [] and the
  # dashboard's concat() call no-ops the EIP section.
  eip_dashboard_widgets = [for w in local.eip_widget_definitions : w if var.enable_egress_eips]
}

resource "aws_cloudwatch_dashboard" "ac_monitoring" {
  count = var.enable_ssm_maintenance && var.enable_cloudwatch_alarms ? 1 : 0

  dashboard_name = "${var.name_prefix}-ac-monitoring"

  dashboard_body = jsonencode({
    widgets = concat([
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "AC Disk Usage by Instance"
          region = data.aws_region.current.id
          metrics = [
            ["LayerV/NHP", "DiskUsagePercent", "Component", "AC", { "stat" : "Maximum" }]
          ]
          view    = "timeSeries"
          stacked = false
          period  = 900
          annotations = {
            horizontal = [
              {
                label = "Warning Threshold"
                value = var.disk_usage_threshold_percent
                color = "#ff7f0e"
              }
            ]
          }
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "SSM Association Compliance"
          region = data.aws_region.current.id
          metrics = [
            ["AWS/SSM", "AssociationCompliantCount", "AssociationId", aws_ssm_association.bootstrap_instance[0].association_id],
            ["AWS/SSM", "AssociationNonCompliantCount", "AssociationId", aws_ssm_association.bootstrap_instance[0].association_id]
          ]
          view    = "timeSeries"
          stacked = false
          period  = 3600
        }
      },
      {
        type   = "alarm"
        x      = 0
        y      = 6
        width  = 24
        height = 3
        properties = {
          title = "Active Alarms"
          alarms = concat([
            aws_cloudwatch_metric_alarm.disk_usage_high[0].arn,
            aws_cloudwatch_metric_alarm.registration_failure[0].arn,
            aws_cloudwatch_metric_alarm.server_connection_failure[0].arn,
            aws_cloudwatch_metric_alarm.aop_replay_detected[0].arn,
            aws_cloudwatch_metric_alarm.servers_healthy_low[0].arn,
            aws_cloudwatch_metric_alarm.registration_stale[0].arn,
            aws_cloudwatch_metric_alarm.udp_handler_panic[0].arn,
            aws_cloudwatch_metric_alarm.l3_flush_schedule_wait_timeout[0].arn,
            ],
            var.enable_egress_eips ? [
              aws_cloudwatch_metric_alarm.eip_pool_utilization_high[0].arn,
              aws_cloudwatch_metric_alarm.eip_claim_failure[0].arn,
            ] : []
          )
        }
      },
      {
        type   = "text"
        x      = 0
        y      = 9
        width  = 24
        height = 2
        properties = {
          markdown = <<-EOT
            ## NHP AC Instance Monitoring

            **Environment:** ${var.environment} | **Instance Tag:** ${var.ac_instance_tag} | **Disk Threshold:** ${var.disk_usage_threshold_percent}%

            Disk metrics are collected every 30 minutes via SSM State Manager. Log rotation runs daily at 3 AM UTC.
          EOT
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 11
        width  = 12
        height = 6
        properties = {
          title  = "AC Server Connections"
          region = data.aws_region.current.id
          # Gauges are emitted with the publisher base dims
          # [Component, Environment, Region]; the dimension order in the
          # widget metric tuples must match exactly or no data is returned.
          metrics = [
            ["LayerV/NHP", "ServersConnected", "Component", "AC", "Environment", var.environment, "Region", data.aws_region.current.id, { "stat" : "Average", "label" : "Connected" }],
            ["LayerV/NHP", "ServersHealthy", "Component", "AC", "Environment", var.environment, "Region", data.aws_region.current.id, { "stat" : "Average", "label" : "Healthy" }]
          ]
          view    = "timeSeries"
          stacked = false
          period  = 60
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 11
        width  = 12
        height = 6
        properties = {
          title  = "AC Registration Events"
          region = data.aws_region.current.id
          # Both lines read the publisher base-dim stream
          # {Component, Environment, Region} directly: RegistrationSuccess and (as
          # of #968) RegistrationFailure each dual-publish an unbreakdown base
          # counter, so a single fleet-wide stream exists for each without
          # hard-coding ACs. This replaces a prior
          # SEARCH('{...,Component,Environment,Region,ACId}') for Failure that
          # never matched: the breakdown stream carries ACId AND ErrorCode (5 dim
          # names), and CloudWatch SEARCH matches the exact dimension-name set, so
          # the 4-name schema returned nothing and the Failure line was blank. The
          # Failure line is the alarmable count — lifecycle/transport drops
          # (canceled/timeout/stopped) are excluded from the base counter (see
          # recordRegistrationFailure); the per-ErrorCode breakdown remains
          # queryable ad hoc.
          metrics = [
            ["LayerV/NHP", "RegistrationSuccess", "Component", "AC", "Environment", var.environment, "Region", data.aws_region.current.id, { "stat" : "Sum", "label" : "Success" }],
            ["LayerV/NHP", "RegistrationFailure", "Component", "AC", "Environment", var.environment, "Region", data.aws_region.current.id, { "stat" : "Sum", "label" : "Failure" }]
          ]
          view    = "timeSeries"
          stacked = false
          period  = 300
        }
      }
      ],
      # EIP Pool widgets - only included when egress EIPs are enabled.
      # Uses a local to avoid Terraform tuple length mismatch in conditional expressions.
      local.eip_dashboard_widgets
    )
  })
}
