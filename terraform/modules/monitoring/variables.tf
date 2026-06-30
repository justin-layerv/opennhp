variable "environment" {
  description = "Environment name"
  type        = string
}

variable "cell_id" {
  description = "Cell identifier for multi-cell deployments (e.g., cell0, cell1)"
  type        = string
  default     = "cell0"
}

variable "nlb_arn_suffix" {
  description = "NLB ARN suffix for CloudWatch metrics"
  type        = string
}

variable "target_group_arn_suffix" {
  description = "Target group ARN suffix for CloudWatch metrics"
  type        = string
}

variable "https_target_group_arn_suffix" {
  description = "HTTPS target group ARN suffix (NLB TLS listener → server :8888) for TCP-target-reset alarms. Optional; when null, no HTTPS alarm is created."
  type        = string
  default     = null
}

variable "https_green_target_group_arn_suffix" {
  description = "Green HTTPS target group ARN suffix when blue/green is enabled, so the alarm covers traffic post-flip. Optional; when null, no green-side alarm is created."
  type        = string
  default     = null
}

# #2628: gates the three NLB health/flow alarms (UnHealthyHostCount, no-healthy-hosts,
# TCP resets). When nhp-server is private the public NLB is gone and the root repoints
# the dashboard widgets at the internal relay NLB — but these three alarms are gated OFF
# rather than repointed, because the internal NLB already carries its own
# no-healthy-targets alarm (modules/compute::internal_tg_no_healthy_targets); repointing
# them would duplicate that page (and TCP_Target_Reset_Count is dataless on a UDP TG).
# STATIC bool (root passes !var.take_server_private), NOT derived from a computed
# nlb_arn_suffix — gating count on a computed ARN trips "Invalid count argument" on
# greenfield applies (cf. the enable_sns_alerts precedent).
variable "nlb_alarms_enabled" {
  description = "Create the public-NLB health/flow CloudWatch alarms. Set false when the server is private (#2628); the internal relay NLB has its own no-healthy-targets alarm, so these would duplicate it. Default true."
  type        = bool
  default     = true
}

variable "asg_name" {
  description = "Auto Scaling Group name"
  type        = string
}

variable "server_log_group_name" {
  description = "CloudWatch log group that receives nhp-server structured JSON logs from /nhp-server/logs/server-*.log via the CloudWatch Agent. A metric filter on this group drives the ServerAsyncRuntimePanic alarm for recovered ErrRuntimePanic events in msgToPacketRoutine."
  type        = string
}

variable "server_stderr_log_group_name" {
  description = "CloudWatch log group that receives the nhp-server container's stdout/stderr via the docker awslogs driver. A metric filter on this group drives the ServerPanic alarm; ServerStartupEvent is EMF-auto-extracted from JSON lines the Go server emits on startup (#1107)."
  type        = string
}

variable "name_prefix" {
  description = "Name prefix for resources"
  type        = string
}

variable "tags" {
  description = "Tags for resources"
  type        = map(string)
  default     = {}
}

# Slack integration variables
variable "slack_workspace_id" {
  description = "Slack workspace ID for AWS Chatbot (get from AWS Chatbot console after authorizing)"
  type        = string
  default     = ""
}

variable "slack_channel_id" {
  description = "Slack channel ID for alerts (e.g., C01234567 - get from channel details in Slack)"
  type        = string
  default     = ""
}

variable "enable_slack_notifications" {
  description = "Enable Slack notifications via AWS Chatbot"
  type        = bool
  default     = false
}

variable "chatbot_owned_externally" {
  description = <<-EOT
    Whether the AWS Chatbot Slack channel configuration for
    `(slack_workspace_id, slack_channel_id)` is owned by another stack
    (e.g., website CDK's `LayerV-Monitoring`, which subscribes this module's
    `aws_sns_topic.alerts` to its own `ProdSlackChannel`).

    Chatbot enforces `(workspace, channel)` uniqueness account-wide, so two
    repos can't both create a config for the same pair. When this is set to
    true, this module:
      - skips creating `aws_chatbot_slack_channel_configuration.alerts`
      - skips the dedicated IAM role/policy (the external owner has its own)
      - still creates `aws_sns_topic.alerts` (the external owner subscribes
        it) and adds an explicit `chatbot.amazonaws.com` allow to the topic
        policy so the cross-region subscribe is authorized by policy text.

    Both prod and sandbox set this to true after their respective cross-repo
    handoffs: prod to website CDK's `LayerV-Monitoring` (see website repo
    `CLAUDE.md` *Cross-repo handoff*); sandbox to alerts-infra's
    `sandbox-alerts-sandbox` Chatbot config in
    `accounts/layerv-sandbox/1-main/main.tf`. Default false so a brand-new env
    without an alerts-infra subscriber still gets self-contained Slack
    delivery on first apply.
  EOT
  type        = bool
  default     = false
}

variable "alarm_on_missing_data" {
  description = <<-EOT
    How to treat missing metric data for availability alarms.

    - true:  "breaching" - missing data triggers alarm (recommended for prod)
    - false: "notBreaching" - missing data is OK (quieter during deploys)

    Affects: no-healthy-hosts, low-instances alarms
  EOT
  type        = bool
  default     = null # If null, defaults to true for prod, false otherwise
}

# DynamoDB monitoring variables
variable "dynamodb_table_names" {
  description = "List of DynamoDB table names to monitor"
  type        = list(string)
  default     = []
}

variable "enable_dynamodb_monitoring" {
  description = "Enable DynamoDB monitoring alarms"
  type        = bool
  default     = true
}

variable "alert_emails" {
  description = "Email addresses for CloudWatch alarm SNS notifications. Each address must confirm the subscription."
  type        = list(string)
  default     = []
}

variable "qurl_browser_rejected_alarm_actions_enabled" {
  description = "Whether qURL browser timing rejection-ratio alarms should execute alarm/OK actions. Defaults false so the #1840 alarms can bake report-only for 7 days before paging is enabled."
  type        = bool
  default     = false
}

# Mirrors the root var.deploy_relay (= compute's relay_enabled). Static input
# boolean, so it is safe to use directly in an alarm `count` (no
# count-depends-on-computed problem — contrast compute's enable_sns_alerts,
# which exists only because compute receives a COMPUTED SNS ARN across a module
# boundary; this module owns aws_sns_topic.alerts in-module, so its ARN is
# plan-time-known and no static SNS gate is needed). Gates the
# relay-forward-reject alarm so it only exists where a relay is actually wired
# (#2643, part of #2208).
variable "deploy_relay" {
  description = "Whether the NHP-Relay stack is deployed for this cell (mirrors the root var.deploy_relay / compute's relay_enabled). Gates the relay-forward-reject server-side alarm, which is inert without a relay sending NHP_RLY forwards."
  type        = bool
  default     = false
}
