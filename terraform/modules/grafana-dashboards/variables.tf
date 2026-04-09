# Grafana Dashboards Module Variables
#
# NOTE: This module expects a grafana provider to be passed from the caller.
# The provider configuration (url, auth) should be defined in the root module.

variable "grafana_url" {
  description = "Grafana Cloud URL (for generating dashboard URLs in outputs)"
  type        = string
}

variable "create_dashboards" {
  description = "Create dashboard and folder resources. False = only create datasources/IAM (for non-primary environments)."
  type        = bool
  default     = true
}

variable "environment" {
  description = "Environment name (sandbox, prod)"
  type        = string
}

variable "prometheus_datasource_uid" {
  description = "UID of the Prometheus/Mimir datasource in Grafana Cloud (find in Connections > Data sources)"
  type        = string
  default     = "grafanacloud-prom"
}

variable "tempo_datasource_uid" {
  description = "UID of the Tempo datasource in Grafana Cloud"
  type        = string
  default     = "grafanacloud-traces"
}

variable "folder_name" {
  description = "Grafana folder name for QURL dashboards"
  type        = string
  default     = "QURL"
}

# ==============================================================================
# CloudWatch Data Source (for NHP Infrastructure dashboard)
# ==============================================================================

variable "cloudwatch_datasource_enabled" {
  description = "Enable CloudWatch data source and NHP Infrastructure dashboard"
  type        = bool
  default     = false
}

variable "cloudwatch_assume_role_arn" {
  description = "IAM role ARN for Grafana Cloud to assume for CloudWatch access. If empty and cloudwatch_datasource_enabled=true, a role is created automatically."
  type        = string
  default     = ""
}

variable "grafana_cloud_aws_account_id" {
  description = "Grafana Cloud's AWS account ID for IAM trust policy (find in Grafana Cloud > CloudWatch integration setup)"
  type        = string
  default     = ""
}

variable "grafana_cloud_external_id" {
  description = "External ID for Grafana Cloud IAM assume role (find in Grafana Cloud > CloudWatch integration setup)"
  type        = string
  default     = null
}

variable "name_prefix" {
  description = "Name prefix for IAM resources"
  type        = string
  default     = "nhp"
}

variable "aws_region" {
  description = "AWS region for CloudWatch data source"
  type        = string
  default     = "us-east-2"
}

variable "nhp_folder_name" {
  description = "Grafana folder name for NHP dashboards"
  type        = string
  default     = "NHP"
}

# ==============================================================================
# Athena Data Source (for AWS Cost dashboard)
# ==============================================================================

variable "athena_datasource_enabled" {
  description = "Enable Athena data source and AWS Cost dashboard"
  type        = bool
  default     = false
}

variable "athena_assume_role_arn" {
  description = "IAM role ARN for Grafana Cloud to assume for Athena access (in mgmt account)"
  type        = string
  default     = ""
}

variable "athena_workgroup" {
  description = "Athena workgroup name for cost queries"
  type        = string
  default     = ""
}

variable "athena_database" {
  description = "Glue database name for cost data"
  type        = string
  default     = ""
}

variable "athena_region" {
  description = "AWS region where Athena resources live"
  type        = string
  default     = "us-east-1"
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

# ==============================================================================
# QURL Alerting (alerts.tf)
# ==============================================================================
#
# These variables drive the Grafana alert rules in alerts.tf. The rules fire
# against the existing Prometheus and Loki datasources in Grafana Cloud and
# publish to the existing CloudWatch SNS topic from the monitoring module —
# unifying the qurl-api alerting pipeline with every other prod alert in the
# stack.
#
# Background: 2026-03-24 incident. The qurl-operations dashboard had 5xx and
# burn-rate panels labelled "page-level alert" and "ticket-level alert" — but
# no alert rules were ever created. POST /v1/qurls returned 500 for over a
# week before any human noticed. See docs/slo.md for the full SLO definition.

variable "qurl_alerts_enabled" {
  description = "Create the Grafana alert rules and SNS contact point for qurl-api. Set to true only for prod cells."
  type        = bool
  default     = false
}

variable "qurl_alerts_paused" {
  description = "Ship Grafana alert rules paused so they soak for 24h before going live. Flip to false after the soak period to begin paging."
  type        = bool
  default     = true
}

variable "qurl_alerts_sns_topic_arn" {
  description = "ARN of the SNS topic that Grafana publishes alerts to. Reuses the monitoring module's existing aws_sns_topic.alerts so the new qurl-api alerts land in the same Slack/email channels as every other prod alert."
  type        = string
  default     = ""
}

variable "qurl_alerts_runbook_base_url" {
  description = "Base URL for the alert runbooks. Each rule's annotations.runbook_url is constructed by appending the runbook filename. Default points at the layervai/nhp main branch."
  type        = string
  default     = "https://github.com/layervai/nhp/blob/main/docs/runbooks"
}

variable "qurl_alerts_slo_target_percent" {
  description = "Availability SLO target as a percentage. Used in the burn-rate denominator. Must match the dashboard template variable's default at qurl-operations.json line 99 so panels and alerts stay in lockstep."
  type        = number
  default     = 99.99

  validation {
    condition     = var.qurl_alerts_slo_target_percent >= 90 && var.qurl_alerts_slo_target_percent <= 99.999
    error_message = "qurl_alerts_slo_target_percent must be between 90 and 99.999 (e.g., 99.99 for four nines). Values outside this range produce nonsensical burn-rate denominators and are almost certainly a typo."
  }
}

variable "qurl_alerts_loki_datasource_uid" {
  description = "UID of the Loki datasource in Grafana Cloud (find in Connections > Data sources). Used by the error-log spike rule."
  type        = string
  default     = "grafanacloud-logs"
}
