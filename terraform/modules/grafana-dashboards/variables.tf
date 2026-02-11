# Grafana Dashboards Module Variables
#
# NOTE: This module expects a grafana provider to be passed from the caller.
# The provider configuration (url, auth) should be defined in the root module.

variable "grafana_url" {
  description = "Grafana Cloud URL (for generating dashboard URLs in outputs)"
  type        = string
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

variable "loki_datasource_uid" {
  description = "UID of the Loki datasource in Grafana Cloud"
  type        = string
  default     = "grafanacloud-logs"
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
  default     = ""
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

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}
