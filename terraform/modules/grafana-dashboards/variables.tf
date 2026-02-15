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
