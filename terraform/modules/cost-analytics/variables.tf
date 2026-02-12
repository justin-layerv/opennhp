# Cost Analytics Module Variables
#
# All resources run in the management account (us-east-1).
# The caller passes a single aws provider pointing to mgmt us-east-1.

variable "name_prefix" {
  description = "Resource naming prefix (e.g., layerv-nhp-mgmt)"
  type        = string
}

variable "grafana_cloud_aws_account_id" {
  description = "Grafana Cloud's AWS account ID for IAM trust policy"
  type        = string
}

variable "grafana_cloud_external_id" {
  description = "External ID for Grafana Cloud IAM assume role (optional)"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}
