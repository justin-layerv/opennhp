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

variable "asg_name" {
  description = "Auto Scaling Group name"
  type        = string
}

variable "server_stderr_log_group_name" {
  description = "CloudWatch log group that receives the nhp-server container's stdout/stderr via the docker awslogs driver. Metric filters on this group drive the ServerPanic and ServerStartupEvent alarms."
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
