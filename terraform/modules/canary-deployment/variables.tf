# Canary Deployment Module - Variables
# Step Functions-orchestrated canary deployment with ASG instance refresh checkpoints

# ==============================================================================
# Required Variables
# ==============================================================================

variable "environment" {
  description = "Deployment environment (sandbox, prod)"
  type        = string
}

variable "name_prefix" {
  description = "Prefix for resource names (e.g., nhp-prod)"
  type        = string
}

variable "cell_id" {
  description = "Cell identifier for multi-cell deployments"
  type        = string
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "asg_name" {
  description = "Auto Scaling Group name to perform canary deployments on"
  type        = string
}

variable "asg_arn" {
  description = "Auto Scaling Group ARN for IAM permissions"
  type        = string
}

variable "nlb_arn_suffix" {
  description = "NLB ARN suffix for CloudWatch alarm dimensions"
  type        = string
}

variable "target_group_arn_suffix" {
  description = "Target group ARN suffix for CloudWatch alarm dimensions"
  type        = string
}

variable "alerts_sns_topic_arn" {
  description = "SNS topic ARN for deployment notifications and alarm actions"
  type        = string
}

variable "logs_kms_key_arn" {
  description = "KMS key ARN for encrypting CloudWatch Logs"
  type        = string
}

variable "ssm_image_tag_parameter" {
  description = "SSM parameter name for the deployed image tag"
  type        = string
}

# ==============================================================================
# Canary Configuration
# ==============================================================================

variable "checkpoint_percentages" {
  description = "Instance refresh checkpoint percentages for canary stages. Each checkpoint pauses the refresh for health validation."
  type        = list(number)
  default     = [20, 50, 100]

  validation {
    condition     = length(var.checkpoint_percentages) > 0 && var.checkpoint_percentages[length(var.checkpoint_percentages) - 1] == 100
    error_message = "checkpoint_percentages must be non-empty and end with 100."
  }
}

variable "checkpoint_delay_seconds" {
  description = "Seconds to observe at each canary checkpoint before auto-resuming the instance refresh."
  type        = number
  default     = 300

  validation {
    condition     = var.checkpoint_delay_seconds >= 60 && var.checkpoint_delay_seconds <= 3600
    error_message = "checkpoint_delay_seconds must be between 60 and 3600."
  }
}

variable "instance_warmup_seconds" {
  description = "Instance warmup time in seconds. New instances are not counted toward health until this elapses."
  type        = number
  default     = 180

  validation {
    condition     = var.instance_warmup_seconds >= 60 && var.instance_warmup_seconds <= 600
    error_message = "instance_warmup_seconds must be between 60 and 600."
  }
}

variable "max_cpu_percent" {
  description = "Maximum average CPU utilization percentage before triggering rollback."
  type        = number
  default     = 90

  validation {
    condition     = var.max_cpu_percent >= 50 && var.max_cpu_percent <= 100
    error_message = "max_cpu_percent must be between 50 and 100."
  }
}
