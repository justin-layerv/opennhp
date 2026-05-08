# Canary Deployment Module - Variables
# Step Functions-orchestrated canary deployment with ASG instance refresh checkpoints
# Instantiate once per deployable component (server, ac).

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

variable "component" {
  description = "Component this canary deployment targets (server, ac, or frps). Used in resource names, SSM paths, and alarm names."
  type        = string

  validation {
    # `frps` admitted alongside `server` and `ac` for the qurl-reverse-
    # tunnel-server canary path. frps has no NLB, so callers using
    # `component = \"frps\"` must also pass `disable_nlb_health_checks
    # = true` (a precondition below catches the half-mix).
    condition     = contains(["server", "ac", "frps"], var.component)
    error_message = "component must be 'server', 'ac', or 'frps'."
  }
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
  description = "NLB ARN suffix for CloudWatch alarm dimensions. Pass an empty string when `disable_nlb_health_checks = true` (frps path)."
  type        = string
  default     = ""
}

variable "target_group_arn_suffix" {
  description = "Target group ARN suffix for CloudWatch alarm dimensions. Pass an empty string when `disable_nlb_health_checks = true` (frps path)."
  type        = string
  default     = ""
}

# ==============================================================================
# NLB Health Checks (component-shape switch)
# ==============================================================================
# server and ac route through an NLB and emit
# `AWS/NetworkELB.HealthyHostCount` / `UnHealthyHostCount` against a target
# group. The canary state machine reads these metrics to decide whether
# to advance or rollback. qurl-reverse-tunnel-server has no NLB — Cloud Map A-record
# resolution drives routing — so the NLB-keyed alarms have no signal and
# would sit in INSUFFICIENT_DATA, never advancing the canary.
#
# `disable_nlb_health_checks = true` makes the module:
#   - Skip the two NLB-keyed alarms (canary_unhealthy, canary_low_healthy).
#   - Build the composite alarm rule from CPU only.
#   - Pass empty NLB_ARN_SUFFIX / TARGET_GROUP_ARN_SUFFIX env vars to the
#     orchestrator Lambda; canary_orchestrator.py treats empty values as
#     "skip NLB metric queries; advance on CPU + ASG-instance health
#     alone."
#
# Default false preserves the existing server/ac behavior unchanged.
variable "disable_nlb_health_checks" {
  description = <<-EOT
    Disable NLB-keyed health checks in the canary state machine. Default
    false preserves the existing server/ac behavior (which rely on NLB
    target-group health). Set true for components without an NLB
    (qurl-reverse-tunnel-server); the canary then advances on CPU + ASG-instance health.
  EOT
  type        = bool
  default     = false
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

variable "launch_template_arn" {
  description = "Launch template ARN for ec2:RunInstances permission (required for DesiredConfiguration in StartInstanceRefresh)"
  type        = string
}

variable "ebs_kms_key_arn" {
  description = "KMS key ARN for EBS encryption (required for ec2:RunInstances validation with encrypted volumes)"
  type        = string
  default     = null
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

variable "min_healthy_percentage" {
  description = <<-EOT
    Minimum percentage of healthy instances during a rolling instance refresh.
    Threaded into BOTH `StartInstanceRefresh.Preferences.MinHealthyPercentage`
    AND the canary's own health gate on the NLB-disabled (frps) path so the
    SFN-side replacement preference and the Lambda-side advance threshold
    can't drift silently. Default 90 matches the historical hardcoded
    constant.

    Small-fleet caveat: `ceil(asg_desired * percentage / 100)` rounds up,
    so for fleet sizes where the rounded count equals the fleet itself
    the gate effectively means "all instances healthy". At the default
    90% the rollover is at fleet size 11 — fleets ≤ 10 instances treat
    "90%" as "100%". The PR 4 target (6-instance frps fleet at 2/AZ × 3
    AZs) and the current 3-instance shape both fall inside that window.
    `handle_check_health` logs the resolved `min_healthy_count` on every
    poll so the operator can see the actual threshold in CloudWatch
    Logs without re-deriving it. Drop the percentage if "tolerates one
    unhealthy" matters before fleets grow past ~10.
  EOT
  type        = number
  default     = 90

  validation {
    condition     = var.min_healthy_percentage >= 50 && var.min_healthy_percentage <= 100 && floor(var.min_healthy_percentage) == var.min_healthy_percentage
    error_message = "min_healthy_percentage must be an integer between 50 and 100."
  }
}
