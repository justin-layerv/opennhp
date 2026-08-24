# DynamoDB Module Variables

variable "environment" {
  description = "Environment name (sandbox, prod)"
  type        = string
}

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "cell_id" {
  description = "Cell identifier for multi-cell deployments (e.g., cell0, cell1)"
  type        = string
  default     = "cell0"
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

variable "kms_key_arn" {
  description = "KMS key ARN for DynamoDB encryption. If null, AWS managed key is used."
  type        = string
  default     = null
}

variable "enable_matched_cohort_canary" {
  description = "Create the isolated candidate AC-assignment authority used by the production matched-cohort canary."
  type        = bool
  default     = false
}

variable "enable_native_session_operations" {
  description = "Enable the sandbox-only durable native-session operation IAM fences."
  type        = bool
  default     = false

  validation {
    condition     = !var.enable_native_session_operations || var.environment == "sandbox"
    error_message = "enable_native_session_operations is restricted to sandbox."
  }
}

variable "native_session_operations_use_local_agent_keys" {
  description = "Grant native-operation ConditionCheckItem on this module's qurl-agent-keys table. False when the runtime uses the external Control identity table."
  type        = bool
  default     = false

  validation {
    condition     = !var.native_session_operations_use_local_agent_keys || (var.enable_native_session_operations && var.deploy_qurl_tables)
    error_message = "Local native-operation agent-key authority requires the native operation protocol and local qurl tables."
  }
}

# ==================== QURL Service Tables ====================

variable "deploy_qurl_tables" {
  description = "Whether to create QURL service DynamoDB tables"
  type        = bool
  default     = false
}

variable "alarm_sns_topic_arn" {
  description = "SNS topic ARN for DDB throttle alarms (see `alarms.tf`). Pass the shared monitoring topic so the alarms route to the same Chatbot subscription as the other infra-level alerts. `null` (default) disables alarm creation entirely — keeps test fixtures + isolated-module deploys plan-clean. Matches the `default = null` convention used by other optional module inputs in this repo (e.g. `bootstrap_alb_elb_5xx_threshold_per_minute`)."
  type        = string
  default     = null
}

variable "enable_sns_alerts" {
  description = "Static boolean: set true when this module's SNS-routed DynamoDB throttle alarms should be created and alarm_sns_topic_arn is wired. DynamoDB throttle alarm counts gate on this value to avoid count-depends-on-computed."
  type        = bool
  default     = false
}
