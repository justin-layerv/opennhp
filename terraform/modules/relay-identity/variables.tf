variable "environment" {
  description = "Deployment environment (nhp convention: sandbox or prod)."
  type        = string

  # Keep this module boundary even though environment wrappers validate the
  # same values. Direct module callers must retain the same fail-closed shape;
  # the Lambda repeats it at runtime for untrusted invocation payloads.
  validation {
    condition     = contains(["sandbox", "prod"], var.environment)
    error_message = "environment must be sandbox or prod."
  }
}

variable "name_prefix" {
  description = "Stable resource prefix. The existing relay secret is named <name_prefix>-relay."
  type        = string
}

variable "secrets_kms_key_arn" {
  description = "Optional CMK used by the relay identity secret."
  type        = string
  default     = null
}

variable "iam_propagation_duration" {
  description = "Duration to wait for the relay identity Lambda role and policies to propagate before function creation or invocation."
  type        = string
  default     = "60s"
}

variable "tags" {
  description = "Base tags applied to relay identity resources."
  type        = map(string)
  default     = {}
}
