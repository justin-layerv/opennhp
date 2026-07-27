variable "target_security_group_id" {
  description = "SG id owned by another module; the rule below attaches to it"
  type        = string
  default     = null
}
