variable "target_security_group_id" {
  description = "SG id owned by another module; rules below attach to it"
  type        = string
  default     = null
}
