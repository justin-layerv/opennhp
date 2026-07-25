variable "environment" {
  type    = string
  default = "prod"

  validation {
    condition     = var.environment == "prod"
    error_message = "This root is permanently bound to prod."
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-2"

  validation {
    condition     = var.aws_region == "us-east-2"
    error_message = "The production Connector Authority home region is us-east-2."
  }
}

variable "aws_account_id" {
  type    = string
  default = "235500187906"

  validation {
    condition     = var.aws_account_id == "235500187906"
    error_message = "This root is permanently bound to the production AWS account."
  }
}

variable "vpc_cidr" {
  type    = string
  default = "10.202.0.0/16"

  validation {
    condition     = var.vpc_cidr == "10.202.0.0/16"
    error_message = "The reviewed production Control VPC CIDR is 10.202.0.0/16; change it only with a live overlap audit."
  }
}

variable "otp_email_from" {
  type    = string
  default = "noreply@notify.layerv.ai"
}

variable "ses_configuration_set_name" {
  type    = string
  default = "layerv-nhp-prod-agent-otp"
}

variable "authority_runtime_contract" {
  description = "Production Connector Authority runtime contract. It remains unconditionally null throughout sandbox measurement."
  type        = any
  default     = null

  validation {
    condition     = var.authority_runtime_contract == null
    error_message = "Production Authority runtime contract must remain null throughout sandbox measurement."
  }
}

variable "authority_runtime_contract_evidence_verified" {
  description = "Production evidence latch remains false throughout sandbox measurement."
  type        = bool
  default     = false

  validation {
    condition     = !var.authority_runtime_contract_evidence_verified
    error_message = "Production Authority evidence latch must remain false throughout sandbox measurement."
  }
}

variable "authority_runtime_functions_enabled" {
  description = "Production runtime-slice gate remains false throughout sandbox measurement."
  type        = bool
  default     = false

  validation {
    condition     = !var.authority_runtime_functions_enabled
    error_message = "Production Authority runtime functions must remain disabled throughout sandbox measurement."
  }
}

variable "hub_edge_enabled" {
  description = "Production Hub public edge gate remains false throughout sandbox measurement."
  type        = bool
  default     = false

  validation {
    condition     = !var.hub_edge_enabled
    error_message = "Production Hub public edge must remain dark throughout sandbox measurement."
  }
}

variable "hub_worker_enabled" {
  description = "Production Hub Fargate worker gate remains false throughout sandbox measurement."
  type        = bool
  default     = false

  validation {
    condition     = !var.hub_worker_enabled
    error_message = "Production Hub Fargate worker must remain dark throughout sandbox measurement."
  }
}

variable "tags" {
  type = map(string)
  default = {
    CostCenter   = "infrastructure"
    Organization = "LayerV"
    Owner        = "platform-team"
  }
}
