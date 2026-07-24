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
  description = "Nullable closed Connector Authority runtime contract. This schema-only precursor intentionally rejects every non-null root value; production must remain null until its independent repository, publication, and measurement evidence are reviewed."
  type        = any
  default     = null
}

variable "tags" {
  type = map(string)
  default = {
    CostCenter   = "infrastructure"
    Organization = "LayerV"
    Owner        = "platform-team"
  }
}
