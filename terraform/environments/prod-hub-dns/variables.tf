variable "environment" {
  description = "Environment label for the standalone production Hub DNS root."
  type        = string
  default     = "prod-hub-dns"

  validation {
    condition     = var.environment == "prod-hub-dns"
    error_message = "The production Hub DNS root environment is fixed to prod-hub-dns."
  }
}

variable "aws_region" {
  description = "Region containing the production Hub NLB."
  type        = string
  default     = "us-east-2"

  validation {
    condition     = var.aws_region == "us-east-2"
    error_message = "The production Hub edge is fixed to us-east-2."
  }
}

variable "hub_dns_enabled" {
  description = "Create the explicit production Hub alias. Source-locked false until the Hub edge exists and is verified."
  type        = bool
  default     = false

  validation {
    condition     = !var.hub_dns_enabled
    error_message = "Production Hub DNS remains source-locked until the governed Hub edge rollout is complete."
  }
}

variable "hub_dns_name" {
  description = "Exact public A-alias record name for the production Connector Hub."
  type        = string
  default     = "hub.nhp.layerv.ai"

  validation {
    condition     = var.hub_dns_name == "hub.nhp.layerv.ai"
    error_message = "Production Hub DNS must publish exactly hub.nhp.layerv.ai."
  }
}

variable "hosted_zone_id" {
  description = "Management-account layerv.ai Route 53 zone ID."
  type        = string
  default     = "Z0748438C8EK6UAW94ST"

  validation {
    condition     = var.hosted_zone_id == "Z0748438C8EK6UAW94ST"
    error_message = "Production Hub DNS must use the reviewed layerv.ai hosted zone."
  }
}

variable "hub_nlb_name" {
  description = "Exact production Control Hub edge NLB name."
  type        = string
  default     = "layerv-nhp-prod-hub-edge"

  validation {
    condition     = var.hub_nlb_name == "layerv-nhp-prod-hub-edge"
    error_message = "Production Hub DNS must target the reviewed Hub edge NLB name."
  }
}

variable "management_route53_role_arn" {
  description = "Exact management-account role used for production Route 53 writes."
  type        = string
  default     = "arn:aws:iam::165115313779:role/nhp-ac-route53-access"

  validation {
    condition     = var.management_route53_role_arn == "arn:aws:iam::165115313779:role/nhp-ac-route53-access"
    error_message = "Production Hub DNS must use the reviewed management-account Route 53 role."
  }
}
