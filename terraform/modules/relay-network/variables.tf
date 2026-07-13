variable "environment" {
  description = "Deployment environment (sandbox or prod)."
  type        = string

  validation {
    condition     = contains(["sandbox", "prod"], var.environment)
    error_message = "environment must be sandbox or prod."
  }
}

variable "name_prefix" {
  description = "Environment resource-name prefix."
  type        = string
}

variable "vpc_cidr" {
  description = "Dedicated relay DMZ VPC CIDR. This boundary intentionally uses a /16 split into /24 subnets."
  type        = string

  validation {
    condition     = can(cidrnetmask(var.vpc_cidr)) && cidrnetmask(var.vpc_cidr) == "255.255.0.0"
    error_message = "vpc_cidr must be a valid IPv4 /16 CIDR."
  }
}

variable "main_vpc_id" {
  description = "Main NHP VPC ID peered with the relay DMZ."
  type        = string

  validation {
    condition     = can(regex("^vpc-[0-9a-f]+$", var.main_vpc_id))
    error_message = "main_vpc_id must be a VPC ID."
  }
}

variable "main_private_subnet_cidr_blocks" {
  description = "Exact main-VPC private subnet CIDRs reachable from relay subnets on UDP 62206."
  type        = list(string)

  validation {
    condition = (
      length(var.main_private_subnet_cidr_blocks) > 0 &&
      alltrue([for cidr in var.main_private_subnet_cidr_blocks : can(cidrhost(cidr, 0))])
    )
    error_message = "main_private_subnet_cidr_blocks must contain valid CIDRs."
  }

}

variable "main_private_route_table_ids" {
  description = "Main-VPC private route table IDs that receive exact routes back to relay subnets."
  type        = list(string)

  validation {
    condition = (
      length(var.main_private_route_table_ids) > 0 &&
      alltrue([for id in var.main_private_route_table_ids : can(regex("^rtb-[0-9a-f]+$", id))])
    )
    error_message = "main_private_route_table_ids must contain route table IDs."
  }
}

variable "relay_secret_arn" {
  description = "Root-owned relay identity secret allowed through the Secrets Manager endpoint."
  type        = string

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:.+$", var.relay_secret_arn))
    error_message = "relay_secret_arn must be a Secrets Manager ARN."
  }
}

variable "relay_repo_arn" {
  description = "Relay ECR repository ARN allowed through the ECR endpoints."
  type        = string

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:ecr:[a-z0-9-]+:[0-9]{12}:repository/.+$", var.relay_repo_arn))
    error_message = "relay_repo_arn must be an ECR repository ARN."
  }
}

variable "relay_image_tag_parameter_name" {
  description = "Stable relay image-tag Parameter Store path."
  type        = string

  validation {
    condition     = var.relay_image_tag_parameter_name == "/${var.environment}/nhp/relay/image-tag"
    error_message = "relay_image_tag_parameter_name must be /<environment>/nhp/relay/image-tag."
  }
}

variable "apply_role_ready_token" {
  description = "Opaque root token for the relay-DMZ apply-role IAM propagation wait. Only independent network DAG roots consume it so provider data remains plan-known."
  type        = string

  validation {
    condition     = trimspace(var.apply_role_ready_token) != ""
    error_message = "apply_role_ready_token must be non-empty."
  }
}

variable "tags" {
  description = "Base tags for all relay DMZ resources."
  type        = map(string)
  default     = {}
}
