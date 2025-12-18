# Variables for production environment
# Values are set in terraform.tfvars

# SAFEGUARD: Requires explicit confirmation to deploy to production
variable "confirm_prod_deployment" {
  description = "Must be set to 'yes-deploy-to-production' to apply changes"
  type        = string
  default     = ""

  validation {
    condition     = var.confirm_prod_deployment == "yes-deploy-to-production"
    error_message = "PRODUCTION DEPLOYMENT BLOCKED: Set confirm_prod_deployment=\"yes-deploy-to-production\" to proceed."
  }
}

variable "environment" {
  type = string
}

variable "aws_region" {
  type = string
}

variable "aws_account_id" {
  type = string
}

variable "domain_name" {
  type = string
}

variable "hosted_zone" {
  type    = string
  default = null
}

variable "multi_tenant" {
  type = bool
}

variable "min_capacity" {
  type = number
}

variable "max_capacity" {
  type = number
}

variable "vpc_cidr" {
  type = string
}

variable "tags" {
  type = map(string)
}

variable "is_primary_account" {
  type    = bool
  default = true
}

variable "primary_account_id" {
  type    = string
  default = ""
}

variable "github_org" {
  type    = string
  default = "layervai"
}

variable "github_repo" {
  type    = string
  default = "nhp"
}

variable "deploy_ac" {
  type    = bool
  default = true
}

variable "acme_email" {
  type    = string
  default = ""
}

variable "terraform_state_bucket" {
  type    = string
  default = ""
}

variable "terraform_lock_table" {
  type    = string
  default = "terraform-state-lock"
}
