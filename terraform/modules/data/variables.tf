variable "environment" {
  description = "Environment name"
  type        = string
}

variable "multi_tenant" {
  description = "Enable multi-tenant mode with etcd"
  type        = bool
}

variable "deploy_etcd" {
  description = "Deploy etcd infrastructure. Set to false for cloud deployments using DynamoDB backend."
  type        = bool
  default     = null # Defaults to multi_tenant when null
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs"
  type        = list(string)
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
}

variable "name_prefix" {
  description = "Name prefix for resources"
  type        = string
}

variable "tags" {
  description = "Tags for resources"
  type        = map(string)
  default     = {}
}

variable "efs_kms_key_arn" {
  description = "KMS key ARN for EFS encryption"
  type        = string
  default     = null
}

variable "secrets_kms_key_arn" {
  description = "KMS key ARN for Secrets Manager encryption"
  type        = string
  default     = null
}

variable "logs_kms_key_arn" {
  description = "KMS key ARN for CloudWatch Logs encryption"
  type        = string
  default     = null
}

variable "terraform_state_bucket" {
  description = "S3 bucket for Terraform state (used for Lambda layer storage)"
  type        = string
  default     = null
}

variable "lambda_layer_bucket" {
  description = "S3 bucket containing Lambda layer artifacts (cryptography layer)"
  type        = string
  default     = null
}
