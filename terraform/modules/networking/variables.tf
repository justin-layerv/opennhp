variable "environment" {
  description = "Environment name"
  type        = string
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

variable "allow_private_ingress_443" {
  description = "Allow port 443 from internet on private subnets (for NHP-protected resources behind NLB)"
  type        = bool
  default     = false
}

variable "logs_kms_key_arn" {
  description = "KMS key ARN for encrypting CloudWatch log groups (VPC flow logs)"
  type        = string
  default     = null
}

variable "deploy_vpc_endpoints" {
  description = "Deploy additional VPC endpoints for QURL service AWS dependencies (DynamoDB gateway, SQS interface). Reduces NAT gateway costs and improves security by keeping AWS traffic within VPC."
  type        = bool
  default     = false
}
