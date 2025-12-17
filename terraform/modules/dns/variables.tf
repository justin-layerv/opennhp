variable "environment" {
  description = "Environment name"
  type        = string
}

variable "domain_name" {
  description = "Domain name for NHP server"
  type        = string
}

variable "hosted_zone_name" {
  description = "Route 53 hosted zone name (optional)"
  type        = string
  default     = null
}

variable "nlb_dns_name" {
  description = "NLB DNS name"
  type        = string
}

variable "nlb_zone_id" {
  description = "NLB zone ID"
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
