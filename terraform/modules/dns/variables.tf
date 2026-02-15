# DNS Module Variables

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "domain_name" {
  description = "Domain name for NHP server"
  type        = string
}

variable "hosted_zone_name" {
  description = "Route 53 hosted zone name (optional, used for zone lookup)"
  type        = string
  default     = null
}

variable "hosted_zone_id" {
  description = "Route 53 hosted zone ID (optional, bypasses zone lookup for cross-account zones)"
  type        = string
  default     = null
}

variable "nlb_dns_name" {
  description = "NLB DNS name for UDP traffic"
  type        = string
}

variable "nlb_zone_id" {
  description = "NLB zone ID"
  type        = string
}

variable "alb_dns_name" {
  description = "ALB DNS name for HTTPS traffic (optional)"
  type        = string
  default     = null
}

variable "alb_zone_id" {
  description = "ALB zone ID (optional)"
  type        = string
  default     = null
}

variable "create_wildcard" {
  description = "Create wildcard DNS record"
  type        = bool
  default     = false
}

variable "skip_main_record" {
  description = "Skip creating the main A record (use when AC module manages the domain)"
  type        = bool
  default     = false
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
