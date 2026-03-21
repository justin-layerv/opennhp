variable "name_prefix" {
  description = "Resource naming prefix (e.g., layerv-nhp-sandbox)"
  type        = string
}

variable "environment" {
  description = "Deployment environment (e.g., sandbox, prod)"
  type        = string
  default     = "sandbox"
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
