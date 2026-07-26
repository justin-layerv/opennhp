# Inputs for the sandbox Hub-DNS root. Every value has a default equal to the
# live sandbox identity; terraform.tfvars pins them explicitly so the record's
# identity is legible in one place.

variable "environment" {
  description = "Environment label (drives default_tags Environment)."
  type        = string
  default     = "sandbox-hub-dns"
}

variable "aws_region" {
  description = "AWS region for the provider and the Hub NLB lookup."
  type        = string
  default     = "us-east-2"
}

variable "hub_dns_name" {
  description = "Public A-alias record name for the Connector Hub UDP edge."
  type        = string
  default     = "hub.nhp.layerv.xyz"
}

variable "hosted_zone_id" {
  description = "Route 53 hosted zone ID for layerv.xyz (same account)."
  type        = string
  default     = "Z10394893FM38A1RXLL32"
}

variable "hub_nlb_name" {
  description = "Name of the Connector Hub public UDP NLB to alias (discovered by data source)."
  type        = string
  default     = "layerv-nhp-sandbox-hub-edge"

  validation {
    condition     = var.hub_nlb_name == "layerv-nhp-sandbox-hub-edge"
    error_message = "Sandbox proof DNS must target exactly the source-fenced Hub NLB."
  }
}

variable "cell0_dns_name" {
  description = "Public A-alias record name for the cell0 NHP-server UDP edge."
  type        = string
  default     = "cell0.nhp.layerv.xyz"
}

variable "cell0_nlb_name" {
  description = "Name of the cell0 public UDP:62206 server NLB to alias (discovered by data source)."
  type        = string
  default     = "layerv-nhp-sandbox-edge"

  validation {
    condition     = var.cell0_nlb_name == "layerv-nhp-sandbox-edge"
    error_message = "Sandbox proof DNS must target exactly the source-fenced cell0 NLB."
  }
}

variable "tags" {
  description = "Additional resource tags."
  type        = map(string)
  default     = {}
}
