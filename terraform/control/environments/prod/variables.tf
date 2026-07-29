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

variable "provisioned_cells" {
  description = "Production cell catalog remains empty throughout sandbox proof."
  type = map(object({
    cell_id               = string
    status                = string
    endpoint_revision     = number
    nhp_host              = string
    nhp_port              = number
    server_public_key_b64 = string
    selection_weight      = string
    updated_at            = string
  }))
  default = {}

  validation {
    condition     = length(var.provisioned_cells) == 0
    error_message = "Production provisioned_cells must remain empty throughout sandbox proof."
  }
}

variable "provisioned_cell_catalog_materialization_enabled" {
  description = "Production catalog materialization remains disabled throughout sandbox proof."
  type        = bool
  default     = false

  validation {
    condition     = !var.provisioned_cell_catalog_materialization_enabled
    error_message = "Production provisioned-cell catalog materialization must remain disabled throughout sandbox proof."
  }
}

variable "authority_runtime_contract" {
  description = "Production Connector Authority runtime contract. It remains unconditionally null throughout sandbox measurement."
  type        = any
  default     = null

  validation {
    condition     = var.authority_runtime_contract == null
    error_message = "Production Authority runtime contract must remain null throughout sandbox measurement."
  }
}

variable "authority_runtime_contract_evidence_verified" {
  description = "Production evidence latch remains false throughout sandbox measurement."
  type        = bool
  default     = false

  validation {
    condition     = !var.authority_runtime_contract_evidence_verified
    error_message = "Production Authority evidence latch must remain false throughout sandbox measurement."
  }
}

variable "authority_runtime_functions_enabled" {
  description = "Production runtime-slice gate remains false throughout sandbox measurement."
  type        = bool
  default     = false

  validation {
    condition     = !var.authority_runtime_functions_enabled
    error_message = "Production Authority runtime functions must remain disabled throughout sandbox measurement."
  }
}

variable "hub_edge_enabled" {
  description = "Production Hub public edge gate remains false throughout sandbox measurement."
  type        = bool
  default     = false

  validation {
    condition     = !var.hub_edge_enabled
    error_message = "Production Hub public edge must remain dark throughout sandbox measurement."
  }
}

variable "hub_public_udp_ingress_cidrs" {
  description = "Production Hub source fence remains unset while the production Hub edge is dark."
  type        = list(string)
  default     = null

  validation {
    condition     = var.hub_public_udp_ingress_cidrs == null
    error_message = "Production Hub UDP ingress remains unset throughout sandbox measurement."
  }
}

variable "hub_worker_enabled" {
  description = "Production Hub Fargate worker gate remains false throughout sandbox measurement."
  type        = bool
  default     = false

  validation {
    condition     = !var.hub_worker_enabled
    error_message = "Production Hub Fargate worker must remain dark throughout sandbox measurement."
  }
}

variable "operator_alarm_topic_arns" {
  description = <<-EOT
    Production Authority alarm destination stays empty while the production
    runtime slice is validation-locked dark: with no functions there are no
    alarms to route, and the module's own precondition already rejects an
    enabled runtime with an empty destination list.

    Choosing the production destination is NHP #3280's decision, not this
    root's. That issue is reconciling six configured production email
    subscriptions that are absent from live AWS; adopting one of them here
    before it is confirmed would wire the Authority to a destination that
    silently delivers nothing.
  EOT
  type        = list(string)
  default     = []

  validation {
    condition     = length(var.operator_alarm_topic_arns) == 0
    error_message = "The production Authority alarm destination must remain unset until NHP #3280 confirms the production operator recipients and the production runtime slice opens."
  }
}

variable "tags" {
  type = map(string)
  default = {
    CostCenter   = "infrastructure"
    Organization = "LayerV"
    Owner        = "platform-team"
  }
}

variable "authority_proof_mutation_controls_enabled" {
  description = "Production attended-proof mutation control gate is permanently closed. This control mutates live authorization state and exists only for the sandbox two-cell UDP proof."
  type        = bool
  default     = false

  validation {
    condition     = !var.authority_proof_mutation_controls_enabled
    error_message = "Production Authority proof mutation controls must remain permanently disabled."
  }
}

variable "authority_proof_policy_consumers_staged" {
  description = "Production proof-policy consumer staging is permanently disabled."
  type        = bool
  default     = false

  validation {
    condition     = !var.authority_proof_policy_consumers_staged
    error_message = "Production Authority proof-policy consumer staging must remain permanently disabled."
  }
}

variable "authority_proof_mutation_owner_id" {
  description = "Production proof tenant must remain unset; the mutation control cannot exist in production."
  type        = string
  default     = null

  validation {
    condition     = var.authority_proof_mutation_owner_id == null
    error_message = "Production Authority proof mutation owner must remain null."
  }
}

variable "authority_proof_mutation_controller_role_arns" {
  description = "Production proof controller list must remain empty; the mutation control cannot exist in production."
  type        = list(string)
  default     = []

  validation {
    condition     = length(var.authority_proof_mutation_controller_role_arns) == 0
    error_message = "Production Authority proof mutation controllers must remain empty."
  }
}
