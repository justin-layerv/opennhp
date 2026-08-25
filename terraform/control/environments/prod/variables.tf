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
  description = <<-EOT
    Exact reviewed production native-UDP cell catalog. Production runs a single
    cell, cell0, which must therefore take general placement — there is no
    second cell to fall back to, so `general_assignable` is true.

    Endpoint identity is pinned from live production readback, not derived by
    any Control caller:

      * nhp_host `cell0.nhp.layerv.ai` resolves today to the production server
        NLB.
      * nhp_port 443 is the post-#3649 public client edge. The production NLB
        does not reach that shape until the #3649 apply moves its UDP listener
        62206 -> 443, so this catalog must materialize AFTER that apply; a row
        advertising 443 against a 62206 listener places agents on a dead port.
      * server_public_key_b64 is the `publicKey` field of the
        `layerv-nhp-prod-server` secret — the SERVER-IDENTITY key that
        `module.compute.server_public_key_b64` exposes, not the shared AC
        registration key. Conflating the two silently fails every agent knock
        HMAC validation.

    endpoint_revision starts at 1: this is the first catalog row production has
    ever carried, created directly at the 443 edge. Sandbox sits at 2 because
    its row predated that move.

    updated_at is the deterministic row-mutation revision consumed by
    qurl-service's optimistic cell fence. Change it in the same review as every
    row mutation; never reuse a value across two different row contents.
  EOT
  type = map(object({
    cell_id               = string
    status                = string
    endpoint_revision     = number
    nhp_host              = string
    nhp_port              = number
    server_public_key_b64 = string
    selection_weight      = string
    updated_at            = string
    general_assignable    = optional(bool, true)
  }))
  default = {
    cell0 = {
      cell_id               = "cell0"
      status                = "active"
      endpoint_revision     = 1
      nhp_host              = "cell0.nhp.layerv.ai"
      nhp_port              = 443
      server_public_key_b64 = "e4cvt8Il90hResvhyawFqhgXqbi2Qddlqa3Iy0vPniU="
      selection_weight      = "1"
      updated_at            = "2026-08-06T00:00:00Z"
      general_assignable    = true
    }
  }

  validation {
    condition = jsonencode(var.provisioned_cells) == jsonencode({
      cell0 = {
        cell_id               = "cell0"
        status                = "active"
        endpoint_revision     = 1
        nhp_host              = "cell0.nhp.layerv.ai"
        nhp_port              = 443
        server_public_key_b64 = "e4cvt8Il90hResvhyawFqhgXqbi2Qddlqa3Iy0vPniU="
        selection_weight      = "1"
        updated_at            = "2026-08-06T00:00:00Z"
        general_assignable    = true
      }
    })
    error_message = "The production catalog must contain exactly active, generally-assignable cell0 with the reviewed producer values; update this validation in the same review as any attended lifecycle, endpoint, or assignability revision."
  }
}

variable "provisioned_cell_catalog_materialization_enabled" {
  description = "Production catalog materialization. Production ships a live catalog, so this stays true; removing a live catalog row is a drain/migrate procedure, not an input flip."
  type        = bool
  default     = true

  validation {
    condition     = var.provisioned_cell_catalog_materialization_enabled
    error_message = "The production provisioned-cell catalog must stay materialized; removing a live catalog row is a drain/migrate procedure, not an input flip."
  }
}

variable "authority_runtime_contract" {
  description = "Production Connector Authority runtime contract. Supplied by the reviewed production Control dispatch once the immutable authority image is published to the production ECR repository; it cannot be pinned here because the digest does not exist until that publication runs."
  type        = any
  default     = null
}

variable "authority_runtime_contract_evidence_verified" {
  description = "Production evidence latch. Supplied true by the reviewed production Control dispatch once the published image's provenance has been read back; defaults false so an unreviewed plan cannot assert it."
  type        = bool
  default     = false
}

variable "authority_runtime_functions_enabled" {
  description = "Production runtime-slice gate. Supplied true by the reviewed production Control dispatch after the foundation and image publication converge; defaults false so the foundation apply does not create functions against an unpublished digest."
  type        = bool
  default     = false
}

variable "hub_edge_enabled" {
  description = "Production Hub public edge gate. Supplied true by the reviewed production Control dispatch; defaults false so the foundation apply lands before any public listener exists."
  type        = bool
  default     = false
}

variable "hub_public_udp_ingress_cidrs" {
  description = <<-EOT
    Production Hub public UDP source policy.

    NHP is a network-hiding knock protocol built to sit on a public UDP port: it
    never answers an unauthenticated packet, authenticates a Noise handshake
    against a pinned server key, and enforces cookie-based return routability on
    the Hub LST path. Customer SDKs dial the Hub from arbitrary networks, so the
    production edge is open by the same reasoning as qurl-go ADR 0001.

    The module accepts exactly one broad value, the literal ["0.0.0.0/0"]. Every
    other broad CIDR still fails validation, so a fat-fingered supernet cannot
    slip in and opening an edge stays greppable.
  EOT
  type        = list(string)
  default     = ["0.0.0.0/0"]

  validation {
    condition     = length(var.hub_public_udp_ingress_cidrs) == 1 && var.hub_public_udp_ingress_cidrs[0] == "0.0.0.0/0"
    error_message = "Production Hub UDP ingress must remain exactly [\"0.0.0.0/0\"]; narrowing or widening it is a reviewed edge-policy change, not an input edit."
  }
}

variable "hub_worker_enabled" {
  description = "Production Hub Fargate worker gate (slice 5b). Supplied true by the reviewed production Control dispatch; requires hub_edge_enabled and a live authority runtime. Defaults false so the ordering stays explicit."
  type        = bool
  default     = false
}

variable "operator_alarm_topic_arns" {
  description = <<-EOT
    Operator destination for every production Connector Authority alarm.

    This is the standard production operator notification path, not a new topic:
    layerv-nhp-prod-cell0-alerts is created by terraform/modules/monitoring and
    carries CONFIRMED subscriptions today — one email subscription and one AWS
    Chatbot HTTPS subscription, both holding real subscription ARNs rather than
    PendingConfirmation (readback 2026-08-06). The Control root deliberately
    reuses it rather than declaring its own, because an isolated Control topic
    would start life silently unsubscribed.

    That confirmed-subscriber readback is what this variable needed from NHP
    #3280. #3280 is reconciling six *configured* production email subscriptions
    that are absent from live AWS; it stays open on its own merits, but it no
    longer gates this destination, because the destination's delivery path is
    directly proven rather than inferred from configuration.

    The cell0 name is historical (the monitoring module keys its topic on a
    cell). The topic is account-wide in practice and the Authority is a
    Control-scope, cell-independent service; renaming it is a monitoring-module
    change, not a prerequisite for routing these alarms.
  EOT
  type        = list(string)
  default     = ["arn:aws:sns:us-east-2:235500187906:layerv-nhp-prod-cell0-alerts"]

  validation {
    condition = (
      length(var.operator_alarm_topic_arns) == 1 &&
      var.operator_alarm_topic_arns[0] == "arn:aws:sns:us-east-2:235500187906:layerv-nhp-prod-cell0-alerts"
    )
    error_message = "The production Authority alarm destination must remain the reviewed operator topic; change it only alongside proof that the new destination has a confirmed subscriber."
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

variable "authority_proof_policy_selected_color" {
  description = "Production proof-policy selector is permanently disabled."
  type        = string
  default     = null

  validation {
    condition     = var.authority_proof_policy_selected_color == null
    error_message = "Production Authority proof-policy selector must remain null."
  }
}

variable "authority_proof_policy_prepared_color" {
  description = "Production proof-policy preparation is permanently disabled."
  type        = string
  default     = null

  validation {
    condition     = var.authority_proof_policy_prepared_color == null
    error_message = "Production Authority proof-policy prepared color must remain null."
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

variable "authority_selector_ssm_pointer_enabled" {
  description = "Read the Authority blue/green switch pointer from SSM instead of the committed contract. Staged after the pointer parameter exists; requires the alias hold."
  type        = bool
  default     = false
}

variable "authority_blue_green_alias_hold_enabled" {
  type        = bool
  default     = false
  description = "Blue/green alias semantics for the Authority runtime: the selected colour holds its live version and only standby advances. Dark by default."

  validation {
    condition     = var.authority_blue_green_alias_hold_enabled == false
    error_message = "authority_blue_green_alias_hold_enabled is sandbox-only while the Authority blue/green cutover is unproven."
  }
}

variable "authority_tenant_pinning_enabled" {
  type        = bool
  default     = true
  description = "Durable tenant home-cell pinning on IssueAssignment. Committed true as the day-0 production value: every tenant's home cell is recorded from its first assignment, so no later migration exists when a second cell becomes assignable. Inert until the runtime gates deploy functions."
}
