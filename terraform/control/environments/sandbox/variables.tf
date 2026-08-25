variable "environment" {
  type    = string
  default = "sandbox"

  validation {
    condition     = var.environment == "sandbox"
    error_message = "This root is permanently bound to sandbox."
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-2"

  validation {
    condition     = var.aws_region == "us-east-2"
    error_message = "The sandbox Connector Authority home region is us-east-2."
  }
}

variable "aws_account_id" {
  type    = string
  default = "767397897469"

  validation {
    condition     = var.aws_account_id == "767397897469"
    error_message = "This root is permanently bound to the sandbox AWS account."
  }
}

variable "vpc_cidr" {
  type    = string
  default = "10.102.0.0/16"

  validation {
    condition     = var.vpc_cidr == "10.102.0.0/16"
    error_message = "The reviewed sandbox Control VPC CIDR is 10.102.0.0/16; change it only with a live overlap audit."
  }
}

variable "otp_email_from" {
  type    = string
  default = "noreply@notify.layerv.xyz"
}

variable "ses_configuration_set_name" {
  type    = string
  default = "layerv-nhp-sandbox-agent-otp"
}

variable "provisioned_cells" {
  description = "Exact reviewed sandbox native-UDP cell catalog. cell0 and cell1 are both assignable. cell1 was briefly drained because it advertised itself as assignable while its NHP servers had native registration and qURL v2 admission compiled out, so any agent the Authority placed there failed enrollment with errCode 52107. Both are now wired in terraform/environments/sandbox-cell1/main.tf, so cell1 is assignable AND capable; check_active_cell_capability.py fails the build if that ever stops being true. Endpoint identities are pinned from live cell producer output/readback; no Control caller derives them. updated_at is the deterministic catalog mutation revision and must change in the same review as every row mutation."
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
      endpoint_revision     = 2
      nhp_host              = "cell0.nhp.layerv.xyz"
      nhp_port              = 443
      server_public_key_b64 = "9dVku2oF589tWz9/Hn01STtstgkum4MM4kgKEp7lCw8="
      selection_weight      = "1"
      updated_at            = "2026-08-01T18:00:00Z"
      general_assignable    = true
    }
    cell1 = {
      cell_id               = "cell1"
      status                = "active"
      endpoint_revision     = 2
      nhp_host              = "cell1.nhp.layerv.xyz"
      nhp_port              = 443
      server_public_key_b64 = "Sb4lH7rfkKTagGvpKeBx/ArYual9fM4EQCQkiqxGNBs="
      selection_weight      = "1"
      updated_at            = "2026-08-01T18:00:00Z"
      general_assignable    = false
    }
  }

  validation {
    condition = jsonencode(var.provisioned_cells) == jsonencode({
      cell0 = {
        cell_id               = "cell0"
        status                = "active"
        endpoint_revision     = 2
        nhp_host              = "cell0.nhp.layerv.xyz"
        nhp_port              = 443
        server_public_key_b64 = "9dVku2oF589tWz9/Hn01STtstgkum4MM4kgKEp7lCw8="
        selection_weight      = "1"
        updated_at            = "2026-08-01T18:00:00Z"
        general_assignable    = true
      }
      cell1 = {
        cell_id               = "cell1"
        status                = "active"
        endpoint_revision     = 2
        nhp_host              = "cell1.nhp.layerv.xyz"
        nhp_port              = 443
        server_public_key_b64 = "Sb4lH7rfkKTagGvpKeBx/ArYual9fM4EQCQkiqxGNBs="
        selection_weight      = "1"
        updated_at            = "2026-08-01T18:00:00Z"
        general_assignable    = false
      }
    })
    error_message = "The sandbox catalog must contain exactly active cell0 and active cell1 with the reviewed producer values; cell1 is non-assignable (general_assignable=false) while staying active; update this validation in the same review as any attended lifecycle, endpoint, or assignability revision."
  }
}

variable "provisioned_cell_catalog_materialization_enabled" {
  description = "Restored sandbox catalog materialization. The Authority-first holdback is complete, so Terraform owns and publishes the reviewed cell0/cell1 rows. Kept as a validated variable rather than a literal so the module gate stays a single reviewed input; a tfvars or -var override cannot turn materialization back off, because unmaterializing a live row is a drain/migrate procedure, not an input flip."
  type        = bool
  default     = true

  validation {
    condition     = var.provisioned_cell_catalog_materialization_enabled
    error_message = "The sandbox provisioned-cell catalog must stay materialized; removing a live catalog row is a drain/migrate procedure, not an input flip."
  }
}

variable "authority_runtime_contract" {
  description = "Nullable closed Connector Authority runtime contract. The permanent workflow supplies the only supported non-null value through its exact-main byte-verifying generator."
  type        = any
  default     = null
}

variable "authority_runtime_contract_evidence_verified" {
  description = "Internal exact-main generator latch. The generated ephemeral tfvars file sets this with the complete verified sandbox contract; committed inputs must leave it false."
  type        = bool
  default     = false
}

variable "authority_runtime_functions_enabled" {
  description = "Second, independent runtime-slice gate. Committed inputs leave it false so contract binding (Step 3) stays a foundation_contract-only transition; the Step-4 runtime apply supplies it true (via -var or the generated tfvars) on top of a bound contract. See the module variable of the same name."
  type        = bool
  default     = false
}

variable "hub_edge_enabled" {
  description = "Dark-first Step-5 gate for the Connector Hub public UDP edge (the three public edge subnets, the internet gateway and public route table + 0.0.0.0/0 route, and the public UDP-443 Hub NLB, listener, and target group). Committed inputs leave it false; the Step-5 edge apply supplies it true (via -var or the generated tfvars). See the module variable of the same name."
  type        = bool
  default     = false
}

variable "hub_public_udp_ingress_cidrs" {
  description = <<-EOT
    Sources admitted by the sandbox Hub public UDP-443 NLB. Sandbox is open to
    developers inside and outside the company (qurl-go ADR 0001), so this is the
    open-edge value. The pin below is kept, not removed: it now guards the open
    value, so drifting to some other list still fails the plan and any future
    change to sandbox access remains a reviewed, deliberate edit here.
  EOT
  type        = list(string)
  default     = ["0.0.0.0/0"]

  validation {
    condition     = length(var.hub_public_udp_ingress_cidrs) == 1 && var.hub_public_udp_ingress_cidrs[0] == "0.0.0.0/0"
    error_message = "Sandbox Hub UDP ingress is open by decision (qurl-go ADR 0001) and must remain exactly [\"0.0.0.0/0\"]; changing sandbox access requires superseding that ADR."
  }
}

variable "hub_worker_enabled" {
  description = "Dark-first Step-5 gate for the Connector Hub Fargate worker (slice 5b): the ECS cluster/service/task-definition, the Hub key-material secret + keygen, the worker security group, and the ECR/S3 image-pull endpoints; it also opens the Lambda interface endpoint to the worker's task role. Requires hub_edge_enabled and a live authority runtime. Committed inputs leave it false; the Step-5 worker apply supplies it true (via -var or the generated tfvars). See the module variable of the same name."
  type        = bool
  default     = false
}

variable "operator_alarm_topic_arns" {
  description = <<-EOT
    Operator destination for every Connector Authority alarm (NHP #3455).

    This is the standard sandbox operator notification path, not a new topic:
    layerv-nhp-sandbox-cell0-alerts is created by terraform/modules/monitoring
    and is the only sandbox SNS topic that carries a CONFIRMED subscription
    today (an AWS Chatbot HTTPS subscription; it has no email subscribers). The
    Control root deliberately reuses it rather than declaring its own, because
    an isolated Control topic would start life silently unsubscribed — the exact
    condition NHP #3280 is reconciling in production.

    The cell0 name is historical (the monitoring module keys its topic on a
    cell). The topic is account-wide in practice and the Authority is a
    Control-scope, cell-independent service; renaming it is a monitoring-module
    change, not a prerequisite for routing these alarms.
  EOT
  type        = list(string)
  default     = ["arn:aws:sns:us-east-2:767397897469:layerv-nhp-sandbox-cell0-alerts"]

  validation {
    condition = (
      length(var.operator_alarm_topic_arns) == 1 &&
      var.operator_alarm_topic_arns[0] == "arn:aws:sns:us-east-2:767397897469:layerv-nhp-sandbox-cell0-alerts"
    )
    error_message = "The sandbox Authority alarm destination must remain the reviewed operator topic; change it only alongside proof that the new destination has a confirmed subscriber."
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
  description = "Attended-proof Authority mutation control gate. It stays false until the qurl-service MutateProofAgent operation and its qurl-conformance constant ship and are bound by a reviewed contract."
  type        = bool
  default     = false
}

variable "authority_proof_policy_consumers_staged" {
  description = "Stages proof-aware IA/RA/ICR versions and read-only policy without moving either live alias. Requires the mutation control."
  type        = bool
  default     = false
}

variable "authority_proof_policy_selected_color" {
  description = "Selected sandbox IA/RA/ICR + ca-pm proof color during the retained equal-pool rollout window."
  type        = string
  default     = null
}

variable "authority_proof_policy_prepared_color" {
  description = "Inactive sandbox IA/RA/ICR proof color prepared by a separate saved-plan apply."
  type        = string
  default     = null
}

variable "authority_proof_mutation_owner_id" {
  description = "Dedicated sandbox proof tenant that owns every uniquely tagged ephemeral proof agent. Null until the mutation control is enabled."
  type        = string
  default     = null
}

variable "authority_proof_mutation_controller_role_arns" {
  description = "Attended proof controller role ARNs permitted to invoke the mutation control alias. Empty until the mutation control is enabled."
  type        = list(string)
  default     = []
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
}

variable "authority_tenant_pinning_enabled" {
  type        = bool
  default     = true
  description = "Durable tenant home-cell pinning on IssueAssignment. Committed true is the reviewed sandbox activation (qurl-service tenancy-pinning B6, deferred step 3): the merge activates it on the next control deploy."
}
