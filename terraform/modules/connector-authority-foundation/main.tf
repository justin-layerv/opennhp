data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  name_prefix                           = "layerv-nhp-${var.environment}-control"
  control_table_prefix                  = local.name_prefix
  is_prod                               = var.environment == "prod"
  availability_zones                    = slice(data.aws_availability_zones.available.names, 0, 3)
  otp_sender_domain                     = lower(try(split("@", var.otp_email_from)[1], ""))
  authority_ecr_repository_name         = "layerv/qurl-connector-authority"
  authority_image_digest_parameter_name = "/${var.environment}/nhp/control/connector-authority/image-digest"
  hub_ecr_repository_name               = "layerv/nhp-hub"
  hub_image_digest_parameter_name       = "/${var.environment}/nhp/control/hub/image-digest"
  authority_active_color_parameter_name = "/${var.environment}/nhp/control/authority/active-color"
  hub_public_key_parameter_name         = "/${var.environment}/nhp/control/hub/identity/public-key"

  common_tags = merge(var.tags, {
    Application = "nhp"
    Component   = "connector-authority"
    Environment = var.environment
    ManagedBy   = "terraform"
    Repository  = "layervai/nhp"
    Scope       = "control"
  })
}

resource "terraform_data" "foundation_contract" {
  input = merge(
    {
      account_id           = data.aws_caller_identity.current.account_id
      control_table_prefix = local.control_table_prefix
      region               = data.aws_region.current.region
    },
    jsondecode(
      local.authority_runtime_contract_enabled
      ? jsonencode({
        authority_image_uri = local.authority_runtime_image_uri
        # The contract is recorded with the EFFECTIVE selector (the live SSM
        # pointer once the pointer gate is on) so a pointer move presents as
        # this resource's reviewed before/after -- the same flip shape the
        # plan checker already validates -- rather than as an invisible
        # data-source read. With the gate off this merge is the identity.
        authority_runtime_contract = merge(
          var.authority_runtime_contract,
          { selected_authority_color = local.authority_runtime_effective_selected_color },
        )
      })
      : "{}"
    ),
    var.authority_proof_policy_consumers_staged ? {
      authority_proof_policy_consumers_staged = true
    } : {},
    local.authority_proof_policy_rollout_active ? {
      authority_proof_policy_selected_color = var.authority_proof_policy_selected_color
      authority_proof_policy_prepared_color = var.authority_proof_policy_prepared_color
    } : {},
  )

  lifecycle {
    precondition {
      condition     = data.aws_caller_identity.current.account_id == var.aws_account_id
      error_message = "Connector Authority foundation is targeting the wrong AWS account."
    }

    precondition {
      condition = (
        !var.authority_selector_ssm_pointer_enabled ||
        (var.authority_blue_green_alias_hold_enabled && local.authority_runtime_functions_deploy)
      )
      error_message = "The SSM selector pointer requires the blue/green alias hold and a deployed Authority runtime."
    }

    precondition {
      # A corrupted pointer value (anything but the two closed colours) must
      # fail the plan, not render a nonsense colour into alias targets, PC
      # qualifiers, and the Hub environment.
      condition = (
        !local.authority_runtime_contract_enabled ||
        contains(["blue", "green"], local.authority_runtime_effective_selected_color)
      )
      error_message = "The effective Authority selector (SSM pointer included) must be exactly blue or green."
    }

    precondition {
      condition     = local.control_table_prefix == "layerv-nhp-${var.environment}-control"
      error_message = "The global control namespace must be exactly layerv-nhp-<env>-control."
    }

    precondition {
      # Redundant with today's constructed prefix by design: keep this guard at
      # the authority boundary if a future refactor accepts a prefix as input.
      condition     = !can(regex("-cell[0-9]+($|-)", local.control_table_prefix))
      error_message = "The Connector Authority may not use a cell-scoped table prefix."
    }

    precondition {
      condition     = length(local.availability_zones) == 3
      error_message = "The Control VPC requires three available AZs in its home region."
    }

    precondition {
      condition     = alltrue([for user_id in local.otp_redis_user_ids : length(user_id) <= 40])
      error_message = "Every Connector OTP Redis user ID must be at most 40 characters."
    }

    precondition {
      condition     = local.authority_contract_shape_valid
      error_message = "authority_runtime_contract must use the exact closed version-1 object, catalog, caller concurrency/rate, function, and evidence key sets."
    }

    precondition {
      condition     = local.authority_contract_identity_valid
      error_message = "authority_runtime_contract environment, AWS, image, QAT1, Redis, or provisioned-cell identity does not match the live Control foundation."
    }

    precondition {
      condition     = local.authority_contract_graph_valid
      error_message = "authority_runtime_contract must contain the complete Hub group plus only complete provisioned-cell operation groups, and ready must contain exact 3 + 4N."
    }

    precondition {
      condition     = local.authority_contract_integer_capacity_valid
      error_message = "authority_runtime_contract replica, limit, quota, headroom, concurrency, and retention values must be exact Terraform integers."
    }

    precondition {
      condition     = local.authority_contract_capacity_valid
      error_message = "authority_runtime_contract capacity must satisfy caller concurrency/rate aggregation, every provisioned-allocation request-rate ceiling, steady/rollout algebra, rollback bounds, and the retained account-concurrency envelope."
    }

    precondition {
      condition     = local.authority_contract_evidence_valid
      error_message = "authority_runtime_contract catalog, basis, and result evidence must use the exact versioned NHP shape; measurement forbids result evidence and ready requires it."
    }

    precondition {
      condition     = local.authority_contract_enablement_valid
      error_message = "authority_runtime_contract must remain null until the exact-main evidence generator verifies every referenced blob and explicitly opens the internal evidence latch."
    }

    precondition {
      # The runtime slice (functions/aliases/concurrency/exec roles + the
      # lockstep dependency-endpoint opening) may deploy only on top of a bound
      # contract. Setting the gate against a null contract is a fail-closed hard
      # error rather than a silent no-op.
      condition     = !var.authority_runtime_functions_enabled || local.authority_runtime_contract_enabled
      error_message = "authority_runtime_functions_enabled requires a non-null authority_runtime_contract."
    }

    precondition {
      # An alarm with no alarm_actions is silent on a real fault, which is
      # strictly worse than no alarm at all because the console shows a green
      # OK. Running the Authority without a reviewed operator destination is a
      # hard error, not a degraded mode.
      condition     = !var.authority_runtime_functions_enabled || length(var.operator_alarm_topic_arns) > 0
      error_message = "authority_runtime_functions_enabled requires at least one operator_alarm_topic_arns destination; the Authority may not run with an unrouted alarm set."
    }

    precondition {
      # Shape is enforced on the variable; locality is enforced here, where the
      # module's own partition/region/account are resolved. A cross-account or
      # cross-region topic cannot be published to by these alarms.
      condition = alltrue([
        for arn in var.operator_alarm_topic_arns :
        split(":", arn)[1] == data.aws_partition.current.partition &&
        split(":", arn)[3] == data.aws_region.current.region &&
        split(":", arn)[4] == data.aws_caller_identity.current.account_id
      ])
      error_message = "Every operator_alarm_topic_arns destination must be an SNS topic in this module's own partition, region, and account."
    }

    precondition {
      # Total, disjoint classification of the handler's emitted custom metric
      # inventory. Adding a metric to the qurl-service Authority handler without
      # deciding here whether it is alarmed or explicitly dashboard-only fails
      # the plan instead of silently landing unmonitored.
      condition = (
        setunion(
          local.authority_alarmed_custom_metrics,
          toset(keys(local.authority_unalarmed_custom_metrics)),
        ) == local.authority_emitted_custom_metrics &&
        length(setintersection(
          local.authority_alarmed_custom_metrics,
          toset(keys(local.authority_unalarmed_custom_metrics)),
        )) == 0
      )
      error_message = "Every emitted Connector Authority custom metric must be classified exactly once as alarmed or explicitly unalarmed."
    }

    precondition {
      condition = (
        !var.hub_edge_enabled ||
        (
          var.hub_public_udp_ingress_cidrs != null &&
          length(var.hub_public_udp_ingress_cidrs) > 0
        )
      )
      error_message = "hub_edge_enabled requires at least one exact public IPv4 /32 in hub_public_udp_ingress_cidrs."
    }

    precondition {
      # The Hub worker slice (5b) fronts the 5a public UDP NLB target group and
      # invokes the 3 live authority aliases, so it may deploy only on top of
      # BOTH a live public edge and a live authority runtime. Setting the gate
      # while either dependency is dark is a fail-closed hard error.
      condition     = !var.hub_worker_enabled || (var.hub_edge_enabled && local.authority_runtime_functions_deploy)
      error_message = "hub_worker_enabled requires hub_edge_enabled and a live authority runtime (the worker fronts the 5a NLB target group and invokes the 3 live authority aliases)."
    }

    precondition {
      # The single most important fence: the attended-proof mutation control
      # MUTATES live authorization state, so prod may never plan it, it must
      # name its dedicated proof tenant and at least one attended controller
      # identity that is not a runtime caller role, and it must sit on a bound
      # contract that already budgets it.
      condition     = local.authority_proof_mutation_fence_valid
      error_message = "authority_proof_mutation_controls_enabled requires environment sandbox, a non-null authority_proof_mutation_owner_id, exactly the deterministic in-account proof-controller role ARN, and a bound contract listing the proof function."
    }

    precondition {
      condition     = local.authority_proof_absent_when_disabled_valid
      error_message = "authority_runtime_contract may not carry an attended-proof mutation function while authority_proof_mutation_controls_enabled is false."
    }

    precondition {
      condition     = local.authority_proof_policy_consumers_fence_valid
      error_message = "authority_proof_policy_consumers_staged is sandbox-only and requires the live attended-proof mutation control and Authority runtime."
    }

    precondition {
      condition     = local.authority_proof_policy_rollout_fence_valid
      error_message = "The attended-proof rollout requires sandbox, staged IA/RA/ICR policy, live Hub/runtime/proof controls, the fixed blue basis selector, complete selected/prepared colors, equal active/standby pools, and the exact IA/RA/ICR + ca-pm graph."
    }

    precondition {
      condition     = local.authority_proof_policy_selected_alias_ready
      error_message = "A selector apply may not retarget its selected alias; when selected equals prepared, every selected IA/RA/ICR + ca-pm alias must already point at the staged published version."
    }

    precondition {
      # Proof operations must never acquire a hub or cell caller budget. The
      # capacity closures are keyed on the hub/cell suffix maps, so an overlap
      # would silently give a runtime caller a preinvoke allowance for a
      # mutating operation.
      condition = length(setintersection(
        toset(keys(local.authority_contract_proof_operation_suffixes)),
        toset(concat(
          keys(local.authority_contract_hub_operation_suffixes),
          keys(local.authority_contract_cell_operation_suffixes),
        )),
      )) == 0
      error_message = "An attended-proof mutation operation may not also be a hub or cell operation."
    }
  }
}
