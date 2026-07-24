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
        authority_image_uri        = local.authority_runtime_image_uri
        authority_runtime_contract = var.authority_runtime_contract
      })
      : "{}"
    ),
  )

  lifecycle {
    precondition {
      condition     = data.aws_caller_identity.current.account_id == var.aws_account_id
      error_message = "Connector Authority foundation is targeting the wrong AWS account."
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
  }
}
