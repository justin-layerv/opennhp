# --------------------------------------------------------------------------
# Assigned-cell Connector Authority activation (cell0)
# --------------------------------------------------------------------------
# Production Control owns the selected Authority color and publishes the exact
# four-operation alias graph. Derive from that output so a reviewed color flip
# cannot leave cell0 pinned to retired aliases. The remote-state read is gated
# because the production Control state does not exist before its foundation
# rollout; the default-off gate keeps ordinary production plans dark until a
# separate reviewed activation removes the source lock and turns the handoff on.
data "terraform_remote_state" "control" {
  count   = var.connector_authority_cell_from_control_enabled ? 1 : 0
  backend = "s3"

  config = {
    bucket = "layerv-terraform-state-235500187906"
    key    = "nhp/prod/control/terraform.tfstate"
    region = "us-east-2"
  }
}

locals {
  # null while the handoff is disabled or Control's runtime is dark, which
  # keeps the assigned-cell registration path dark too.
  control_cell0_alias_targets = var.connector_authority_cell_from_control_enabled ? try(
    data.terraform_remote_state.control[0].outputs.authority_cell_alias_targets["cell0"],
    null
  ) : null

  # The explicit object remains source-locked null until a separately reviewed
  # activation. Normal production activation derives from Control so the
  # selected alias color has one owner.
  connector_authority_cell_config = var.connector_authority_cell_config != null ? var.connector_authority_cell_config : (
    local.control_cell0_alias_targets == null ? null : {
      environment                            = var.environment
      aws_account_id                         = var.aws_account_id
      aws_region                             = var.aws_region
      issue_registration_otp_alias_arn       = local.control_cell0_alias_targets["issue_registration_otp"]
      activate_registration_alias_arn        = local.control_cell0_alias_targets["activate_registration"]
      complete_registration_alias_arn        = local.control_cell0_alias_targets["complete_registration"]
      complete_credential_recovery_alias_arn = local.control_cell0_alias_targets["complete_credential_recovery"]

      # Reviewed budgets from
      # terraform/modules/compute/tests/connector_authority.tftest.hcl.
      # Internally consistent: handler_budget + response_reserve == packet_budget
      # (3200ms + 700ms = 3900ms), with authority_lambda_timeout inside the
      # handler budget.
      authority_lambda_timeout = "3s"
      handler_budget           = "3200ms"
      packet_budget            = "3900ms"
      response_reserve         = "700ms"
      write_budget             = "137ms"
    }
  )
}
