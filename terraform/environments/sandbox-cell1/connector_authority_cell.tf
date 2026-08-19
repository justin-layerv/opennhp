# --------------------------------------------------------------------------
# Assigned-cell Connector Authority activation (cell1)
# --------------------------------------------------------------------------
# cell1 was assignable but could not enroll anyone. The registry lists it
# `status = active, selection_weight = 1` alongside cell0, so the Connector
# Authority hands it its share of new agents — and #3739 turned on
# agent_otp_registration_enabled here, so its servers advertise native
# registration. But this root never set connector_authority_cell_config, whose
# default is null, so user_data emitted no NHP_CONNECTOR_REGISTRATION_*
# variables at all. Verified on the live cell1 server-init.sh: it carries
# AGENT_OTP_REGISTRATION_ENABLED=true and QURL_V2_ADMISSION_ENABLED=true with
# not one NHP_CONNECTOR_* line, while cell0's carries all eleven.
#
# With that config absent, loadConnectorCellAuthorityConfigs returns nil,
# configureConnectorCellAuthority returns early, and s.connectorRegistrationHandler
# stays nil — the same dark-capability shape cell0 was in before #3172.
#
# What a developer saw: an agent placed on cell1 dispatches NHP_OTP, no issuer
# alias exists to invoke, and NHP_OTP carries no acknowledgement in the
# protocol, so the SDK cannot be told. It sits in the caller's OTP callback
# until the assignment ticket expires. No code is ever emailed, and nothing
# names a cause. Measured over 30 days: ca-iro-cell1, ca-ar-cell1, ca-cr-cell1
# and ca-ccr-cell1 have ZERO invocations, against 3/40/32 on cell0. Placement is
# a coin flip, which is why the emailed-code path looked intermittently dead
# while the sandbox proof — pinned to cell0 — stayed green.
#
# This mirrors terraform/environments/sandbox/connector_authority_cell.tf
# exactly, reading cell1's key instead of cell0's. Keep the two in step.
#
# The alias ARNs are READ FROM CONTROL, never pinned here, for the reason that
# file gives: Control colors every cell operation with
# authority_runtime_contract.selected_authority_color. The Control-first deploy,
# this root's apply, and its blue/green refresh carry a reviewed color flip into
# every running cell1 server; the value is materialized rather than dynamically
# read at runtime. Control already publishes the cell1 targets
# (authority_selected_alias_targets.cells["cell1"]); only this root was not
# reading them.
data "terraform_remote_state" "control" {
  backend = "s3"

  config = {
    bucket = "layerv-terraform-state-767397897469"
    key    = "nhp/sandbox/control/terraform.tfstate"
    region = "us-east-2"
  }
}

locals {
  # null while Control's runtime is dark, which keeps this slice dark too.
  control_cell1_alias_targets = try(
    data.terraform_remote_state.control.outputs.authority_cell_alias_targets["cell1"],
    null
  )

  # An explicit var still wins, so prod parity and break-glass overrides are
  # unchanged; sandbox simply no longer needs one.
  connector_authority_cell_config = var.connector_authority_cell_config != null ? var.connector_authority_cell_config : (
    local.control_cell1_alias_targets == null ? null : {
      # protocol_environment, NOT var.environment. This root's var.environment
      # is the INFRASTRUCTURE namespace "sandbox-cell1", which keeps resource
      # names and /sandbox-cell1/... SSM paths from colliding with cell0. The
      # Authority environment is "sandbox" for both cells, carried separately.
      #
      # Getting this wrong is not a typo, it is unbuildable: modules/compute
      # requires contains(["sandbox","prod"], config.environment), and this
      # root's variables.tf validates var.environment is neither of those, so
      # var.environment here could never satisfy the compute precondition. It
      # would also reconstruct expected alias ARNs as
      # layerv-nhp-sandbox-cell1-ca-iro-cell1 when the functions Control
      # actually publishes are layerv-nhp-sandbox-ca-iro-cell1.
      environment                            = var.protocol_environment
      aws_account_id                         = var.aws_account_id
      aws_region                             = var.aws_region
      issue_registration_otp_alias_arn       = local.control_cell1_alias_targets["issue_registration_otp"]
      activate_registration_alias_arn        = local.control_cell1_alias_targets["activate_registration"]
      complete_registration_alias_arn        = local.control_cell1_alias_targets["complete_registration"]
      complete_credential_recovery_alias_arn = local.control_cell1_alias_targets["complete_credential_recovery"]

      # Reviewed budgets from
      # terraform/modules/compute/tests/connector_authority.tftest.hcl, identical
      # to cell0's. Internally consistent: handler_budget + response_reserve ==
      # packet_budget (3200ms + 700ms = 3900ms), with authority_lambda_timeout
      # inside the handler budget.
      authority_lambda_timeout = "3s"
      handler_budget           = "3200ms"
      packet_budget            = "3900ms"
      response_reserve         = "700ms"
      write_budget             = "137ms"
    }
  )
}
