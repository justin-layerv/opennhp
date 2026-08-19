# --------------------------------------------------------------------------
# Assigned-cell Connector Authority activation (cell0)
# --------------------------------------------------------------------------
# This capability has been dark since it was introduced. With
# connector_authority_cell_config null, user_data emits no
# NHP_CONNECTOR_REGISTRATION_* variables, so loadConnectorCellAuthorityConfigs
# returns a nil registration config, configureConnectorCellAuthority returns
# early, and s.connectorRegistrationHandler stays nil. handleConnectorRegistration*
# then never intercepts: an assigned-cell NHP_REG falls through to the GENERIC
# qURL knock handler and is answered with aspId "qurl". qurl-go requires aspId
# "agent" on that reply (register_wire.go), so every native enrollment failed with
#
#     qurl: registration reply malformed: native registration reply aspId is invalid
#
# which reads like a malformed reply but is really this capability being absent.
#
# The variable's guidance is "activate only after the Control runtime has been
# applied and verified"; that precondition is now met.
#
# The alias ARNs are READ FROM CONTROL, never pinned here. Control colors every
# cell operation with authority_runtime_contract.selected_authority_color, so
# a Control-first deploy followed by this root's apply and blue/green refresh
# carries a reviewed color flip into every running server. This is materialized
# configuration, not a dynamic runtime read; the workflow and its live
# convergence gate enforce that order. A literal color here would be a second
# source of truth and would strand the cells on a retired alias the day the
# selector moves -- the same stale-literal failure mode as the pre-1.1 Hub pin.
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
  control_cell0_alias_targets = try(
    data.terraform_remote_state.control.outputs.authority_cell_alias_targets["cell0"],
    null
  )

  # An explicit var still wins, so prod parity and break-glass overrides are
  # unchanged; sandbox simply no longer needs one.
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
