module "control" {
  source = "../../../modules/connector-authority-foundation"

  environment                                      = var.environment
  aws_account_id                                   = var.aws_account_id
  vpc_cidr                                         = var.vpc_cidr
  otp_email_from                                   = var.otp_email_from
  ses_configuration_set_name                       = var.ses_configuration_set_name
  provisioned_cells                                = var.provisioned_cells
  provisioned_cell_catalog_materialization_enabled = var.provisioned_cell_catalog_materialization_enabled
  authority_runtime_contract                       = var.authority_runtime_contract
  authority_runtime_contract_evidence_verified     = var.authority_runtime_contract_evidence_verified
  authority_runtime_functions_enabled              = var.authority_runtime_functions_enabled
  hub_edge_enabled                                 = var.hub_edge_enabled
  hub_public_udp_ingress_cidrs                     = var.hub_public_udp_ingress_cidrs
  hub_worker_enabled                               = var.hub_worker_enabled
  authority_proof_mutation_controls_enabled        = var.authority_proof_mutation_controls_enabled
  authority_blue_green_alias_hold_enabled          = var.authority_blue_green_alias_hold_enabled
  authority_proof_policy_consumers_staged          = var.authority_proof_policy_consumers_staged
  authority_proof_policy_selected_color            = var.authority_proof_policy_selected_color
  authority_proof_policy_prepared_color            = var.authority_proof_policy_prepared_color
  authority_proof_mutation_owner_id                = var.authority_proof_mutation_owner_id
  authority_proof_mutation_controller_role_arns    = var.authority_proof_mutation_controller_role_arns
  operator_alarm_topic_arns                        = var.operator_alarm_topic_arns
  tags                                             = var.tags
}
