output "control_table_prefix" {
  value = module.control.control_table_prefix
}

output "control_table_names" {
  value = module.control.control_table_names
}

output "provisioned_cells" {
  value = module.control.provisioned_cells
}

output "vpc_id" {
  value = module.control.vpc_id
}

output "isolated_subnet_ids" {
  value = module.control.isolated_subnet_ids
}

output "interface_endpoint_ids" {
  value = module.control.interface_endpoint_ids
}

output "authority_data_kms_key_arn" {
  value = module.control.authority_data_kms_key_arn
}

output "qat1_signing_kms_key_arn" {
  value = module.control.qat1_signing_kms_key_arn
}

output "otp_pepper_secret_arn" {
  value = module.control.otp_pepper_secret_arn
}

output "otp_redis_endpoint" {
  value = module.control.otp_redis_endpoint
}

output "otp_redis_user_group_id" {
  value = module.control.otp_redis_user_group_id
}

output "otp_redis_issuer_user_id" {
  value = module.control.otp_redis_issuer_user_id
}

output "otp_redis_issuer_user_arn" {
  value = module.control.otp_redis_issuer_user_arn
}

output "otp_redis_activator_user_id" {
  value = module.control.otp_redis_activator_user_id
}

output "otp_redis_activator_user_arn" {
  value = module.control.otp_redis_activator_user_arn
}

output "ses_identity_arn" {
  description = "Constructed expected SES identity ARN; do not consume before the nhp#3273 ownership transfer and live verification."
  value       = module.control.ses_identity_arn
}

output "authority_ecr_repository_url" {
  value = module.control.authority_ecr_repository_url
}

output "authority_image_uri" {
  value = module.control.authority_image_uri
}

output "authority_image_digest_parameter_name" {
  value = module.control.authority_image_digest_parameter_name
}

output "authority_proof_mutation_alias_arn" {
  description = "Exact selected-color ca-pm alias Control grants atomically to the deterministic proof-controller role, or null while dark."
  value       = try(module.control.authority_selected_alias_targets.proof.mutate_proof_agent, null)
}

output "authority_proof_credential_recovery_alias_arn" {
  description = "Exact selected-color ca-pcr alias granted only to the deterministic proof-controller role, or null while dark."
  value       = try(module.control.authority_selected_alias_targets.proof.prepare_proof_credential_recovery, null)
}

output "authority_publisher_role_arn" {
  value = module.control.authority_publisher_role_arn
}

output "authority_publisher_role_name" {
  value = module.control.authority_publisher_role_name
}

output "authority_publisher_github_environment" {
  value = module.control.authority_publisher_github_environment
}

output "hub_ecr_repository_url" {
  value = module.control.hub_ecr_repository_url
}

output "hub_ecr_repository_arn" {
  value = module.control.hub_ecr_repository_arn
}

output "hub_image_digest_parameter_name" {
  value = module.control.hub_image_digest_parameter_name
}

output "hub_public_key_parameter_name" {
  description = "Public-only Hub X25519 identity parameter; null while the worker is dark."
  value       = module.control.hub_public_key_parameter_name
}

output "hub_publisher_role_arn" {
  value = module.control.hub_publisher_role_arn
}

output "hub_publisher_role_name" {
  value = module.control.hub_publisher_role_name
}

output "hub_publisher_github_environment" {
  value = module.control.hub_publisher_github_environment
}

output "hub_publisher_github_subject" {
  value = module.control.hub_publisher_github_subject
}

output "hub_nlb_dns_name" {
  description = "Public Hub UDP NLB DNS name; null while the edge is dark."
  value       = module.control.hub_nlb_dns_name
}

output "hub_nlb_zone_id" {
  description = "Public Hub UDP NLB hosted zone id for a Route 53 alias; null while dark."
  value       = module.control.hub_nlb_zone_id
}

output "hub_udp_listener_arn" {
  description = "Public Hub UDP-62206 listener ARN; null while the edge is dark."
  value       = module.control.hub_udp_listener_arn
}

output "authority_cell_alias_targets" {
  description = <<-DESC
    Exact selected-color assigned-cell Authority alias ARNs, keyed by cell id then
    operation (issue_registration_otp, activate_registration, complete_registration,
    complete_credential_recovery, resolve_connector_resource), or null while the runtime is dark.

    Single source of truth for the cell servers' NHP_CONNECTOR_REGISTRATION_* wiring.
    The cell roots read this through terraform_remote_state rather than
    pinning a literal alias color. Deployment orchestration must settle Control
    before applying those roots and refreshing their fleets because the aliases are
    materialized into server configuration rather than read dynamically at runtime.

    Derived from authority_selected_alias_targets.cells, which colors every cell
    operation with var.authority_runtime_contract.selected_authority_color. Do NOT
    source cell aliases from the proof outputs: mutate_proof_agent follows the
    INDEPENDENT proof rollout selector and legitimately sits on a different color
    (ca-pm was :green while selected_authority_color was blue).
  DESC
  value       = try(module.control.authority_selected_alias_targets.cells, null)
}
