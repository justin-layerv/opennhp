output "control_table_prefix" {
  value = module.control.control_table_prefix
}

output "control_table_names" {
  value = module.control.control_table_names
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

output "otp_redis_authority_user_arn" {
  value = module.control.otp_redis_authority_user_arn
}

output "ses_identity_arn" {
  description = "Constructed expected SES identity ARN; do not consume before the nhp#3273 ownership transfer and live verification."
  value       = module.control.ses_identity_arn
}

output "authority_ecr_repository_url" {
  value = module.control.authority_ecr_repository_url
}

output "authority_image_digest_parameter_name" {
  value = module.control.authority_image_digest_parameter_name
}
