# NHP Keypair Module Outputs

output "registration_key_parameter_name" {
  description = "SSM Parameter Store name for registration keypair (contains private key)"
  value       = "/nhp/pool/registration-key"
}

output "registration_public_key_parameter_name" {
  description = "SSM Parameter Store name for registration public key (for AC config)"
  value       = aws_ssm_parameter.registration_public_key.name
}

output "registration_public_key" {
  description = "Base64-encoded registration public key (for AC config)"
  value       = aws_ssm_parameter.registration_public_key.value
}

output "server_keypair_policy_arn" {
  description = "IAM policy ARN for server access to keypairs"
  value       = aws_iam_policy.server_keypair_access.arn
}
