output "name_prefix" {
  description = "Exact environment-global Connector Authority resource prefix."
  value       = local.name_prefix
}

output "control_table_prefix" {
  description = "Required DYNAMODB_CONTROL_TABLE_PREFIX; never a cell prefix."
  value       = local.control_table_prefix
}

output "control_table_names" {
  description = "Canonical global credential, identity, and assignment table names."
  value       = local.control_table_names
}

output "control_table_arns" {
  description = "Canonical global credential, identity, and assignment table ARNs."
  value = {
    api_keys            = aws_dynamodb_table.api_keys.arn
    agent_keys          = aws_dynamodb_table.agent_keys.arn
    customers           = aws_dynamodb_table.customers.arn
    api_key_idempotency = aws_dynamodb_table.api_key_idempotency.arn
    connector_authority = aws_dynamodb_table.connector_authority.arn
  }
}

output "vpc_id" {
  description = "Dedicated environment-global Control VPC ID."
  value       = aws_vpc.control.id
}

output "isolated_subnet_ids" {
  description = "Three no-default-route subnets for future Hub workers, authority functions, Redis, and endpoints."
  value       = aws_subnet.isolated[*].id
}

output "isolated_route_table_ids" {
  description = "Route tables with no internet, NAT, peering, or transit default route."
  value       = aws_route_table.isolated[*].id
}

output "interface_endpoint_ids" {
  description = "Fail-closed interface endpoints. Runtime replaces deny policies and adds exact SG ingress."
  value       = { for service, endpoint in aws_vpc_endpoint.interface : service => endpoint.id }
}

output "interface_endpoint_security_group_id" {
  description = "Dark endpoint SG with no ingress; runtime adds exact caller SG references."
  value       = aws_security_group.interface_endpoints.id
}

output "dynamodb_endpoint_id" {
  description = "Fail-closed DynamoDB gateway endpoint for future authority functions."
  value       = aws_vpc_endpoint.dynamodb.id
}

output "authority_data_kms_key_arn" {
  description = "Dedicated symmetric authority data key ARN."
  value       = aws_kms_key.authority_data.arn
}

output "qat1_signing_kms_key_arn" {
  description = "Dedicated asymmetric P-256 qat1 ticket-signing key ARN."
  value       = aws_kms_key.qat1_signing.arn
}

output "otp_pepper_secret_arn" {
  description = "Authority OTP pepper secret metadata ARN; value is seeded out of band before runtime publication."
  value       = aws_secretsmanager_secret.otp_pepper.arn
}

output "otp_redis_endpoint" {
  description = "TLS Redis endpoint for bounded OTP challenges."
  value       = aws_elasticache_serverless_cache.otp.endpoint[0].address
}

output "otp_redis_port" {
  description = "TLS Redis port for bounded OTP challenges."
  value       = aws_elasticache_serverless_cache.otp.endpoint[0].port
}

output "otp_redis_security_group_id" {
  description = "Dark Redis SG with no ingress; runtime adds exact function SG references."
  value       = aws_security_group.otp_redis.id
}

output "otp_redis_user_group_id" {
  description = "Redis RBAC group with a disabled default user and one IAM-authenticated authority user."
  value       = aws_elasticache_user_group.otp.user_group_id
}

output "otp_redis_authority_user_arn" {
  description = "IAM-authenticated Redis user ARN for the future OTP function elasticache:Connect policy."
  value       = aws_elasticache_user.otp_authority.arn
}

output "otp_email_from" {
  description = "Validated Connector OTP sender input. SES ownership transfers separately under nhp#3273."
  value       = var.otp_email_from
}

output "ses_identity_arn" {
  description = "Constructed expected SES identity ARN. Do not consume it until nhp#3273 transfers ownership and live existence is verified; this module does not own or read the identity."
  value       = "arn:${data.aws_partition.current.partition}:ses:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:identity/${local.otp_sender_domain}"
}

output "ses_configuration_set_name" {
  description = "Validated SES configuration-set input for future OTP functions."
  value       = var.ses_configuration_set_name
}

output "authority_ecr_repository_url" {
  description = "Immutable-tag ECR repository for the separately published authority image."
  value       = aws_ecr_repository.authority.repository_url
}

output "authority_ecr_repository_arn" {
  description = "ECR repository ARN for narrow publisher and Lambda retrieval policies in later slices."
  value       = aws_ecr_repository.authority.arn
}

output "authority_image_digest_parameter_name" {
  description = "SSM parameter that qurl-service publication updates with an immutable sha256 digest."
  value       = aws_ssm_parameter.authority_image_digest.name
}
