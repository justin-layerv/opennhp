output "ebs_key_arn" {
  description = "ARN of KMS key for EBS encryption"
  value       = aws_kms_key.ebs.arn
}

output "ebs_key_id" {
  description = "ID of KMS key for EBS encryption"
  value       = aws_kms_key.ebs.key_id
}

output "efs_key_arn" {
  description = "ARN of KMS key for EFS encryption"
  value       = aws_kms_key.efs.arn
}

output "efs_key_id" {
  description = "ID of KMS key for EFS encryption"
  value       = aws_kms_key.efs.key_id
}

output "secrets_key_arn" {
  description = "ARN of KMS key for Secrets Manager encryption"
  value       = aws_kms_key.secrets.arn
}

output "secrets_key_id" {
  description = "ID of KMS key for Secrets Manager encryption"
  value       = aws_kms_key.secrets.key_id
}

output "logs_key_arn" {
  description = "ARN of KMS key for CloudWatch Logs encryption"
  value       = aws_kms_key.logs.arn
}

output "logs_key_id" {
  description = "ID of KMS key for CloudWatch Logs encryption"
  value       = aws_kms_key.logs.key_id
}

output "rds_key_arn" {
  description = "ARN of KMS key for RDS encryption"
  value       = aws_kms_key.rds.arn
}

output "rds_key_id" {
  description = "ID of KMS key for RDS encryption"
  value       = aws_kms_key.rds.key_id
}

output "qurl_v2_issuer_key_arn" {
  description = "ARN of the qURL v2 issuer signing key (ECDSA P-256); null when qurl_v2_issuer_key_enabled = false"
  value       = one(aws_kms_key.qurl_v2_issuer[*].arn)
}

output "qurl_v2_issuer_key_id" {
  description = "ID of the qURL v2 issuer signing key; null when not provisioned"
  value       = one(aws_kms_key.qurl_v2_issuer[*].key_id)
}

output "qurl_v2_issuer_key_alias" {
  description = "Alias name of the qURL v2 issuer signing key; null when not provisioned"
  value       = one(aws_kms_alias.qurl_v2_issuer[*].name)
}

output "qurl_v2_resource_key_envelope_key_arn" {
  description = "ARN of the qURL v2 software-custody resource-key envelope key (AES-256); null when qurl_v2_resource_keys_enabled = false"
  value       = one(aws_kms_key.qurl_v2_resource_key_envelope[*].arn)
}

