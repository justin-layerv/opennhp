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
