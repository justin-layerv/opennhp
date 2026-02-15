# ==============================================================================
# ACME Certificate Manager Outputs
# ==============================================================================

output "certificate_secret_arn" {
  description = "ARN of the Secrets Manager secret containing the TLS certificate"
  value       = aws_secretsmanager_secret.certificate.arn
}

output "certificate_secret_name" {
  description = "Name of the Secrets Manager secret containing the TLS certificate"
  value       = aws_secretsmanager_secret.certificate.name
}

output "lambda_function_arn" {
  description = "ARN of the certificate manager Lambda function"
  value       = aws_lambda_function.cert_manager.arn
}

output "lambda_function_name" {
  description = "Name of the certificate manager Lambda function"
  value       = aws_lambda_function.cert_manager.function_name
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for certificate alerts"
  value       = local.sns_topic_arn
}

output "kms_key_arn" {
  description = "ARN of the KMS key used for certificate encryption"
  value       = local.kms_key_arn
}

output "domains" {
  description = "List of domains covered by the certificate"
  value       = var.domains
}

output "acme_directory" {
  description = "ACME directory URL (production or staging)"
  value       = local.acme_directory
}

# IAM policy document for consumers (AC instances) to read the certificate
output "consumer_policy_json" {
  description = "IAM policy JSON allowing read access to the certificate secret. Attach this to AC instance roles."
  value = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadCertificateSecret"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = aws_secretsmanager_secret.certificate.arn
      },
      {
        Sid    = "DecryptCertificateSecret"
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = local.kms_key_arn != null ? local.kms_key_arn : "*"
        Condition = local.kms_key_arn == null ? {
          StringEquals = {
            "kms:ViaService" = "secretsmanager.${data.aws_region.current.id}.amazonaws.com"
          }
        } : null
      }
    ]
  })
}

# Outputs for manual certificate generation/testing
output "invoke_command" {
  description = "AWS CLI command to manually invoke the certificate manager"
  value       = "aws lambda invoke --function-name ${aws_lambda_function.cert_manager.function_name} --payload '{\"type\":\"force_renew\"}' /dev/stdout"
}

output "check_status_command" {
  description = "AWS CLI command to check certificate status"
  value       = "aws lambda invoke --function-name ${aws_lambda_function.cert_manager.function_name} --payload '{\"type\":\"check_status\"}' /dev/stdout"
}
