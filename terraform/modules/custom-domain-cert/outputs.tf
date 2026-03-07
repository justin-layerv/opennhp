# ==============================================================================
# Custom Domain Certificate Manager Outputs
# ==============================================================================

output "lambda_function_name" {
  description = "Name of the custom domain certificate manager Lambda function"
  value       = aws_lambda_function.cert_manager.function_name
}

output "lambda_function_arn" {
  description = "ARN of the custom domain certificate manager Lambda function"
  value       = aws_lambda_function.cert_manager.arn
}

output "lambda_role_arn" {
  description = "ARN of the Lambda execution IAM role"
  value       = aws_iam_role.lambda.arn
}

output "acme_zone_id" {
  description = "Route53 hosted zone ID for the ACME delegation zone"
  value       = aws_route53_zone.acme.zone_id
}

output "acme_zone_nameservers" {
  description = "Nameservers for the ACME delegation zone (delegate from parent zone)"
  value       = aws_route53_zone.acme.name_servers
}

output "acme_zone_name" {
  description = "Name of the ACME delegation zone"
  value       = aws_route53_zone.acme.name
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for certificate alerts"
  value       = local.sns_topic_arn
}

output "acme_account_secret_arn" {
  description = "ARN of the Secrets Manager secret containing the shared ACME account key"
  value       = aws_secretsmanager_secret.acme_account.arn
}
