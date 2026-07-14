# Status Page Module Outputs

output "api_url" {
  description = "Compatibility API Gateway URL for the cached status endpoint; the frontend reads same-origin /status.json."
  value       = "${aws_apigatewayv2_stage.default.invoke_url}/status"
}

output "cloudfront_domain_name" {
  description = "CloudFront distribution domain name"
  value       = aws_cloudfront_distribution.status.domain_name
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID (for cache invalidation)"
  value       = aws_cloudfront_distribution.status.id
}

output "cloudfront_hosted_zone_id" {
  description = "CloudFront distribution Route53 hosted zone ID (for alias records)"
  value       = aws_cloudfront_distribution.status.hosted_zone_id
}

output "status_url" {
  description = "Public URL for the status page"
  value       = var.status_domain != null ? "https://${var.status_domain}" : "https://${aws_cloudfront_distribution.status.domain_name}"
}

output "lambda_function_name" {
  description = "Status aggregator Lambda function name"
  value       = aws_lambda_function.status_aggregator.function_name
}

output "s3_bucket_name" {
  description = "S3 bucket name for status page frontend"
  value       = aws_s3_bucket.status.id
}

output "ssm_sns_topic_arn_parameter" {
  description = "SSM parameter name storing the SNS topic ARN (for CI/CD notifications)"
  value       = aws_ssm_parameter.sns_topic_arn.name
}

output "nhp_auth_enabled" {
  description = "Whether NHP authentication is enabled for the status page"
  value       = var.enable_nhp_auth
}

output "nhp_auth_function_name" {
  description = "CloudFront Function name for NHP auth (null if auth disabled)"
  value       = var.enable_nhp_auth ? aws_cloudfront_function.nhp_auth[0].name : null
}
