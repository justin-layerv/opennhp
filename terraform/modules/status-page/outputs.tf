# Status Page Module Outputs

output "api_url" {
  description = "API Gateway invoke URL for the status endpoint"
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
