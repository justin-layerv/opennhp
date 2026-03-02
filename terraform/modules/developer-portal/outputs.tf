# Developer Portal Module Outputs

output "api_url" {
  description = "API Gateway invoke URL"
  value       = aws_apigatewayv2_stage.default.invoke_url
}

output "api_id" {
  description = "API Gateway HTTP API ID"
  value       = aws_apigatewayv2_api.developer_portal.id
}

output "playground_lambda_function_name" {
  description = "Playground proxy Lambda function name"
  value       = aws_lambda_function.playground.function_name
}

output "rate_limits_table_name" {
  description = "DynamoDB rate limits table name"
  value       = aws_dynamodb_table.rate_limits.name
}

output "rate_limits_table_arn" {
  description = "DynamoDB rate limits table ARN"
  value       = aws_dynamodb_table.rate_limits.arn
}

output "custom_domain_url" {
  description = "Custom domain URL for the developer portal API (null if no custom domain configured)"
  value       = local.has_custom_domain ? "https://${var.custom_domain}" : null
}

output "custom_domain_target_domain_name" {
  description = "API Gateway custom domain target domain name for Route53 alias"
  value       = local.has_custom_domain ? aws_apigatewayv2_domain_name.developer_portal[0].domain_name_configuration[0].target_domain_name : null
}

output "custom_domain_target_hosted_zone_id" {
  description = "API Gateway custom domain target hosted zone ID for Route53 alias"
  value       = local.has_custom_domain ? aws_apigatewayv2_domain_name.developer_portal[0].domain_name_configuration[0].hosted_zone_id : null
}
