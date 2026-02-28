# Billing Module Outputs

output "api_url" {
  description = "API Gateway invoke URL for billing endpoints"
  value       = aws_apigatewayv2_stage.default.invoke_url
}

output "api_id" {
  description = "API Gateway HTTP API ID"
  value       = aws_apigatewayv2_api.billing.id
}

output "usage_events_queue_arn" {
  description = "SQS usage events queue ARN"
  value       = aws_sqs_queue.usage_events.arn
}

output "usage_events_queue_url" {
  description = "SQS usage events queue URL"
  value       = aws_sqs_queue.usage_events.url
}

output "usage_events_dlq_arn" {
  description = "SQS usage events dead-letter queue ARN"
  value       = aws_sqs_queue.usage_events_dlq.arn
}

output "checkout_session_lambda_function_name" {
  description = "Checkout session Lambda function name"
  value       = aws_lambda_function.checkout_session.function_name
}

output "stripe_webhook_lambda_function_name" {
  description = "Stripe webhook Lambda function name"
  value       = aws_lambda_function.stripe_webhook.function_name
}

output "usage_reporter_lambda_function_name" {
  description = "Usage reporter Lambda function name"
  value       = aws_lambda_function.usage_reporter.function_name
}

output "reconciliation_lambda_function_name" {
  description = "Reconciliation Lambda function name"
  value       = aws_lambda_function.reconciliation.function_name
}

output "payment_grace_lambda_function_name" {
  description = "Payment grace Lambda function name"
  value       = aws_lambda_function.payment_grace.function_name
}

output "invoices_lambda_function_name" {
  description = "Invoices Lambda function name"
  value       = aws_lambda_function.invoices.function_name
}

output "webhook_dedup_table_name" {
  description = "Webhook deduplication DynamoDB table name"
  value       = aws_dynamodb_table.webhook_dedup.name
}

output "webhook_dedup_table_arn" {
  description = "Webhook deduplication DynamoDB table ARN"
  value       = aws_dynamodb_table.webhook_dedup.arn
}
