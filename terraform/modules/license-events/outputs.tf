# License Events Module Outputs

output "sns_topic_arn" {
  description = "SNS topic ARN for publishing license events"
  value       = aws_sns_topic.license_events.arn
}

output "sns_topic_name" {
  description = "SNS topic name"
  value       = aws_sns_topic.license_events.name
}

output "sqs_queue_url" {
  description = "SQS queue URL for receiving license events"
  value       = aws_sqs_queue.license_events.url
}

output "sqs_queue_arn" {
  description = "SQS queue ARN for IAM policies"
  value       = aws_sqs_queue.license_events.arn
}

output "sqs_queue_name" {
  description = "SQS queue name"
  value       = aws_sqs_queue.license_events.name
}

output "dlq_queue_url" {
  description = "Dead letter queue URL for failed messages"
  value       = aws_sqs_queue.license_events_dlq.url
}

output "dlq_queue_arn" {
  description = "Dead letter queue ARN"
  value       = aws_sqs_queue.license_events_dlq.arn
}
