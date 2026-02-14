output "sns_topic_arn" {
  description = "SNS topic ARN for alerts"
  value       = aws_sns_topic.alerts.arn
}

output "dashboard_name" {
  description = "CloudWatch dashboard name"
  value       = aws_cloudwatch_dashboard.main.dashboard_name
}

output "alert_email_subscriptions" {
  description = "Email addresses subscribed to alarm notifications. Each must confirm the subscription via email link before receiving alerts."
  value       = [for sub in aws_sns_topic_subscription.alert_emails : sub.endpoint]
}
