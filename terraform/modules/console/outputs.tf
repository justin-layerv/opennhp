# Console Module Outputs

output "alb_dns_name" {
  description = "ALB DNS name for console"
  value       = aws_lb.console.dns_name
}

output "alb_zone_id" {
  description = "ALB zone ID"
  value       = aws_lb.console.zone_id
}

output "alb_arn" {
  description = "ALB ARN"
  value       = aws_lb.console.arn
}

output "console_url" {
  description = "Console URL"
  value       = var.domain_name != null ? "https://${var.domain_name}" : "http://${aws_lb.console.dns_name}"
}

output "ecs_cluster_name" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.console.name
}

output "ecs_service_name" {
  description = "ECS service name"
  value       = aws_ecs_service.console.name
}

output "security_group_id" {
  description = "Console ECS security group ID"
  value       = aws_security_group.console.id
}

output "fqdn" {
  description = "Console fully qualified domain name"
  value       = var.domain_name != null && var.hosted_zone != null ? aws_route53_record.console[0].fqdn : null
}

output "task_role_arn" {
  description = "Console ECS task role ARN (for granting permissions to publish to SNS, etc.)"
  value       = aws_iam_role.console_task.arn
}
