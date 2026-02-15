# QURL Service Module Outputs

output "cluster_name" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.qurl.name
}

output "cluster_arn" {
  description = "ECS cluster ARN"
  value       = aws_ecs_cluster.qurl.arn
}

output "service_name" {
  description = "ECS service name"
  value       = aws_ecs_service.qurl.name
}

output "service_arn" {
  description = "ECS service ARN"
  value       = aws_ecs_service.qurl.id
}

output "alb_dns_name" {
  description = "ALB DNS name"
  value       = aws_lb.qurl.dns_name
}

output "alb_zone_id" {
  description = "ALB hosted zone ID"
  value       = aws_lb.qurl.zone_id
}

output "alb_arn" {
  description = "ALB ARN"
  value       = aws_lb.qurl.arn
}

output "security_group_id" {
  description = "ECS tasks security group ID"
  value       = aws_security_group.ecs.id
}

output "api_endpoint" {
  description = "QURL API endpoint URL"
  value       = var.domain_name != null ? "https://${var.domain_name}" : "http://${aws_lb.qurl.dns_name}"
}

output "log_group_name" {
  description = "CloudWatch log group name"
  value       = aws_cloudwatch_log_group.qurl.name
}

output "ecs_cluster_ssm_param" {
  description = "SSM parameter name containing ECS cluster name (for CI)"
  value       = aws_ssm_parameter.ecs_cluster.name
}

output "ecs_service_ssm_param" {
  description = "SSM parameter name containing ECS service name (for CI)"
  value       = aws_ssm_parameter.ecs_service.name
}
