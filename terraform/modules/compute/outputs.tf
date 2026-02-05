output "nlb_dns_name" {
  description = "NLB DNS name"
  value       = aws_lb.server.dns_name
}

output "nlb_arn" {
  description = "NLB ARN"
  value       = aws_lb.server.arn
}

output "nlb_arn_suffix" {
  description = "NLB ARN suffix for CloudWatch"
  value       = aws_lb.server.arn_suffix
}

output "nlb_zone_id" {
  description = "NLB zone ID for Route 53"
  value       = aws_lb.server.zone_id
}

output "asg_name" {
  description = "Auto Scaling Group name"
  value       = aws_autoscaling_group.server.name
}

output "asg_arn" {
  description = "Auto Scaling Group ARN"
  value       = aws_autoscaling_group.server.arn
}

output "server_secret_arn" {
  description = "Server secret ARN"
  value       = aws_secretsmanager_secret.server.arn
}

output "cloudmap_service_arn" {
  description = "Cloud Map service ARN"
  value       = aws_service_discovery_service.server.arn
}

output "cloudmap_service_dns" {
  description = "Cloud Map DNS name"
  value       = "server.${var.namespace_name}"
}

output "security_group_id" {
  description = "Server security group ID"
  value       = aws_security_group.server.id
}

output "target_group_arn_suffix" {
  description = "Target group ARN suffix for CloudWatch"
  value       = aws_lb_target_group.udp.arn_suffix
}

output "https_target_group_arn_suffix" {
  description = "HTTPS target group ARN suffix for CloudWatch (null if QURL resolve endpoint not enabled)"
  value       = var.enable_qurl_resolve_endpoint ? aws_lb_target_group.https[0].arn_suffix : null
}

# =============================================================================
# SSM Parameter Outputs for CI/CD
# =============================================================================

output "ssm_image_tag_parameter" {
  description = "SSM parameter name for the deployed image tag"
  value       = aws_ssm_parameter.image_tag.name
}

output "ssm_asg_name_parameter" {
  description = "SSM parameter name for the ASG name"
  value       = aws_ssm_parameter.asg_name.name
}

# =============================================================================
# NLB Outputs for Blue/Green Deployment (Phase 2)
# =============================================================================

output "nlb_udp_listener_arn" {
  description = "NLB UDP listener ARN - used for blue/green traffic switching"
  value       = aws_lb_listener.udp.arn
}

output "target_group_arn" {
  description = "UDP target group ARN"
  value       = aws_lb_target_group.udp.arn
}
