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

output "log_group_name" {
  description = "CloudWatch log group name"
  value       = aws_cloudwatch_log_group.server.name
}

output "log_group_stderr_name" {
  description = "CloudWatch log group name for container stdout/stderr (panics, runtime errors, EMF metric emissions). Consumed by the monitoring module: a metric filter drives the ServerPanic alarm, and CloudWatch auto-extracts ServerStartupEvent from EMF JSON lines emitted by the Go server at startup (#1107)."
  value       = aws_cloudwatch_log_group.server_stderr.name
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

output "ssm_deployed_commit_parameter" {
  description = "SSM parameter name for deployed commit SHA"
  value       = aws_ssm_parameter.deployed_commit.name
}

output "ssm_deployed_at_parameter" {
  description = "SSM parameter name for deployment timestamp"
  value       = aws_ssm_parameter.deployed_at.name
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

# =============================================================================
# Blue/Green Deployment Outputs
# =============================================================================

output "blue_green_enabled" {
  description = "Whether blue/green deployment infrastructure is enabled"
  value       = var.enable_blue_green
}

output "green_asg_name" {
  description = "Green Auto Scaling Group name (null if blue/green not enabled)"
  value       = var.enable_blue_green ? aws_autoscaling_group.server_green[0].name : null
}

output "green_asg_arn" {
  description = "Green Auto Scaling Group ARN (null if blue/green not enabled)"
  value       = var.enable_blue_green ? aws_autoscaling_group.server_green[0].arn : null
}

output "udp_target_group_blue_arn" {
  description = "Blue UDP target group ARN (same as target_group_arn)"
  value       = aws_lb_target_group.udp.arn
}

output "udp_target_group_green_arn" {
  description = "Green UDP target group ARN (null if blue/green not enabled)"
  value       = var.enable_blue_green ? aws_lb_target_group.udp_green[0].arn : null
}

output "https_target_group_blue_arn" {
  description = "Blue HTTPS target group ARN (null if QURL resolve endpoint not enabled)"
  value       = var.enable_qurl_resolve_endpoint ? aws_lb_target_group.https[0].arn : null
}

output "https_target_group_green_arn" {
  description = "Green HTTPS target group ARN (null if blue/green or QURL resolve not enabled)"
  value       = var.enable_blue_green && var.enable_qurl_resolve_endpoint ? aws_lb_target_group.https_green[0].arn : null
}

output "nlb_https_listener_arn" {
  description = "NLB HTTPS listener ARN (null if QURL resolve endpoint not enabled)"
  value       = var.enable_qurl_resolve_endpoint ? aws_lb_listener.https[0].arn : null
}

output "ssm_active_color_parameter" {
  description = "SSM parameter name for active deployment color (null if blue/green not enabled)"
  value       = var.enable_blue_green ? aws_ssm_parameter.active_color[0].name : null
}

output "ssm_green_image_tag_parameter" {
  description = "SSM parameter name for green ASG image tag (null if blue/green not enabled)"
  value       = var.enable_blue_green ? aws_ssm_parameter.green_image_tag[0].name : null
}

output "ssm_green_asg_name_parameter" {
  description = "SSM parameter name for green ASG name (null if blue/green not enabled)"
  value       = var.enable_blue_green ? aws_ssm_parameter.green_asg_name[0].name : null
}

# =============================================================================
# Launch Template Outputs
# =============================================================================

output "launch_template_arn" {
  description = "Server launch template ARN (for canary deployment IAM)"
  value       = aws_launch_template.server.arn
}
