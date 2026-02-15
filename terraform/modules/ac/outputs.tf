# AC Module Outputs

output "nlb_dns_name" {
  description = "AC NLB DNS name"
  value       = aws_lb.ac.dns_name
}

output "nlb_arn" {
  description = "AC NLB ARN"
  value       = aws_lb.ac.arn
}

output "nlb_arn_suffix" {
  description = "AC NLB ARN suffix for CloudWatch"
  value       = aws_lb.ac.arn_suffix
}

output "nlb_zone_id" {
  description = "AC NLB zone ID for Route 53"
  value       = aws_lb.ac.zone_id
}

output "fqdn" {
  description = "AC fully qualified domain name"
  value       = var.skip_dns_records ? var.domain_name : (var.enable_cloudfront ? aws_route53_record.ac_cloudfront[0].fqdn : aws_route53_record.ac[0].fqdn)
}

output "asg_name" {
  description = "Auto Scaling Group name"
  value       = aws_autoscaling_group.ac.name
}

output "asg_arn" {
  description = "Auto Scaling Group ARN"
  value       = aws_autoscaling_group.ac.arn
}

output "security_group_id" {
  description = "AC security group ID"
  value       = aws_security_group.ac.id
}

output "cloudmap_service_arn" {
  description = "Cloud Map service ARN"
  value       = aws_service_discovery_service.ac.arn
}

output "cloudmap_service_dns" {
  description = "Cloud Map DNS name for AC discovery"
  value       = "ac.${var.namespace_name}"
}

output "log_group_name" {
  description = "CloudWatch log group name"
  value       = aws_cloudwatch_log_group.ac.name
}

output "instance_role_arn" {
  description = "AC instance IAM role ARN"
  value       = aws_iam_role.ac.arn
}

# Note: plugin_bucket outputs removed - plugins now managed by unified plugins module

output "ac_secret_arn" {
  description = "ARN of the AC secret containing the private key"
  value       = aws_secretsmanager_secret.ac.arn
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
# Blue/Green Deployment Outputs
# =============================================================================

output "blue_green_enabled" {
  description = "Whether blue/green deployment is enabled for AC"
  value       = var.enable_blue_green
}

output "green_asg_name" {
  description = "AC Green ASG name for CI/CD scripts (null if blue/green not enabled)"
  value       = var.enable_blue_green ? aws_autoscaling_group.ac_green[0].name : null
}

output "green_asg_arn" {
  description = "AC Green ASG ARN (null if blue/green not enabled)"
  value       = var.enable_blue_green ? aws_autoscaling_group.ac_green[0].arn : null
}

output "tcp_target_group_blue_arn" {
  description = "Blue TCP target group ARN (existing)"
  value       = aws_lb_target_group.ac_tcp.arn
}

output "tcp_target_group_green_arn" {
  description = "Green TCP target group ARN (null if blue/green not enabled)"
  value       = var.enable_blue_green ? aws_lb_target_group.ac_tcp_green[0].arn : null
}

output "ssm_active_color_parameter" {
  description = "SSM parameter name for AC active deployment color"
  value       = var.enable_blue_green ? aws_ssm_parameter.active_color[0].name : null
}

output "ssm_green_image_tag_parameter" {
  description = "SSM parameter name for AC green ASG image tag"
  value       = var.enable_blue_green ? aws_ssm_parameter.green_image_tag[0].name : null
}

output "ssm_green_asg_name_parameter" {
  description = "SSM parameter name for AC green ASG name"
  value       = var.enable_blue_green ? aws_ssm_parameter.green_asg_name[0].name : null
}
