# Console EC2 Module Outputs

output "nlb_dns_name" {
  description = "Console NLB DNS name"
  value       = aws_lb.console.dns_name
}

output "nlb_arn" {
  description = "Console NLB ARN"
  value       = aws_lb.console.arn
}

output "nlb_zone_id" {
  description = "Console NLB zone ID for Route 53"
  value       = aws_lb.console.zone_id
}

output "fqdn" {
  description = "Console fully qualified domain name"
  value       = var.hosted_zone_id != null && !var.internal_only ? aws_route53_record.console[0].fqdn : var.domain_name
}

output "api_endpoint" {
  description = "Console API endpoint URL (HTTPS for external, HTTP for internal)"
  value       = var.internal_only ? "http://${aws_lb.console.dns_name}:${var.console_port}" : "https://${var.domain_name}"
}

output "internal_endpoint" {
  description = "Console internal endpoint for AC routing (HTTP URL)"
  value       = "http://${aws_lb.console.dns_name}:${var.console_port}"
}

output "asg_name" {
  description = "Auto Scaling Group name"
  value       = aws_autoscaling_group.console.name
}

output "security_group_id" {
  description = "Console security group ID"
  value       = aws_security_group.console.id
}

output "log_group_name" {
  description = "CloudWatch log group name"
  value       = aws_cloudwatch_log_group.console.name
}

output "instance_role_arn" {
  description = "Console instance IAM role ARN"
  value       = aws_iam_role.console.arn
}

output "internal_only" {
  description = "Whether Console is in internal-only mode (behind AC/NHP)"
  value       = var.internal_only
}

output "console_port" {
  description = "Console port number"
  value       = var.console_port
}

output "public_url" {
  description = "Console public URL (for frontend VITE_LOGIN_URL)"
  value       = var.internal_only ? "https://${var.console_app_id}${var.ac_domain}" : "https://${var.domain_name}"
}

output "public_url_ssm_parameter" {
  description = "SSM parameter name storing console public URL"
  value       = aws_ssm_parameter.console_public_url.name
}
