# Demo Gateway Module Outputs

output "nlb_dns_name" {
  description = "Demo Gateway NLB DNS name"
  value       = aws_lb.demo_gateway.dns_name
}

output "nlb_arn" {
  description = "Demo Gateway NLB ARN"
  value       = aws_lb.demo_gateway.arn
}

output "nlb_zone_id" {
  description = "Demo Gateway NLB zone ID for Route 53"
  value       = aws_lb.demo_gateway.zone_id
}

output "fqdn" {
  description = "Demo Gateway fully qualified domain name"
  value       = var.hosted_zone_id != null ? aws_route53_record.demo_gateway[0].fqdn : var.domain_name
}

output "asg_name" {
  description = "Auto Scaling Group name"
  value       = aws_autoscaling_group.demo_gateway.name
}

output "security_group_id" {
  description = "Demo Gateway security group ID"
  value       = aws_security_group.demo_gateway.id
}

output "log_group_name" {
  description = "CloudWatch log group name"
  value       = aws_cloudwatch_log_group.demo_gateway.name
}

output "instance_role_arn" {
  description = "Demo Gateway instance IAM role ARN"
  value       = aws_iam_role.demo_gateway.arn
}
