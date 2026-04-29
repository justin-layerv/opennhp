# QURL FRP Server Module Outputs

output "security_group_id" {
  description = "FRP server security group ID"
  value       = aws_security_group.frps.id
}

output "cloud_map_dns_name" {
  description = "Cloud Map DNS name for FRP server discovery"
  value       = "frps.${var.namespace_name}"
}

output "asg_name" {
  description = "Auto Scaling Group name"
  value       = aws_autoscaling_group.frps.name
}

output "log_group_name" {
  description = "CloudWatch log group name"
  value       = aws_cloudwatch_log_group.frps.name
}

output "instance_role_arn" {
  description = "FRP server instance IAM role ARN"
  value       = aws_iam_role.frps.arn
}

output "ssm_image_tag_parameter" {
  description = "SSM parameter name for the deployed image tag"
  value       = aws_ssm_parameter.image_tag.name
}
