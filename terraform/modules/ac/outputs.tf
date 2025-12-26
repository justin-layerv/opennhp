# AC Module Outputs

output "nlb_dns_name" {
  description = "AC NLB DNS name"
  value       = aws_lb.ac.dns_name
}

output "nlb_arn" {
  description = "AC NLB ARN"
  value       = aws_lb.ac.arn
}

output "nlb_zone_id" {
  description = "AC NLB zone ID for Route 53"
  value       = aws_lb.ac.zone_id
}

output "fqdn" {
  description = "AC fully qualified domain name"
  value       = var.enable_cloudfront ? aws_route53_record.ac_cloudfront[0].fqdn : aws_route53_record.ac[0].fqdn
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

output "plugin_bucket_arn" {
  description = "S3 bucket ARN for Traefik plugins"
  value       = aws_s3_bucket.plugins.arn
}

output "plugin_bucket_name" {
  description = "S3 bucket name for Traefik plugins"
  value       = aws_s3_bucket.plugins.id
}

output "ac_secret_arn" {
  description = "ARN of the AC secret containing the private key"
  value       = aws_secretsmanager_secret.ac.arn
}
