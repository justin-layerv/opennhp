output "vpc_id" {
  description = "VPC ID"
  value       = module.networking.vpc_id
}

output "nlb_dns_name" {
  description = "NLB DNS name for NHP server"
  value       = module.compute.nlb_dns_name
}

output "server_repo_url" {
  description = "ECR repository URL for NHP server"
  value       = module.ecr.server_repo_url
}

output "ac_repo_url" {
  description = "ECR repository URL for NHP AC"
  value       = module.ecr.ac_repo_url
}

output "github_actions_role_arn" {
  description = "GitHub Actions IAM role ARN"
  value       = module.ecr.github_actions_role_arn
}

output "etcd_endpoint" {
  description = "etcd endpoint for multi-tenant configuration"
  value       = module.data.etcd_endpoint
}

output "cloudmap_service_dns" {
  description = "Cloud Map DNS name for server discovery"
  value       = module.compute.cloudmap_service_dns
}

output "ac_nlb_dns" {
  description = "AC NLB DNS name (HTTPS endpoint)"
  value       = var.deploy_ac ? module.ac[0].nlb_dns_name : null
}

output "ac_fqdn" {
  description = "AC fully qualified domain name"
  value       = var.deploy_ac && var.hosted_zone != null ? module.ac[0].fqdn : null
}

output "dns_fqdn" {
  description = "DNS fully qualified domain name for NHP server"
  value       = var.hosted_zone != null ? module.dns[0].fqdn : null
}

# ASG names for CI/CD instance refresh
output "asg_name" {
  description = "NHP Server Auto Scaling Group name"
  value       = module.compute.asg_name
}

output "ac_asg_name" {
  description = "AC Auto Scaling Group name"
  value       = var.deploy_ac ? module.ac[0].asg_name : null
}

# Traefik plugins bucket (for traefik-plugins repo)
output "plugin_bucket_name" {
  description = "S3 bucket name for Traefik plugins"
  value       = var.deploy_ac ? module.ac[0].plugin_bucket_name : null
}

output "plugin_bucket_arn" {
  description = "S3 bucket ARN for Traefik plugins"
  value       = var.deploy_ac ? module.ac[0].plugin_bucket_arn : null
}

# RDS outputs
output "rds_endpoint" {
  description = "RDS Aurora cluster endpoint"
  value       = var.deploy_rds ? module.rds[0].cluster_endpoint : null
}

output "rds_reader_endpoint" {
  description = "RDS Aurora cluster reader endpoint"
  value       = var.deploy_rds ? module.rds[0].cluster_reader_endpoint : null
}

output "rds_port" {
  description = "RDS Aurora cluster port"
  value       = var.deploy_rds ? module.rds[0].cluster_port : null
}

output "rds_database_name" {
  description = "RDS database name"
  value       = var.deploy_rds ? module.rds[0].database_name : null
}

output "rds_secret_arn" {
  description = "Secrets Manager ARN for RDS credentials"
  value       = var.deploy_rds ? module.rds[0].secret_arn : null
}

output "rds_security_group_id" {
  description = "Security group ID for RDS access"
  value       = var.deploy_rds ? module.rds[0].security_group_id : null
}

# Console outputs
output "console_url" {
  description = "Console application URL"
  value       = var.deploy_console && var.deploy_rds ? module.console[0].console_url : null
}

output "console_alb_dns" {
  description = "Console ALB DNS name"
  value       = var.deploy_console && var.deploy_rds ? module.console[0].alb_dns_name : null
}

output "console_repo_url" {
  description = "ECR repository URL for Console"
  value       = module.ecr.console_repo_url
}
