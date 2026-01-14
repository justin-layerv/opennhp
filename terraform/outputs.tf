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

# Plugin bucket (unified for all plugins)
output "plugin_bucket_name" {
  description = "S3 bucket name for plugins (NHP Server and Traefik)"
  value       = module.plugins.bucket_name
}

output "plugin_bucket_arn" {
  description = "S3 bucket ARN for plugins"
  value       = module.plugins.bucket_arn
}

output "plugin_upload_policy_arn" {
  description = "IAM policy ARN for uploading plugins (attach to GitHub Actions role)"
  value       = module.plugins.upload_policy_arn
}

output "plugin_download_policy_arn" {
  description = "IAM policy ARN for downloading plugins (attached to EC2 instance roles)"
  value       = module.plugins.download_policy_arn
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

# Demo Gateway outputs
output "demo_gateway_nlb_dns" {
  description = "Demo Gateway NLB DNS name"
  value       = var.deploy_demo_gateway ? module.demo_gateway[0].nlb_dns_name : null
}

output "demo_gateway_fqdn" {
  description = "Demo Gateway fully qualified domain name"
  value       = var.deploy_demo_gateway ? module.demo_gateway[0].fqdn : null
}

output "demo_gateway_asg_name" {
  description = "Demo Gateway Auto Scaling Group name"
  value       = var.deploy_demo_gateway ? module.demo_gateway[0].asg_name : null
}

# Console EC2 outputs
output "console_ec2_nlb_dns" {
  description = "Console EC2 NLB DNS name"
  value       = var.deploy_console_ec2 && var.deploy_rds ? module.console_ec2[0].nlb_dns_name : null
}

output "console_ec2_api_endpoint" {
  description = "Console EC2 API endpoint URL"
  value       = var.deploy_console_ec2 && var.deploy_rds ? module.console_ec2[0].api_endpoint : null
}

output "console_ec2_asg_name" {
  description = "Console EC2 Auto Scaling Group name"
  value       = var.deploy_console_ec2 && var.deploy_rds ? module.console_ec2[0].asg_name : null
}

output "console_ec2_public_url" {
  description = "Console EC2 public URL (for frontend builds)"
  value       = var.deploy_console_ec2 && var.deploy_rds ? module.console_ec2[0].public_url : null
}

# ============================================================================
# Pluggable Storage Backend Outputs (DynamoDB for cloud, etcd for on-prem)
# DynamoDB and keypair infrastructure for per-AC assignment architecture
# See docs/design/PLUGGABLE_STORAGE_BACKEND.md for full design.
# ============================================================================

# DynamoDB Tables - Names
output "dynamodb_licenses_table_name" {
  description = "DynamoDB table name for licenses"
  value       = module.dynamodb.licenses_table_name
}

output "dynamodb_ac_assignments_table_name" {
  description = "DynamoDB table name for AC assignments"
  value       = module.dynamodb.ac_assignments_table_name
}

output "dynamodb_resources_table_name" {
  description = "DynamoDB table name for resources"
  value       = module.dynamodb.resources_table_name
}

# DynamoDB Tables - ARNs (for cross-stack references, monitoring, backups)
output "dynamodb_licenses_table_arn" {
  description = "DynamoDB table ARN for licenses"
  value       = module.dynamodb.licenses_table_arn
}

output "dynamodb_ac_assignments_table_arn" {
  description = "DynamoDB table ARN for AC assignments"
  value       = module.dynamodb.ac_assignments_table_arn
}

output "dynamodb_resources_table_arn" {
  description = "DynamoDB table ARN for resources"
  value       = module.dynamodb.resources_table_arn
}

# DynamoDB IAM Policies
output "dynamodb_read_policy_arn" {
  description = "IAM policy ARN for DynamoDB read access (for NHP Server)"
  value       = module.dynamodb.read_policy_arn
}

output "dynamodb_write_policy_arn" {
  description = "IAM policy ARN for DynamoDB write access (for Console)"
  value       = module.dynamodb.write_policy_arn
}

# NHP Keypair
output "nhp_registration_public_key" {
  description = "NHP registration public key (for AC config)"
  value       = module.nhp_keypair.registration_public_key
}

output "nhp_keypair_policy_arn" {
  description = "IAM policy ARN for NHP keypair access"
  value       = module.nhp_keypair.server_keypair_policy_arn
}
