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

# QURL Link (when external_dns=true, these are needed for manual DNS setup)
output "qurl_link_acm_validation_records" {
  description = "ACM certificate validation DNS records (create in Route53 when qurl_link_external_dns=true)"
  value = var.deploy_qurl_link && var.qurl_link_external_dns ? {
    for dvo in aws_acm_certificate.qurl_link[0].domain_validation_options : dvo.domain_name => {
      name  = dvo.resource_record_name
      type  = dvo.resource_record_type
      value = dvo.resource_record_value
    }
  } : null
}

output "qurl_link_cloudfront_domain" {
  description = "CloudFront distribution domain name for qurl.link alias record"
  value       = var.deploy_qurl_link ? module.qurl_link[0].cloudfront_domain_name : null
}

output "qurl_link_cloudfront_zone_id" {
  description = "CloudFront distribution hosted zone ID for Route53 alias record"
  value       = var.deploy_qurl_link ? module.qurl_link[0].cloudfront_hosted_zone_id : null
}

output "qurl_link_url_ssm_param" {
  description = "SSM parameter name containing the QURL link URL (for CI smoke tests)"
  value       = aws_ssm_parameter.qurl_link_url.name
}

# ============================================================================
# KMS and Alerting Outputs
# ============================================================================

output "secrets_kms_key_arn" {
  description = "KMS key ARN for Secrets Manager encryption"
  value       = module.kms.secrets_key_arn
}

output "logs_kms_key_arn" {
  description = "KMS key ARN for CloudWatch Logs encryption"
  value       = module.kms.logs_key_arn
}

output "sns_topic_arn" {
  description = "SNS topic ARN for alerts"
  value       = module.monitoring.sns_topic_arn
}

# ============================================================================
# Blue/Green Deployment Outputs
# ============================================================================

output "blue_green_enabled" {
  description = "Whether blue/green deployment is enabled"
  value       = module.compute.blue_green_enabled
}

output "green_asg_name" {
  description = "Green ASG name for CI/CD scripts (null if blue/green not enabled)"
  value       = module.compute.green_asg_name
}

output "ssm_active_color_parameter" {
  description = "SSM parameter name for active deployment color"
  value       = module.compute.ssm_active_color_parameter
}

output "ssm_green_image_tag_parameter" {
  description = "SSM parameter name for green ASG image tag"
  value       = module.compute.ssm_green_image_tag_parameter
}

# ============================================================================
# AC Blue/Green Deployment Outputs
# ============================================================================

output "ac_blue_green_enabled" {
  description = "Whether blue/green deployment is enabled for AC"
  value       = var.deploy_ac ? module.ac[0].blue_green_enabled : false
}

output "ac_green_asg_name" {
  description = "AC Green ASG name for CI/CD scripts (null if not enabled)"
  value       = var.deploy_ac ? module.ac[0].green_asg_name : null
}

output "ac_ssm_active_color_parameter" {
  description = "SSM parameter name for AC active deployment color"
  value       = var.deploy_ac ? module.ac[0].ssm_active_color_parameter : null
}

output "ac_ssm_green_image_tag_parameter" {
  description = "SSM parameter name for AC green ASG image tag"
  value       = var.deploy_ac ? module.ac[0].ssm_green_image_tag_parameter : null
}

# ============================================================================
# Canary Deployment Outputs
# ============================================================================

output "canary_state_machine_arn" {
  description = "Step Functions state machine ARN for canary deployment"
  value       = var.enable_canary_deployment ? module.canary_deployment[0].state_machine_arn : null
}

output "canary_composite_alarm_name" {
  description = "CloudWatch composite alarm name for canary health"
  value       = var.enable_canary_deployment ? module.canary_deployment[0].composite_alarm_name : null
}

# ============================================================================
# Status Page Outputs
# ============================================================================

output "status_page_url" {
  description = "Status page URL"
  value       = var.deploy_status_page ? module.status_page[0].status_url : null
}

output "status_page_api_url" {
  description = "Status page API endpoint URL"
  value       = var.deploy_status_page ? module.status_page[0].api_url : null
}

output "status_page_cloudfront_distribution_id" {
  description = "CloudFront distribution ID for status page (for cache invalidation)"
  value       = var.deploy_status_page ? module.status_page[0].cloudfront_distribution_id : null
}

# ============================================================================
# Cost Analytics Outputs
# ============================================================================

output "cost_analytics_bucket" {
  description = "S3 bucket for AWS cost data (mgmt account)"
  value       = var.deploy_cost_analytics ? module.cost_analytics[0].cost_data_bucket_name : null
}

# ============================================================================
# Billing Outputs
# ============================================================================

output "billing_api_url" {
  description = "Billing API Gateway invoke URL"
  value       = var.deploy_billing ? module.billing[0].api_url : null
}

output "billing_usage_events_queue_url" {
  description = "SQS queue URL for billing usage events"
  value       = var.deploy_billing ? module.billing[0].usage_events_queue_url : null
}

output "billing_checkout_session_lambda_name" {
  description = "Billing checkout session Lambda function name"
  value       = var.deploy_billing ? module.billing[0].checkout_session_lambda_function_name : null
}

output "billing_stripe_webhook_lambda_name" {
  description = "Billing Stripe webhook Lambda function name"
  value       = var.deploy_billing ? module.billing[0].stripe_webhook_lambda_function_name : null
}

output "billing_usage_reporter_lambda_name" {
  description = "Billing usage reporter Lambda function name"
  value       = var.deploy_billing ? module.billing[0].usage_reporter_lambda_function_name : null
}

output "billing_reconciliation_lambda_name" {
  description = "Billing reconciliation Lambda function name"
  value       = var.deploy_billing ? module.billing[0].reconciliation_lambda_function_name : null
}

output "billing_payment_grace_lambda_name" {
  description = "Billing payment grace Lambda function name"
  value       = var.deploy_billing ? module.billing[0].payment_grace_lambda_function_name : null
}

output "billing_invoices_lambda_name" {
  description = "Billing invoices Lambda function name"
  value       = var.deploy_billing ? module.billing[0].invoices_lambda_function_name : null
}
