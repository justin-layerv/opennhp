# Sandbox Environment
# Sources the root module with sandbox-specific configuration

module "nhp" {
  source = "../.."

  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }

  environment            = var.environment
  aws_region             = var.aws_region
  aws_account_id         = var.aws_account_id
  domain_name            = var.domain_name
  hosted_zone            = var.hosted_zone
  multi_tenant           = var.multi_tenant
  min_capacity           = var.min_capacity
  max_capacity           = var.max_capacity
  vpc_cidr               = var.vpc_cidr
  tags                   = var.tags
  is_primary_account     = var.is_primary_account
  primary_account_id     = var.primary_account_id
  github_org             = var.github_org
  github_repo            = var.github_repo
  deploy_ac              = var.deploy_ac
  acme_email             = var.acme_email
  terraform_state_bucket = var.terraform_state_bucket
  terraform_lock_table   = var.terraform_lock_table

  # AC configuration
  ac_auth_service_id = var.ac_auth_service_id
  ac_resource_ids    = var.ac_resource_ids

  # Security services
  enable_cloudtrail = var.enable_cloudtrail

  # GitHub OIDC - set to false if org manages centrally or SCP blocks creation
  create_oidc_provider = var.create_oidc_provider

  # Server configuration
  dev_mode      = var.dev_mode
  resource_mode = var.resource_mode
  auth_url      = var.auth_url

  # Monitoring
  enable_slack_notifications = var.enable_slack_notifications
  slack_workspace_id         = var.slack_workspace_id
  slack_channel_id           = var.slack_channel_id

  # RDS
  deploy_rds              = var.deploy_rds
  rds_database_name       = var.rds_database_name
  rds_min_capacity        = var.rds_min_capacity
  rds_max_capacity        = var.rds_max_capacity
  rds_deletion_protection = var.rds_deletion_protection

  # Production domains (qurl.site, qurl.link)
  production_domains  = var.production_domains
  production_zone_ids = var.production_zone_ids

  # Deployment configuration
  image_tag = var.image_tag

  # NHP Server plugins
  server_plugins = var.server_plugins

  # Traefik plugins
  traefik_plugins = var.traefik_plugins

  # Plugin repos - repos that can assume the GitHub Actions role
  plugin_repos = var.plugin_repos

  # Demo Gateway
  deploy_demo_gateway            = var.deploy_demo_gateway
  demo_gateway_domain            = var.demo_gateway_domain
  demo_gateway_hosted_zone_id    = var.demo_gateway_hosted_zone_id
  demo_gateway_fallback_url      = var.demo_gateway_fallback_url
  cross_account_route53_role_arn = var.cross_account_route53_role_arn

  # Console EC2
  deploy_console_ec2 = var.deploy_console_ec2
  console_ec2_domain = var.console_ec2_domain
  console_cookie_domain = var.console_cookie_domain
}

# Re-export outputs
output "vpc_id" {
  value = module.nhp.vpc_id
}

output "nlb_dns_name" {
  value = module.nhp.nlb_dns_name
}

output "server_repo_url" {
  value = module.nhp.server_repo_url
}

output "ac_repo_url" {
  value = module.nhp.ac_repo_url
}

output "github_actions_role_arn" {
  value = module.nhp.github_actions_role_arn
}

output "etcd_endpoint" {
  value = module.nhp.etcd_endpoint
}

output "cloudmap_service_dns" {
  value = module.nhp.cloudmap_service_dns
}

output "ac_nlb_dns" {
  value = module.nhp.ac_nlb_dns
}

output "ac_fqdn" {
  value = module.nhp.ac_fqdn
}

output "dns_fqdn" {
  value = module.nhp.dns_fqdn
}

# ASG outputs for CI/CD
output "asg_name" {
  value = module.nhp.asg_name
}

output "ac_asg_name" {
  value = module.nhp.ac_asg_name
}

output "plugin_bucket_name" {
  value = module.nhp.plugin_bucket_name
}

output "plugin_bucket_arn" {
  value = module.nhp.plugin_bucket_arn
}

# RDS outputs
output "rds_endpoint" {
  value = module.nhp.rds_endpoint
}

output "rds_secret_arn" {
  value = module.nhp.rds_secret_arn
}

output "rds_database_name" {
  value = module.nhp.rds_database_name
}

# Console EC2 outputs
output "console_ec2_nlb_dns" {
  value = module.nhp.console_ec2_nlb_dns
}

output "console_ec2_api_endpoint" {
  value = module.nhp.console_ec2_api_endpoint
}

output "console_ec2_asg_name" {
  value = module.nhp.console_ec2_asg_name
}

# Demo Gateway outputs
output "demo_gateway_nlb_dns" {
  value = module.nhp.demo_gateway_nlb_dns
}

output "demo_gateway_fqdn" {
  value = module.nhp.demo_gateway_fqdn
}

output "demo_gateway_asg_name" {
  value = module.nhp.demo_gateway_asg_name
}

# Console repo
output "console_repo_url" {
  value = module.nhp.console_repo_url
}
