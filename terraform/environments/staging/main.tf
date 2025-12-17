# Staging Environment
# Sources the root module with staging-specific configuration

module "nhp" {
  source = "../.."

  environment        = var.environment
  aws_region         = var.aws_region
  aws_account_id     = var.aws_account_id
  domain_name        = var.domain_name
  multi_tenant       = var.multi_tenant
  min_capacity       = var.min_capacity
  max_capacity       = var.max_capacity
  vpc_cidr           = var.vpc_cidr
  tags               = var.tags
  is_primary_account = var.is_primary_account
  primary_account_id = var.primary_account_id
  github_org         = var.github_org
  github_repo        = var.github_repo
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
