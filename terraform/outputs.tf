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
