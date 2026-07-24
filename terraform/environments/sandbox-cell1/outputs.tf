# Outputs for the sandbox cell1 root.

output "vpc_id" {
  description = "cell1 VPC ID."
  value       = module.networking.vpc_id
}

output "vpc_cidr" {
  description = "cell1 VPC CIDR (non-overlapping with cell0 10.100.0.0/16 and relay 10.101.0.0/16)."
  value       = module.networking.vpc_cidr
}

output "nlb_dns_name" {
  description = "cell1 public NLB DNS name (native SDK UDP:62206 knock endpoint)."
  value       = module.compute.nlb_dns_name
}

output "nlb_arn" {
  description = "cell1 public NLB ARN."
  value       = module.compute.nlb_arn
}

output "udp_listener_arn" {
  description = "cell1 public NLB UDP:62206 listener ARN. Also published to SSM at /sandbox-cell1/nhp/server/udp-listener-arn by modules/compute for the control/deploy plane."
  value       = module.compute.nlb_udp_listener_arn
}

output "udp_listener_arn_ssm_path" {
  description = "SSM parameter path carrying the cell1 UDP listener ARN (distinct from cell0's /sandbox/nhp/server/udp-listener-arn)."
  value       = "/${var.environment}/nhp/server/udp-listener-arn"
}

output "server_role_arn" {
  description = "cell1 NHP server IAM role ARN (assigned-cell Connector Authority caller identity)."
  value       = module.compute.server_role_arn
}

output "server_public_key_b64" {
  description = "cell1 NHP server-identity X25519 public key (for agent knock-packet HMAC validation on this cell)."
  value       = module.compute.server_public_key_b64
}

output "asg_name" {
  description = "cell1 blue NHP server ASG name (for CI/CD)."
  value       = module.compute.asg_name
}

output "cell_fqdn" {
  description = "Public per-cell DNS name resolving to cell1's NLB."
  value       = module.dns.fqdn
}
