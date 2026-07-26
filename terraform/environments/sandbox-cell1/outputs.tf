# Outputs for the sandbox cell1 root.

output "vpc_id" {
  description = "cell1 VPC ID."
  value       = module.networking.vpc_id
}

output "vpc_cidr" {
  description = "cell1 VPC CIDR (non-overlapping with cell0 10.100.0.0/16, relay 10.101.0.0/16, Control 10.102.0.0/16, and the proof runner 10.103.0.0/28)."
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

output "qurl_service_runtime_contract_parameter" {
  description = "Canonical SSM String parameter promoted atomically by the qurl-service main workflow."
  value       = aws_ssm_parameter.qurl_service_runtime_contract.name
}

output "qurl_service_publisher_role_arn" {
  description = "Main-ref-only qurl-service role scoped to the cell1 promotion record and ECS deployment surface."
  value       = aws_iam_role.qurl_service_publisher.arn
}

output "qurl_service_cluster_name" {
  description = "Cell1 qurl-service ECS cluster name; null while deploy_qurl_service=false."
  value       = try(module.qurl_service[0].cluster_name, null)
}

output "qurl_service_service_name" {
  description = "Cell1 qurl-service ECS service name; null while deploy_qurl_service=false."
  value       = try(module.qurl_service[0].service_name, null)
}

output "qurl_service_task_definition_arn" {
  description = "Terraform-registered cell1 qurl-service task definition; compare against the live service and running task."
  value       = try(module.qurl_service[0].task_definition_arn, null)
}

output "qurl_service_private_endpoint" {
  description = "Private cell-local qurl-service origin; null while deploy_qurl_service=false. This is not a public API endpoint."
  value       = local.qurl_service_deployable ? local.qurl_service_private_origin : null
}

output "qurl_service_internal_alb_arn" {
  description = "Cell1 private qurl-service ALB ARN; null while deploy_qurl_service=false."
  value       = try(module.qurl_service[0].alb_arn, null)
}

output "qurl_service_target_group_arn" {
  description = "Cell1 qurl-service target group used for healthy-host proof; null while deploy_qurl_service=false."
  value       = try(module.qurl_service[0].target_group_arn, null)
}

output "qurl_service_runtime_image_uri" {
  description = "Exact repository@sha256 image URI from the single atomic runtime contract; null while deploy_qurl_service=false."
  value       = try(module.qurl_service[0].runtime_image_uri, null)
}

output "qurl_service_runtime_source_revision" {
  description = "Full 40-hex qurl-service source revision paired atomically with runtime_image_uri; null while deploy_qurl_service=false."
  value       = try(module.qurl_service[0].runtime_source_revision, null)
}
