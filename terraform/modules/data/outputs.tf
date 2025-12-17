output "namespace_id" {
  description = "Service Discovery namespace ID"
  value       = aws_service_discovery_private_dns_namespace.main.id
}

output "namespace_name" {
  description = "Service Discovery namespace name"
  value       = aws_service_discovery_private_dns_namespace.main.name
}

output "etcd_endpoint" {
  description = "etcd endpoint"
  value       = var.multi_tenant ? "etcd.${aws_service_discovery_private_dns_namespace.main.name}:2379" : null
}

output "etcd_secret_arn" {
  description = "etcd credentials secret ARN"
  value       = var.multi_tenant ? aws_secretsmanager_secret.etcd[0].arn : null
}

output "etcd_security_group_id" {
  description = "etcd security group ID"
  value       = var.multi_tenant ? aws_security_group.etcd[0].id : null
}
