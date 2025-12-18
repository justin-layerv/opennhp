output "namespace_id" {
  description = "Service Discovery namespace ID"
  value       = aws_service_discovery_private_dns_namespace.main.id
}

output "namespace_name" {
  description = "Service Discovery namespace name"
  value       = aws_service_discovery_private_dns_namespace.main.name
}

output "etcd_endpoint" {
  description = "etcd client endpoint (first member for simple configs)"
  value       = var.multi_tenant ? "etcd-0.${aws_service_discovery_private_dns_namespace.main.name}:2379" : null
}

output "etcd_endpoints" {
  description = "All etcd member endpoints for client configuration"
  value = var.multi_tenant ? [
    for i in range(local.etcd_cluster_size) :
    "etcd-${i}.${aws_service_discovery_private_dns_namespace.main.name}:2379"
  ] : []
}

output "etcd_secret_arn" {
  description = "etcd credentials secret ARN"
  value       = var.multi_tenant ? aws_secretsmanager_secret.etcd[0].arn : null
}

output "etcd_tls_secret_arn" {
  description = "etcd TLS certificates secret ARN"
  value       = var.multi_tenant ? aws_secretsmanager_secret.etcd_tls[0].arn : null
}

output "etcd_security_group_id" {
  description = "etcd security group ID"
  value       = var.multi_tenant ? aws_security_group.etcd[0].id : null
}
