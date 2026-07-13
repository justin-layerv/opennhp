output "vpc_id" {
  description = "Dedicated relay DMZ VPC ID."
  value       = aws_vpc.relay.id
}

output "public_subnet_ids" {
  description = "Public ALB subnet IDs."
  value       = aws_subnet.public[*].id
}

output "relay_subnet_ids" {
  description = "Isolated relay-node subnet IDs."
  value       = aws_subnet.relay[*].id
}

output "relay_subnet_cidr_blocks" {
  description = "Exact relay subnet CIDRs routed to the main VPC."
  value       = local.relay_subnet_cidr_blocks
}

output "endpoint_subnet_ids" {
  description = "Isolated interface-endpoint subnet IDs."
  value       = aws_subnet.endpoint[*].id
}

output "availability_zones" {
  description = "The three availability zones used by every DMZ subnet tier."
  value       = local.azs
}

output "endpoint_security_group_id" {
  description = "Interface endpoint SG; modules/relay owns its relay-source ingress rule."
  value       = aws_security_group.endpoints.id
}

output "peering_connection_id" {
  description = "DMZ-to-main VPC peering connection ID."
  value       = aws_vpc_peering_connection.main.id
}

output "flow_log_group_name" {
  description = "DMZ VPC Flow Logs CloudWatch log group."
  value       = aws_cloudwatch_log_group.flow.name
}

output "resolver_log_group_name" {
  description = "DMZ Resolver query log CloudWatch log group."
  value       = aws_cloudwatch_log_group.resolver.name
}

output "logs_kms_key_arn" {
  description = "Dedicated KMS key for the DMZ Flow and Resolver log groups."
  value       = aws_kms_key.logs.arn
}

output "dns_blocked_metric_name" {
  description = "Metric emitted for blocked DMZ DNS queries."
  value       = one(aws_cloudwatch_log_metric_filter.dns_blocked.metric_transformation[*].name)
}

output "dns_blocked_metric_namespace" {
  description = "Namespace for the blocked-DNS metric."
  value       = one(aws_cloudwatch_log_metric_filter.dns_blocked.metric_transformation[*].namespace)
}
