output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "VPC CIDR block"
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  description = "Public subnet IDs"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "Private subnet IDs"
  value       = aws_subnet.private[*].id
}

output "private_subnet_cidr_blocks" {
  description = "Private subnet CIDR blocks"
  value       = aws_subnet.private[*].cidr_block
}

output "private_route_table_ids" {
  description = "Active private route table IDs. Consumers that add cross-VPC routes must use these stable resource outputs instead of mutable Name-tag discovery."
  value       = local.active_private_route_table_ids
}

output "availability_zones" {
  description = "The three availability zones used by this networking module."
  value       = local.azs
}

output "vpc_endpoint_security_group_id" {
  description = "Security group ID shared by interface VPC endpoints."
  value       = aws_security_group.vpc_endpoints.id
}

output "isolated_subnet_ids" {
  description = "Isolated subnet IDs"
  value       = aws_subnet.isolated[*].id
}
