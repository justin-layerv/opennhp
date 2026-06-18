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

output "vpc_endpoint_security_group_id" {
  description = "Security group ID shared by interface VPC endpoints."
  value       = aws_security_group.vpc_endpoints.id
}

output "isolated_subnet_ids" {
  description = "Isolated subnet IDs"
  value       = aws_subnet.isolated[*].id
}
