# RDS Module Outputs

output "cluster_endpoint" {
  description = "Writer endpoint for the Aurora cluster"
  value       = aws_rds_cluster.main.endpoint
}

output "cluster_reader_endpoint" {
  description = "Reader endpoint for the Aurora cluster"
  value       = aws_rds_cluster.main.reader_endpoint
}

output "cluster_port" {
  description = "Port for the Aurora cluster"
  value       = aws_rds_cluster.main.port
}

output "cluster_id" {
  description = "Aurora cluster identifier"
  value       = aws_rds_cluster.main.id
}

output "cluster_arn" {
  description = "Aurora cluster ARN"
  value       = aws_rds_cluster.main.arn
}

output "database_name" {
  description = "Name of the default database"
  value       = aws_rds_cluster.main.database_name
}

output "master_username" {
  description = "Master username"
  value       = aws_rds_cluster.main.master_username
}

output "secret_arn" {
  description = "Secrets Manager secret ARN containing credentials"
  value       = aws_secretsmanager_secret.rds.arn
}

output "secret_name" {
  description = "Secrets Manager secret name"
  value       = aws_secretsmanager_secret.rds.name
}

output "security_group_id" {
  description = "Security group ID for RDS"
  value       = aws_security_group.rds.id
}

output "connection_string" {
  description = "PostgreSQL connection string (without password)"
  value       = "postgresql://${aws_rds_cluster.main.master_username}@${aws_rds_cluster.main.endpoint}:${aws_rds_cluster.main.port}/${aws_rds_cluster.main.database_name}?sslmode=require"
}
