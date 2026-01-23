# Redis Cluster Module Outputs

output "endpoint" {
  description = "Redis cluster endpoint for client connections"
  value       = aws_elasticache_serverless_cache.redis.endpoint[0].address
}

output "port" {
  description = "Redis cluster port"
  value       = aws_elasticache_serverless_cache.redis.endpoint[0].port
}

output "reader_endpoint" {
  description = "Redis cluster reader endpoint (same as endpoint for serverless)"
  value       = aws_elasticache_serverless_cache.redis.reader_endpoint[0].address
}

output "arn" {
  description = "Redis cluster ARN"
  value       = aws_elasticache_serverless_cache.redis.arn
}

output "security_group_id" {
  description = "Security group ID for Redis cluster"
  value       = aws_security_group.redis.id
}

output "connection_url" {
  description = "Redis connection URL for application configuration"
  value       = "rediss://${aws_elasticache_serverless_cache.redis.endpoint[0].address}:${aws_elasticache_serverless_cache.redis.endpoint[0].port}"
}
