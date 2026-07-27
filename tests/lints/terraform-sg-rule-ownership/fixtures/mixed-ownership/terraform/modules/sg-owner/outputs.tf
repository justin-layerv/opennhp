output "security_group_id" {
  description = "Exported SG id — lets another module attach rules to it"
  value       = aws_security_group.bad_cross_module_redis.id
}
