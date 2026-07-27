output "security_group_id" {
  description = "Cross-module target SG id — the handoff the resolver follows"
  value       = aws_security_group.clean_cross_module.id
}
