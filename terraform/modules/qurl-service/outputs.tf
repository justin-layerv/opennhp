# QURL Service Module Outputs

output "cluster_name" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.qurl.name
}

output "cluster_arn" {
  description = "ECS cluster ARN"
  value       = aws_ecs_cluster.qurl.arn
}

output "service_name" {
  description = "ECS service name"
  value       = aws_ecs_service.qurl.name
}

output "service_arn" {
  description = "ECS service ARN"
  value       = aws_ecs_service.qurl.id
}

output "alb_dns_name" {
  description = "ALB DNS name"
  value       = aws_lb.qurl.dns_name
}

output "alb_zone_id" {
  description = "ALB hosted zone ID"
  value       = aws_lb.qurl.zone_id
}

output "alb_arn" {
  description = "ALB ARN"
  value       = aws_lb.qurl.arn
}

output "internal_alb_dns_name" {
  description = "Internal ALB DNS name (null when internal_alb_enabled = false). Root TF aliases internal_domain_name to this hostname."
  value       = var.internal_alb_enabled ? aws_lb.qurl_internal[0].dns_name : null
}

output "internal_alb_zone_id" {
  description = "Internal ALB hosted zone ID for Route 53 alias targets (null when internal_alb_enabled = false)."
  value       = var.internal_alb_enabled ? aws_lb.qurl_internal[0].zone_id : null
}

output "security_group_id" {
  description = "ECS tasks security group ID"
  value       = aws_security_group.ecs.id
}

output "api_endpoint" {
  description = "QURL API endpoint URL"
  value       = var.domain_name != null ? "https://${var.domain_name}" : "http://${aws_lb.qurl.dns_name}"
}

output "log_group_name" {
  description = "CloudWatch log group name"
  value       = aws_cloudwatch_log_group.qurl.name
}

output "ecs_cluster_ssm_param" {
  description = "SSM parameter name containing ECS cluster name (for CI)"
  value       = aws_ssm_parameter.ecs_cluster.name
}

output "ecs_service_ssm_param" {
  description = "SSM parameter name containing ECS service name (for CI)"
  value       = aws_ssm_parameter.ecs_service.name
}

# ============================================================================
# Wiring-fence echoes — consumed ONLY by the root-level
# `check "bootstrap_alb_qurl_attachment_wired"` block in terraform/main.tf.
# DO NOT consume from non-fence contexts: these outputs are intentionally
# `var.foo` round-trips, NOT derived module state. They exist to let the
# root-level check detect what was actually threaded into this module
# (which `try()` at the call site can't disambiguate).
# ============================================================================

# See PR #2082 for the empty-TG / 503 outage these guard against and
# issue #2083 for the structural fence story. Null = wiring missing OR
# deploy_bootstrap_alb=false (both legitimate during pre-Wave-5 posture);
# the root check disambiguates by also gating on var.deploy_bootstrap_alb.
output "bootstrap_alb_target_group_arn" {
  description = "Echo of var.bootstrap_alb_target_group_arn — consumed by the root-level attachment-fence check. Null when no attachment is configured."
  value       = var.bootstrap_alb_target_group_arn
}

output "bootstrap_alb_security_group_id" {
  description = "Echo of var.bootstrap_alb_security_group_id — consumed by the root-level attachment-fence check. Null when no attachment is configured."
  value       = var.bootstrap_alb_security_group_id
}
