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

output "task_definition_arn" {
  description = "Terraform-registered qurl-service task definition ARN. Live proof must compare this with the running ECS service/task revision."
  value       = aws_ecs_task_definition.qurl.arn
}

# The effective task shape is NOT the container reservation: Fargate accepts
# only a fixed set of CPU/memory combinations, so memory is rounded up to a
# whole GB (and CPU is raised to at least 512 when the ADOT sidecar is on).
# Exported so a root that pins this shape somewhere else — notably a publisher
# role's ecs:task-cpu / ecs:task-memory IAM conditions — can fence its copy
# against the real value instead of re-deriving the arithmetic by hand.
output "task_cpu" {
  description = "Effective Fargate task-level CPU units registered by this module."
  value       = local.task_cpu
}

output "task_memory" {
  description = "Effective Fargate task-level memory (MiB) registered by this module, rounded up to a whole GB for CPU/memory-combination validity."
  value       = local.task_memory
}

output "runtime_image_uri" {
  description = "Complete immutable qurl-service repository@sha256 URI when the module is in digest-pinned mode; null on the legacy tag-managed path."
  value       = var.image_uri
}

output "runtime_source_revision" {
  description = "Full qurl-service source revision paired with runtime_image_uri and rendered into QURL_RUNTIME_SOURCE_REVISION; null on the legacy tag-managed path."
  value       = var.source_revision
}

output "alb_dns_name" {
  description = "Primary ALB DNS name. Internet-facing in public mode and internal in private mode."
  value       = aws_lb.qurl.dns_name
}

output "alb_zone_id" {
  description = "ALB hosted zone ID"
  value       = aws_lb.qurl.zone_id
}

output "alb_arn" {
  description = "Primary ALB ARN."
  value       = aws_lb.qurl.arn
}

output "alb_is_internal" {
  description = "True when the primary ALB is private and has no public CIDR ingress."
  value       = !var.public_ingress_enabled
}

output "target_group_arn" {
  description = "Primary target group ARN used for live health convergence proof."
  value       = aws_lb_target_group.qurl.arn
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

# ============================================================================
# Resource-lifecycle SQS queue outputs
# ============================================================================
# Lit only when `qurl_scanner_lambda_enabled` is true; otherwise the queue
# resource has `count = 0` and these outputs resolve to `null` via the
# `try()` fallback. The activation PR consumes the URL output to wire
# `WEBHOOK_EVENTS_SQS_QUEUE_URL` on the qurl-api ECS task.

output "resource_lifecycle_queue_arn" {
  description = "ARN of the resource-lifecycle SQS queue. Null when `qurl_scanner_lambda_enabled = false`."
  value       = try(aws_sqs_queue.resource_lifecycle_queue[0].arn, null)
}

output "resource_lifecycle_queue_url" {
  description = "URL of the resource-lifecycle SQS queue (for `WEBHOOK_EVENTS_SQS_QUEUE_URL` on qurl-api). Null when `qurl_scanner_lambda_enabled = false`."
  value       = try(aws_sqs_queue.resource_lifecycle_queue[0].url, null)
}

output "resource_lifecycle_queue_name" {
  description = "Name of the resource-lifecycle SQS queue (for CloudWatch dashboards). Null when `qurl_scanner_lambda_enabled = false`."
  value       = try(aws_sqs_queue.resource_lifecycle_queue[0].name, null)
}

output "resource_lifecycle_queue_dlq_arn" {
  description = "ARN of the resource-lifecycle DLQ. Null when `qurl_scanner_lambda_enabled = false`."
  value       = try(aws_sqs_queue.resource_lifecycle_queue_dlq[0].arn, null)
}

output "resource_lifecycle_queue_dlq_url" {
  description = "URL of the resource-lifecycle DLQ. Null when `qurl_scanner_lambda_enabled = false`."
  value       = try(aws_sqs_queue.resource_lifecycle_queue_dlq[0].url, null)
}
