# Outputs consumed by the nhp-side qurl-service stack and operator
# runbooks. A paired follow-up PR registers the qurl-service ECS
# service against `target_group_arn` and writes its task SG ingress
# rule referencing `alb_security_group_id`.

output "alb_arn" {
  description = "ARN of the bootstrap application load balancer."
  value       = aws_lb.this.arn
}

output "alb_dns_name" {
  description = "Public DNS name AWS assigns to the bootstrap ALB. The Route53 alias for `var.dns_name` (module-managed same-account when `manage_dns_alias=true`, or root-cross-account-managed via `aws_route53_record.bootstrap_alb_cross_account`) points at this."
  value       = aws_lb.this.dns_name
}

output "alb_zone_id" {
  description = "Hosted zone ID for the bootstrap ALB; used by alias records pointing at it (the module's own `alb_alias` same-account, or the root `aws_route53_record.bootstrap_alb_cross_account` cross-account)."
  value       = aws_lb.this.zone_id
}

# NOTE: `alb_listener_arn` is deliberately NOT exported. Surfacing it
# would invite future callers to attach additional path-based listener
# rules — which violates the "narrow surface" invariant this stack is
# built around. If a future endpoint genuinely needs to live on this
# ALB, any caller can fetch the ARN with `terraform state show` once,
# but the absence of the output is the cheapest available signal that
# extending this ALB is not the intended path.

output "target_group_arn" {
  description = "Target group ARN for qurl-service. The qurl-service ECS service (intra-repo in nhp) registers against this via `aws_ecs_service.load_balancer { target_group_arn = ... }`. Wired in a paired follow-up PR — consumed as `module.bootstrap_alb[0].target_group_arn` from nhp's root, surfaced at the root level via `output.bootstrap_alb_target_group_arn`."
  value       = aws_lb_target_group.qurl_service.arn
}

output "alb_security_group_id" {
  description = "Bootstrap ALB security group ID. The qurl-service task SG (intra-repo, in `terraform/modules/qurl-service/`) must add an ingress rule on `var.target_port` referencing this SG ID — that's the actual access control between this ALB and qurl-service ENIs (the ALB-side egress is widened to `var.vpc_cidr_block` because reaching across to the task SG ID directly is brittle on the egress direction; see `security_groups.tf` header)."
  value       = aws_security_group.alb.id
}

output "web_acl_arn" {
  description = "WAFv2 WebACL ARN. Surfaced so a follow-up can attach `aws_wafv2_web_acl_logging_configuration` against THIS ACL — WAF logging is a recommended follow-up (out of scope here) so the WAF rules' blocked-request payloads are inspectable for incident response."
  value       = aws_wafv2_web_acl.this.arn
}

output "alb_access_logs_bucket" {
  description = "S3 bucket name receiving ALB access logs. CloudTrail data events on this bucket are out-of-stack; configure if/when the platform's broader audit-log strategy lands."
  value       = aws_s3_bucket.alb_access_logs.id
}

output "athena_query_results_bucket" {
  description = "S3 bucket name for Athena query results against the access-log bucket. 30d retention by default — operator runs CTAS / SELECT queries against the access-log bucket and outputs land here."
  value       = aws_s3_bucket.athena_query_results.id
}

output "alerts_topic_arn" {
  description = "SNS topic ARN that this stack's alarms publish to. alerts-infra (the org-wide AWS Chatbot home) subscribes to this topic via cross-account subscription — producer keeps SNS, alerts-infra owns chat-platform routing."
  value       = aws_sns_topic.alerts.arn
}

output "certificate_arn" {
  description = "ACM cert ARN attached to the HTTPS listener (provisioned in-stack when `provision_certificate=true`, else `existing_certificate_arn`). Non-empty after a successful module apply: the listener's lifecycle.precondition rejects the misconfigured combo (provision_certificate=false + empty existing_certificate_arn) before the listener resource lands."
  value       = local.effective_certificate_arn
}
