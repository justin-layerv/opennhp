# ── The cross-component contract to 5c (server-trusts-relay) ──
#
# 5c registers the relay as an NHP_RELAY peer in the server's relay.toml. The
# load-bearing field there is the relay PUBKEY (Noise IK auth + the server's
# lookupRelayPeer gate). The relay's IP is NOT registered: with
# DisableRelayPeerValidation=true (5c) the server authenticates the relay by
# pubkey alone and skips the CheckRecvAddress source-IP pin — so the
# shared-keypair fleet's many dynamic source IPs all authenticate, no registered
# IP needed.
output "secret_arn" {
  description = "ARN of the shared relay keypair secret consumed by this fleet."
  value       = var.relay_secret_arn
}

output "alb_dns_name" {
  description = "The relay ALB's AWS DNS name. The root-owned relay alias points here; a cross-account caller publishes its own alias against this."
  value       = aws_lb.relay.dns_name
}

output "alb_zone_id" {
  description = "The relay ALB's canonical hosted-zone ID, for a cross-account alias record."
  value       = aws_lb.relay.zone_id
}

output "alb_security_group_id" {
  description = "Security group ID of the relay ALB."
  value       = aws_security_group.alb.id
}

output "asg_name" {
  description = "The relay Auto Scaling Group name. The CI deploy leg (a follow-up) uses this to trigger an instance refresh on image-tag updates."
  value       = aws_autoscaling_group.relay.name
}

output "ssm_image_tag_parameter" {
  description = "SSM parameter name holding the relay image tag, updated by the CI deploy leg."
  value       = var.ssm_image_tag_parameter
}

output "canonical_listener_arn" {
  description = "Canonical relay HTTPS listener whose exact rule is switched only by the attended selector helper."
  value       = aws_lb_listener.https.arn
}

output "canonical_rule_arn" {
  description = "Canonical POST /relay/* forwarding rule."
  value       = aws_lb_listener_rule.relay.arn
}

output "blue_target_group_arn" {
  description = "Ordinary relay target group retained for rollback."
  value       = aws_lb_target_group.relay.arn
}

output "matched_cohort_candidate_asg_name" {
  description = "Full-size isolated candidate relay ASG."
  value       = var.enable_matched_cohort_canary ? aws_autoscaling_group.relay_candidate[0].name : null
}

output "matched_cohort_candidate_target_group_arn" {
  description = "Candidate relay target group reserved for the canonical selector after candidate smoke."
  value       = var.enable_matched_cohort_canary ? aws_lb_target_group.relay_candidate[0].arn : null
}

output "matched_cohort_candidate_listener_arn" {
  description = "Source-fenced candidate relay HTTPS listener."
  value       = var.enable_matched_cohort_canary ? aws_lb_listener.candidate_https[0].arn : null
}

output "matched_cohort_candidate_dns_name" {
  description = "Restricted candidate relay ALB DNS name outside the canonical maintenance WAF."
  value       = var.enable_matched_cohort_canary ? aws_lb.relay_candidate[0].dns_name : null
}

output "matched_cohort_maintenance_rule" {
  description = "Exact canonical relay fixed-response gate changed only by the attended maintenance helper."
  value = var.enable_matched_cohort_canary ? {
    rule_arn     = aws_lb_listener_rule.relay_maintenance[0].arn
    open_path    = "/__layerv_matched_cohort_maintenance_disabled__"
    closed_path  = "/relay/*"
    methods      = ["POST", "OPTIONS"]
    status_code  = "503"
    content_type = "application/json"
    message_body = jsonencode({ error = "maintenance" })
  } : null
}

output "matched_cohort_candidate_rule_arn" {
  description = "Exact POST /relay/* candidate rule on the source-fenced listener."
  value       = var.enable_matched_cohort_canary ? aws_lb_listener_rule.relay_candidate[0].arn : null
}

output "matched_cohort_blue_rollback_authority" {
  description = "Exact active relay fleet authority retained for matched-cohort rollback."
  value = var.enable_matched_cohort_canary ? {
    asg_name                = aws_autoscaling_group.relay.name
    min_size                = local.relay_min_capacity
    max_size                = local.relay_max_capacity
    desired_capacity        = local.relay_min_capacity
    launch_template_id      = aws_launch_template.relay.id
    launch_template_version = tostring(aws_launch_template.relay.latest_version)
    image_parameter         = var.ssm_image_tag_parameter
    image_tag               = nonsensitive(data.aws_ssm_parameter.matched_cohort_blue_image_tag[0].value)
    target_group_arns       = [aws_lb_target_group.relay.arn]
  } : null
}

output "matched_cohort_candidate_authority" {
  description = "Exact isolated relay candidate fleet authority."
  value = var.enable_matched_cohort_canary ? {
    asg_name                = aws_autoscaling_group.relay_candidate[0].name
    min_size                = local.relay_min_capacity
    max_size                = local.relay_max_capacity
    desired_capacity        = local.relay_min_capacity
    launch_template_id      = aws_launch_template.relay_candidate[0].id
    launch_template_version = tostring(aws_launch_template.relay_candidate[0].latest_version)
    image_parameter         = var.matched_cohort_image_tag_parameter
    image_tag               = nonsensitive(data.aws_ssm_parameter.matched_cohort_candidate_image_tag[0].value)
    target_group_arns       = [aws_lb_target_group.relay_candidate[0].arn]
  } : null
}
