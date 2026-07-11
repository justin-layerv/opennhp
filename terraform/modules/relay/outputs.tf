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
