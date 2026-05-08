# QURL FRP Server Module Outputs

output "security_group_id" {
  description = "FRP server security group ID"
  value       = aws_security_group.frps.id
}

output "cloud_map_dns_names" {
  description = "Per-AZ Cloud Map DNS names for qurl-reverse-tunnel-server discovery, keyed by AZ suffix. qurl-service hashes OwnerID to one of these suffixes; frpc and qurl-router consume the resulting `frps_addr` from the API."
  value       = { for s in var.frps_az_suffixes : s => "frps-${s}.${var.namespace_name}" }
}

output "cloud_map_service_ids" {
  description = "Per-AZ Cloud Map service IDs, keyed by AZ suffix. Exposed for debugging / reconciliation tooling — operational registration is handled inside user_data on the instance itself. Marked `sensitive` to keep the IDs out of `terraform output` and CI logs by default; operators that need them can target the output explicitly with `terraform output -raw cloud_map_service_ids` or read state directly. The companion `cloud_map_dns_names` output covers the operator-facing case."
  sensitive   = true
  value       = { for s, svc in aws_service_discovery_service.frps_per_az : s => svc.id }
}

output "frps_az_suffixes" {
  description = "AZ suffixes for which per-AZ Cloud Map services were created. Mirrors the input variable; surfaced as an output so qurl-service wiring can read it directly from the module instead of duplicating the list at the root."
  value       = var.frps_az_suffixes
}

output "asg_name" {
  description = "Auto Scaling Group name"
  value       = aws_autoscaling_group.frps.name
}

output "asg_arn" {
  description = "Auto Scaling Group ARN. Surfaced for the canary-deployment module's IAM scope (see terraform/main.tf::module.canary_deployment_qurl_reverse_tunnel_server)."
  value       = aws_autoscaling_group.frps.arn
}

output "launch_template_arn" {
  description = "Launch template ARN. Required by the canary-deployment module to grant ec2:RunInstances on the LT version under DesiredConfiguration in StartInstanceRefresh (mirrors module.compute and module.ac wiring)."
  value       = aws_launch_template.frps.arn
}

output "log_group_name" {
  description = "CloudWatch log group name"
  value       = aws_cloudwatch_log_group.frps.name
}

output "instance_role_arn" {
  description = "FRP server instance IAM role ARN"
  value       = aws_iam_role.frps.arn
}

output "ssm_image_tag_parameter" {
  description = "SSM parameter name for the deployed image tag"
  value       = aws_ssm_parameter.image_tag.name
}

# Per-AZ empty-registration alarms (#1542). Map keyed by AZ suffix so root
# wiring / dashboards can target the alarm for a specific suffix without
# index-arithmetic or list-order assumptions. Empty map when the watchdog
# is disabled (var.frps_empty_az_alarm_enabled = false).
output "cloud_map_empty_az_alarm_arns" {
  description = "Map of AZ suffix → CloudWatch alarm ARN for the per-AZ Cloud Map empty-registration alarms (#1542). Empty when either var.frps_empty_az_alarm_enabled or var.enable_cloudwatch_alarms is false (the watchdog is gated on the AND of both — see local.enable_empty_az_watchdog in monitoring_empty_az.tf)."
  value = {
    for s, alarm in aws_cloudwatch_metric_alarm.empty_az_per_suffix :
    s => alarm.arn
  }
}

# Operator-facing pre-flight notice for the WEIGHTED → MULTIVALUE flip
# (PR 4). Surfaces in `terraform output` so the operator running the
# value flip sees the gotcha BEFORE running `terraform apply`. The
# variable comment on `cloud_map_routing_policy` carries the same
# warning for plan-time reading; this output covers the apply-time
# pre-flight check (`terraform output cloud_map_replacement_warning`
# in the canary-deploy runbook).
#
# Value is empty when the policy stays at its default WEIGHTED. Set to
# a non-empty notice once the operator has flipped to MULTIVALUE so a
# `terraform output` audit shows the impending REPLACEMENT semantics
# until the deploy finishes and the next apply produces a clean diff.
output "cloud_map_replacement_warning" {
  description = "Tense-neutral advisory for the WEIGHTED → MULTIVALUE Cloud Map routing policy flip (PR 4). Empty string under the WEIGHTED default; non-empty when MULTIVALUE is set, describing the REPLACEMENT semantics that fired or will fire on the next apply (per-AZ services + green services replaced, launch-template version bumps, instance refresh fires) so a `terraform output` audit catches the foot-gun whether read pre-flip or post-flip. See `var.cloud_map_routing_policy` for the full cutover sequence."
  # Tense-neutral wording: the output stays non-empty after PR 4's
  # apply lands (cloud_map_routing_policy stays = MULTIVALUE), so a
  # future operator running `terraform output cloud_map_replacement_warning`
  # post-flip should not be misled into thinking another replacement is
  # impending. "any apply that flips this variable" reads truthfully
  # both before (the next plan) and after (the historical apply) the
  # flip. Set explicitly to "" once we want the warning to vanish.
  value = var.cloud_map_routing_policy == "MULTIVALUE" ? format(
    "MULTIVALUE routing is set: any apply that flips cloud_map_routing_policy from WEIGHTED triggers REPLACEMENT of %d per-AZ Cloud Map service(s)%s — service IDs change, launch-template version bumps, instance refresh fires. See cloud_map_routing_policy variable doc for the cutover sequence.",
    length(var.frps_az_suffixes),
    var.enable_blue_green ? format(" + %d green service(s)", length(var.frps_az_suffixes)) : "",
  ) : ""
}
