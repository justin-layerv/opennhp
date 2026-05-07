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
