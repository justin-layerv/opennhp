output "controller_role_arn" {
  description = "OIDC role assumed only by layervai/nhp's protected udp-proof-sandbox GitHub environment."
  value       = aws_iam_role.controller.arn
}

output "broker_function_name" {
  description = "Invoke with strict action, github_run_id, and github_run_attempt commands; scheduled sweeps use the same bounded broker."
  value       = aws_lambda_function.broker.function_name
}

output "broker_function_arn" {
  description = "Exact runner broker ARN granted to the controller role."
  value       = aws_lambda_function.broker.arn
}

output "jit_kms_key_arn" {
  description = "Dedicated key for the one-time GitHub JIT configuration secret."
  value       = aws_kms_key.jit.arn
}

output "jit_secret_prefix" {
  description = "Create one tagged secret named <prefix><NHP controller github_run_id>/<github_run_attempt> before invoking broker start."
  value       = local.jit_secret_prefix
}

output "launch_template_id" {
  description = "Terraform-owned exact launch template used only by the broker."
  value       = aws_launch_template.runner.id
}

output "stable_source_ipv4" {
  description = "Persistent public egress address. Allowlist only its /32 at sandbox UDP proof edges."
  value       = aws_eip.source.public_ip
}

output "stable_source_cidr" {
  description = "Persistent reviewed source /32 for sandbox Hub and cell UDP ingress."
  value       = "${aws_eip.source.public_ip}/32"
}

output "required_jit_labels" {
  description = "Exact labels each client JIT configuration must carry, plus the dynamic run-<NHP controller github_run_id>-attempt-<github_run_attempt> label."
  value       = ["self-hosted", "Linux", "X64", "udp-proof", var.environment]
}
