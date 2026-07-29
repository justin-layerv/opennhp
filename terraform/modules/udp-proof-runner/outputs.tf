output "controller_role_arn" {
  description = "OIDC role assumed only by layervai/nhp's protected udp-proof-sandbox GitHub environment."
  value       = aws_iam_role.controller.arn
}

output "manifest_producer_role_arn" {
  description = "Read-only OIDC role assumed only by NHP's protected trusted-main deployment-manifest producer."
  value       = aws_iam_role.manifest_producer.arn
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

output "proof_account_credential_secret_arn" {
  description = "Stable empty secret container that an operator seeds out of band with the sandbox proof account credential."
  value       = aws_secretsmanager_secret.proof_account_credential.arn
}

output "proof_otp_mailbox_recipient" {
  description = "Exact private SES recipient used only by qurl-go's attended NHP_OTP proof."
  value       = local.proof_mailbox_recipient
}

output "proof_otp_mailbox_queue_url" {
  description = "Exact private SQS queue consumed by the qurl-go proof runner."
  value       = aws_sqs_queue.proof_otp_mailbox.url
}

output "proof_otp_mailbox_bucket" {
  description = "Private one-day S3 mailbox containing the SES receipt objects referenced by the proof queue."
  value       = aws_s3_bucket.proof_otp_mailbox.id
}

output "assignment_handshake_bucket" {
  description = "Versioned one-day checkpoint/receipt channel used only by the attended assignment proof."
  value       = aws_s3_bucket.assignment_handshake.bucket
}

output "assignment_handshake_kms_key_arn" {
  description = "Exact KMS key ARN clients must name explicitly when writing handshake objects."
  value       = aws_kms_key.assignment_handshake.arn
}
