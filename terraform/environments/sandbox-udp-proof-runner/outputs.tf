output "stable_source_cidr" {
  description = "The runner's persistent EIP as a /32 — the sole public source admitted by the Hub/cell UDP-62206 NLB security groups."
  value       = module.udp_proof_runner.stable_source_cidr
}

output "stable_source_ipv4" {
  description = "The runner's persistent EIP (bare IPv4)."
  value       = module.udp_proof_runner.stable_source_ipv4
}

output "controller_role_arn" {
  description = "The GitHub OIDC controller role ARN (assumed by the attended proof controller workflow)."
  value       = module.udp_proof_runner.controller_role_arn
}

output "manifest_producer_role_arn" {
  description = "The trusted-main read-only deployment-manifest producer role ARN."
  value       = module.udp_proof_runner.manifest_producer_role_arn
}

output "broker_function_name" {
  description = "The serialized broker Lambda that launches one JIT runner per approved proof."
  value       = module.udp_proof_runner.broker_function_name
}

output "required_jit_labels" {
  description = "The exact self-hosted runner labels the client proof workflows must target."
  value       = module.udp_proof_runner.required_jit_labels
}

output "launch_template_id" {
  description = "The hardened runner launch template id."
  value       = module.udp_proof_runner.launch_template_id
}

output "proof_account_credential_secret_arn" {
  description = "Stable empty secret container to seed out of band before enabling qurl-go OTP proof."
  value       = module.udp_proof_runner.proof_account_credential_secret_arn
}

output "proof_otp_mailbox_recipient" {
  description = "Exact private SES recipient for the attended qurl-go OTP proof."
  value       = module.udp_proof_runner.proof_otp_mailbox_recipient
}

output "proof_otp_mailbox_queue_url" {
  description = "Exact private SQS queue consumed by the proof runner."
  value       = module.udp_proof_runner.proof_otp_mailbox_queue_url
}

output "proof_otp_mailbox_bucket" {
  description = "Private one-day SES receipt bucket consumed by the proof runner."
  value       = module.udp_proof_runner.proof_otp_mailbox_bucket
}
