output "stable_source_cidr" {
  description = "The runner's persistent EIP as a /32 — the reviewable source for Hub/cell UDP-62206 ingress (currently a no-op: those edges are 0.0.0.0/0)."
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
