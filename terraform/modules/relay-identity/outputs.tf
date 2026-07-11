# These dependencies intentionally make every fleet-facing identity output wait
# for public-key publication. The relay could consume the secret earlier, but
# gating all consumers here prevents a fleet from converging before servers can
# obtain the matching public trust key.
output "secret_arn" {
  description = "ARN of the stable relay private-key secret. Pass only to relay fleets."
  value       = aws_secretsmanager_secret.relay.arn
  depends_on  = [aws_lambda_invocation.publish_public_key]
}

output "secret_name" {
  description = "Name of the stable relay private-key secret."
  value       = aws_secretsmanager_secret.relay.name
  depends_on  = [aws_lambda_invocation.publish_public_key]
}

output "relay_public_key_b64" {
  description = "Live AWSCURRENT public X25519 identity trusted by NHP servers, returned after the identity Lambda confirms the public-only SSM parameter. Private material never enters this output or Terraform state."
  # This is safe only because the refreshable status invocation derives and
  # validates the public half, then confirms it matches SSM. Its postcondition
  # validates this exact result. The provider already marks invocation results
  # non-sensitive, so an explicit sensitivity cast is redundant and obscures
  # the provider contract. Do not copy this treatment onto adjacent Secrets
  # Manager material.
  value      = jsondecode(data.aws_lambda_invocation.status.result).versions.AWSCURRENT.publicKey
  sensitive  = false
  depends_on = [data.aws_lambda_invocation.status]
}

output "public_key_parameter_name" {
  description = "Stable public-only SSM parameter updated when AWSCURRENT changes during a guarded rotation."
  value       = aws_ssm_parameter.relay_public_key.name
}
