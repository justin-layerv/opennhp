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
  description = "Public X25519 identity trusted by NHP servers, read from a public-only SSM parameter. Private material never enters this output or Terraform state."
  # This is safe only because the Lambda derives, validates, and publishes the
  # public half into a non-SecureString parameter. Do not cargo-cult
  # nonsensitive() onto the adjacent Secrets Manager material.
  value      = nonsensitive(data.aws_ssm_parameter.relay_public_key.value)
  sensitive  = false
  depends_on = [aws_lambda_invocation.publish_public_key]
}

output "public_key_parameter_name" {
  description = "Stable public-only SSM parameter updated when AWSCURRENT changes during a guarded rotation."
  value       = aws_ssm_parameter.relay_public_key.name
}
