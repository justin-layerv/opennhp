output "bucket_arn" {
  description = "Exact runtime-attestation bucket ARN — the sandbox-udp-proof-runner root's runtime_attestation_bucket_arn."
  value       = aws_s3_bucket.attestations.arn
}

output "bucket_name" {
  description = "Exact runtime-attestation bucket name."
  value       = aws_s3_bucket.attestations.bucket
}

output "kms_key_arn" {
  description = "Exact CMK ARN for attestation objects — the sandbox-udp-proof-runner root's runtime_attestation_kms_key_arn."
  value       = aws_kms_key.attestations.arn
}

output "bucket_policy_sha256" {
  description = "Canonical SHA-256 of the published bucket policy, as pinned in the collector contract."
  value       = local.bucket_policy_sha256
}

output "repair_document_name" {
  description = "Exact State Manager document that installs and re-verifies the collector."
  value       = aws_ssm_document.repair.name
}

output "repair_document_version" {
  description = "Exact repair document version pinned by every association and by the collector contract."
  value       = aws_ssm_document.repair.document_version
}

output "repair_association_ids" {
  description = "Repair association id per attested workload key."
  value       = { for key, association in aws_ssm_association.repair : key => association.association_id }
}

output "collector_contract" {
  description = "The canonical collector contract published to SSM."
  value       = local.collector_contract
}

output "bucket_arn_parameter_name" {
  description = "SSM parameter holding the exact attestation bucket ARN."
  value       = aws_ssm_parameter.runtime_attestation_bucket_arn.name
}

output "collector_contract_parameter_name" {
  description = "SSM parameter holding the canonical collector contract."
  value       = aws_ssm_parameter.runtime_attestation_collector_contract.name
}
