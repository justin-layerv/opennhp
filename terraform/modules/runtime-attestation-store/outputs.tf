output "bucket_arn" {
  description = "Exact runtime-attestation bucket ARN."
  value       = aws_s3_bucket.attestations.arn
}

output "bucket_name" {
  description = "Exact runtime-attestation bucket name."
  value       = aws_s3_bucket.attestations.bucket
}

output "kms_key_arn" {
  description = "Exact CMK ARN for attestation objects."
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
  description = "The canonical collector contract: digests of the collector, its units, the repair document, and the bucket policy."
  value       = local.collector_contract
}
