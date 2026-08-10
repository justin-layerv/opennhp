output "bucket_arn" {
  description = "Exact runtime-attestation bucket ARN."
  value       = module.runtime_attestation_store.bucket_arn
}

output "kms_key_arn" {
  description = "Exact CMK ARN for attestation objects."
  value       = module.runtime_attestation_store.kms_key_arn
}

output "bucket_policy_sha256" {
  description = "Canonical bucket-policy digest pinned by the published collector contract."
  value       = module.runtime_attestation_store.bucket_policy_sha256
}

output "repair_document_name" {
  description = "Exact State Manager document that installs and re-verifies the collector."
  value       = module.runtime_attestation_store.repair_document_name
}

output "repair_document_version" {
  description = "Exact repair document version pinned by every association and the collector contract."
  value       = module.runtime_attestation_store.repair_document_version
}

output "repair_association_ids" {
  description = "Repair association id per attested workload key."
  value       = module.runtime_attestation_store.repair_association_ids
}

output "collector_contract" {
  description = "The canonical collector contract: digests of the collector, its units, the repair document, and the bucket policy."
  value       = module.runtime_attestation_store.collector_contract
}
