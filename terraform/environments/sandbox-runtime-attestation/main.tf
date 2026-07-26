# -----------------------------------------------------------------------------
# Sandbox runtime-attestation store — the immutable per-node runtime evidence
# channel for the UDP-proof deployment manifest.
#
# Launch-template, SSM tag, AMI, or ECR lookups cannot prove what each current
# in-service instance is running: NHP servers run a Docker container, and
# qurl-reverse-tunnel-server pulls an ECR image only to extract a host binary
# and then removes the container. This root provisions the evidence channel
# that closes that gap, and publishes the two parameters the read-only producer
# reads:
#
#   /sandbox/nhp/udp-proof/runtime-attestation-bucket-arn
#   /sandbox/nhp/udp-proof/runtime-attestation-collector-contract
#
# After applying, feed `bucket_arn` and `kms_key_arn` into the
# sandbox-udp-proof-runner root's runtime_attestation_bucket_arn /
# runtime_attestation_kms_key_arn so the producer role gains its read-only
# S3/KMS grants.
# -----------------------------------------------------------------------------

locals {
  name_prefix = "layerv-nhp-${var.environment}"

  common_tags = merge(
    {
      Project     = "LayerV-NHP"
      Environment = var.environment
      ManagedBy   = "terraform"
      Component   = "runtime-attestation-store"
    },
    var.tags,
  )
}

module "runtime_attestation_store" {
  source = "../../modules/runtime-attestation-store"

  environment = var.environment
  name_prefix = local.name_prefix
  bucket_name = var.bucket_name

  attested_node_roles     = var.attested_node_roles
  asg_name_ssm_parameters = var.asg_name_ssm_parameters

  tags = local.common_tags
}
