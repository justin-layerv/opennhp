# -----------------------------------------------------------------------------
# Sandbox runtime-attestation store — the immutable per-node runtime evidence
# channel for the attested cell0, cell1 and qRTS fleets.
#
# Launch-template, SSM tag, AMI, or ECR lookups cannot prove what each current
# in-service instance is running: NHP servers run a Docker container, and
# qurl-reverse-tunnel-server pulls an ECR image only to extract a host binary
# and then removes the container. This root provisions the evidence channel
# that closes that gap.
#
# It was built for the attended UDP proof's deployment-manifest producer and
# used to publish two parameters under /sandbox/nhp/udp-proof/ for it. That
# producer was deleted with the proof in #3799 and the parameters were retired;
# the store itself is unaffected, because the collector and its repair
# association attest the live fleets regardless of who reads the evidence.
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
