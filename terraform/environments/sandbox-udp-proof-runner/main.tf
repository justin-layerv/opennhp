# -----------------------------------------------------------------------------
# Sandbox UDP proof runner — Step 8 of the two-cell UDP substrate.
# Composes terraform/modules/udp-proof-runner (the NHP-owned compute boundary for
# the attended qurl-go + Connector UDP proof) in its own isolated root.
#
# The stable-source /32 (module output stable_source_cidr) is intentionally NOT
# added to the Hub / cell0 / cell1 UDP:62206 ingress: all three edges are already
# open to 0.0.0.0/0 on UDP 62206 (public SDK edges — see modules/compute
# server_nhp_udp and connector-authority-foundation hub_worker SG), so a /32 grant
# is a redundant subset and would, at the Hub, fight the fail-closed Control
# convergence gate. The EIP still gives a stable, reviewable source for the
# attended controller's records and any future tightening.
# -----------------------------------------------------------------------------

locals {
  name_prefix = "layerv-nhp-${var.environment}"

  common_tags = merge(
    {
      Project     = "LayerV-NHP"
      Environment = var.environment
      ManagedBy   = "terraform"
      Component   = "udp-proof-runner"
    },
    var.tags,
  )
}

# Reviewed x86_64 Ubuntu Noble AMI, resolved from the Canonical public SSM
# parameter (AMI IDs are public, so insecure_value surfaces the plaintext id).
# The module re-validates the resolved id is x86_64 via data.aws_ami.
data "aws_ssm_parameter" "ubuntu_ami" {
  name = var.ubuntu_ami_ssm_parameter
}

module "udp_proof_runner" {
  source = "../../modules/udp-proof-runner"

  environment       = var.environment
  name_prefix       = local.name_prefix
  vpc_cidr          = var.runner_vpc_cidr
  availability_zone = var.availability_zone

  ami_id = nonsensitive(data.aws_ssm_parameter.ubuntu_ami.insecure_value)

  github_oidc_provider_arn = var.github_oidc_provider_arn
  runner_archive_url       = var.runner_archive_url
  runner_archive_sha256    = var.runner_archive_sha256

  # Default to the dedicated proof sealing CMK this root creates; a caller may
  # override with the qurl-connector-confirmed key(s) via proof_kms_key_arns.
  proof_kms_key_arns = var.proof_kms_key_arns != null ? var.proof_kms_key_arns : [aws_kms_key.proof_agent_seal.arn]

  runtime_attestation_bucket_arn  = var.runtime_attestation_bucket_arn
  runtime_attestation_kms_key_arn = var.runtime_attestation_kms_key_arn

  tags = local.common_tags
}
