# -----------------------------------------------------------------------------
# Sandbox UDP proof runner — Step 8 of the two-cell UDP substrate.
# Composes terraform/modules/udp-proof-runner (the NHP-owned compute boundary for
# the attended qurl-go + Connector UDP proof) in its own isolated root.
#
# The stable-source /32 (module output stable_source_cidr) is the sole public
# caller admitted by the Hub / cell0 / cell1 UDP:62206 NLB security groups.
# Those SGs are attached when each NLB is created; target SGs trust only the NLB
# SG identity. Keep this EIP stable across runner churn or every proof edge must
# be deliberately replaced/reviewed with a new exact /32.
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

  # Both client proofs use this sandbox-only CMK under separate exact encryption
  # contexts. Keeping the key non-overridable prevents the stable qurl-go alias,
  # Connector setup, and runner IAM from silently diverging.
  proof_kms_key_arns = [aws_kms_key.proof_agent_seal.arn]

  runtime_attestation_bucket_arn  = var.runtime_attestation_bucket_arn
  runtime_attestation_kms_key_arn = var.runtime_attestation_kms_key_arn

  # The catalog table is SSE-KMS, so the producer's dynamodb:GetItem is dead
  # without a DynamoDB-scoped kms:Decrypt on this Control-owned CMK.
  provisioned_cell_catalog_kms_key_arn = var.provisioned_cell_catalog_kms_key_arn
  proof_account_credential_sha256      = var.proof_account_credential_sha256
  proof_mailbox_route53_zone_id        = var.proof_mailbox_route53_zone_id
  proof_mailbox_domain                 = var.proof_mailbox_domain

  tags = local.common_tags
}
