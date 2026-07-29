# -----------------------------------------------------------------------------
# Dedicated sandbox proof sealing CMK.
#
# The attended proof runs both clients against one sandbox-only sealing CMK:
# Connector seals its x25519 private key under its existing
# qurl-agent-x25519-private-key context, while qurl-go wraps only its
# SealedFileAgentState data key under the separate qurl-go/agent-state context.
# There is no pre-existing sandbox sealing key, so this root creates a dedicated,
# purpose-built CMK for the proof:
#   * Connector's attended setup points LAYERV_AWS_KMS_KEY_ID here to seal its
#     private key, while qurl-go uses the stable Terraform-owned alias directly;
#   * modules/udp-proof-runner grants only context-separated Connector decrypt
#     and qurl-go sealed-state encrypt/decrypt on exactly this key (see
#     proof_kms_key_arns in main.tf).
# Both sides are governed by account IAM (the default-shape key policy below), and
# the module additionally constrains every cryptographic operation to its
# reviewed client-specific encryption context.
# -----------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "proof_agent_seal" {
  description             = "Sandbox UDP proof: seals client agent state under reviewed contexts"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  # Default-shape policy: account root administers; principals get key use via
  # their IAM policies (the runner's context-scoped client grants live in
  # modules/udp-proof-runner/iam.tf).
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "EnableAccountIAM"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-udp-proof-agent-seal"
  })
}

resource "aws_kms_alias" "proof_agent_seal" {
  name          = "alias/${local.name_prefix}-udp-proof-agent-seal"
  target_key_id = aws_kms_key.proof_agent_seal.key_id
}
