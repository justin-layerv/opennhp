# -----------------------------------------------------------------------------
# Dedicated sandbox proof sealing CMK.
#
# The attended proof runs the Connector agent, which seals its x25519 PRIVATE key
# into a KMS blob (qurl-connector pkg/agentstate/keyprovider.go, key provider
# aws-kms, encryption context purpose=qurl-agent-x25519-private-key) and unseals
# it to run. There is no pre-existing sandbox sealing key — it is a proof-setup
# value the agent is pointed at via LAYERV_AWS_KMS_KEY_ID. So this root creates a
# dedicated, purpose-built CMK for the sandbox proof:
#   * the attended setup points the proof agent's LAYERV_AWS_KMS_KEY_ID here to
#     SEAL (encrypt) its private key once during onboarding;
#   * modules/udp-proof-runner grants the runner role DescribeKey + Encrypt +
#     Decrypt on
#     exactly this key (see proof_kms_key_arns in main.tf) so the runner can
#     UNSEAL it during the proof.
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
  # their IAM policies (the runner's scoped Encrypt + Decrypt grants live in
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
