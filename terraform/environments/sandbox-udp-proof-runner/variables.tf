variable "environment" {
  description = "Environment label. The proof runner is intentionally sandbox-only."
  type        = string
  default     = "sandbox"
}

variable "aws_region" {
  description = "AWS region."
  type        = string
  default     = "us-east-2"
}

variable "runner_vpc_cidr" {
  description = "Dedicated, unpeered /28 for the runner VPC. Non-overlapping with cell0 (10.100/10.101), cell1/Control (10.102), prod (10.200)."
  type        = string
  default     = "10.103.0.0/28"
}

variable "availability_zone" {
  description = "Single sandbox AZ for the ephemeral runner ENI."
  type        = string
  default     = "us-east-2a"
}

variable "ubuntu_ami_ssm_parameter" {
  description = "Canonical public SSM parameter for the reviewed x86_64 Ubuntu Noble AMI."
  type        = string
  default     = "/aws/service/canonical/ubuntu/server/noble/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

variable "github_oidc_provider_arn" {
  description = "Existing sandbox-account GitHub Actions OIDC provider ARN."
  type        = string
  default     = "arn:aws:iam::767397897469:oidc-provider/token.actions.githubusercontent.com"
}

variable "runner_archive_url" {
  description = "Exact official GitHub Actions runner linux-x64 release archive URL."
  type        = string
  default     = "https://github.com/actions/runner/releases/download/v2.336.0/actions-runner-linux-x64-2.336.0.tar.gz"
}

variable "runner_archive_sha256" {
  description = "Lowercase SHA-256 of runner_archive_url (verified by download+hash)."
  type        = string
  default     = "04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d"
}

variable "proof_kms_key_arns" {
  description = <<-EOT
    Exact sandbox CMK key/<uuid> ARNs the runner may DescribeKey + Decrypt for
    the sealed-state proof (encryption context purpose=qurl-agent-x25519-private-key,
    set by the external layervai/qurl-connector app). Aliases and wildcards are
    rejected by the module.

    ⚠️ REQUIRED — no default on purpose. The exact sealing CMK is owned/produced by
    the qurl-connector app and is NOT wired by reference in this repo. A live KMS
    investigation (2026-07-25) showed the earlier candidate,
    alias/layerv-nhp-sandbox-control-authority-data
    (key/83680792-1ed7-4825-beb2-2e67f8056aee), is the DATA-PLANE key — its grants
    are all DynamoDB/ECR (agent-keys table, connector-authority repo), with NO
    qurl-agent-x25519-private-key encryption context — so it is NOT the agent
    PRIVATE-key sealing key. Rather than silently grant Decrypt on a wrong key,
    this input is required: supply the confirmed sealing CMK (from the qurl-connector
    owners) via terraform.tfvars before apply. A wrong key still fails safe (the
    attended proof's decrypt fails, no silent misbehavior).
  EOT
  type        = set(string)
}

variable "tags" {
  description = "Additional resource tags."
  type        = map(string)
  default     = {}
}
