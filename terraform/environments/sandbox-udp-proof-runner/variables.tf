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
  description = "Dedicated, unpeered /28 for the runner VPC. Non-overlapping with cell0/relay (10.100/10.101), Control (10.102), cell1 (10.104), and prod (10.200)."
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

variable "runtime_attestation_bucket_arn" {
  description = "Exact versioned sandbox runtime-attestation bucket ARN; null until the collector storage predecessor is provisioned."
  type        = string
  default     = null
  nullable    = true
}

variable "runtime_attestation_kms_key_arn" {
  description = "Exact CMK ARN for runtime-attestation objects; set with runtime_attestation_bucket_arn."
  type        = string
  default     = null
  nullable    = true
}

variable "provisioned_cell_catalog_kms_key_arn" {
  description = <<-EOT
    Exact CMK ARN encrypting layerv-nhp-sandbox-control-connector-authority — the
    provisioned-cell catalog the deployment-manifest producer reads.

    This is the Connector Authority data key (aws_kms_key.authority_data /
    alias/layerv-nhp-sandbox-authority-data, created by
    terraform/modules/connector-authority-foundation) and it is owned by the
    Control root, not by this one. Pinned here as a literal because the two roots
    have separate state and this root reads no remote state; verified against the
    live table with `aws dynamodb describe-table`.

    Distinct from the dedicated proof sealing key: that is the runner's sealed-agent-state key
    with a purpose=qurl-agent-x25519-private-key encryption context, not the
    DynamoDB/ECR data-plane key.
  EOT
  type        = string
  default     = "arn:aws:kms:us-east-2:767397897469:key/83680792-1ed7-4825-beb2-2e67f8056aee"
  nullable    = true
}

variable "tags" {
  description = "Additional resource tags."
  type        = map(string)
  default     = {}
}
