variable "environment" {
  description = "Deployment environment. This proof runner is intentionally sandbox-only."
  type        = string

  validation {
    condition     = var.environment == "sandbox"
    error_message = "The UDP proof runner may be composed only in sandbox."
  }
}

variable "name_prefix" {
  description = "Environment resource-name prefix."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,39}$", var.name_prefix))
    error_message = "name_prefix must be 3-40 lowercase alphanumeric/hyphen characters beginning with a letter."
  }
}

variable "vpc_cidr" {
  description = "Dedicated, unpeered runner VPC CIDR. Exactly one IPv4 /28 is required."
  type        = string

  validation {
    condition     = can(cidrnetmask(var.vpc_cidr)) && cidrnetmask(var.vpc_cidr) == "255.255.255.240"
    error_message = "vpc_cidr must be a valid IPv4 /28 CIDR."
  }
}

variable "availability_zone" {
  description = "Single sandbox AZ for each ephemeral runner ENI."
  type        = string

  validation {
    condition     = can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9][a-z]$", var.availability_zone))
    error_message = "availability_zone must be an AWS availability zone name."
  }
}

variable "ami_id" {
  description = "Reviewed x86_64 Ubuntu AMI ID. Resolve and pin it in the composing sandbox root."
  type        = string

  validation {
    condition     = can(regex("^ami-([0-9a-f]{8}|[0-9a-f]{17})$", var.ami_id))
    error_message = "ami_id must be an EC2 AMI ID with exactly 8 or 17 lowercase hexadecimal characters."
  }
}

variable "instance_type" {
  description = "Fixed runner instance type. Keep the controller unable to select arbitrary or accelerated instance families."
  type        = string
  default     = "m7i.large"

  validation {
    condition     = contains(["m7i.large", "m7i.xlarge"], var.instance_type)
    error_message = "instance_type must be m7i.large or m7i.xlarge."
  }
}

variable "root_volume_gib" {
  description = "Encrypted ephemeral root volume size for images, worktrees, and packet captures."
  type        = number
  default     = 100

  validation {
    condition     = var.root_volume_gib >= 60 && var.root_volume_gib <= 200 && floor(var.root_volume_gib) == var.root_volume_gib
    error_message = "root_volume_gib must be an integer from 60 through 200."
  }
}

variable "max_runtime_minutes" {
  description = "Hard boot-to-termination TTL independently enforced by the instance and scheduled sweeper."
  type        = number
  default     = 180

  validation {
    condition     = var.max_runtime_minutes >= 30 && var.max_runtime_minutes <= 240 && floor(var.max_runtime_minutes) == var.max_runtime_minutes
    error_message = "max_runtime_minutes must be an integer from 30 through 240."
  }
}

variable "github_oidc_provider_arn" {
  description = "Existing sandbox-account GitHub Actions OIDC provider ARN."
  type        = string

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:oidc-provider/token\\.actions\\.githubusercontent\\.com$", var.github_oidc_provider_arn))
    error_message = "github_oidc_provider_arn must be the token.actions.githubusercontent.com provider ARN."
  }
}

variable "github_repository" {
  description = "The sole repository allowed to assume the controller role."
  type        = string
  default     = "layervai/nhp"

  validation {
    condition     = var.github_repository == "layervai/nhp"
    error_message = "The UDP proof runner is NHP-owned and may only trust layervai/nhp."
  }
}

variable "github_environment" {
  description = "Protected GitHub environment that gates the attended proof controller."
  type        = string
  default     = "udp-proof-sandbox"

  validation {
    condition     = var.github_environment == "udp-proof-sandbox"
    error_message = "github_environment must remain udp-proof-sandbox."
  }
}

variable "manifest_github_environment" {
  description = "Protected GitHub environment used only by the trusted-main deployment-manifest producer."
  type        = string
  default     = "udp-proof-manifest-sandbox"

  validation {
    condition     = var.manifest_github_environment == "udp-proof-manifest-sandbox"
    error_message = "manifest_github_environment must remain udp-proof-manifest-sandbox."
  }
}

variable "runtime_attestation_bucket_arn" {
  description = "Exact versioned sandbox bucket ARN for runtime attestations. Null keeps S3 access absent until the collector predecessor is provisioned."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = (
      var.runtime_attestation_bucket_arn == null ||
      can(regex("^arn:aws[a-z-]*:s3:::layerv-nhp-sandbox-[a-z0-9.-]+$", var.runtime_attestation_bucket_arn))
    )
    error_message = "runtime_attestation_bucket_arn must be null or one exact layerv-nhp-sandbox-* bucket ARN."
  }
}

variable "runtime_attestation_kms_key_arn" {
  description = "Exact CMK ARN for the runtime-attestation bucket. Must be set or unset with runtime_attestation_bucket_arn."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = (
      (var.runtime_attestation_bucket_arn == null) ==
      (var.runtime_attestation_kms_key_arn == null)
    )
    error_message = "runtime_attestation_bucket_arn and runtime_attestation_kms_key_arn must be set or unset together."
  }

  validation {
    condition = (
      var.runtime_attestation_kms_key_arn == null ||
      can(regex(
        "^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})$",
        var.runtime_attestation_kms_key_arn,
      ))
    )
    error_message = "runtime_attestation_kms_key_arn must be null or one exact KMS key ARN."
  }
}

variable "provisioned_cell_catalog_kms_key_arn" {
  description = <<-EOT
    Exact CMK ARN encrypting the provisioned-cell catalog table
    (`<name_prefix>-control-connector-authority`) the manifest producer reads.

    The table is SSE-KMS with a customer-managed key, so DynamoDB calls
    `kms:Decrypt` under the CALLER's identity: `dynamodb:GetItem` alone returns
    a KMS AccessDeniedException, not a DynamoDB one. Null keeps the decrypt
    absent (and the catalog read failing) rather than inventing a wildcard key.
  EOT
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = (
      var.provisioned_cell_catalog_kms_key_arn == null ||
      can(regex(
        "^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})$",
        var.provisioned_cell_catalog_kms_key_arn,
      ))
    )
    error_message = "provisioned_cell_catalog_kms_key_arn must be null or one exact KMS key ARN."
  }

  # Null-consistency with the other CMK this module wires in: the two protect
  # different stores under different services, and each grant is bound by its
  # own kms:ViaService. Passing one ARN for both is the copy-paste failure this
  # rejects — it would silently widen whichever grant got the wrong key.
  validation {
    condition = (
      var.provisioned_cell_catalog_kms_key_arn == null ||
      var.runtime_attestation_kms_key_arn == null ||
      var.provisioned_cell_catalog_kms_key_arn != var.runtime_attestation_kms_key_arn
    )
    error_message = "provisioned_cell_catalog_kms_key_arn must differ from runtime_attestation_kms_key_arn."
  }
}

variable "runner_archive_url" {
  description = "Exact official GitHub Actions runner linux-x64 release archive URL."
  type        = string

  validation {
    condition = can(regex(
      "^https://github\\.com/actions/runner/releases/download/v[0-9]+\\.[0-9]+\\.[0-9]+/actions-runner-linux-x64-[0-9]+\\.[0-9]+\\.[0-9]+\\.tar\\.gz$",
      var.runner_archive_url,
    ))
    error_message = "runner_archive_url must be an exact official actions/runner linux-x64 release archive URL."
  }
}

variable "runner_archive_sha256" {
  description = "Lowercase SHA-256 of runner_archive_url."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.runner_archive_sha256))
    error_message = "runner_archive_sha256 must be a lowercase SHA-256 digest."
  }
}

variable "proof_kms_key_arns" {
  description = "Exact sandbox CMK ARNs the runner may describe and decrypt for the sealed-state proof. Wildcards and aliases are rejected."
  type        = set(string)

  validation {
    condition = (
      length(var.proof_kms_key_arns) > 0 &&
      alltrue([for arn in var.proof_kms_key_arns : can(regex(
        "^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})$",
        arn,
      ))])
    )
    error_message = "proof_kms_key_arns must contain one or more exact KMS key ARNs (no aliases or wildcards)."
  }
}

variable "tags" {
  description = "Base tags for all runner-foundation resources."
  type        = map(string)
  default     = {}
}
