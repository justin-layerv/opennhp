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
