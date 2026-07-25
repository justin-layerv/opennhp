variable "environment" {
  description = "LayerV environment that owns this one global Connector Authority foundation."
  type        = string

  validation {
    condition     = contains(["sandbox", "prod"], var.environment)
    error_message = "environment must be sandbox or prod."
  }
}

variable "aws_account_id" {
  description = "Expected AWS account. The module refuses to plan in a different account."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "aws_account_id must be a 12-digit AWS account ID."
  }
}

variable "vpc_cidr" {
  description = "Dedicated Control VPC CIDR. It must not overlap a cell or relay VPC."
  type        = string

  validation {
    condition = try(
      can(cidrnetmask(var.vpc_cidr)) && tonumber(split("/", var.vpc_cidr)[1]) <= 20,
      false,
    )
    error_message = "vpc_cidr must be a valid IPv4 CIDR with a prefix no narrower than /20; the module creates three /28-or-larger subnets with cidrsubnet(..., 8, ...)."
  }
}

variable "otp_email_from" {
  description = "Validated SES From address for future Connector OTP functions. This foundation does not own or send through the SES identity."
  type        = string

  validation {
    condition     = can(regex("^[^@[:space:]]+@([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\\.)+[A-Za-z]{2,}$", var.otp_email_from))
    error_message = "otp_email_from must be a bare local@ASCII-domain address with no display name or whitespace."
  }
}

variable "ses_configuration_set_name" {
  description = "Existing or future SES configuration set that Connector OTP sends must use. Ownership transfers separately under nhp#3273."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{1,64}$", var.ses_configuration_set_name))
    error_message = "ses_configuration_set_name must be 1-64 SES-safe characters."
  }
}

variable "authority_runtime_functions_enabled" {
  description = <<-EOT
    Second, independent enable gate for the Connector Authority Lambda runtime
    slice (the 3 hub functions, blue/green aliases, execution roles,
    steady/rollout concurrency, and the lockstep dependency-endpoint opening).

    It is deliberately separate from authority_runtime_contract: binding the
    contract (Step 3) must NOT create any function, so the contract-binding
    apply stays a foundation_contract-only transition. This gate flips true
    only in the later runtime apply (Step 4), and only ever when a non-null
    contract is already bound (the module fails closed if it is set true while
    the contract is null). Committed inputs leave it false; prod stays dark.
  EOT
  type        = bool
  default     = false
}

variable "hub_edge_enabled" {
  description = <<-EOT
    Dark-first enable gate for the Connector Hub public UDP edge (Step 5): the
    three public edge subnets, the internet gateway and public route table, and
    the public UDP-62206 Hub network load balancer + listener + target group.

    Independent of the authority runtime gate: the Hub NLB is caller-facing
    while the runtime functions are dark, and they flip in separate applies.
    When false the Control VPC keeps its no-public-edge posture (no internet
    gateway, no public subnet, no non-local route). Committed inputs leave it
    false; prod stays dark.
  EOT
  type        = bool
  default     = false
}

variable "tags" {
  description = "Additional tags applied to every supported resource."
  type        = map(string)
  default     = {}
}
