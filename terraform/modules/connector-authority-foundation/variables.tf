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

variable "provisioned_cells" {
  description = <<-EOT
    Canonical environment-global native-UDP cell catalog. The map key is the
    public cell_id and must match the embedded cell_id. Terraform owns these
    low-churn registry rows; runtime assignment state remains Authority-owned.
    qurl-service's placement repository exposes only GetItem/Query for catalog
    rows, while registration and recovery transactions bind them with
    ConditionCheck rather than writing them. Adding any runtime catalog writer
    requires an ownership redesign before rollout.
    Public NHP endpoints are opaque authority data and must never be derived
    from cell_id by an SDK, Hub, or caller.

    updated_at is a deterministic, checked-in mutation revision, not wall-clock
    apply time. Change it in the same review as every row mutation. It is part
    of qurl-service's optimistic cell fence, so timestamp() or another
    per-plan value would create perpetual drift and invalidate in-flight work.

    Terraform verifies the server key's canonical padded-base64 wire shape and
    rejects the all-zero placeholder. The cell producer remains authoritative
    for the actual X25519 identity; qurl-service independently performs
    canonical-field and low-order X25519 validation on every registry read.
  EOT
  type = map(object({
    cell_id               = string
    status                = string
    endpoint_revision     = number
    nhp_host              = string
    nhp_port              = number
    server_public_key_b64 = string
    selection_weight      = string
    updated_at            = string
  }))
  default = {}

  validation {
    condition = alltrue([
      for cell_id, cell in var.provisioned_cells :
      cell.cell_id == cell_id &&
      length(cell_id) <= 32 &&
      can(regex("^[a-z0-9]+(?:-[a-z0-9]+)*$", cell_id))
    ])
    error_message = "Each provisioned_cells key must equal its embedded cell_id and use the canonical 1-32 byte lowercase alphanumeric/hyphen grammar."
  }

  validation {
    condition = alltrue([
      for cell in values(var.provisioned_cells) :
      contains(["active", "draining", "disabled"], cell.status) &&
      cell.endpoint_revision >= 1 &&
      floor(cell.endpoint_revision) == cell.endpoint_revision &&
      cell.endpoint_revision <= 9223372036854775807
    ])
    error_message = "Each provisioned cell needs an active, draining, or disabled status and a positive integer endpoint_revision that fits qurl-service's signed int64 runtime contract."
  }

  validation {
    condition = alltrue([
      for cell in values(var.provisioned_cells) :
      cell.nhp_host == lower(trimspace(cell.nhp_host)) &&
      length(cell.nhp_host) <= 253 &&
      can(regex("^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+nhp\\.layerv\\.(ai|xyz)$", cell.nhp_host)) &&
      !contains(["internal", "localhost", "metadata", "private"], split(".", cell.nhp_host)[0]) &&
      cell.nhp_port == 62206
    ])
    error_message = "Each nhp_host must be a canonical LayerV-owned public DNS name under nhp.layerv.ai or nhp.layerv.xyz, must not use a private or metadata first label, and nhp_port must be UDP 62206."
  }

  validation {
    condition = (
      length(distinct([
        for cell in values(var.provisioned_cells) :
        "${cell.nhp_host}:${cell.nhp_port}"
      ])) == length(var.provisioned_cells) &&
      length(distinct([
        for cell in values(var.provisioned_cells) :
        cell.server_public_key_b64
      ])) == length(var.provisioned_cells)
    )
    error_message = "Provisioned cells must not duplicate a public UDP endpoint or server public key."
  }

  validation {
    condition = alltrue([
      for cell in values(var.provisioned_cells) :
      can(regex("^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$", cell.server_public_key_b64)) &&
      cell.server_public_key_b64 != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    ])
    error_message = "Each server_public_key_b64 must have the canonical padded standard-base64 shape of a 32-byte producer key and must not be the all-zero placeholder; qurl-service performs the cryptographic X25519 validation at runtime."
  }

  validation {
    # The Control roots pin Terraform 1.14.x: this relies on that toolchain's
    # tonumber/tostring expansion of exponents into canonical decimal values.
    # Re-prove the exponent-boundary fixtures before changing the version pin.
    # DynamoDB trims leading and trailing zeros, so trim both before enforcing
    # its 38-significant-digit ceiling.
    condition = alltrue([
      for cell in values(var.provisioned_cells) :
      length(cell.selection_weight) <= 256 &&
      can(regex("^(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$", cell.selection_weight)) &&
      try(tonumber(cell.selection_weight) >= tonumber("1E-130"), false) &&
      try(tonumber(cell.selection_weight) <= tonumber("9.9999999999999999999999999999999999999E+125"), false) &&
      try(length(regexall("[eE]", tostring(tonumber(cell.selection_weight)))) == 0, false) &&
      try(
        length(trim(replace(tostring(tonumber(cell.selection_weight)), ".", ""), "0")) <= 38,
        false,
      )
    ])
    error_message = "Each selection_weight must be a positive DynamoDB Number with at most 38 significant digits and an adjusted exponent from -130 through +125."
  }

  validation {
    condition = alltrue([
      for cell in values(var.provisioned_cells) :
      can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,9})?Z$", cell.updated_at)) &&
      try(timecmp(cell.updated_at, cell.updated_at) == 0, false)
    ])
    error_message = "Each updated_at must be a valid canonical UTC RFC3339 timestamp."
  }
}

variable "provisioned_cell_catalog_materialization_enabled" {
  description = <<-EOT
    Fail-closed deployment gate for the Terraform-owned provisioned-cell rows
    and their root output. The reviewed provisioned_cells input remains
    available to the independently generated Authority identity contract while
    this is false, but no row is written or published until a separate attended
    catalog transition flips the gate true.
  EOT
  type        = bool
  default     = false
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

variable "hub_public_udp_ingress_cidrs" {
  description = <<-EOT
    Exact public IPv4 /32 sources admitted by the Hub UDP-62206 NLB security
    group. A live Hub edge requires a non-empty, sorted, duplicate-free list;
    sandbox pins this to the proof runner's persistent EIP. null is allowed only
    while the edge is dark, which keeps production unchanged during sandbox
    proof. Broad public CIDRs are never valid.
  EOT
  type        = list(string)
  default     = null

  validation {
    condition = var.hub_public_udp_ingress_cidrs == null || (
      length(var.hub_public_udp_ingress_cidrs) > 0 &&
      alltrue([
        for cidr in var.hub_public_udp_ingress_cidrs :
        can(cidrnetmask(cidr)) && try(tonumber(split("/", cidr)[1]) == 32, false)
      ])
    )
    error_message = "hub_public_udp_ingress_cidrs must be null or a non-empty list of exact IPv4 /32 CIDRs."
  }

  validation {
    condition = (
      var.hub_public_udp_ingress_cidrs == null ||
      var.hub_public_udp_ingress_cidrs == sort(distinct(var.hub_public_udp_ingress_cidrs))
    )
    error_message = "hub_public_udp_ingress_cidrs must be sorted and duplicate-free."
  }
}

variable "hub_worker_enabled" {
  description = <<-EOT
    Dark-first enable gate for the Connector Hub Fargate worker (Step 5, slice
    5b): the ECS cluster/task/service, the execution and task roles, the seeded
    key-material secret plus its retry-safe CREATE_ONLY keygen Lambda and
    public-only identity parameter, the dedicated worker security group, the
    Hub log group, and the ECR/S3 image-pull endpoints. It also opens the caller
    (Lambda) interface endpoint to the Hub task role.

    It requires BOTH hub_edge_enabled AND a live authority runtime
    (authority_runtime_functions_enabled on a bound contract): the worker fronts
    the 5a public UDP NLB target group and invokes the three live authority
    aliases (issue/refresh assignment, credential recovery). The module fails
    closed if this is set while either dependency is dark. Committed inputs leave
    it false; prod stays dark.
  EOT
  type        = bool
  default     = false
}

variable "tags" {
  description = "Additional tags applied to every supported resource."
  type        = map(string)
  default     = {}
}
