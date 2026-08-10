variable "environment" {
  description = "Environment label. The runtime-attestation store is intentionally sandbox-only."
  type        = string

  validation {
    condition     = var.environment == "sandbox"
    error_message = "The runtime-attestation store is sandbox-only."
  }
}

variable "name_prefix" {
  description = "Resource name prefix (layerv-nhp-sandbox)."
  type        = string

  validation {
    condition     = can(regex("^layerv-nhp-[a-z0-9-]+$", var.name_prefix))
    error_message = "name_prefix must look like layerv-nhp-<environment>."
  }
}

variable "bucket_name" {
  description = <<-EOT
    Exact runtime-attestation bucket name. The `layerv-nhp-sandbox-*` shape is
    enforced below rather than being a cosmetic label: the bucket's self-binding
    policy and every attested node's write grant are scoped to this exact name,
    so a rename is a boundary change. It was also the shape the retired
    UDP-proof manifest producer required.
  EOT
  type        = string
  default     = "layerv-nhp-sandbox-runtime-attestations"

  validation {
    condition     = can(regex("^layerv-nhp-sandbox-[a-z0-9][a-z0-9.-]{1,42}[a-z0-9]$", var.bucket_name))
    error_message = "bucket_name must be one exact layerv-nhp-sandbox-* S3 bucket name."
  }
}

variable "attested_node_roles" {
  description = <<-EOT
    Exact IAM role NAMES of the EC2 node roles that publish runtime
    attestations, keyed by the producer's workload key. Each role may only
    `s3:PutObject` beneath `runtime/$${aws:userid}/`; for an EC2 role AWS
    defines `aws:userid` as `<role-id>:<instance-id>`, so the prefix is
    self-bound and one instance cannot write another instance's row.

    Roles are owned by other roots (sandbox, sandbox-cell1). This module adds
    only the exact read grants the collector needs; S3 and KMS authority comes
    from the bucket and key policies, which are the artifacts the producer
    digests.
  EOT
  type        = map(string)
  default = {
    nhp_cell0                  = "layerv-nhp-sandbox-server"
    nhp_cell1                  = "layerv-nhp-sandbox-cell1-server"
    qurl_reverse_tunnel_server = "layerv-nhp-sandbox-frps"
  }

  validation {
    condition = alltrue([
      for role in values(var.attested_node_roles) :
      can(regex("^layerv-nhp-sandbox-[a-z0-9-]+$", role))
    ])
    error_message = "Every attested node role must be an exact layerv-nhp-sandbox-* role name."
  }

  validation {
    condition     = length(keys(var.attested_node_roles)) == length(distinct(values(var.attested_node_roles)))
    error_message = "Each attested node role must appear exactly once."
  }
}

variable "asg_name_ssm_parameters" {
  description = <<-EOT
    Canonical SSM parameters holding each attested fleet's exact ASG names,
    keyed by the same workload keys as attested_node_roles. The repair
    association targets those exact ASGs, which is what the producer verifies
    (`Targets == [{tag:aws:autoscaling:groupName: [<asg>...]}]`).

    A blue/green fleet lists EVERY colour's ASG parameter, not the active one.
    The association is plan-time state while the active colour changes at
    runtime, so resolving <env>/nhp/server/active-color here would re-encode
    create-time colour into the plan and drift on the next switch. Targeting
    every colour keeps the plan stable across a switch AND guarantees the
    colour that is active now is always covered.

    <env>/nhp/server/asg-name must NOT appear: modules/compute publishes it
    from the base/blue group for CI/CD instance refreshes, so it names blue no
    matter which colour serves traffic. Targeting it left the active green
    fleet with no collector installed and no attestations at all.
  EOT
  type        = map(list(string))
  default = {
    nhp_cell0 = [
      "/sandbox/nhp/server/blue-asg-name",
      "/sandbox/nhp/server/green-asg-name",
    ]
    nhp_cell1 = [
      "/sandbox-cell1/nhp/server/blue-asg-name",
      "/sandbox-cell1/nhp/server/green-asg-name",
    ]
    # Not blue/green: the whole /sandbox/nhp/reverse-tunnel-server/ path is
    # asg-name, image-tag and min-client-version, with no active-color marker.
    qurl_reverse_tunnel_server = [
      "/sandbox/nhp/reverse-tunnel-server/asg-name",
    ]
  }

  validation {
    condition     = alltrue([for parameters in values(var.asg_name_ssm_parameters) : length(parameters) > 0])
    error_message = "Every attested fleet must list at least one ASG name parameter."
  }

  validation {
    condition = alltrue([
      for parameters in values(var.asg_name_ssm_parameters) :
      length(parameters) == length(distinct(parameters))
    ])
    error_message = "Each fleet's ASG name parameters must be distinct."
  }

  validation {
    condition = alltrue(flatten([
      for parameters in values(var.asg_name_ssm_parameters) : [
        for parameter in parameters : !endswith(parameter, "/server/asg-name")
      ]
    ]))
    error_message = "The colour-blind <env>/nhp/server/asg-name must not be an attested ASG source; list each colour's <colour>-asg-name instead."
  }
}

variable "repair_schedule_expression" {
  description = <<-EOT
    State Manager association schedule. This repairs and re-verifies the exact
    collector/unit bytes; it is deliberately NOT the freshness clock (the timer
    publishes every five minutes and the producer rejects objects older than
    ten). SSM's minimum association interval is 30 minutes.
  EOT
  type        = string
  default     = "rate(30 minutes)"

  validation {
    condition     = can(regex("^rate\\([1-9][0-9]* (?:minutes|hours)\\)$", var.repair_schedule_expression))
    error_message = "repair_schedule_expression must be a rate(N minutes|hours) expression."
  }
}

variable "noncurrent_version_retention_days" {
  description = <<-EOT
    Days to keep superseded attestation versions. The store is append-only from
    the nodes' side and the collector rewrites one key every five minutes, so
    without expiry the version count grows without bound. The producer only
    ever reads the current version.
  EOT
  type        = number
  default     = 7

  validation {
    condition     = var.noncurrent_version_retention_days >= 1 && floor(var.noncurrent_version_retention_days) == var.noncurrent_version_retention_days
    error_message = "noncurrent_version_retention_days must be a whole number of days >= 1."
  }
}

variable "tags" {
  description = "Additional resource tags."
  type        = map(string)
  default     = {}
}
