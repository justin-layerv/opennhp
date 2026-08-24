# NHP-Relay module inputs (#2208 Phase-2 #5).
#
# The relay is the HTTPS-only browser edge:
#   Browser JS-Agent --HTTPS POST /relay/{serverId}--> NHP-Relay
#     --NHP_RLY--> internal NHP-Server endpoint
#
# Horizontal fleet (#2208). The relay fleet shares ONE keypair and autoscales
# behind the ALB across AZs. The fleet works because the cell server authenticates
# each NHP_RLY by the relay's Noise IK pubkey (the handshake decrypts it) plus
# HandleRelayForward's lookupRelayPeer(relay.toml) registration check — NOT by the
# relay's source IP. The server therefore must run with DisableRelayPeerValidation
# = true (set via the server's device options; 5c), which skips the per-peer
# source-address pin (CheckRecvAddress) that would otherwise reject all-but-one
# instance under load. Each instance is independent (own UDP socket + pending map;
# the server replies with an authenticated return to the sending instance, which holds the browser's
# HTTP connection) — no cross-instance coordination. The fleet routes by serverId
# to one of N cells (cell_servers); each cell has its own shared server keypair +
# server/AC fleets. See docs/design/NHP_RELAY_TOPOLOGY.md.

# ── Identity / tagging ──

variable "environment" {
  description = "Deployment environment (nhp convention: `sandbox` or `prod`)."
  type        = string

  validation {
    condition     = contains(["sandbox", "prod"], var.environment)
    error_message = "environment must be `sandbox` or `prod` (nhp convention)."
  }
}

variable "name_prefix" {
  description = "Resource name prefix for the environment's single relay fleet."
  type        = string
}

variable "account_id" {
  description = "AWS account ID (passed in, not data.aws_caller_identity, so the prevent_destroy access-log bucket names stay known at plan). See access_logs.tf for the full rationale. #2623."
  type        = string

  validation {
    # It lands directly in a prevent_destroy bucket name; a malformed value
    # (trailing space, literal "default") otherwise fails as a confusing
    # malformed-ARN/bucket error mid-apply instead of a clear plan-time error.
    # Mirrors modules/bootstrap-alb/variables.tf::account_id.
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "tags" {
  description = "Base tags applied to every resource."
  type        = map(string)
  default     = {}
}

# ── Networking ──

variable "vpc_id" {
  description = "VPC ID. Pass `module.networking.vpc_id`."
  type        = string
}

variable "network_ready_token" {
  description = "Opaque relay-network readiness token. Public load balancers and the ASG wait on it without deferring this module's provider data sources at plan time."
  type        = string

  validation {
    condition     = trimspace(var.network_ready_token) != ""
    error_message = "network_ready_token must be non-empty."
  }
}

variable "vpc_endpoint_security_group_id" {
  description = "Security group ID shared by interface VPC endpoints. Relay instances use this for tightly scoped AWS control-plane egress (ECR, SSM, Secrets Manager, CloudWatch Logs/Metrics) instead of internet-wide outbound."
  type        = string

  validation {
    condition     = can(regex("^sg-[0-9a-f]+$", var.vpc_endpoint_security_group_id))
    error_message = "vpc_endpoint_security_group_id must be a security group ID."
  }
}

variable "server_security_group_id" {
  description = "NHP server instance security group ID. Relay nodes accept only authenticated UDP return traffic from this SG."
  type        = string

  validation {
    condition     = can(regex("^sg-[0-9a-f]+$", var.server_security_group_id))
    error_message = "server_security_group_id must be a security group ID."
  }
}

variable "public_subnet_ids" {
  description = "Public subnet IDs for the internet-facing browser ALB (≥2 AZs). Pass the relay-network public subnet IDs."
  type        = list(string)

  validation {
    condition     = length(var.public_subnet_ids) >= 2
    error_message = "public_subnet_ids must include at least 2 subnets (ALB requirement: distinct AZs)."
  }
}

variable "relay_subnet_ids" {
  description = "Isolated relay-DMZ subnet IDs for the relay ASG. These subnets have no NAT, public-IP mapping, or default route."
  type        = list(string)

  validation {
    condition     = length(var.relay_subnet_ids) >= 1
    error_message = "relay_subnet_ids must include at least 1 subnet."
  }
}

variable "nhp_server_cidr_blocks" {
  description = "Exact main-VPC private subnet CIDRs that host the internal NHP server/NLB path. Relay nodes get UDP 62206 egress only to these CIDRs over peering."
  type        = list(string)

  validation {
    condition     = length(var.nhp_server_cidr_blocks) >= 1
    error_message = "nhp_server_cidr_blocks must include at least 1 CIDR."
  }

  validation {
    condition     = alltrue([for cidr in var.nhp_server_cidr_blocks : can(cidrhost(cidr, 0))])
    error_message = "nhp_server_cidr_blocks entries must be valid CIDR notation."
  }
}

variable "asg_name" {
  description = "Remote name for the singleton relay ASG. PR 1 uses a DMZ-specific name so Terraform can create the replacement before retiring the old main-VPC ASG."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9_-]{0,254}$", var.asg_name))
    error_message = "asg_name must be a valid Auto Scaling group name."
  }
}

# ── Relay node image / AMI ──

variable "relay_repo_url" {
  description = "ECR repository URL for the relay image (`.../layerv/nhp-relay`). Pass `module.ecr.relay_repo_url`."
  type        = string
}

variable "relay_repo_arn" {
  description = "ECR repository ARN for the relay image. Scopes the instance role's ECR pull grant. Pass `module.ecr.relay_repo_arn`."
  type        = string
}

variable "server_ami_id" {
  description = "AMI for the relay node. Defaults to the SSM-published server AMI (`/$${environment}/nhp/server/ami-id`) when null — that AMI ships Docker + awscli + openssl + the systemd-resolved stub-disable fix the relay needs when resolving its internal NLB target at startup via Go's pure resolver; a stock Ubuntu AMI crash-loops. Override only with an AMI that carries the same baked-in fixes."
  type        = string
  default     = null
}

variable "ssm_image_tag_parameter" {
  description = "Root-owned shared SSM parameter name containing the relay image tag."
  type        = string

  validation {
    condition     = var.ssm_image_tag_parameter == "/${var.environment}/nhp/relay/image-tag"
    error_message = "ssm_image_tag_parameter must use the stable /<environment>/nhp/relay/image-tag path."
  }
}

variable "enable_matched_cohort_canary" {
  description = "Create an isolated candidate relay fleet and restricted candidate listener without changing the canonical relay rule."
  type        = bool
  default     = false
}

variable "matched_cohort_image_tag_parameter" {
  description = "SSM image slot consumed only by the isolated candidate relay fleet."
  type        = string
  default     = ""

  validation {
    condition = !var.enable_matched_cohort_canary || (
      var.matched_cohort_image_tag_parameter == "/${var.environment}/nhp/relay/green-image-tag"
    )
    error_message = "matched_cohort_image_tag_parameter must be /<environment>/nhp/relay/green-image-tag when enabled."
  }
}

variable "matched_cohort_cell_servers" {
  description = "Candidate relay cell table. Every host must be a green-only server endpoint."
  type = list(object({
    name       = string
    public_key = string
    host       = string
    port       = number
  }))
  default = []

  validation {
    condition = !var.enable_matched_cohort_canary || (
      length(var.matched_cohort_cell_servers) == length(var.cell_servers) &&
      length(var.matched_cohort_cell_servers) > 0 &&
      alltrue([for s in var.matched_cohort_cell_servers : trimspace(s.host) != "" && s.port == 62206])
    )
    error_message = "matched_cohort_cell_servers must contain one non-empty green-only UDP 62206 endpoint per ordinary cell."
  }
}

variable "matched_cohort_smoke_ingress_cidrs" {
  description = "Sorted duplicate-free IPv4 /32 sources allowed to reach the candidate relay listener."
  type        = list(string)
  default     = []

  validation {
    condition = !var.enable_matched_cohort_canary || (
      length(var.matched_cohort_smoke_ingress_cidrs) > 0 &&
      var.matched_cohort_smoke_ingress_cidrs == sort(distinct(var.matched_cohort_smoke_ingress_cidrs)) &&
      alltrue([for cidr in var.matched_cohort_smoke_ingress_cidrs : can(cidrhost(cidr, 0)) && endswith(cidr, "/32")])
    )
    error_message = "matched_cohort_smoke_ingress_cidrs must be a non-empty sorted duplicate-free list of IPv4 /32s when enabled."
  }
}

variable "relay_secret_arn" {
  description = "ARN of the independently owned relay identity secret. Only relay instances receive read access."
  type        = string

  validation {
    condition     = can(regex("^arn:(aws|aws-us-gov|aws-cn):secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:.+$", var.relay_secret_arn))
    error_message = "relay_secret_arn must be a Secrets Manager secret ARN."
  }
}

variable "instance_type" {
  description = "EC2 instance type for relay nodes. The relay is a lightweight stateless UDP forwarder; t3.small is ample per instance (scale horizontally, not vertically)."
  type        = string
  default     = "t3.small"
}

# ── Fleet capacity / autoscaling ──

variable "min_capacity" {
  description = "Minimum relay instances. Default (null) = ONE PER AZ — length(relay_subnet_ids), which is the AZ count — for AZ-redundant HA."
  type        = number
  default     = null

  validation {
    condition     = var.min_capacity == null || var.min_capacity >= 1
    error_message = "min_capacity must be null (one per AZ) or >= 1."
  }
}

variable "max_capacity" {
  description = "Maximum relay instances — the scale-out ceiling for request bursts / distributed floods the WAF per-source-IP limit does not cap. Default (null) = 2 per AZ (2 x the one-per-AZ baseline)."
  type        = number
  default     = null

  validation {
    condition     = var.max_capacity == null || var.max_capacity >= 1
    error_message = "max_capacity must be null (2 per AZ) or >= 1."
  }
}

variable "scale_requests_per_target" {
  description = "Target-tracking threshold: ALB request count per relay target (the per-target sum over the metric period, not literally per-minute), averaged across the fleet. Sparse knock traffic stays at min_capacity; sustained high volume scales out toward max_capacity. The WAF per-source-IP rate limit is the first-line DoS control; this is capacity elasticity, not the DoS gate."
  type        = number
  default     = 1000

  validation {
    condition     = var.scale_requests_per_target >= 50
    error_message = "scale_requests_per_target must be >= 50 (too low would thrash the fleet on health-check traffic)."
  }
}

# ── Cell routing (relay.toml [[servers]]) ──
# One entry per CELL the relay fronts. The browser's POST /relay/{serverId}
# selects the cell by the cell server's pubkey fingerprint. One relay fleet
# fronts all cells; a cell's many server instances share the cell keypair, so a
# single entry (the shared pubkey + the cell's stable in-VPC server endpoint)
# routes to the whole cell; the endpoint distributes across its server fleet.

variable "cell_servers" {
  description = "Cell-routing table rendered into relay.toml. One object per cell: name, public_key (the cell's shared NHP server X25519 pubkey, 44-char std base64 — its fingerprint is the {serverId} in POST /relay/{serverId}), host (stable in-VPC server endpoint; #2208 #8 uses the cell's internal UDP NLB DNS rather than raw CloudMap), port (NHP knock UDP, 62206). Pass a one-element list for the single current cell; append entries as cells are added."
  type = list(object({
    name       = string
    public_key = string
    host       = string
    port       = number
  }))

  validation {
    condition     = length(var.cell_servers) > 0
    error_message = "cell_servers must list at least one cell — a relay with no routable cell server is useless."
  }

  validation {
    # Empty allowed here (a greenfield apply before the server keygen runs yields
    # ""); the launch-template precondition fails loud on empty so a keyless relay
    # never boots.
    condition     = alltrue([for s in var.cell_servers : s.public_key == "" || can(regex("^[A-Za-z0-9+/]{43}=$", s.public_key))])
    error_message = "each cell_servers[*].public_key must be empty or a 44-char standard-base64 X25519 key (pass module.compute.server_public_key_b64)."
  }

  validation {
    condition     = alltrue([for s in var.cell_servers : s.port > 0 && s.port < 65536])
    error_message = "each cell_servers[*].port must be a valid UDP port (1-65535)."
  }

  validation {
    condition     = alltrue([for s in var.cell_servers : s.port == 62206])
    error_message = "each cell_servers[*].port must be 62206. The relay data plane is intentionally locked to NHP UDP only."
  }
}

# ── Relay listen ports ──

variable "listen_port" {
  description = "TCP port the relay's HTTP endpoint binds (behind the ALB). Matches the relay container HEALTHCHECK and the ALB target group. The ALB SG allows ingress here from the ALB only."
  type        = number
  default     = 8080
}

variable "udp_listen_port" {
  description = "Private UDP port the relay binds for sending NHP_RLY and receiving the server's authenticated RelayReturn on the SAME socket. The server replies to this (instance-IP, port), so the relay SG must allow UDP ingress here from inside the VPC. This is 62207 and must not be public; native SDKs bypass the relay and enter their assigned cell's public NLB on UDP 62206."
  type        = number
  default     = 62207

  validation {
    condition     = var.udp_listen_port == 62207
    error_message = "udp_listen_port is the fixed private relay return socket and must remain 62207."
  }
}

variable "cors_allowed_origins" {
  description = "#2631: comma-separated exact-match allowlist of browser Origins permitted to call the relay cross-origin. In practice the qURL knock portal only (`https://qurl.link`, per env) — the sole page that POSTs a knock to the relay. The resource domains (`*.qurl.site`, custom whitelabel) are the data plane and connect directly through the AC, never the relay, so they are NOT listed. The relay echoes the matched origin (never `*`). Empty (default) disables CORS (no Access-Control-* headers → a browser cross-origin POST is blocked), so the relay stays behaviorally dark until set. The ALB also forwards OPTIONS /relay/* (alb.tf) so the daemon can answer the preflight."
  type        = string
  default     = ""
}

# ── Monitoring (#2630) ──

variable "alarm_sns_topic_arn" {
  description = "SNS topic ARN for relay CloudWatch alarm notifications (#2630). Pass `module.monitoring.sns_topic_arn` from the root (mirrors how modules/ac wires its alarm_actions). Empty (default) leaves the alarms action-less — they still evaluate and show in the console, but page nobody — so a misconfigured root doesn't fail apply."
  type        = string
  default     = ""
}

# ── KMS ──

variable "ebs_kms_key_arn" {
  description = "CMK for the relay node's encrypted EBS root volume."
  type        = string
  default     = null
}

variable "logs_kms_key_arn" {
  description = "CMK for the relay CloudWatch log group."
  type        = string
  default     = null
}

variable "secrets_kms_key_arn" {
  description = "CMK encrypting the relay keypair secret. The keygen Lambda and the instance role get scoped Decrypt on it."
  type        = string
  default     = null
}

variable "certificate_arn" {
  description = "Root-owned regional ACM certificate ARN attached to this fleet's HTTPS listener."
  type        = string

  validation {
    condition     = can(regex("^arn:(aws|aws-us-gov|aws-cn):acm:[a-z0-9-]+:[0-9]{12}:certificate/[a-f0-9-]{36}$", var.certificate_arn))
    error_message = "certificate_arn must be a valid regional ACM ARN."
  }
}

# ── WAF ──
#
# Browser-facing surface posting an OPAQUE BINARY NHP packet
# (application/octet-stream). The load-bearing control is the per-source-IP
# rate-based rule; managed groups are defense-in-depth. CommonRuleSet's body
# inspection (SQLi/XSS) false-positives on binary bodies, so it ships
# count-only by default — observe sampled-requests before enforcing.

variable "waf_managed_rule_groups" {
  description = "AWS-managed WAF rule groups (full canonical names, `AWSManagedRules...`). Lean default for a browser-facing binary-POST surface: IP-reputation (cheap known-bad) + CommonRuleSet (count-only, see `waf_count_only_rule_groups`). Anonymous-IP / BotControl deliberately omitted — real browser users behind VPNs would false-positive Anonymous-IP, and BotControl's fixed ~$10/mo floor isn't justified for a dark sandbox surface (add later with evidence)."
  type        = list(string)
  default = [
    "AWSManagedRulesAmazonIpReputationList",
    "AWSManagedRulesCommonRuleSet",
  ]

  validation {
    condition     = length(var.waf_managed_rule_groups) == length(toset(var.waf_managed_rule_groups))
    error_message = "waf_managed_rule_groups must not contain duplicate entries."
  }

  validation {
    condition     = alltrue([for n in var.waf_managed_rule_groups : contains(["AWSManagedRulesAmazonIpReputationList", "AWSManagedRulesAnonymousIpList", "AWSManagedRulesCommonRuleSet", "AWSManagedRulesBotControlRuleSet"], n)])
    error_message = "Each entry must have a priority in alb.tf's `waf_managed_rule_priorities`. Allowed: AmazonIpReputationList, AnonymousIpList, CommonRuleSet, BotControlRuleSet. To add another, extend BOTH the priority map AND this allowlist."
  }
}

variable "waf_count_only_rule_groups" {
  description = "Managed groups overridden to `count` (observe, don't block). Default count-only's CommonRuleSet because the relay POST body is an opaque binary NHP packet that routinely false-positives CRS body rules (SQLi_BODY / XSS_BODY). Drop it from this list to enforce once sampled-requests confirm a low false-positive rate."
  type        = list(string)
  default     = ["AWSManagedRulesCommonRuleSet"]

  validation {
    condition     = length(var.waf_count_only_rule_groups) == length(toset(var.waf_count_only_rule_groups))
    error_message = "waf_count_only_rule_groups must not contain duplicate entries."
  }
}

variable "waf_rate_limit_per_source_ip" {
  description = "Per-source-IP request rate limit (requests per 5-minute window) on `/relay/*`. The load-bearing relay DoS control. Default 300: a single user's knock + re-knock-renewal loop is a handful of requests per session; 300/5min absorbs aggressive retry while staying far below a flood. Tune with evidence once #6 brings real browser traffic."
  type        = number
  default     = 300

  validation {
    condition     = var.waf_rate_limit_per_source_ip >= 100 && var.waf_rate_limit_per_source_ip <= 2000
    error_message = "waf_rate_limit_per_source_ip must be 100–2000 (module policy; AWS hard floor is 10 but <100 false-positives a normal session's retries)."
  }
}

# ── Access logs (#2623) ──

variable "access_log_glacier_transition_days" {
  description = "Days after which relay ALB access-log objects TRANSITION to Glacier (not expire). The hot tier (S3 Standard) covers the typical incident window; older logs land in Glacier (cheaper at rest, operator-explicit retrieval). Objects then live in Glacier indefinitely (no expiration — relay forensics retention is years-long). The ceiling bounds the TRANSITION timing only, not object lifetime."
  type        = number
  default     = 90

  validation {
    # AWS lifecycle floor is 30 (lower fails apply). Ceiling 365 is module policy:
    # past a year is cold-archive timing, not investigation retention.
    condition     = var.access_log_glacier_transition_days >= 30 && var.access_log_glacier_transition_days <= 365
    error_message = "access_log_glacier_transition_days must be 30–365 (AWS lifecycle floor is 30; module-policy ceiling is 365 for the TRANSITION timing — object lifetime in Glacier is unbounded by design)."
  }
}

variable "access_log_athena_query_retention_days" {
  description = "Days the separate Athena query-results bucket retains output. Athena results are derived fan-out from the access-log bucket — useful in the post-incident triage window, re-runnable after."
  type        = number
  default     = 30

  validation {
    condition     = var.access_log_athena_query_retention_days >= 7 && var.access_log_athena_query_retention_days <= 90
    error_message = "access_log_athena_query_retention_days must be 7–90 (derived, re-runnable query output; no need to retain past the triage window)."
  }
}
