# QURL FRP Server Module Variables
# FRP tunnel server for proxying traffic to customer backends via qurl-reverse-proxy

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for EC2 instances"
  type        = list(string)
}

variable "instance_type" {
  description = "EC2 instance type for FRP server"
  type        = string
  default     = "t3.small"
}

variable "namespace_id" {
  description = "Cloud Map namespace ID"
  type        = string
}

variable "namespace_name" {
  description = "Cloud Map namespace name"
  type        = string
}

variable "ac_security_group_id" {
  description = "AC security group ID (for ingress rules allowing AC to reach FRP server)"
  type        = string
}

variable "qurl_api_internal_url" {
  description = "URL for the QURL API used by the FRP auth plugin for token validation. Prefers the workload-account internal-ALB hostname when qurl_internal_service_domain is set (qurl-service #335); falls back to the public domain on greenfield envs. Empty string means 'not configured'; the ASG precondition enforces that this must be set whenever qurl_api_token_secret_arn is set."
  type        = string
  default     = ""

  validation {
    # Accept empty (dormant default) or a value with an explicit https://
    # scheme AND no embedded whitespace. Requiring https closes a
    # defense-in-depth gap: the QURL service token travels with every
    # auth-plugin request, and the current wiring points at the public
    # edge (NAT → CloudFront), so http:// would expose the token in
    # transit. The `[^[:space:]]+$` anchor rejects accidental trailing
    # whitespace / embedded CR from tfvars — user_data is careful about
    # whitespace in the token but treats the URL as a plan-time literal,
    # so this is the only guard on operator typo at config time. The
    # qurl-service #335 internal-ALB lift terminates HTTPS with its own
    # ACM cert (validated via the cross-account mgmt zone), so this
    # stays at `^https://`. Relax to `^https?://` only if a future
    # plain-HTTP path (VPC endpoint terminating at the service, etc.)
    # becomes the preferred consumer route.
    condition     = var.qurl_api_internal_url == "" || can(regex("^https://[^[:space:]]+$", var.qurl_api_internal_url))
    error_message = "qurl_api_internal_url must be empty or a well-formed https:// URL with no embedded whitespace. (See variable comment for rationale on disallowing http://.)"
  }
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

variable "logs_kms_key_arn" {
  description = "KMS key ARN for CloudWatch Logs encryption"
  type        = string
  default     = null
}

variable "ebs_kms_key_arn" {
  description = "KMS key ARN for EBS encryption"
  type        = string
  default     = null
}

variable "image_tag" {
  description = "qurl-frps binary version tag (used to download from S3 or ECR). Default is a placeholder CI must overwrite on first deploy rather than `latest`, to prevent an unattended Terraform apply from pulling a moving tag."
  type        = string
  default     = "v0.0.0-bootstrap"
}

variable "enable_cloudwatch_alarms" {
  description = "Enable CloudWatch alarms for FRP server monitoring"
  type        = bool
  default     = true
}

variable "alarm_sns_topic_arn" {
  description = "SNS topic ARN for alarm notifications (optional)"
  type        = string
  default     = ""
}

variable "frps_bind_port" {
  description = "FRP server control port (frpc connects here)"
  type        = number
  default     = 7000

  validation {
    # Floor at 1024: the qurl-frps systemd unit runs as the unprivileged
    # `frps` user with no `AmbientCapabilities=CAP_NET_BIND_SERVICE`, so a
    # privileged port would fail `bindPort` setup with an opaque systemd
    # "Permission denied" at boot instead of a clear plan-time rejection.
    condition     = var.frps_bind_port >= 1024 && var.frps_bind_port < 65536
    error_message = "frps_bind_port must be an unprivileged TCP port (1024-65535) — the frps systemd unit runs as an unprivileged user without CAP_NET_BIND_SERVICE."
  }
}

variable "frps_vhost_http_port" {
  description = "FRP vhost HTTP port (proxied HTTP traffic)"
  type        = number
  default     = 8080

  validation {
    # Same unprivileged-port floor as frps_bind_port — see rationale there.
    condition     = var.frps_vhost_http_port >= 1024 && var.frps_vhost_http_port < 65536
    error_message = "frps_vhost_http_port must be an unprivileged TCP port (1024-65535) — the frps systemd unit runs as an unprivileged user without CAP_NET_BIND_SERVICE."
  }
}

variable "frps_dashboard_port" {
  description = "FRP web dashboard port (localhost-only, used by user_data readiness check and SSM debugging). Default 7500 matches upstream FRP's documented default so the dashboard URL in operator runbooks stays stable if anyone consults the FRP docs directly."
  type        = number
  default     = 7500

  validation {
    # Same unprivileged-port floor as frps_bind_port — see rationale there.
    condition     = var.frps_dashboard_port >= 1024 && var.frps_dashboard_port < 65536
    error_message = "frps_dashboard_port must be an unprivileged TCP port (1024-65535) — the frps systemd unit runs as an unprivileged user without CAP_NET_BIND_SERVICE."
  }
}

variable "frps_subdomain_host" {
  description = "Subdomain host for FRP vhost routing (e.g., qurl.site). MUST match the qurl-router base domain (`qurl_router_config.base_domain` in root main.tf) so customer tunnel registrations resolve correctly. Threaded from `var.qurl_site_domain` at the root so sandbox (qurl.site.layerv.xyz) and prod (qurl.site) don't drift. The default below exists for isolated-module testing only."
  type        = string
  default     = "qurl.site"

  validation {
    # FRP's `subDomainHost` drives customer vhost resolution — a typo (empty,
    # leading/trailing dot, uppercase, whitespace) turns into a silent
    # misrouting that only manifests when a real tunnel registration tries
    # to resolve. Reject at plan time. Regex mirrors DNS-safe lowercase
    # hostname syntax — same shape as the `qurl_site_domain` validation at
    # the root envs.
    condition     = can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]\\.[a-z]{2,}$", var.frps_subdomain_host))
    error_message = "frps_subdomain_host must be a DNS-safe lowercase domain (e.g., qurl.site, qurl.site.layerv.xyz). No empty values, leading/trailing dots, uppercase, or whitespace."
  }
}

variable "frps_ecr_repo_arn" {
  description = "Override for the ECR repository ARN that scopes qurl-frps IAM pull permissions. Defaults to a computed `arn:aws:ecr:<region>:<account>:repository/layerv/qurl-reverse-tunnel-server` when unset — matching the repo name created by the ECR module's `core_ecr_repos`. Set explicitly to pin to a different repo."
  type        = string
  default     = null
}

variable "plugin_bucket_arn" {
  description = "Plugin bucket ARN used to scope the S3 fallback binary download IAM grant (when `docker pull` from ECR fails). Empty means no S3 fallback — user_data will still log and exit FATAL if ECR fails, but the `aws s3 cp` branch would AccessDenied-fail the same way, so omitting the grant explicitly documents 'ECR-only'. Integrity verification for the S3 path is tracked in #1258. Current posture: sandbox and prod both wire this from `module.plugins.bucket_arn` (see `terraform/main.tf`), so both environments run with the S3 fallback grant present. The empty default is only exercised when the module is consumed in isolation for testing."
  type        = string
  default     = ""
}

variable "plugin_bucket_name" {
  description = "Plugin bucket name threaded into user_data's `aws s3 cp` fallback command. Kept in lockstep with `plugin_bucket_arn` (same S3 bucket) so the IAM grant and the runtime command can never point at different buckets. Empty means user_data uses no fallback command (the ECR path is the only way in). Current posture: sandbox and prod both wire this from `module.plugins.bucket_name` (matching `plugin_bucket_arn`). Empty is only for isolated-module testing."
  type        = string
  default     = ""
}

variable "qurl_api_token_secret_arn" {
  description = "Secrets Manager ARN for the QURL internal service token (used by nhp-frps built-in tunnel auth plugin). The stored secret MUST be a raw token string, NOT a JSON envelope — user_data rejects JSON-shaped values at boot to avoid silent auth failures. When set, qurl_api_internal_url must also be set (enforced via ASG precondition)."
  type        = string
  default     = ""
}

variable "qurl_tunnel_auth_mode" {
  description = <<-EOT
    Selects which qurl-frps auth mode the deployed instance runs in. One of:

      ""             - Legacy api mode (default). qurl-frps validates each
                       NewProxy by calling qurl-service GET /resources/{id}
                       and matching FRP run_id against resource.connector_id.
                       The token in qurl_api_token_secret_arn is written to
                       the env as QURL_API_TOKEN.

      "tunnel-auth"  - Per-user API-key mode (qurl-reverse-tunnel-server PR
                       #83). qurl-frps reads the user's lv_live_* API key
                       from FRP Login.Metas[qurl_api_key] (or PrivilegeKey
                       fallback) and forwards it to qurl-service POST
                       /internal/v1/tunnel/auth. Requires the
                       qurl-reverse-tunnel-client follow-up
                       (layervai/qurl-reverse-tunnel-client#114) so qurl-frpc
                       actually populates the meta. The token in
                       qurl_api_token_secret_arn is written to the env as
                       QURL_INTERNAL_SERVICE_TOKEN, and
                       QURL_TUNNEL_AUTH_MODE=tunnel-auth is also exported.

    Defaults to "" (legacy mode) so this module change is a no-op for
    existing deploys; the env-shape flip only happens when the root
    explicitly opts into tunnel-auth mode for a given environment.

    "noop" is intentionally not exposed here — single-tenant deploys
    that want to disable auth should leave qurl_api_token_secret_arn
    empty, which produces the noop env shape via the existing branches
    in user_data.sh.tpl.
  EOT
  type        = string
  default     = ""

  validation {
    condition     = var.qurl_tunnel_auth_mode == "" || var.qurl_tunnel_auth_mode == "tunnel-auth"
    error_message = "qurl_tunnel_auth_mode must be \"\" (legacy api mode) or \"tunnel-auth\". Other values are rejected at startup by qurl-frps; reject here to surface the typo at plan time instead of at boot."
  }
}

# ==================== Per-AZ Cloud Map ====================
# Each suffix produces a Cloud Map service `frps-${suffix}.${namespace_name}`.
# Each ASG instance reads its AZ from IMDS at boot and registers with the
# matching service, so qurl-service can hash an OwnerID to a fixed AZ and
# both `frpc` and qurl-router converge on the same instance. See #1499.
#
# Default `["a", "b", "c"]` matches us-east-2{a,b,c} and us-east-1{a,b,c} —
# the regions sandbox and prod run in. The validation rejects entries that
# aren't a single lowercase letter so a typo (e.g. `"us-east-2a"`,
# `"A"`, `"a "`) fails plan instead of producing a Cloud Map service named
# `frps-us-east-2a` whose registrations the qurl-service hash never targets.
variable "frps_az_suffixes" {
  description = "AZ suffix letters for per-AZ Cloud Map services. One Cloud Map service `frps-$${suffix}.$${namespace_name}` is created per entry, and each ASG instance registers with the service whose suffix matches the trailing letter of its IMDS-reported AZ. Default `[\"a\", \"b\", \"c\"]` matches us-east-{1,2}{a,b,c}. Must agree with qurl-service's QURL_FRPS_AZ_SUFFIXES env var (see cross-repo contract in #1499)."
  type        = list(string)
  default     = ["a", "b", "c"]

  # NOTE: these two validation blocks are intentionally duplicated on the
  # root variable `var.frps_az_suffixes` in `terraform/variables.tf`. The
  # root copy fails plan even when `deploy_frps = false` keeps this module
  # out of the graph; the module copy fails for module-direct consumers
  # (smoke fixtures, isolated tests). Keep both in lockstep.
  validation {
    # Single lowercase letter — last char of an AWS AZ name (`us-east-2a` →
    # `a`). `length(...) > 0` makes the empty list explicit (zero AZ suffixes
    # would produce zero Cloud Map services and a silently-broken module).
    condition     = length(var.frps_az_suffixes) > 0 && alltrue([for s in var.frps_az_suffixes : can(regex("^[a-z]$", s))])
    error_message = "frps_az_suffixes must be a non-empty list of single lowercase letters (e.g., [\"a\", \"b\", \"c\"]) — each entry is the trailing letter of an AWS AZ name."
  }

  validation {
    # `toset` collapses duplicates; comparing lengths catches `["a","a","b"]`
    # which would otherwise produce a `for_each` collision on the Cloud Map
    # services. Phrased as a separate validation block so the error message
    # is unambiguous.
    condition     = length(toset(var.frps_az_suffixes)) == length(var.frps_az_suffixes)
    error_message = "frps_az_suffixes must not contain duplicates (each suffix maps to a distinct Cloud Map service)."
  }
}

# ==================== ASG Sizing ====================
# Module defaults remain 1/1/1 so the module is consumable in isolation
# (e.g., a smoke test fixture or single-AZ debug deploy). Production envs
# override to N/N/N where N == length(frps_az_suffixes) — the per-AZ Cloud
# Map fanout above means each ASG instance lands on its own AZ-keyed
# service, eliminating the in-memory-tunnel-registration split-brain that
# the old MULTIVALUE single-service config caused at N>1. See module
# header for the full per-AZ contract (#1499).

variable "min_size" {
  description = "ASG minimum size. Module default 1; production envs override to length(frps_az_suffixes) for one-instance-per-AZ via the per-AZ Cloud Map fanout."
  type        = number
  default     = 1

  validation {
    # `floor(...) == ...` rejects non-integers — `type = number` on its own
    # accepts 1.5, which would only fail at AWS-API time mid-apply.
    condition     = var.min_size >= 1 && floor(var.min_size) == var.min_size
    error_message = "min_size must be an integer >= 1 — qurl-frps is the only path for tunnel traffic; N=0 means tunnel resources 502."
  }
}

variable "max_size" {
  description = "ASG maximum size. Module default 1; production envs override to match min_size and length(frps_az_suffixes)."
  type        = number
  default     = 1

  validation {
    condition     = var.max_size >= 1 && floor(var.max_size) == var.max_size
    error_message = "max_size must be an integer >= 1 — see min_size for rationale (qurl-frps is the only path for tunnel traffic)."
  }
}

variable "desired_capacity" {
  description = "ASG desired capacity. Module default 1; production envs override to length(frps_az_suffixes) for one-instance-per-AZ steady state."
  type        = number
  default     = 1

  validation {
    condition     = var.desired_capacity >= 1 && floor(var.desired_capacity) == var.desired_capacity
    error_message = "desired_capacity must be an integer >= 1 — see min_size for rationale (qurl-frps is the only path for tunnel traffic)."
  }
}
