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

# ==================== ASG Sizing ====================
# Defaults are 1/1/1 because nhp-frps holds tunnel registrations in memory per
# instance and Cloud Map uses MULTIVALUE routing — scaling beyond 1 today would
# route ~(N-1)/N of tunnel requests to instances that don't have the
# registration. Tracked in #1499 (consistent-hash routing in qurl-router OR
# shared registry in nhp-frps). When that lands, override these from the root
# (one instance per AZ in both sandbox and prod).

variable "min_size" {
  description = "ASG minimum size. Defaults to 1; do not raise without resolving #1499 (multi-AZ tunnel routing)."
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
  description = "ASG maximum size. Defaults to 1; see min_size and #1499 before raising."
  type        = number
  default     = 1

  validation {
    condition     = var.max_size >= 1 && floor(var.max_size) == var.max_size
    error_message = "max_size must be an integer >= 1 — see min_size for rationale (qurl-frps is the only path for tunnel traffic)."
  }
}

variable "desired_capacity" {
  description = "ASG desired capacity. Defaults to 1; see min_size and #1499 before raising."
  type        = number
  default     = 1

  validation {
    condition     = var.desired_capacity >= 1 && floor(var.desired_capacity) == var.desired_capacity
    error_message = "desired_capacity must be an integer >= 1 — see min_size for rationale (qurl-frps is the only path for tunnel traffic)."
  }
}
