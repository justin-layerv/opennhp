# QURL FRP Server Module Variables
# FRP tunnel server for proxying traffic to customer backends via qurl-reverse-tunnel-client

variable "environment" {
  description = "Environment name"
  type        = string

  validation {
    condition     = trimspace(var.environment) != ""
    error_message = "environment must be non-empty."
  }
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
  description = "qurl-reverse-tunnel-server binary version tag (used to download from S3 or ECR). Default is a placeholder CI must overwrite on first deploy rather than `latest`, to prevent an unattended Terraform apply from pulling a moving tag."
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

variable "enable_sns_alerts" {
  description = "Static boolean: set true when this module's SNS-routed alarms should be created and alarm_sns_topic_arn is wired. SNS-routed alarm counts gate on this value to avoid count-depends-on-computed."
  type        = bool
  default     = false
}

# Per-AZ Cloud Map empty-registration watchdog (#1542) — detection layer
# that catches the (a=2, b=1, c=0) ASG distribution that satisfies
# `GroupInServiceInstances < 1` while leaving one AZ's Cloud Map service
# empty. PR #1549 ships the structural fence (one ASG per AZ); this
# watchdog stays in place after #1549 as defense in depth.
variable "frps_empty_az_alarm_enabled" {
  description = <<-EOT
    Deploy the per-AZ Cloud Map empty-registration watchdog. Default true.

    First apply after this PR adds (per env where deploy_frps = true):
      - 1 Lambda function (empty_az_watchdog, ~2 KB packaged, python3.12)
      - 1 IAM role + 1 inline policy + 1 managed-policy attachment
      - 1 EventBridge rule + 1 target + 1 lambda:InvokeFunction permission
      - 1 CloudWatch log group (KMS-encrypted)
      - length(frps_az_suffixes) per-AZ alarms (3 by default; PAGE)
      - 1 Lambda Errors self-failure alarm (TICKET)
      - 1 EventBridge FailedInvocations self-failure alarm (TICKET)
    Cost ≈ $1.40/month at the default 3-AZ fanout (see monitoring_empty_az.tf
    cost note).

    Detection-only — no traffic-path coupling. Set to `false` to opt out
    (e.g., for module-isolated test fixtures where iterating Cloud Map
    services per AZ is not desired).

    Note: this watchdog is also gated on `enable_cloudwatch_alarms` (see
    `monitoring_empty_az.tf` `local.enable_empty_az_watchdog`). Disabling
    `enable_cloudwatch_alarms` removes the entire detection layer
    (Lambda, EventBridge rule, IAM, alarms) — there's no value in
    running the metric-emitting Lambda when no alarms consume the
    metric. If you ever want metrics for a dashboard but no paging,
    add a separate gate.

    Greenfield flap expectation: on a fresh apply where `deploy_frps =
    true` flips for the first time, the per-AZ alarms create in the
    same plan as the ASG/Cloud Map services. EventBridge first-fires
    at ~rate(5 min); Cloud Map registration takes 30-90s post-launch;
    cold AMI pull adds ~5-7 min. Total >~10-15 min from apply to
    first non-zero datapoint per AZ is plausible. The per-AZ alarm's
    `evaluation_periods = 2 × period 300s` (10-min floor) may
    transition to ALARM and page once before the first
    PerAZRegistrationCount publish lands. Existing-env applies
    don't see this (instances already registered); greenfield envs
    should expect a possible one-shot flap on first apply and ack.
  EOT
  type        = bool
  default     = true
}

variable "frps_bind_port" {
  description = "FRP server control port (frpc connects here)"
  type        = number
  default     = 7000

  validation {
    # Floor at 1024: the qurl-reverse-tunnel-server systemd unit runs as the unprivileged
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

# --- FRPS ASG launch-readiness gate (qurl-reverse-tunnel-server#195) ---------
# An EC2_INSTANCE_LAUNCHING lifecycle hook holds a refreshed/launched instance
# in Pending:Wait (NOT InService) until user_data signals CONTINUE after the FRP
# readiness probe passes, so ASG-health consumers (the post-deploy smoke) never
# select a still-starting box. See the frps launch hook resources and the
# launch-readiness gate near the end of user_data.sh.tpl.

variable "frps_launch_readiness_default_result" {
  description = <<-EOT
    Lifecycle-hook `default_result` for the FRPS launch-readiness hook. user_data
    only ever signals CONTINUE (on a fully healthy boot); EVERY failure path exits
    without signaling and falls through to this `default_result` at
    `heartbeat_timeout`. So this is the single knob governing what happens to any
    boot that never reached the CONTINUE signal.

    Defaults to the SAFE value "CONTINUE": a broken or misconfigured boot waits out
    the timeout and is then admitted ungated (today's behavior). Because user_data
    signals no explicit ABANDON anywhere, the CONTINUE default cannot turn a
    steady-state scale-out of a broken image (no instance-refresh => no
    auto_rollback) into an ABANDON->relaunch->ABANDON loop.

    Flip to "ABANDON" only AFTER sandbox validation confirms (a) a healthy instance
    actively emits CONTINUE before `heartbeat_timeout` (not a timeout fallthrough),
    and (b) a forced-broken boot is replaced at the timeout and trips
    instance-refresh `auto_rollback` (health_check_type=EC2 cannot otherwise detect
    a dead FRP). ABANDON is the post-validation target because it is what lets
    auto_rollback catch FRP-readiness failures.
  EOT
  type        = string
  default     = "CONTINUE"

  validation {
    condition     = contains(["CONTINUE", "ABANDON"], var.frps_launch_readiness_default_result)
    error_message = "frps_launch_readiness_default_result must be \"CONTINUE\" (safe default) or \"ABANDON\" (post-sandbox-validation target)."
  }
}

variable "frps_launch_readiness_heartbeat_timeout" {
  description = <<-EOT
    `heartbeat_timeout` (seconds) — the maximum time an instance may sit in
    Pending:Wait before `default_result` is applied. The clock starts at instance
    launch, so this must exceed worst-case cold-boot for the ENTIRE user_data: apt,
    the AWS CLI install, the container image pull (the dominant cost), config, the
    ~60s FRP readiness window, and Cloud Map registration. Because user_data signals
    only CONTINUE, this timeout is ALSO the latency before a broken boot resolves to
    `default_result`. Default 600 is a starting point; the sandbox validator should
    measure real cold-boot from launch and set this from data.
  EOT
  type        = number
  default     = 600

  validation {
    # AWS allows 30..7200s; floor at 60 so a fat-fingered tiny value can't
    # ABANDON every healthy-but-still-booting instance.
    condition     = var.frps_launch_readiness_heartbeat_timeout >= 60 && var.frps_launch_readiness_heartbeat_timeout <= 7200
    error_message = "frps_launch_readiness_heartbeat_timeout must be 60-7200 seconds (AWS lifecycle-hook bound; floored at 60 to leave room for cold-boot)."
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
  description = "Override for the ECR repository ARN that scopes qurl-reverse-tunnel-server IAM pull permissions. Defaults to a computed `arn:aws:ecr:<region>:<account>:repository/layerv/qurl-reverse-tunnel-server` when unset — matching the repo name created by the ECR module's `core_ecr_repos`. Set explicitly to pin to a different repo."
  type        = string
  default     = null
}

variable "plugin_bucket_arn" {
  description = "Plugin bucket ARN used to scope the S3 fallback binary download IAM grant (when `docker pull` from ECR fails). Empty means no S3 fallback — user_data will still log and exit FATAL if ECR fails, but the `aws s3 cp` branch would AccessDenied-fail the same way, so omitting the grant explicitly documents 'ECR-only'. Integrity verification for the S3 path is tracked in #1258. Current posture: sandbox and prod both wire this from `module.plugins.bucket_arn` (see `terraform/main.tf`), so both environments run with the S3 fallback grant present. The empty default is only exercised when the module is consumed in isolation for testing."
  type        = string
  default     = ""
}

variable "plugin_bucket_name" {
  description = "Plugin bucket name used for the S3-hosted FRPS init script (`scripts/frps-init.sh`) and threaded into user_data's binary fallback command. Kept in lockstep with `plugin_bucket_arn` and `plugin_download_policy_arn` so the runtime `aws s3 cp` and IAM/KMS grants cannot drift. Current posture: sandbox and prod both wire this from `module.plugins.bucket_name`; empty is only for isolated-module validation and will fail the launch-template size precondition for real applies while the rendered init script exceeds EC2's user_data cap."
  type        = string
  default     = ""
}

variable "plugin_download_policy_arn" {
  description = "ARN of the shared plugin-bucket download policy granting s3:GetObject plus KMS decrypt for the bucket CMK. Required with plugin_bucket_name because the launch-template user_data downloads scripts/frps-init.sh from the plugin bucket at boot."
  type        = string
  default     = ""
}

variable "qurl_api_token_secret_arn" {
  description = "Secrets Manager ARN for the QURL internal service token (used by nhp-frps built-in tunnel auth plugin). The stored secret MUST be a raw token string, NOT a JSON envelope — user_data rejects JSON-shaped values at boot to avoid silent auth failures. When set, qurl_api_internal_url must also be set (enforced via ASG precondition)."
  type        = string
  default     = ""
}

variable "secrets_kms_key_arn" {
  description = "KMS key ARN for customer-managed Secrets Manager secrets this instance role reads. When set, the role gets kms:Decrypt so user_data can fetch CMK-encrypted secrets."
  type        = string
  default     = null
}

variable "nhp_server_internal_url" {
  description = <<-EOT
    Base URL qurl-reverse-tunnel-server uses to validate AC-issued knock tokens
    with nhp-server. Required under qurl_tunnel_auth_mode="tunnel-auth".

    Prefer the VPC-internal Cloud Map origin (http://server.<namespace>:8888)
    so nhp-server sees a private source IP; HTTPS public origins remain
    accepted for direct-module/nonstandard topologies. Must be an origin only
    with no trailing slash; qurl-reverse-tunnel-server appends
    /nhp/internal/token/validate. The .internal suffix matches the private DNS
    namespace in modules/data/main.tf; HTTP .internal hostnames are expected
    to be lowercase Cloud Map/private DNS names.
  EOT
  type        = string
  default     = ""

  validation {
    # Mirror of root `terraform_data.nhp_server_internal_url_preconditions`
    # and modules/qurl-service/variables.tf::nhp_server_internal_url. Examples:
    # accept "", https://nhp.example.com, http://server.nhp.sandbox.internal:8888;
    # reject http://server.nhp.sandbox.internal:99999 and any path/query/fragment.
    # The HTTPS branch is an origin-shape-only escape hatch for direct-module
    # nonstandard topologies; runtime URL parsing owns host/port semantics there.
    condition = (
      var.nhp_server_internal_url == ""
      || can(regex("^https://[^[:space:]/?#]+$", var.nhp_server_internal_url))
      || can(regex("^http://([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+internal:([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$", var.nhp_server_internal_url))
    )
    error_message = "nhp_server_internal_url must be empty, an HTTPS origin URL or an HTTP private hosted-zone origin ending in .internal with an explicit valid TCP port (1-65535); either form must have no path, query, fragment, or trailing slash (for example http://server.nhp.sandbox.internal:8888)."
  }
}

variable "nhp_internal_auth_secret_arn" {
  description = "Secrets Manager ARN for the NHP internal auth HMAC secret. Required under qurl_tunnel_auth_mode=\"tunnel-auth\" so qurl-reverse-tunnel-server can sign knock-token validation requests to nhp-server."
  type        = string
  default     = ""
}

variable "connect_layerv_host" {
  description = "Customer-facing public FRP control hostname (for example connect.layerv.xyz). Used only as the active-registration boundary label; the registered upstream endpoint remains the instance-private FRP vhost listener."
  type        = string
  default     = ""

  validation {
    condition     = var.connect_layerv_host == "" || can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$", var.connect_layerv_host))
    error_message = "connect_layerv_host must be empty or a bare lowercase DNS hostname with no scheme, port, path, or whitespace."
  }
}

variable "tunnel_server_az_control_ports" {
  description = "Per-AZ public NHP-protected FRP control listener ports, keyed by AZ suffix. Threaded from the root module's tunnel_server_az_control_port local so NHP resource rows and qurl-reverse-tunnel-server active-registration boundary labels share one port map."
  type        = map(number)
  default     = {}

  validation {
    condition     = alltrue([for suffix in keys(var.tunnel_server_az_control_ports) : can(regex("^[a-z]$", suffix))])
    error_message = "tunnel_server_az_control_ports keys must be single lowercase AZ suffixes such as a, b, or c."
  }

  validation {
    condition     = alltrue([for port in values(var.tunnel_server_az_control_ports) : port >= 1 && port <= 65535])
    error_message = "tunnel_server_az_control_ports values must be valid TCP ports (1-65535)."
  }
}

variable "qurl_tunnel_auth_mode" {
  description = <<-EOT
    Selects which qurl-reverse-tunnel-server auth mode the deployed instance runs in. One of:

      ""             - Legacy placeholder kept for module API compatibility.
                       Current qurl-reverse-tunnel-server images no longer
                       accept unset mode; do not use this with a modern
                       image.

      "tunnel-auth"  - Knock-token-as-identity mode. qurl-reverse-tunnel-server
                       validates the AC-issued knock token with nhp-server,
                       stashes the server-resolved owner_id for the FRP
                       run_id, authorizes NewProxy through qurl-service
                       POST /internal/v1/tunnel/auth-by-owner, and publishes
                       active target registrations to qurl-service. The token
                       in qurl_api_token_secret_arn is written to the env as
                       QURL_INTERNAL_SERVICE_TOKEN, and QURL_TUNNEL_AUTH_MODE,
                       NHP_SERVER_INTERNAL_URL, NHP_INTERNAL_AUTH_SECRET, and
                       QURL_TUNNEL_INSTANCE_* are exported.

    Defaults to "" for module API compatibility with environments that have
    not deployed qurl-reverse-tunnel-server. Any environment that sets
    deploy_frps=true with a current image must set "tunnel-auth".

    "noop" is intentionally not exposed here — this module is for the
    multi-tenant FRPS-behind-AC topology.
  EOT
  type        = string
  default     = ""

  validation {
    condition     = var.qurl_tunnel_auth_mode == "" || var.qurl_tunnel_auth_mode == "tunnel-auth"
    error_message = "qurl_tunnel_auth_mode must be \"\" (module-compat placeholder) or \"tunnel-auth\". Other values are rejected at startup by qurl-reverse-tunnel-server; reject here to surface the typo at plan time instead of at boot."
  }
}

variable "min_client_version" {
  description = "Initial qurl-connector minimum version for the qurl-reverse-tunnel-server runtime gate. Empty seeds the SSM parameter as disabled. Values may include the v prefix because qurl-reverse-tunnel-server normalizes it before comparison. After first apply, ignore_changes makes this seed write-once; update the SSM value directly for hot changes."
  type        = string
  default     = ""

  validation {
    condition     = var.min_client_version == "" || can(regex("^v?[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?$", var.min_client_version))
    error_message = "min_client_version must be empty or a semantic version like 1.2.3, v1.2.3, or 1.2.3-beta.1; build metadata is not supported by qurl-reverse-tunnel-server."
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
  # (smoke fixtures, isolated tests). Keep both in lockstep with each other
  # and with cloudmap-common.sh's supported service-name regex.
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
    error_message = "min_size must be an integer >= 1 — qurl-reverse-tunnel-server is the only path for tunnel traffic; N=0 means tunnel resources 502."
  }
}

variable "max_size" {
  description = "ASG maximum size. Module default 1; production envs override to match min_size and length(frps_az_suffixes)."
  type        = number
  default     = 1

  validation {
    condition     = var.max_size >= 1 && floor(var.max_size) == var.max_size
    error_message = "max_size must be an integer >= 1 — see min_size for rationale (qurl-reverse-tunnel-server is the only path for tunnel traffic)."
  }
}

variable "desired_capacity" {
  description = "ASG desired capacity. Module default 1; production envs override to length(frps_az_suffixes) for one-instance-per-AZ steady state."
  type        = number
  default     = 1

  validation {
    condition     = var.desired_capacity >= 1 && floor(var.desired_capacity) == var.desired_capacity
    error_message = "desired_capacity must be an integer >= 1 — see min_size for rationale (qurl-reverse-tunnel-server is the only path for tunnel traffic)."
  }
}

# ==================== Per-AZ ASG Sizing (preferred) ====================
# Per-AZ sizing knobs. When set (non-null), they OVERRIDE the legacy
# `min_size`/`max_size`/`desired_capacity` triple by computing the
# effective single-ASG fleet size as `per_az * length(frps_az_suffixes)`.
#
# Default null preserves backwards compatibility: existing callers that set
# the legacy triple keep working unchanged. New callers should prefer the
# per-AZ form because it expresses the actual operational invariant —
# "N instances per AZ, summed across the AZ suffix list" — instead of
# repeating an arithmetic product in tfvars that drifts when
# `frps_az_suffixes` changes.
#
# Effective value precedence (see `local.effective_*` in main.tf):
#   - per-AZ var set (non-null)  → per_az * length(frps_az_suffixes)
#   - per-AZ var null            → legacy triple (min_size/max_size/desired_capacity)
#
# Validation block on each per-AZ var rejects fractional values; the
# composition rule (min ≤ desired ≤ max) is enforced once, post-resolution,
# in `aws_autoscaling_group.frps` via the existing `precondition` so
# either form (legacy, per-AZ, or even a half-mix during a migration plan)
# fails plan with the same error message.

variable "desired_capacity_per_az" {
  description = <<-EOT
    Per-AZ ASG desired capacity. When set (non-null), the module computes the
    effective ASG `desired_capacity` as `desired_capacity_per_az *
    length(frps_az_suffixes)` and the legacy `desired_capacity` variable is
    ignored. Default null keeps the legacy triple (`min_size`/`max_size`/
    `desired_capacity`) as the source of truth for backwards compatibility.

    PR sequence: this variable's introduction defaults null so it's a no-op
    for current deploys. The multi-instance-per-AZ rollout sets
    `desired_capacity_per_az = 2` in prod tfvars to flip the steady-state
    distribution from 1/AZ to 2/AZ once the router-side HRW dispatch is
    enabled (traefik-plugins #134).
  EOT
  type        = number
  default     = null

  validation {
    condition     = var.desired_capacity_per_az == null || (var.desired_capacity_per_az >= 1 && floor(var.desired_capacity_per_az) == var.desired_capacity_per_az)
    error_message = "desired_capacity_per_az must be null or an integer >= 1 — qurl-reverse-tunnel-server must have at least one instance per AZ; fractional values are rejected at plan time rather than at the ASG API."
  }
}

variable "min_size_per_az" {
  description = <<-EOT
    Per-AZ ASG minimum size. When set (non-null), the module computes the
    effective ASG `min_size` as `min_size_per_az * length(frps_az_suffixes)`
    and the legacy `min_size` variable is ignored. Default null keeps the
    legacy `min_size` as the source of truth.
  EOT
  type        = number
  default     = null

  validation {
    condition     = var.min_size_per_az == null || (var.min_size_per_az >= 1 && floor(var.min_size_per_az) == var.min_size_per_az)
    error_message = "min_size_per_az must be null or an integer >= 1 — see desired_capacity_per_az."
  }
}

variable "max_size_per_az" {
  description = <<-EOT
    Per-AZ ASG maximum size. When set (non-null), the module computes the
    effective ASG `max_size` as `max_size_per_az * length(frps_az_suffixes)`
    and the legacy `max_size` variable is ignored. Default null keeps the
    legacy `max_size` as the source of truth.

    Default null also means "fixed-size fleet" remains the safe default —
    autoscaling above the steady-state distribution requires explicitly
    setting this to a value strictly greater than `desired_capacity_per_az`,
    which a separate `precondition` in `aws_autoscaling_group.frps` checks.
  EOT
  type        = number
  default     = null

  validation {
    condition     = var.max_size_per_az == null || (var.max_size_per_az >= 1 && floor(var.max_size_per_az) == var.max_size_per_az)
    error_message = "max_size_per_az must be null or an integer >= 1 — see desired_capacity_per_az."
  }
}

# ==================== Cloud Map Routing Policy ====================
# Per-AZ Cloud Map services support either WEIGHTED (current default,
# returns one A record per query) or MULTIVALUE (returns the full set
# of healthy A records, up to 8). The router-side HRW work in
# traefik-plugins #134 needs MULTIVALUE so qurl-router sees every
# healthy instance and can hash a resource_id to a specific instance
# IP. Frpc (qurl-reverse-tunnel-client) does the same on the dial side.
#
# Default WEIGHTED preserves the existing 1-instance-per-AZ behavior
# unchanged. Set MULTIVALUE in tfvars before flipping
# desired_capacity_per_az above 1 — running 2/AZ on WEIGHTED would
# leave half the instances unreachable to the router (bias-uniform A-
# record selection picks one IP at random per query, and the
# qurl-router's per-resource cache would then send all traffic for
# that resource to one of the two instances arbitrarily, defeating the
# whole point of HRW dispatch).
#
# The plan-time precondition in `aws_service_discovery_service.frps_per_az`
# rejects WEIGHTED + (effective desired > length(frps_az_suffixes)) so the
# misconfiguration above can't ship.
variable "cloud_map_routing_policy" {
  description = <<-EOT
    DNS routing policy for the per-AZ Cloud Map services. One of:

      "WEIGHTED"   - (default, backwards compatible) A query returns ONE
                     A record per response, weight-biased. Correct for
                     1-instance-per-AZ; returns a single instance IP that
                     both frpc and qurl-router converge on via the API-
                     supplied `frps_addr`.
      "MULTIVALUE" - A query returns the FULL set of healthy A records
                     (up to 8). Required when running >1 instance per AZ
                     so router-side HRW (traefik-plugins #134) can hash
                     a resource_id to a specific instance IP.

    Set to "MULTIVALUE" before flipping `desired_capacity_per_az` above 1.
    A precondition in `aws_service_discovery_service.frps_per_az` rejects
    `WEIGHTED + effective_desired > length(frps_az_suffixes)` at plan time.

    Replacement semantics: AWS Cloud Map's `UpdateService` API does NOT
    accept a new `RoutingPolicy` (only Description, DnsRecords, and
    HealthCheckConfig.FailureThreshold are mutable in place). The
    provider therefore marks `dns_config.routing_policy` as ForceNew —
    flipping this variable from WEIGHTED → MULTIVALUE produces a
    REPLACEMENT plan for every per-AZ service (and, when blue/green is
    enabled, every green service too). Service IDs change, but user_data
    now resolves IDs from stable service names at boot; the launch
    template does not bump solely because the service IDs changed.
    Operators must cycle the FRPS fleet after the apply so instances
    re-register against the recreated service IDs.

    MULTIVALUE cutover sequence (sandbox blue/green path):
      1. Pre-stage: blue/green ALREADY enabled with green at warm
         standby. Blue is serving traffic, green is dormant on the
         OLD service IDs.
      2. Apply MULTIVALUE flip: terraform replaces both blue and green
         per-AZ services in one apply. Existing instance registrations
         on the OLD services are dropped at delete time.
      3. Existing instances remain registered against the OLD service
         IDs. Start an FRPS instance refresh or replace the ASG
         instances so each fresh instance resolves the stable
         `frps-$${suffix}` service name to the NEW ID and registers.
         Until then, DNS for `frps-$${suffix}.$${namespace}` may
         resolve NXDOMAIN and qurl-service may emit upstreams with no
         live registration behind them.
      4. After all instances re-register, the qurl-service flip is a
         normal blue→green ASG color change.

    MULTIVALUE cutover sequence (prod canary path):
      The canary state machine refreshes instances in checkpoints
      (20% → 50% → 100%). Each checkpoint window is the same window
      as above on a smaller scale. The CloudWatch composite alarm
      will trip if any checkpoint stalls in NXDOMAIN — confirm the
      empty-AZ alarm (#1542) thresholds are tight enough to catch
      a half-cutover before customer traffic is impacted.

    A precondition in `aws_service_discovery_service.frps_per_az`
    rejects WEIGHTED + (effective desired > length(frps_az_suffixes))
    so the misconfiguration "2/AZ on WEIGHTED" can't ship — but no
    fence covers the transition itself. The fence above is the
    runbook responsibility.
  EOT
  type        = string
  default     = "WEIGHTED"

  validation {
    condition     = contains(["WEIGHTED", "MULTIVALUE"], var.cloud_map_routing_policy)
    error_message = "cloud_map_routing_policy must be \"WEIGHTED\" or \"MULTIVALUE\". AWS supports a third value (\"WEIGHTED_RANDOM\") on a different shape of service; qurl-reverse-tunnel-server only uses A-record DNS namespaces, so accept only the two policies that apply."
  }
}

# ==================== Blue/Green Deployment ====================
# Mirrors `modules/ac/blue_green.tf`. When enabled, the module also
# provisions a green ASG, a parallel set of green per-AZ Cloud Map
# services (`frps-green-${suffix}.${namespace}`), and SSM parameters
# (active-color / blue-asg-name / green-asg-name / etc.) that CI/CD
# scripts read to flip `frps_addr` resolution from blue → green during
# a deploy.
#
# Default false keeps the module a no-op for current deploys. Sandbox
# is the first env to flip this on; prod stays on the canary path
# (see `enable_canary` below).

variable "enable_blue_green" {
  description = <<-EOT
    Enable blue/green deployment for qurl-reverse-tunnel-server.

    When true, the module provisions:
      - One green ASG sized to match the blue ASG (effective sizing) —
        warm-standby capacity managed by `green_standby_capacity_per_az`.
      - One green per-AZ Cloud Map service per AZ suffix
        (`frps-green-$${suffix}.$${namespace}`). Active-color SSM parameter
        steers `frps_addr` resolution downstream.
      - SSM parameters: active-color, last-switch-timestamp, blue-asg-name,
        green-asg-name, plus per-color image-tag parameters (CI updates).

    Default false keeps the module a no-op for current deploys. Mutually
    exclusive with `enable_canary` (a precondition rejects both true).

    Note: qurl-reverse-tunnel-server has no NLB/target group — Cloud Map A-record
    resolution is the routing layer. The blue/green flip therefore
    targets the Cloud Map service identity (CI rewrites `frps_addr`
    in the QURL API to point at green's per-AZ services), not a
    listener default-action change as on the AC module.
  EOT
  type        = bool
  default     = false
}

variable "green_standby_capacity_per_az" {
  description = <<-EOT
    Per-AZ desired capacity for the green ASG when in standby (active
    color = blue). N = N-instance warm standby (flip is instant once
    capacity is reached); 0 = cold standby (CI must scale-up before
    flipping).

    Default `null` means "track `min_size_per_az` when set, else 1" — so
    the resolved standby always satisfies `min ≤ desired ≤ max` without
    the operator having to keep two knobs in lockstep across files. The
    MULTIVALUE rollout (which sets `min_size_per_az = 2`) gets
    `effective_standby = 2`
    automatically; an env that wants cold standby can set this explicitly
    to `0`.

    Effective green ASG `desired_capacity` is the resolved
    `effective_standby * length(frps_az_suffixes)`.

    Ignored when `enable_blue_green = false`.
  EOT
  type        = number
  default     = null

  validation {
    condition     = var.green_standby_capacity_per_az == null || (var.green_standby_capacity_per_az >= 0 && var.green_standby_capacity_per_az <= 10 && floor(var.green_standby_capacity_per_az) == var.green_standby_capacity_per_az)
    error_message = "green_standby_capacity_per_az must be null (auto-track min_size_per_az or 1) or an integer between 0 and 10. Floor at 0 = cold standby; ceiling at 10 catches typos that would provision an absurdly large warm fleet."
  }
}

variable "knock_token_reject_threshold_per_minute" {
  description = "Threshold value for the `frps-knock-token-reject-rate` alarm (counts `knock_token_invalid` + `knock_token_validator_error` slog events emitted from the FRP-Login knock-token validator in `internal/tunnelauth/handler.go`). The alarm uses `GreaterThanThreshold` so a default of `3` fires at 4+/min sustained 3-of-5 minutes — same comparator and shape as the bootstrap-ALB `alb_target_5xx` alarm so noise behavior stays uniform across the v1 observability surface. The filters cover upstream validator `valid=false` and transport/upstream/parse failures; local empty-token and defensive post-validation contract rejects still fail closed but have log-only telemetry outside this alarm. Customer-install symptom: a sustained burst here is the operator-paged signal for a blocked UDP knock path on the customer side (skipped firewall step in the install runbook) or an nhp-server outage on the LayerV side."
  type        = number
  default     = 3

  validation {
    condition     = var.knock_token_reject_threshold_per_minute >= 1 && var.knock_token_reject_threshold_per_minute <= 1000
    error_message = "knock_token_reject_threshold_per_minute must be 1 ≤ x ≤ 1000. Floor 1: threshold 0 with GreaterThanThreshold pages on the first single reject; a single legitimate `empty_token_local_skip` from a misconfigured operator probe shouldn't wake on-call. Ceiling 1000: catches typo-class mistakes that would effectively disable the alarm."
  }
}
