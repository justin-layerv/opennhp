# AC Module Variables
# Access Controller with embedded Traefik for TLS termination

variable "environment" {
  description = "Environment name"
  type        = string

  # Fail at plan time rather than silently emitting Environment=unknown
  # (empty) or Environment=" prod " (leading/trailing whitespace from a
  # heredoc-mangled tfvar) from the AC CloudWatch publisher
  # (NewACRegistration's empty-or-whitespace-config fallback). Either
  # would render as a malformed dim value in config.toml and produce
  # the same alarm-mismatch failure mode this fence exists to close.
  # The Go side has a TrimSpace defense too — defense-in-depth.
  # See terraform/CLAUDE.md "Metric / Alarm Dim-Set Rules".
  #
  # The two validation blocks below have partially overlapping coverage
  # (the regex alone would reject most of what the trim/length block
  # catches). Split is intentional: each block emits a distinct
  # operator-actionable message so a bad value surfaces "leading/
  # trailing whitespace" vs "disallowed character" rather than a
  # generic "format mismatch". Operator-friendliness, not strictly
  # required for correctness.
  #
  # Format regex pins the value to alphanumerics + dash + underscore so
  # the same value flows safely into resource names, SSM paths, metric
  # dims, and the config.toml heredoc (TOML-special chars like " or \
  # would otherwise break the heredoc). NOTE: #1924 will mirror this
  # regex on the compute module so the same value flows through both
  # publishers consistently.
  validation {
    condition     = length(trimspace(var.environment)) > 0 && var.environment == trimspace(var.environment)
    error_message = "environment must be non-empty and free of leading/trailing whitespace; the value flows into config.toml, SSM paths, resource names, and CloudWatch metric dims, and whitespace breaks at least the alarm-dim match."
  }
  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9_-]*$", var.environment))
    error_message = "environment must match ^[A-Za-z0-9][A-Za-z0-9_-]*$ — value flows into AC config.toml, SSM paths, resource names, and CloudWatch dims; special characters would break at least one consumer."
  }
}

# =============================================================================
# AMI Configuration
# =============================================================================

variable "ac_ami_id" {
  description = <<-EOT
    Runtime-baked AMI ID for NHP AC instances.

    If not set, reads from SSM parameter: /{environment}/nhp/ac/ami-id
    If neither exists, Terraform fails at plan time (no fallback to vanilla Ubuntu).

    The live Terraform-managed AC still pulls the deploy-selected Docker image
    at boot; this AMI bakes the OS/runtime package layer so user_data can fail
    closed when jq/docker/ipset/etc. are missing instead of running apt.

    Build and publish AMI:
      cd packer && packer build -var 'environment=sandbox' \
        -var 'runtime_packages_only=true' nhp-ac.pkr.hcl
      aws ssm put-parameter --name "/sandbox/nhp/ac/ami-id" \
        --value "ami-xxx" --type String --overwrite
  EOT
  type        = string
  default     = null
}

variable "domain_name" {
  description = "Domain name for the AC (e.g., nhp.layerv.xyz)"
  type        = string
}

variable "hosted_zone" {
  description = "Route 53 hosted zone name (e.g., layerv.xyz)"
  type        = string
}

variable "hosted_zone_id" {
  description = "Route 53 hosted zone ID (bypasses zone lookup for cross-account zones)"
  type        = string
  default     = null
}

variable "skip_dns_records" {
  description = "Skip creating DNS records (for cross-account zones where records are created by the caller with the correct provider)"
  type        = bool
  default     = false
}

variable "route53_record_change_iam_propagation_triggers" {
  description = "Optional trigger map for waiting on Terraform CI Route53 record-change IAM propagation before same-account DNS writes."
  type        = map(string)
  default     = {}
}

variable "route53_record_change_iam_propagation_duration" {
  description = "Duration to wait for Terraform CI Route53 record-change IAM propagation before same-account DNS writes."
  type        = string
  default     = "60s"
}

variable "qurl_internal_alb_readiness_token" {
  description = "Opaque root-produced token that orders only the AC launch template after qurl-service internal-ALB certificate validation and DNS alias readiness. Empty when that path is disabled."
  type        = string
  default     = ""
}

variable "acme_email" {
  description = "Email for Let's Encrypt certificate registration"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
}

variable "public_subnet_ids" {
  description = "Public subnet IDs for NLB"
  type        = list(string)
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for ECS tasks"
  type        = list(string)
}

variable "ac_repo_url" {
  description = "ECR repository URL for AC image"
  type        = string
}

variable "ac_repo_arn" {
  description = "ECR repository ARN for AC image"
  type        = string
}

variable "namespace_id" {
  description = "Cloud Map namespace ID"
  type        = string
}

variable "namespace_name" {
  description = "Cloud Map namespace name"
  type        = string
}

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
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

variable "secrets_kms_key_arn" {
  description = "KMS key ARN for Secrets Manager encryption"
  type        = string
  default     = null
}

variable "enable_cloudfront" {
  description = "Enable CloudFront + WAF in front of NLB for DDoS protection"
  type        = bool
  default     = false
}

# ============================================================================
# NHP AC Configuration Options
# These options control the AC daemon's behavior
# ============================================================================

variable "log_level" {
  description = "NHP AC log level: 0=silent, 1=error, 2=info, 3=audit, 4=debug, 5=trace"
  type        = number
  default     = 2

  validation {
    condition     = var.log_level >= 0 && var.log_level <= 5
    error_message = "log_level must be between 0 (silent) and 5 (trace)."
  }
}

variable "ac_filter_mode" {
  description = "NHP AC datapath filter mode rendered into config.toml as FilterMode: 0=iptables/ipset, 1=eBPF/XDP. Keep prod at 0 until the E5 eBPF flip gates have passed."
  type        = number
  default     = 0

  validation {
    condition     = contains([0, 1], var.ac_filter_mode)
    error_message = "ac_filter_mode must be 0 (iptables/ipset) or 1 (eBPF/XDP)."
  }
}

variable "ipset_default_timeout" {
  description = "Timeout in seconds for defaultset ipset entries (active sessions after NHP knock). Clients must re-knock after this period."
  type        = number
  default     = 120

  validation {
    condition     = var.ipset_default_timeout >= 10 && var.ipset_default_timeout <= 86400
    error_message = "ipset_default_timeout must be between 10 and 86400 seconds."
  }
}

variable "ipset_temp_timeout" {
  description = "Timeout in seconds for tempset ipset entries (initial knock window). Short to limit exposure during knock handshake."
  type        = number
  default     = 5

  validation {
    condition     = var.ipset_temp_timeout >= 1 && var.ipset_temp_timeout <= 60
    error_message = "ipset_temp_timeout must be between 1 and 60 seconds."
  }
}

variable "ipset_max_elements" {
  description = "Maximum number of entries per ipset (defaultset, tempset, etc.). Applied per-ipset; AC creates 6 sets (3 IPv4 + 3 IPv6), so worst-case kernel residency per instance is 6 × ipset_max_elements. Caps kernel memory consumption from ipset population attacks; was 1,000,000 before #1160 T3-08. Default of 10,000 sized to the worst-case legitimate ceiling: 80 pps sustained × 120s defaultset timeout ≈ 9,600 concurrent entries, rounded up. Sandbox and prod both observe 0 entries at steady state; the cap bounds the attack ceiling, not typical load. #2163 confirmed this cap stays and rejected an 8M bump; see docs/design/SESSION_ENFORCEMENT_ARCHITECTURE.md 'ipset maxelem'."
  type        = number
  default     = 10000

  validation {
    # Lower bound 1,000: at the AC's tempset 5s timeout, 1k entries
    # absorbs sustained ~200 pps of legitimate authorized clients —
    # below that, a CPU-constrained dev environment would start
    # evicting authorized clients via the tempset path under modest
    # legitimate load. Floor signals an obvious typo (e.g., 100 or 0)
    # rather than a sensible operational choice.
    # Upper bound 1,000,000: pre-#1160 T3-08 default. Kernel handles
    # this fine memory-wise but the cap loses its point as a
    # population-attack backstop above this; raising further requires
    # auditing the kernel allocator behavior for the specific ipset
    # type (hash:ip,port,ip).
    condition     = var.ipset_max_elements >= 1000 && var.ipset_max_elements <= 1000000
    error_message = "ipset_max_elements must be between 1,000 (floor signals an obvious typo; below this the tempset evicts authorized clients under modest legitimate load) and 1,000,000 (pre-#1160 default; raising further loses the population-attack backstop the cap exists to provide)."
  }
}

# ============================================================================
# L3 Flush-on-Expiry (active session teardown)
# When enabled, the AC actively flushes kernel allow-state (ipset/BPF map +
# conntrack) at the moment an entry's opnTime deadline arrives, terminating
# in-flight TCP connections at session end. Without this, established
# connections outlive ipset expiry via the ESTABLISHED-bypass rule
# (iptables mode) or the XDP conn_track short-circuit (eBPF mode). The
# scheduler, flushers, and safety guards live in endpoints/ac/expiry_*.
# Operator-facing runbooks: docs/runbooks/l3-flush-*.md.
# ============================================================================

variable "enable_l3_flush_on_expiry" {
  description = "Enable the L3 flush-on-expiry scheduler. When false (default), the scheduler is not instantiated and the AC's session-end behavior is unchanged from the pre-flush baseline (established connections outlive ipset expiry). Plumbed into the AC's config.toml as EnableL3FlushOnExpiry; the Go side gates all scheduler construction and flusher wiring on this flag (endpoints/ac/udpac.go::start)."
  type        = bool
  default     = false
}

variable "l3_flush_dry_run" {
  description = "Gate the L3 flush scheduler into log-only mode. When true (default), the scheduler logs each intended flush without invoking conntrack/BPF map deletion. Independent of enable_l3_flush_on_expiry — has no effect when the scheduler is not enabled. Safe-default: an AC that boots with enable_l3_flush_on_expiry=true but l3_flush_dry_run unset/false is auto-forced to dry-run for the first reload (endpoints/ac/config.go::updateBaseConfig) so an operator must explicitly acknowledge real-flush by re-applying with l3_flush_dry_run=false."
  type        = bool
  default     = true
}

variable "l3_flush_real_mode_acknowledged" {
  description = "Durable operator acknowledgement permitting a fresh AC process to boot directly with real L3 flushing. Keep false through dry-run soak; set true only together with enable_l3_flush_on_expiry=true and l3_flush_dry_run=false after rollout gates pass."
  type        = bool
  default     = false
}

variable "l3_flush_conntrack_backend" {
  description = "Conntrack teardown backend for FilterMode=IPTABLES L3 flush. `exec` preserves the fork+exec conntrack path; `netlink` opts into the direct ctnetlink backend and its event-index rollout gates. Ignored under FilterMode=EBPFXDP, where BpfFlusher owns conntrack teardown."
  type        = string
  default     = "exec"

  validation {
    condition     = contains(["exec", "netlink"], lower(var.l3_flush_conntrack_backend))
    error_message = "l3_flush_conntrack_backend must be either \"exec\" or \"netlink\"."
  }
}

variable "l3_flush_conntrack_pool_size" {
  description = "Socket pool size for the netlink conntrack backend. 0 preserves the AC default (currently 16); positive values tune the pre-warmed socket pool and are clamped by the AC at its safety maximum."
  type        = number
  default     = 0

  # Keep the 128 ceiling in lockstep with maxConntrackNetlinkPoolSize and the
  # "currently 16" default in lockstep with defaultConntrackNetlinkPoolSize in
  # endpoints/ac/expiry_conntrack_flusher.go. The AC re-clamps at boot, so drift
  # fails safe, but the Terraform bound and operator-facing docs should stay true.
  validation {
    condition     = var.l3_flush_conntrack_pool_size >= 0 && var.l3_flush_conntrack_pool_size <= 128 && floor(var.l3_flush_conntrack_pool_size) == var.l3_flush_conntrack_pool_size
    error_message = "l3_flush_conntrack_pool_size must be an integer between 0 and 128; use 0 for the AC default."
  }
}

# ============================================================================
# Cloud Mode Registration
# AC registers with NHP servers using credentials for DynamoDB license validation
# ============================================================================

variable "customer_id" {
  description = "Customer ID (ULID format) for license record. Used for querying, not lookup."
  type        = string
}

variable "license_key" {
  description = "License key for server registration. AC sends this to server for validation. Required."
  type        = string
  sensitive   = true
}

variable "license_key_hash" {
  description = "Bcrypt hash of license key for DynamoDB seeding. Generate with: htpasswd -bnBC 10 '' 'your-key' | tr -d ':\\n'"
  type        = string
  sensitive   = true
}

variable "license_key_sha256" {
  description = "SHA256 hash of license key for DynamoDB lookup. Generate with: echo -n 'your-key' | sha256sum | cut -d' ' -f1"
  type        = string
  sensitive   = true
}

variable "server_endpoint" {
  description = "NHP server endpoint for registration (e.g., 'server.nhp.sandbox.internal' for internal, or NLB DNS for external). Required."
  type        = string
}

variable "nhp_dynamodb_licenses_table" {
  description = "DynamoDB table name for license validation. If set, module will seed AC license."
  type        = string
  default     = null
}

variable "nhp_region" {
  description = "AWS region for NHP DynamoDB tables"
  type        = string
  default     = null
}

variable "auth_service_id" {
  description = "Authentication service ID for the AC — the NHP aspId this AC announces it serves. Default `agent` matches the agent staticplugin's PluginID (endpoints/server/staticplugins/agent/plugin.go)."
  type        = string
  default     = "agent"
}

variable "ac_id" {
  description = "AC identifier used for knock routing. All ACs in the same group should share this ID so resources can reference them."
  type        = string
  default     = "layerv-ac-tf"
}

variable "resource_ids" {
  description = "List of resource IDs that this AC protects"
  type        = list(string)
  default     = ["default"]
}

variable "server_secret_arn" {
  description = "ARN of the NHP Server's secret containing public key. Required for cloud registration."
  type        = string
}

variable "cross_account_route53_role_arn" {
  description = "IAM role ARN in management account for cross-account Route 53 access (ACME DNS challenges for production domains)"
  type        = string
  default     = null
}

variable "production_domains" {
  description = "List of production domains for ACME certificate generation"
  type        = list(string)
  default     = []
}

variable "production_zone_ids" {
  description = "Route 53 hosted zone IDs for production domains (for same-account ACME challenges)"
  type        = list(string)
  default     = []
}

variable "additional_tls_domains" {
  description = "Additional domains for TLS certificates in same account (uses standard ACME DNS challenge)"
  type        = list(string)
  default     = []
}

# ============================================================================
# Centralized Certificate Management
# When enabled, ACs fetch TLS certificates from Secrets Manager instead of
# requesting individual certificates via ACME. This scales to thousands of ACs
# without hitting Let's Encrypt rate limits.
# ============================================================================

variable "centralized_cert_enabled" {
  description = "Enable centralized certificate management. When true, ACs fetch TLS cert from Secrets Manager instead of using per-instance ACME."
  type        = bool
  default     = false
}

variable "centralized_cert_secret_arn" {
  description = "ARN of Secrets Manager secret containing TLS certificate (from acme-cert module). Required when centralized_cert_enabled=true."
  type        = string
  default     = null
}

variable "centralized_cert_domains" {
  description = "List of domains covered by the centralized certificate. Used to configure Traefik TLS. Required when centralized_cert_enabled=true."
  type        = list(string)
  default     = []
}

variable "acme_lambda_function_name" {
  description = "Name of the ACME certificate Lambda function (for error messages). Only used when centralized_cert_enabled=true."
  type        = string
  default     = ""
}

variable "use_production_acme" {
  description = "Use production Let's Encrypt (true) or staging (false). Staging certs are not trusted by browsers."
  type        = bool
  default     = null # null means auto-detect based on environment (prod=true, else=false)
}

# ============================================================================
# SSM and Monitoring Configuration
# These control automated maintenance and observability for AC instances
# ============================================================================

variable "enable_ssm_maintenance" {
  description = "Enable SSM-based maintenance (log rotation, disk monitoring)"
  type        = bool
  default     = true
}

variable "ac_instance_tag" {
  description = "Tag value used to identify AC instances (Name tag)"
  type        = string
  default     = "nhp_ac"
}

variable "log_rotation_schedule" {
  description = "Cron expression for log rotation (UTC)"
  type        = string
  default     = "cron(0 3 * * ? *)" # Daily at 3 AM UTC
}

variable "journal_max_size_mb" {
  description = "Maximum size for systemd journal in MB"
  type        = number
  default     = 100
}

variable "log_retention_days" {
  description = "Days to retain rotated log files"
  type        = number
  default     = 7
}

variable "enable_cloudwatch_alarms" {
  description = "Enable CloudWatch alarms for AC monitoring"
  type        = bool
  default     = true
}

variable "disk_usage_threshold_percent" {
  description = "Disk usage percentage threshold for alarms"
  type        = number
  default     = 85
}

variable "alarm_sns_topic_arn" {
  description = "SNS topic ARN for alarm notifications (optional)"
  type        = string
  default     = ""
}

variable "eip_pool_utilization_threshold_percent" {
  description = <<-EOT
    EIP pool utilization percentage threshold for the high-utilization alarm.
    The alarm fires when utilization exceeds this value for
    `evaluation_periods` consecutive 5-minute windows (see
    monitoring.tf::aws_cloudwatch_metric_alarm.eip_pool_utilization_high).

    Default of 80 is a balance between actionable warning and noise: it
    gives operators time to widen ac_max_capacity before the pool exhausts,
    but doesn't fire on routine scale-out.

    Note on blue/green peak transients: with the refresh slack from
    eip.tf (`eip_count = resolved_max_capacity * 2 + 1`), peak utilization
    during a blue/green deploy with both colours at full capacity is:
      - sandbox (max=3, pool=7):  6/7  = 85.7%
      - prod    (max=6, pool=13): 12/13 = 92.3%
    Both exceed 80% briefly (1-2 five-minute windows) during each deploy.
    The alarm's `evaluation_periods = 3` is what keeps this from crying
    wolf — only SUSTAINED >80% (15 min) trips the alarm, which happens
    if and only if the pool is actually exhausting at steady state. Do
    NOT lower evaluation_periods without rethinking this trade-off.

    The lower bound of 50 prevents accidentally setting an aggressive
    value that would alarm on every scale-out event for small pools
    (e.g. a 2-EIP pool reports 50% with one instance running).
  EOT
  type        = number
  default     = 80

  validation {
    condition     = var.eip_pool_utilization_threshold_percent >= 50 && var.eip_pool_utilization_threshold_percent <= 100
    error_message = "eip_pool_utilization_threshold_percent must be between 50 and 100."
  }
}

# ============================================================================
# ASG Capacity Configuration
# ============================================================================

variable "ac_min_capacity" {
  description = "Minimum number of AC instances. Defaults to 2 for prod, 1 otherwise."
  type        = number
  default     = null
}

variable "ac_max_capacity" {
  description = "Maximum number of AC instances. Defaults to 6 for prod, 3 otherwise."
  type        = number
  default     = null
}

# ============================================================================
# Egress EIP Configuration
# Stable public IPs for customer origin firewall whitelisting
# ============================================================================

variable "enable_egress_eips" {
  description = "Allocate Elastic IPs for AC instances to provide stable public IPs for customer origin firewall whitelisting. Creates N EIPs where N = max_capacity (or 2x max_capacity if blue/green is enabled). Requires AWS EIP quota >= N."
  type        = bool
  default     = false
}

variable "server_nlb_source_fenced" {
  description = "Whether the AC registration endpoint is a source-fenced public NHP NLB. When true, every managed AC egress EIP is admitted to that NLB on UDP 62206."
  type        = bool
  default     = false
}

variable "server_nlb_security_group_id" {
  description = "Dedicated security group attached to the source-fenced public NHP NLB. Required when server_nlb_source_fenced is true."
  type        = string
  default     = ""
  nullable    = false
}

# ============================================================================
# Deployment Configuration
# ============================================================================

variable "image_tag" {
  description = "Docker image tag to deploy (defaults to 'latest', set to commit SHA for immutable deployments)"
  type        = string
  default     = "latest"
}

# ============================================================================
# Plugin Configuration
# Traefik plugins are deployed via the unified plugins S3 bucket.
# ============================================================================

variable "plugin_bucket_name" {
  description = "Name of the S3 bucket containing plugins (from plugins module)"
  type        = string
  default     = null
}

variable "plugin_bucket_arn" {
  description = "ARN of the S3 bucket containing plugins (from plugins module)"
  type        = string
  default     = null
}

variable "plugin_download_policy_arn" {
  description = "ARN of the IAM policy for downloading plugins (from plugins module)"
  type        = string
  default     = null
}

variable "traefik_plugins_deploy_bucket_arn" {
  description = "ARN of the S3 bucket used by traefik-plugins CI/CD for plugin deployment"
  type        = string
  default     = null
}

variable "traefik_plugins" {
  description = <<-EOT
    Map of Traefik plugins with their S3 keys (from plugins module output).
    Example:
    traefik_plugins = {
      nhp-token-validator = {
        version    = "v1.0.0"
        plugin_key = "traefik/nhp-token-validator/v1.0.0/"
        config_key = null
      }
    }
  EOT
  type = map(object({
    version    = string
    plugin_key = string
    config_key = optional(string)
  }))
  default = {}
}

# ============================================================================
# ============================================================================
# QURL Router Plugin Configuration
# Routes requests from *.qurl.site subdomains to their target backends
# ============================================================================

variable "qurl_router_config" {
  description = <<-EOT
    QURL Router plugin configuration. When enabled, Traefik routes requests
    from *.qurl.site subdomains by looking up target URLs from the QURL Service.

    Example:
    qurl_router_config = {
      enabled                        = true
      api_url                        = "http://qurl-api.internal:8080"
      base_domain                    = "qurl.site"
      cache_ttl                      = 60
      negative_cache_ttl             = 30
      api_timeout                    = 5
      proxy_timeout                  = 30
      enable_instance_hrw            = false
      instance_discovery_ttl_seconds = 20
      enable_qurl_site_authz         = false
      require_connector_routing_id   = false
    }
  EOT
  type = object({
    enabled            = bool
    api_url            = string # QURL Service internal URL
    base_domain        = string # Base domain for QURL resources (e.g., qurl.site)
    cache_ttl          = optional(number, 60)
    negative_cache_ttl = optional(number, 30)
    max_cache_size     = optional(number, 1000)
    api_timeout        = optional(number, 5)
    proxy_timeout      = optional(number, 30)
    cache_shards       = optional(number, 16)
    # Router-side HRW dispatch (traefik-plugins #134). Optional with a
    # default of false so module-direct consumers that haven't updated
    # their qurl_router_config object pre-rollout don't break — the
    # plugin's default is also false, and the user_data renders the
    # field unconditionally so the rendered config matches.
    #
    # Cross-module fence is at the ROOT, not here. The AC module
    # cannot see the qurl-reverse-tunnel-server's `cloud_map_routing_policy`,
    # so the "HRW requires MULTIVALUE" invariant is enforced in
    # `terraform/main.tf::terraform_data.frps_preconditions`. Module-
    # direct AC consumers that set `enable_instance_hrw = true`
    # without ALSO arranging MULTIVALUE on qurl-reverse-tunnel-server's
    # Cloud Map services will silently render the plugin config but
    # see no behavior change (the plugin's HRW logic falls through to
    # weighted A-record selection when only one IP is returned).
    enable_instance_hrw            = optional(bool, false)
    instance_discovery_ttl_seconds = optional(number, 20)
    # L7 per-session authz gate on the *.qurl.site branch. Default
    # false so module-direct consumers whose qurl_router_config object
    # predates this field stay on the pre-gate behavior — and the
    # plugin's own Go zero-value is also false, so the rendered TOML
    # matches. The L3 OpenTime clamp at iptables continues to enforce
    # session_duration regardless of this flag; flipping false only
    # gives up the consumer-cache bound (cached positive authz can
    # outlive a server-side revoke for up to min(authCacheTTL,
    # remaining_seconds)). See `var.enable_qurl_site_authz` at the
    # root for the full description.
    enable_qurl_site_authz = optional(bool, false)
    # Coordinated hard-cutover gate for ordinary *.qurl.site Connector
    # traffic (traefik-plugins #246). Optional/default false preserves the
    # dark rollout posture for module-direct callers. The plugin fails closed
    # on a missing or malformed connector_routing_id when true. This value is
    # rendered into startup-only user data, so a change requires the normal
    # whole-fleet AC restart/rollout; an apply alone only creates a new launch
    # template version.
    require_connector_routing_id = optional(bool, false)
    # Per-AZ qurl-reverse-tunnel-server boundary URLs. The qurl-router plugin's
    # Config field is `FRPServerURLs []string` (json `frpServerUrls`, plural);
    # empty disables tunnel routing entirely — every tunnel resource that
    # reaches the plugin is silentDrop'd (when enable_qurl_site_authz=true)
    # or 502'd. Per-resource `upstream_addr` from the QURL API is consulted
    # ONLY after the empty-allowlist gate (qurl_router.go ServeHTTP, around
    # the `if q.frpFallback == nil` branch), so a non-empty allowlist is a
    # hard prereq for tunnel resources regardless of what the API returns.
    # Default `[]` for module-direct consumers who don't deploy frps; the
    # root assembly fills this from `var.frps_az_suffixes` + namespace_name
    # + var.frps_vhost_http_port when `deploy_frps && qurl_router_enabled`.
    frp_server_urls = optional(list(string), [])
  })
  default = null

  validation {
    condition     = var.qurl_router_config == null || can(var.qurl_router_config.enabled)
    error_message = "qurl_router_config must include 'enabled' field when set."
  }

  validation {
    # frpServerUrls entries must be non-empty strings — the plugin's
    # validateConfig rejects "" with `frpServerUrls[i] must not be empty`,
    # and surfacing that here gives a plan-time error instead of an AC
    # boot-time crash loop. `optional(list(string), [])` materializes
    # the field whenever qurl_router_config != null, so the leading
    # null-guard covers the only case where direct access would fail.
    condition = (
      var.qurl_router_config == null
      || alltrue([for u in var.qurl_router_config.frp_server_urls : u != ""])
    )
    error_message = "qurl_router_config.frp_server_urls entries must be non-empty strings. The qurl-router plugin's validateConfig rejects empty entries at boot."
  }

  validation {
    # Conservative subset of the shape qurl-service's `BuildUpstreamAddr`
    # emits (`http://frps-{az}.{frps_domain}:{frps_port}`): http(s) +
    # `frps-` host prefix + DNS-shaped suffix + REQUIRED non-zero TCP
    # port. The `frps-` prefix is the operator-side contract
    # (qurl-service's per-AZ Cloud Map convention) — encoding it here
    # keeps this validator in lockstep with the `"http://frps-`
    # render-shape fence in main.tf
    # (terraform_data.ac_user_data_qurl_router_render_check), so the
    # two layers can't disagree on what's accepted.
    #
    # Subset-not-exact: the regex permits multi-letter AZ suffixes
    # (`frps_az_suffixes` is `[a-z]` only by its own validator). Port
    # is required (and non-zero) because `BuildUpstreamAddr` always
    # emits one — catches a root-assembly regression where
    # `frps_vhost_http_port` interpolates to nothing. The plugin
    # parser (`validateUpstreamAddrShape`) remains source-of-truth at
    # AC boot for the full URL shape, including the port range and
    # other things this regex doesn't see (IPv6 brackets, etc.).
    condition = (
      var.qurl_router_config == null
      || alltrue([
        for u in var.qurl_router_config.frp_server_urls :
        can(regex("^https?://frps-[A-Za-z0-9._-]+:[1-9][0-9]*$", u))
      ])
    )
    error_message = "qurl_router_config.frp_server_urls entries must match `^https?://frps-<dns-host>:<non-zero-port>$` — a conservative subset of the shape `BuildUpstreamAddr` in qurl-service emits (`http://frps-{az}.{frps_domain}:{frps_port}`). Port is required; a missing port indicates a root-assembly regression where `frps_vhost_http_port` interpolated to nothing. The render-shape fence in main.tf anchors on the same `\"http://frps-` literal, so the validator and the fence agree on what's accepted. The qurl-router plugin's validateUpstreamAddrShape is still source-of-truth at AC boot — surfacing the shape here gives a plan-time error instead."
  }

  validation {
    # Plugin-level fence: HRW only makes sense when the consumer also
    # has a working A-record-set source (Cloud Map MULTIVALUE). The
    # routing policy is enforced at the qurl-reverse-tunnel-server module / root, not
    # here, so the AC module can't directly check it. What the AC
    # module CAN check is that `instance_discovery_ttl_seconds` is
    # in a sane range — same shape as the root-level validator on
    # `var.instance_discovery_ttl_seconds`.
    condition = (
      var.qurl_router_config == null
      || (
        try(var.qurl_router_config.instance_discovery_ttl_seconds, 20) >= 1
        && try(var.qurl_router_config.instance_discovery_ttl_seconds, 20) <= 600
      )
    )
    error_message = "qurl_router_config.instance_discovery_ttl_seconds must be between 1 and 600. Outside this range the router-side HRW resolver caches stale IP sets or hammers DNS — both produce wrong dispatch decisions silently."
  }

  validation {
    # Module-direct defense-in-depth for the same trap the root-level
    # `terraform_data.qurl_site_authz_preconditions` catches. A module-
    # direct caller that bypasses the root assembly could otherwise set
    # `enable_qurl_site_authz = true` while leaving `enabled = false` —
    # the entire qurl-router middleware block is gated on `enabled`, so
    # the authz flag silently no-ops. The root precondition still does
    # the heavy lifting (it can also assert on cross-variable
    # constraints like `deploy_qurl_service` that this validation
    # can't reach); this is the module-local fence for the in-object
    # subset of the same invariant.
    condition = (
      var.qurl_router_config == null
      || !try(var.qurl_router_config.enable_qurl_site_authz, false)
      || try(var.qurl_router_config.enabled, false)
    )
    error_message = "qurl_router_config.enable_qurl_site_authz=true requires qurl_router_config.enabled=true. The L7 gate has no execution path when the qurl-router middleware itself isn't rendered."
  }

  validation {
    # Module-direct counterpart to the root precondition. The field renders
    # only inside the enabled qurl-router middleware block, so accepting true
    # on a disabled object would silently no-op the requested hard cutover.
    condition = (
      var.qurl_router_config == null
      || !try(var.qurl_router_config.require_connector_routing_id, false)
      || try(var.qurl_router_config.enabled, false)
    )
    error_message = "qurl_router_config.require_connector_routing_id=true requires qurl_router_config.enabled=true. The routing-identity gate has no execution path when the qurl-router middleware isn't rendered."
  }
}

variable "qurl_service_token_secret_arn" {
  description = "ARN of Secrets Manager secret containing the QURL service token for Traefik QURL router"
  type        = string
  default     = null
}

# ============================================================================
# Blue/Green Deployment Configuration
# ============================================================================

variable "enable_blue_green" {
  description = "Enable blue/green deployment infrastructure for AC"
  type        = bool
  default     = false
}

variable "green_standby_min_size" {
  description = "Min instance count for green ASG (1=warm standby, 0=cold)"
  type        = number
  default     = 1

  validation {
    condition     = var.green_standby_min_size >= 0 && var.green_standby_min_size <= 10
    error_message = "green_standby_min_size must be between 0 and 10."
  }
}

variable "alerts_sns_topic_arn" {
  description = "SNS topic ARN for deployment alarms"
  type        = string
  default     = null
}

variable "enable_sns_alerts" {
  description = "Static boolean: set true when this module's SNS-routed blue/green deployment and reconciliation alarms should be created and alerts_sns_topic_arn is wired. Those alarms require a destination, unlike core monitoring alarms that may be created with no actions, and gate count on this value to avoid count-depends-on-computed."
  type        = bool
  default     = false
}

variable "enable_secret_reconciliation" {
  description = "Enable scheduled cleanup of orphaned per-instance AC secrets"
  type        = bool
  default     = true
}

variable "secret_reconciliation_deletion_spike_threshold" {
  description = <<-EOT
    Threshold for the OrphanedSecretsDeleted-per-day alarm
    (`<name_prefix>-ac-secret-reconciliation-deletion-spike`).

    The reconciliation Lambda runs daily and emits one datapoint
    counting orphaned per-instance AC secrets it cleaned up. This
    threshold sets when that count is treated as anomalous.

    `null` selects an env-aware default:
      sandbox -> 60   prod -> 10

    Calibration (sandbox, 15-day window 2026-04-20..05-04):
      datapoints: 37,15,18,8,15,3,25,11,10,26,14,6,6,8,23
      mean ~15  median 14  p95 ~30  max 37
    With 60, all 15 days are clean; ceiling absorbs the observed
    blue/green peak (2-4 cycles/day x 2-instance scale-3-to-1
    + 1 refresh ~= 25-40 terminations) plus headroom. Threshold 10
    fired on 9 of 15 days — pure noise.

    Prod uses canary (not blue/green) and steady-state instance
    churn is much lower; 10 stays appropriate there.

    Re-tune via observed datapoints, not gut feel — query
    `aws cloudwatch get-metric-statistics --namespace LayerV/NHP
    --metric-name OrphanedSecretsDeleted` for the trailing month and
    pick a value above p95 + max(observed deploy burst).
  EOT
  type        = number
  default     = null

  validation {
    # Bounds rationale lives in the variable description above. tl;dr: 1 is the
    # smallest threshold that doesn't alarm on every Lambda run; 500 is where
    # this metric loses discriminating power vs. CloudTrail TerminateInstances.
    # Integer-only: the metric is a whole-secret count.
    condition = var.secret_reconciliation_deletion_spike_threshold == null || (
      var.secret_reconciliation_deletion_spike_threshold >= 1 &&
      var.secret_reconciliation_deletion_spike_threshold <= 500 &&
      var.secret_reconciliation_deletion_spike_threshold == floor(var.secret_reconciliation_deletion_spike_threshold)
    )
    error_message = "secret_reconciliation_deletion_spike_threshold must be null (env-aware default) or an integer between 1 and 500."
  }
}

# ============================================================================
# FRP Tunnel Server Integration
# When set, AC Traefik routes FRP WebSocket and vhost traffic to the FRP server.
# ============================================================================

variable "frp_server_host" {
  description = "DEPRECATED — dead-code gate as of the per-AZ qurl-reverse-tunnel-server fleet (#1499). The only in-tree caller (terraform/main.tf) sets this to \"\" unconditionally, so the `if frp_server_host != \"\"` guard on the legacy `/.well-known/layerv-frp` Traefik FRP-control router is welded shut from the root. The qurl-router plugin no longer reads any single-URL field; see `qurl_router_config.frp_server_urls` for the current operator-declared boundary allowlist. Retained as a module input for API stability; the variable and the gated user_data branches are slated for deletion in a follow-up cleanup PR once the per-AZ rollout is verified in prod (#1499)."
  type        = string
  default     = ""
}

variable "frp_control_port" {
  description = "FRP server control port (for WebSocket control channel routing). MUST match qurl-reverse-tunnel-server module's frps_bind_port — when both modules are composed via the root (terraform/main.tf) the same root variable `var.frps_bind_port` is threaded to both, which prevents drift. The default here exists only so the AC module can be consumed in isolation for testing; in production the root override is the source of truth."
  type        = number
  default     = 7000
}

variable "frp_vhost_http_port" {
  description = "FRP vhost HTTP port (for proxied customer traffic). MUST match qurl-reverse-tunnel-server module's frps_vhost_http_port — same root-variable threading story as `frp_control_port`."
  type        = number
  default     = 8080
}

variable "frp_control_upstream_host" {
  # Template references in `description` are escaped (`$${…}`) so
  # Terraform doesn't parse them as live interpolations at init time
  # — same fix-shape as `var.connect_layerv_host` in the root
  # `terraform/variables.tf`. Rendered description shows the literal
  # `${…}` placeholders.
  description = <<-EOT
    Internal FRPS dial target for the AC Traefik TCP entrypoint on
    `frp_control_port`. Set to the same lex-smallest-AZ Cloud Map host
    the DDB seed row's `dest_host` field uses (e.g.
    `frps-a.nhp.{env}.internal`). The AC Traefik TCP router forwards
    customer SYNs that passed the AC kernel ipset gate to
    `$${frp_control_upstream_host}:$${frp_control_port}`.

    The AC ingress side (NLB:$${frp_control_port} → AC kernel → ipset)
    is the load-bearing fence; this upstream is the AC-userspace →
    private-FRPS leg, gated only by the AC instance's egress posture
    plus the FRPS SG (already AC-SG-only). Additional upstreams below
    provide the per-AZ public-port fanout used by nhp-server placement.

    Empty string disables the TCP entrypoint — the legacy WSS-via-443
    path (now unused) is the only remaining FRP path under that
    posture. The root (terraform/main.tf) sets this when
    `var.deploy_frps && var.deploy_qurl_service` and `connect.layerv.*`
    is wired; greenfield envs default to empty.
    EOT
  type        = string
  default     = ""

  # Defense-in-depth shape fence — mirrors `var.connect_layerv_host`
  # in `terraform/variables.tf`. Today's value is composed upstream
  # from `module.data.namespace_name` + `var.frps_az_suffixes[0]`
  # (already RFC 1035-fenced), so this validation only fires if a
  # future caller wires the variable from a less-fenced source.
  # Empty string permitted (disables the TCP entrypoint per the
  # description above).
  validation {
    condition     = var.frp_control_upstream_host == "" || can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$", var.frp_control_upstream_host))
    error_message = "frp_control_upstream_host must be a bare lowercase DNS name in per-label RFC 1035 form (each label 1-63 chars, alphanumeric with hyphens but not leading/trailing, multiple labels dot-separated; no scheme, port, slashes, whitespace, or userinfo), or empty to disable the FRPS-control TCP entrypoint. Today's values like `frps-a.nhp.sandbox.internal` conform."
  }
}

variable "frp_control_additional_upstreams" {
  description = <<-EOT
    Additional per-AZ FRPS control listeners exposed on the AC NLB. The
    primary listener remains `frp_control_port` -> `frp_control_upstream_host`
    for backward compatibility; this map adds sibling public listener ports
    on the same connect.layerv.* DNS name, each forwarding to one private
    FRPS Cloud Map host on its native upstream_port.

    FRP control is raw TCP, not HTTP or TLS, so one listener cannot route by
    Host/SNI. Per-AZ ingress therefore uses distinct public listener ports
    paired with NHP resource rows whose knock ack returns
    "connect.layerv.*:<listen_port>".
    EOT
  type = map(object({
    listen_port   = number
    upstream_host = string
    upstream_port = number
  }))
  default = {}

  validation {
    condition = alltrue([
      for _, upstream in var.frp_control_additional_upstreams :
      upstream.listen_port >= 1 &&
      upstream.listen_port <= 65535 &&
      upstream.listen_port == floor(upstream.listen_port) &&
      upstream.upstream_port >= 1 &&
      upstream.upstream_port <= 65535 &&
      upstream.upstream_port == floor(upstream.upstream_port) &&
      can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$", upstream.upstream_host))
    ])
    error_message = "Every frp_control_additional_upstreams entry must have integer listen_port/upstream_port in 1..65535 and a bare lowercase RFC-1035 DNS upstream_host."
  }

  validation {
    condition = alltrue([
      for name in keys(var.frp_control_additional_upstreams) :
      can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", name))
    ])
    error_message = "frp_control_additional_upstreams keys must match ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ because they flow into AWS names, tags, Traefik TCP object names, and rendered shell."
  }

  validation {
    condition     = !contains(keys(var.frp_control_additional_upstreams), "ctl")
    error_message = "frp_control_additional_upstreams must not use key \"ctl\" because it would collide with the primary FRPS control target-group name suffix (`-ac-frps-ctl`)."
  }

  validation {
    condition = length(distinct([
      for _, upstream in var.frp_control_additional_upstreams :
      upstream.listen_port
    ])) == length(var.frp_control_additional_upstreams)
    error_message = "frp_control_additional_upstreams listen_port values must be unique; each additional FRPS control upstream owns one public AC NLB listener."
  }
}
