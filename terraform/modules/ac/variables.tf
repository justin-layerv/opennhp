# AC Module Variables
# Access Controller with embedded Traefik for TLS termination

variable "environment" {
  description = "Environment name"
  type        = string
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
  description = "Maximum number of entries per ipset (defaultset, tempset, etc.). Applied per-ipset; AC creates 6 sets (3 IPv4 + 3 IPv6), so worst-case kernel residency per instance is 6 × ipset_max_elements. Caps kernel memory consumption from ipset population attacks; was 1,000,000 before #1160 T3-08. Default of 10,000 sized to the worst-case legitimate ceiling: 80 pps sustained × 120s defaultset timeout ≈ 9,600 concurrent entries, rounded up. Sandbox and prod both observe 0 entries at steady state; the cap bounds the attack ceiling, not typical load."
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
  description = "Authentication service ID for the AC"
  type        = string
  default     = "layerv"
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
      enabled         = true
      api_url         = "http://qurl-api.internal:8080"
      base_domain     = "qurl.site"
      cache_ttl       = 60
      negative_cache_ttl = 30
      api_timeout     = 5
      proxy_timeout   = 30
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
  })
  default = null

  validation {
    condition     = var.qurl_router_config == null || can(var.qurl_router_config.enabled)
    error_message = "qurl_router_config must include 'enabled' field when set."
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
  description = "Internal DNS hostname for the FRP server (e.g., 'frps.nhp.sandbox.internal'). When non-empty, Traefik routes are added for FRP WebSocket control and vhost HTTP traffic."
  type        = string
  default     = ""
}

variable "frp_control_port" {
  description = "FRP server control port (for WebSocket control channel routing). MUST match qurl-frps module's frps_bind_port — when both modules are composed via the root (terraform/main.tf) the same root variable `var.frps_bind_port` is threaded to both, which prevents drift. The default here exists only so the AC module can be consumed in isolation for testing; in production the root override is the source of truth."
  type        = number
  default     = 7000
}

variable "frp_vhost_http_port" {
  description = "FRP vhost HTTP port (for proxied customer traffic). MUST match qurl-frps module's frps_vhost_http_port — same root-variable threading story as `frp_control_port`."
  type        = number
  default     = 8080
}
