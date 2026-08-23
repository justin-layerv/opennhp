# Variables for LayerV NHP infrastructure
# Consistent with layerv/traefik-plugins terraform patterns

# ==================== Environment ====================

variable "environment" {
  description = "Environment name (sandbox, prod)"
  type        = string

  validation {
    condition     = contains(["sandbox", "prod"], var.environment)
    error_message = "Environment must be 'sandbox' or 'prod'."
  }
}

variable "cell_id" {
  description = "Cell identifier for multi-cell deployments (e.g., cell0, cell1). Used for resource naming and tagging."
  type        = string
  default     = "cell0"

  validation {
    # Lowercase alphanumeric with optional internal dashes,
    # bounded length. Rejects leading/trailing/double dashes (legal
    # in some AWS resource names but produces ugly SSM paths like
    # /sandbox/nhp/-cell0/canary/server/state) and rejects values
    # long enough to cause Cell-tag bloat or hit AWS resource-name
    # ceilings before downstream limits would.
    condition     = can(regex("^[a-z0-9]+(-[a-z0-9]+)*$", var.cell_id)) && length(var.cell_id) <= 32
    error_message = "cell_id must be lowercase alphanumeric (max 32 chars) with optional internal single dashes (e.g., cell0, cell-01); leading/trailing dashes and double-dashes are rejected."
  }
}

variable "connector_authority_cell_config" {
  description = "Nullable complete assigned-cell Connector Authority caller bundle. Sandbox supplies the exact two-cell blue graph; prod remains null/dark."
  type = object({
    environment                            = string
    aws_account_id                         = string
    aws_region                             = string
    issue_registration_otp_alias_arn       = string
    activate_registration_alias_arn        = string
    complete_registration_alias_arn        = string
    complete_credential_recovery_alias_arn = string
    resolve_connector_resource_alias_arn   = optional(string)
    authority_lambda_timeout               = string
    handler_budget                         = string
    packet_budget                          = string
    response_reserve                       = string
    write_budget                           = string
  })
  default  = null
  nullable = true
}

# ==================== AWS Configuration ====================

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-2"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]$", var.aws_region))
    error_message = "AWS region must be a valid region format (e.g., us-east-2)."
  }
}

variable "aws_account_id" {
  description = "AWS account ID (used for validation)"
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "AWS account ID must be exactly 12 digits."
  }
}

# ==================== Multi-Account Configuration ====================

variable "is_primary_account" {
  description = "Whether this is the primary account that owns ECR repositories (sandbox = true, prod = false)"
  type        = bool
  default     = true
}

variable "primary_account_id" {
  description = "AWS account ID of the primary account (sandbox). Required if is_primary_account = false"
  type        = string
  default     = ""

  validation {
    condition     = var.primary_account_id == "" || can(regex("^[0-9]{12}$", var.primary_account_id))
    error_message = "Primary account ID must be exactly 12 digits or empty."
  }
}

variable "secondary_account_ids" {
  description = "List of AWS account IDs that can pull from ECR (only used in primary account)"
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for id in var.secondary_account_ids : can(regex("^[0-9]{12}$", id))])
    error_message = "All secondary account IDs must be exactly 12 digits."
  }
}

variable "enable_replication" {
  description = "Enable ECR cross-account replication from primary to secondary accounts. When true, images pushed to sandbox ECR are automatically replicated to prod, eliminating prod's runtime dependency on sandbox."
  type        = bool
  default     = false
}

# ==================== NHP Configuration ====================

variable "domain_name" {
  description = "Domain name for NHP server"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]+[a-z0-9]$", var.domain_name))
    error_message = "Domain name must be a valid hostname."
  }
}

variable "multi_tenant" {
  description = "Enable multi-tenant mode with etcd"
  type        = bool
  default     = true
}

variable "deploy_etcd" {
  description = "Deploy etcd infrastructure. Set to false for cloud deployments using DynamoDB backend."
  type        = bool
  default     = null # Defaults to multi_tenant when null

  validation {
    condition     = var.deploy_etcd != true || var.multi_tenant == true
    error_message = "deploy_etcd = true requires multi_tenant = true. etcd is only used in multi-tenant mode."
  }
}

variable "server_ami_id" {
  description = <<-EOT
    Docker-optimized AMI ID for NHP Server instances. If null, the compute
    module reads from SSM parameter /<environment>/nhp/server/ami-id (aligned
    with sibling /<environment>/nhp/server/* parameters: image-tag, asg-name,
    active-color, ...). Terraform fails at plan time if neither is set (no
    fallback to vanilla Ubuntu). Set to a dummy value for PR validation so
    plan does not depend on environment-specific SSM state.
  EOT
  type        = string
  default     = null
}

variable "ac_ami_id" {
  description = <<-EOT
    Runtime-baked AMI ID for NHP AC instances. If null, the AC module reads
    from SSM parameter /<environment>/nhp/ac/ami-id (aligned with sibling
    /<environment>/nhp/ac/* parameters: image-tag, asg-name, active-color,
    ...). Terraform fails at plan time if neither is set (no fallback to
    vanilla Ubuntu). The Terraform-managed AC still pulls the deploy-selected
    Docker image at boot; this AMI bakes the OS/runtime package layer so
    user_data can fail closed when runtime packages are missing instead of
    running apt.
  EOT
  type        = string
  default     = null
}

variable "min_capacity" {
  description = "Minimum ASG capacity"
  type        = number
  default     = 3

  validation {
    condition     = var.min_capacity >= 1 && var.min_capacity <= 100
    error_message = "Min capacity must be between 1 and 100."
  }
}

variable "max_capacity" {
  description = "Maximum server ASG capacity per color. Capped at 40 so blue+green Cloud Map registrations remain at most 80, preserving 20 entries of headroom below DiscoverInstances' non-pageable 100-result authority ceiling."
  type        = number
  default     = 10

  validation {
    condition     = var.max_capacity >= 1 && var.max_capacity <= 40
    error_message = "Max capacity must be between 1 and 40; two blue/green colors must remain below the Cloud Map DiscoverInstances 100-result ceiling with operational headroom."
  }
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.100.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid CIDR block."
  }
}

variable "deploy_vpc_endpoints" {
  description = "Deploy additional VPC endpoints for QURL service AWS dependencies (DynamoDB gateway, SQS interface). Default false to avoid cost in environments that don't need them."
  type        = bool
  default     = false
}

# ==================== Server Configuration Options ====================

variable "log_level" {
  description = "NHP log level for all components (server, AC, console AC): 0=silent, 1=error, 2=info, 3=audit, 4=debug, 5=trace"
  type        = number
  default     = 2

  validation {
    condition     = var.log_level >= 0 && var.log_level <= 5
    error_message = "log_level must be between 0 (silent) and 5 (trace)."
  }
}

variable "dev_mode" {
  description = "Enable development mode for the NHP server (enables additional debugging features)"
  type        = bool
  default     = false
}

variable "nhp_cors_allowed_origins" {
  description = "Comma-separated list of allowed CORS origins for NHP HTTP server. When empty in non-dev mode, the server logs a warning and falls back to wildcard '*'."
  type        = string
  default     = ""
}

variable "nhp_knock_headertype_verify_require" {
  description = "Root passthrough for the compute module's knock_headertype_verify_require — see modules/compute/variables.tf for the gate semantics and burn-in criteria. Flip true only after MetricKnockHeaderTypeLegacy has drained to zero (see #1257). Variable name uses `_require` to match the shared permit/strict gate convention (cf. NHP_INTERNAL_AUTH_REQUIRE); the env var keeps the upstream NHP_KNOCK_HEADERTYPE_VERIFY name."
  type        = bool
  default     = false
}

variable "nhp_internal_auth_require" {
  description = "Root passthrough for the compute module's internal_auth_require. Flip true only after the target environment/cell has completed permit-mode burn-in: InternalAuthFailPermit stays zero while InternalAuthSuccess confirms signed internal traffic, and all nhp-server instances plus signer fleets have rolled with NHP_INTERNAL_AUTH_SECRET."
  type        = bool
  default     = false
}

variable "nhp_revocation_retry_enabled" {
  description = "Root passthrough for the compute module's revocation_retry_enabled (#2793). Default false preserves the conservative pre-ACK/unmanaged-fleet behavior; environments that have confirmed ACK-capable ACs opt in explicitly via tfvars."
  type        = bool
  default     = false
}

variable "nhp_revocation_retry_interval_seconds" {
  description = "Root passthrough for the compute module's revocation_retry_interval_seconds (#2793). Whole-second resend cadence for un-acked NHP_REV messages."
  type        = number
  default     = 5

  validation {
    condition     = var.nhp_revocation_retry_interval_seconds >= 1 && floor(var.nhp_revocation_retry_interval_seconds) == var.nhp_revocation_retry_interval_seconds
    error_message = "nhp_revocation_retry_interval_seconds must be a whole number of seconds >= 1."
  }
}

variable "nhp_revocation_retry_age_out_seconds" {
  description = "Root passthrough for the compute module's revocation_retry_age_out_seconds (#2793). Whole-second deadline before an un-acked revoke emits RevocationAgedOut; compute module also enforces age-out > interval and > 15s SLO when enabled."
  type        = number
  default     = 60

  validation {
    condition     = var.nhp_revocation_retry_age_out_seconds >= 1 && floor(var.nhp_revocation_retry_age_out_seconds) == var.nhp_revocation_retry_age_out_seconds
    error_message = "nhp_revocation_retry_age_out_seconds must be a positive whole number of seconds."
  }
}

variable "nhp_overload_cookie_time_window_seconds" {
  description = "Root passthrough for the compute module's overload_cookie_time_window_seconds. Default 60s; tune only with NTP/clock-skew evidence because the verifier accepts the current and previous windows."
  type        = number
  default     = 60

  validation {
    condition     = var.nhp_overload_cookie_time_window_seconds > 0
    error_message = "nhp_overload_cookie_time_window_seconds must be positive."
  }
}

variable "nhp_knock_global_rate_limit_pps" {
  description = "Root passthrough for the compute module's knock_global_rate_limit_pps (#1159). Aggregate UDP knock pps cap; defends against distributed low-rate floods that stay under the per-IP limit but aggregate above ECDH throughput. 0 disables. See modules/compute/variables.tf."
  type        = number
  default     = 5000
}

variable "nhp_knock_global_rate_limit_burst" {
  description = "Root passthrough for the compute module's knock_global_rate_limit_burst (#1159). Burst allowance for the global aggregate cap."
  type        = number
  default     = 10000
}

variable "nhp_udp_recv_buffer_bytes" {
  description = "Root passthrough for the compute module's udp_recv_buffer_bytes (#1159). Target SO_RCVBUF for the NHP knock listen socket; user_data raises net.core.rmem_max to match so SetReadBuffer takes effect."
  type        = number
  default     = 8388608
}

variable "public_nhp_udp_ingress_cidrs" {
  description = "Optional exact public /32 sources for the assigned-cell UDP NLB security group. null preserves the legacy production edge; sandbox proof cells set the persistent proof-runner EIP."
  type        = list(string)
  default     = null
}

variable "resource_mode" {
  description = "Resource management mode: 'local' uses config files, 'api' uses external auth service"
  type        = string
  default     = "local"

  validation {
    condition     = contains(["local", "api"], var.resource_mode)
    error_message = "resource_mode must be either 'local' or 'api'"
  }
}

variable "auth_url" {
  description = "URL of the external authentication service (required when resource_mode is 'api')"
  type        = string
  default     = null
}

variable "auth_signing_key" {
  description = "Signing key for authentication tokens (required when resource_mode is 'api')"
  type        = string
  default     = null
  sensitive   = true
}

variable "auth_aes_key" {
  description = "AES encryption key for authentication (required when resource_mode is 'api')"
  type        = string
  default     = null
  sensitive   = true
}

# ==================== GitHub Configuration ====================

variable "github_org" {
  description = "GitHub organization name"
  type        = string
  default     = "layervai"
}

variable "github_repo" {
  description = "GitHub repository name"
  type        = string
  default     = "nhp"
}

variable "traefik_plugins_github_repo" {
  description = "GitHub repository name for traefik-plugins (for S3 plugin upload permissions)"
  type        = string
  default     = "traefik-plugins"
}

variable "traefik_plugins_deploy_bucket_arn" {
  description = <<-EOT
    ARN of the S3 bucket used by traefik-plugins CI/CD for plugin deployment.
    This bucket is used by the SSM deploy document to download plugin tarballs.
    Example: arn:aws:s3:::traefik-plugins-deploy-123456789012
  EOT
  type        = string
  default     = null
}

variable "create_oidc_provider" {
  description = <<-EOT
    Whether to create the GitHub OIDC provider in this account.

    Set to `false` if:
    - Your organization manages the OIDC provider centrally
    - SCP blocks iam:CreateOpenIDConnectProvider
    - The OIDC provider already exists from another deployment

    When false, the module uses a data source to reference the existing provider.
    The GitHub Actions role will still be created and will reference the existing OIDC provider.
  EOT
  type        = bool
  default     = true
}

# ==================== DNS Configuration ====================

variable "hosted_zone" {
  description = "Route 53 hosted zone name (e.g., 'layerv.xyz')"
  type        = string
  default     = null
}

variable "hosted_zone_id" {
  description = "Route 53 hosted zone ID (bypasses zone lookup for cross-account zones)"
  type        = string
  default     = null

  validation {
    condition     = var.hosted_zone_id == null || can(regex("^Z[A-Z0-9]{8,}$", var.hosted_zone_id))
    error_message = "hosted_zone_id must be a valid Route53 hosted zone ID (uppercase, starts with Z, at least 9 characters)."
  }
}

variable "lambda_layer_bucket" {
  description = "S3 bucket containing Lambda layer artifacts (defaults to terraform state bucket)"
  type        = string
  default     = null
}

variable "qurl_alb_access_logs_bucket" {
  description = "S3 bucket for QURL ALB access logs (required for production)"
  type        = string
  default     = null
}

# ==================== AC Configuration ====================

variable "ac_min_capacity" {
  description = "Minimum number of AC instances. Overrides the module default (2 for prod, 1 otherwise)."
  type        = number
  default     = null
}

variable "ac_max_capacity" {
  description = "Maximum number of AC instances. Overrides the module default (6 for prod, 3 otherwise)."
  type        = number
  default     = null
}

variable "ac_filter_mode" {
  description = "Root passthrough for the AC module's datapath FilterMode: 0=iptables/ipset, 1=eBPF/XDP. Default 0 preserves the production baseline; set per environment only after the eBPF flip gates for that environment are satisfied."
  type        = number
  default     = 0

  validation {
    condition     = contains([0, 1], var.ac_filter_mode)
    error_message = "ac_filter_mode must be 0 (iptables/ipset) or 1 (eBPF/XDP)."
  }
}

variable "enable_egress_eips" {
  description = "Allocate Elastic IPs for AC instances for stable egress IPs (2x when blue/green enabled). Customers whitelist these on their origin firewalls."
  type        = bool
  default     = false
}

variable "deploy_ac" {
  description = "Deploy the Access Controller (AC) with embedded Traefik for TLS termination"
  type        = bool
  default     = true
}

variable "acme_email" {
  description = "Email address for Let's Encrypt certificate registration (used by AC's Traefik)"
  type        = string
  default     = ""

  validation {
    condition     = var.acme_email == "" || can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.acme_email))
    error_message = "ACME email must be a valid email address."
  }
}

variable "enable_cloudfront" {
  description = "Enable CloudFront + WAF in front of AC for DDoS protection. Recommended for production."
  type        = bool
  default     = false
}

variable "enable_l3_flush_on_expiry" {
  description = "Root passthrough for the AC module's enable_l3_flush_on_expiry. When true the AC actively flushes kernel allow-state (ipset/BPF map + conntrack) at session-end deadline, terminating in-flight TCP connections. Default false preserves pre-flush behavior (established connections outlive ipset expiry). See modules/ac/variables.tf for full semantics and docs/runbooks/l3-flush-*.md for the rollout sequence."
  type        = bool
  default     = false
}

variable "l3_flush_dry_run" {
  description = "Root passthrough for the AC module's l3_flush_dry_run. When true the scheduler logs intended flushes without invoking conntrack/BPF map deletion — the dry-run audit signal feeds an operator's call to flip to false. Default true; has no effect when enable_l3_flush_on_expiry=false. The Go-side first-load safety auto-defaults dry-run=true if the operator flips enable_l3_flush_on_expiry=true with dry-run unset/false, so a misconfiguration falls back to log-only."
  type        = bool
  default     = true
}

variable "l3_flush_real_mode_acknowledged" {
  description = "Root passthrough for the durable operator acknowledgement that permits an AC restart directly into real L3 flush mode. Must remain false until dry-run rollout gates pass."
  type        = bool
  default     = false
}

variable "l3_flush_conntrack_backend" {
  description = "Root passthrough for the AC module's l3_flush_conntrack_backend. Selects `exec` or `netlink` for FilterMode=IPTABLES L3 flush teardown; ignored under eBPF/XDP."
  type        = string
  default     = "exec"

  validation {
    condition     = contains(["exec", "netlink"], lower(var.l3_flush_conntrack_backend))
    error_message = "l3_flush_conntrack_backend must be either \"exec\" or \"netlink\"."
  }
}

variable "l3_flush_conntrack_pool_size" {
  description = "Root passthrough for the AC module's l3_flush_conntrack_pool_size. 0 preserves the AC default (currently 16); positive values tune the netlink socket pool."
  type        = number
  default     = 0

  # Keep this bound aligned with the AC module and the Go-side
  # maxConntrackNetlinkPoolSize/defaultConntrackNetlinkPoolSize constants.
  validation {
    condition     = var.l3_flush_conntrack_pool_size >= 0 && var.l3_flush_conntrack_pool_size <= 128 && floor(var.l3_flush_conntrack_pool_size) == var.l3_flush_conntrack_pool_size
    error_message = "l3_flush_conntrack_pool_size must be an integer between 0 and 128; use 0 for the AC default."
  }
}

variable "ac_auth_service_id" {
  description = "Authentication service ID for the Access Controller — the NHP aspId the agent-knock dispatch keys on. Default `agent` matches the agent staticplugin's PluginID (endpoints/server/staticplugins/agent/plugin.go); a rename here without renaming the plugin (or vice versa) silently re-introduces 'failed to find service provider' at knock time."
  type        = string
  default     = "agent"

  # Hard fence on the aspId shape. `var.ac_auth_service_id` is
  # interpolated into the DDB seed row's `auth_service_id` field
  # (terraform/resources.tf) and the AC's announced auth service;
  # historically also into a TOML overlay. The shape constraint
  # below preserves the lowercase-dashed convention every aspId in
  # this server uses (`passcode`, `oidc`, `qurl`, `agent`) and
  # defends downstream string interpolation surfaces against quote
  # injection.
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,63}$", var.ac_auth_service_id))
    error_message = "ac_auth_service_id is interpolated into the DDB seed row's `auth_service_id` field and AC config; it must match `^[a-z][a-z0-9-]{0,63}$` (lowercase letters/digits/dashes, leading letter, ≤64 chars). Default value `agent` conforms."
  }
}

variable "ac_resource_ids" {
  description = "List of resource IDs that the Access Controller protects"
  type        = list(string)
  default     = ["default"]
}

# Standalone AC License Credentials (for customer-deployed ACs)

variable "ac_customer_id" {
  description = "Customer ID (ULID format) for standalone AC license"
  type        = string
  default     = null
}

variable "ac_license_key" {
  description = "License key for standalone AC registration (plaintext, stored in Secrets Manager)"
  type        = string
  default     = null
  sensitive   = true
}

variable "ac_license_key_hash" {
  description = "Bcrypt hash of standalone AC license key for DynamoDB seeding"
  type        = string
  default     = null
  sensitive   = true
}

variable "ac_license_key_sha256" {
  description = "SHA256 hash of standalone AC license key for DynamoDB lookup"
  type        = string
  default     = null
  sensitive   = true
}

variable "cross_account_route53_role_arn" {
  description = "IAM role ARN in management account for cross-account Route 53 access (for ACME DNS challenges on production domains like qurl.site)"
  type        = string
  default     = null
}

variable "production_domains" {
  description = "List of production domains for ACME certificate generation (e.g., qurl.site, qurl.link)"
  type        = list(string)
  default     = []
}

variable "production_zone_ids" {
  description = "Route 53 hosted zone IDs for production domains (for same-account ACME challenges)"
  type        = list(string)
  default     = []
}

variable "additional_tls_domains" {
  description = "Additional domains for TLS certificates in same account (e.g., apps.layerv.xyz for console2.apps.layerv.xyz)"
  type        = list(string)
  default     = []
}

variable "use_production_acme" {
  description = "Use production Let's Encrypt (true) or staging (false). Staging certs are not trusted by browsers. Default: auto-detect based on environment."
  type        = bool
  default     = null
}

# ==================== Centralized Certificate Management ====================
# When enabled, ACs fetch TLS certificates from Secrets Manager instead of
# requesting individual certificates via ACME. This scales to thousands of ACs.

variable "centralized_cert_enabled" {
  description = "Enable centralized certificate management for AC fleet. When true, ACs fetch cert from Secrets Manager instead of per-instance ACME."
  type        = bool
  default     = false
}

variable "centralized_cert_secret_arn" {
  description = "Secrets Manager ARN containing TLS certificate (from acme-cert module). Required when centralized_cert_enabled=true."
  type        = string
  default     = null
}

variable "centralized_cert_domains" {
  description = "List of domains covered by the centralized certificate. Used to configure Traefik TLS."
  type        = list(string)
  default     = []
}

variable "acme_lambda_function_name" {
  description = "Name of the ACME certificate Lambda function (for error messages in AC user_data)."
  type        = string
  default     = ""
}

# ==================== Terraform State Configuration ====================

variable "terraform_state_bucket" {
  description = "S3 bucket name for Terraform state (enables GitHub Actions Terraform permissions)"
  type        = string
  default     = ""
}

variable "terraform_lock_table" {
  description = "DynamoDB table name for Terraform state locking"
  type        = string
  default     = "terraform-state-lock"
}

# ==================== Security Services ====================

variable "enable_cloudtrail" {
  description = "Enable AWS CloudTrail for API audit logging. May be blocked by SCPs in some accounts."
  type        = bool
  default     = true
}

variable "config_recording_frequency" {
  description = "AWS Config recording frequency: CONTINUOUS (every change) or DAILY (once per 24h). DAILY reduces costs ~90%."
  type        = string
  default     = "DAILY"
}

variable "config_resource_types" {
  description = "Specific AWS resource types to record. Empty list means all supported types. Default includes types needed by Config rules and SecurityHub."
  type        = list(string)
  default     = []
}

# ==================== Monitoring & Alerting ====================

variable "enable_slack_notifications" {
  description = "Enable Slack notifications via AWS Chatbot"
  type        = bool
  default     = false
}

variable "slack_workspace_id" {
  description = "Slack workspace ID for AWS Chatbot (get from AWS Chatbot console after authorizing)"
  type        = string
  default     = ""
}

variable "slack_channel_id" {
  description = "Slack channel ID for alerts (e.g., C01234567 - get from channel details in Slack)"
  type        = string
  default     = ""
}

variable "chatbot_owned_externally" {
  description = "Whether the AWS Chatbot config for (slack_workspace_id, slack_channel_id) is owned by another stack. See modules/monitoring/variables.tf for the full ownership story and the (workspace, channel) account-wide uniqueness rationale."
  type        = bool
  default     = false
}

variable "qurl_browser_rejected_alarm_actions_enabled" {
  description = "Enable SNS actions for the qURL browser timing rejected-ratio alarms. Leave false for the initial #1840 report-only bake; flip true after the 7-day bake confirms the calibrated thresholds stay quiet outside intentional rejection tests."
  type        = bool
  default     = false
}

# ==================== ASG Lifecycle Hook ====================

variable "enable_termination_cleanup" {
  description = "Enable ASG lifecycle hook for immediate DynamoDB cleanup on server termination. When enabled, a Lambda function cleans up AC assignments before the server terminates, providing instant cleanup instead of waiting for Console health monitor."
  type        = bool
  default     = false
}

# ==================== Deployment Configuration ====================

variable "image_tag" {
  description = "Docker image tag for NHP server and AC. Set to git commit SHA for immutable deployments."
  type        = string
  default     = "latest"
}

# ==================== Plugin Configuration ====================

variable "server_plugins" {
  description = <<-EOT
    List of NHP Server plugins to enable.
    Plugins are statically compiled into the server binary.
    This list specifies which AuthSvcIds are valid for authentication.

    Example:
    server_plugins = ["passcode", "oktaoidc"]
  EOT
  type        = list(string)
  default     = []
}

variable "qurl_config" {
  description = <<-EOT
    QURL plugin configuration for token resolution.
    When enabled, the NHP Server handles the qurl.link → qurl.site authentication flow.

    Example:
    qurl_config = {
      enabled                 = true
      api_url                 = "https://api.qurl.internal"
      allowed_redirect_domain = "qurl.site"
      api_timeout             = 10
      max_idle_conns          = 10
      max_idle_conns_per_host = 5
      idle_conn_timeout       = 30
    }
  EOT
  type = object({
    enabled                 = bool
    api_url                 = string
    allowed_redirect_domain = string
    api_timeout             = number
    max_idle_conns          = number
    max_idle_conns_per_host = number
    idle_conn_timeout       = number
  })
  default = null

  validation {
    condition = var.qurl_config == null ? true : (
      var.qurl_config.api_timeout > 0 &&
      var.qurl_config.max_idle_conns > 0 &&
      var.qurl_config.max_idle_conns_per_host > 0 &&
      var.qurl_config.idle_conn_timeout > 0 &&
      length(var.qurl_config.allowed_redirect_domain) > 0 &&
      length(var.qurl_config.api_url) > 0
    )
    error_message = "qurl_config: all timeout/connection values must be positive, and api_url/allowed_redirect_domain must be non-empty."
  }
}

variable "qurl_service_token_secret_arn" {
  description = "ARN of Secrets Manager secret containing the QURL service token"
  type        = string
  default     = null
}

# ==================== QURL Link Redirect Page ====================

variable "deploy_qurl_link" {
  description = "Deploy the QURL link redirect page (CloudFront + S3)"
  type        = bool
  default     = false
}

variable "qurl_link_frontend_domain" {
  description = "Domain for the QURL link redirect page (e.g., qurl.link). Required when deploy_qurl_link=true."
  type        = string
  default     = null

  validation {
    condition     = var.qurl_link_frontend_domain == null || can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]$", var.qurl_link_frontend_domain))
    error_message = "qurl_link_frontend_domain must be a valid domain name"
  }
}

variable "qurl_link_hosted_zone_id" {
  description = "Route53 hosted zone ID for the QURL link domain. Required when deploy_qurl_link=true."
  type        = string
  default     = null

  validation {
    condition     = var.qurl_link_hosted_zone_id == null || can(regex("^Z[A-Z0-9]{8,}$", var.qurl_link_hosted_zone_id))
    error_message = "qurl_link_hosted_zone_id must be a valid Route53 hosted zone ID (uppercase, starts with Z, at least 9 characters)."
  }
}

variable "qurl_link_external_dns" {
  description = "When true, Route53 records for qurl_link are managed externally (e.g., via AWS CLI in a different account)"
  type        = bool
  default     = false
}

variable "qurl_link_enable_access_logs" {
  description = "Enable CloudFront access logging for QURL link redirect page"
  type        = bool
  default     = false
}

variable "qurl_link_js_agent_enabled" {
  description = "Upload the browser NHP JS-agent bundle to the qurl.link static site, render relay bootstrap config, relax CSP for relay-only browser knocks, and disable public resolve ingress. Requires deploy_relay and relay_dns_name when true. Sandbox enables this for #2208/#2680 relay cutover staging; prod must remain false until a dedicated prod cutover PR."
  type        = bool
  default     = false
}

variable "enable_resolve_cloudfront" {
  description = "Enable CloudFront + WAF in front of resolve.qurl.link for ISP compatibility"
  type        = bool
  default     = false
}

variable "resolve_waf_ip_reputation_block" {
  description = <<-EOT
    Whether the resolve CloudFront WAF's AWSManagedRulesAmazonIpReputationList
    rule blocks (true) or only counts (false) matched requests.

    Default false (count). The resolve endpoint is already token-gated — the app
    returns an "Access Link Invalid" 403 for a missing/invalid token — so the
    IP-reputation list's marginal protection here is low, while it false-positives
    legitimate datacenter-origin traffic: the prod resolve->proxy smoke monitor,
    VPN exit nodes, corporate egress proxies, and link-unfurl bots
    (Slack/iMessage/Google). On 2026-06-02 AWS's reputation list began blocking
    the prod smoke runner IP (57.151.136.166), turning the resolve->proxy canary
    red with a CloudFront "Request blocked" 403. Counting (not blocking) keeps the
    rule evaluated and labeled for visibility while WAF logging (enabled with the
    resolve WebACL) records what it WOULD block. Flip back to true once log review
    confirms the matched set is actually hostile. See the prod-rollout task ledger.
  EOT
  type        = bool
  default     = false
}

variable "enable_resolve_waf_logging" {
  description = <<-EOT
    Enable WAF request logging for the resolve CloudFront WebACL. Default true so
    the IP-reputation rule (run in count mode) is observable. Mirrors
    modules/security's enable_waf_logging toggle and lets an operator turn the
    logs off without tearing down the resolve edge (enable_resolve_cloudfront).
    The logging_filter already keeps only IP-reputation-labeled or BLOCKed
    requests, so on-cost is bounded; this is the explicit off-switch.
  EOT
  type        = bool
  default     = true
}

variable "enable_resolve_access_logs" {
  description = <<-EOT
    Enable CloudFront access logging (standard logging v2 -> S3) for the resolve
    distribution (issue #1799). Default true so per-request x-edge-detailed-
    result-type is available for origin-error RCA without waiting to enable it
    mid-incident. Mirrors enable_resolve_waf_logging: gated on top of
    enable_resolve_cloudfront so logs can be turned off without tearing down the
    resolve edge. The delivered record_fields deliberately omit cs-uri-query so
    the ?token= access credential is never logged; see the delivery resources in
    main.tf. Storage is a short-retention S3 bucket (90d prod / 30d non-prod,
    matching the resolve WAF log group), bounded cost at resolve traffic; this is
    the explicit off-switch.
  EOT
  type        = bool
  default     = true
}

variable "traefik_plugins" {
  description = <<-EOT
    Map of Traefik plugins to deploy.
    Each plugin specifies:
    - version: S3 key prefix for plugin files (e.g., "v1.0.0" or "latest")
    - config: Optional map of configuration values

    Example:
    traefik_plugins = {
      nhp-token-validator = {
        version = "v1.0.0"
        config  = {}
      }
    }
  EOT
  type = map(object({
    version = string
    config  = optional(map(string), {})
  }))
  default = {}
}

variable "plugin_repos" {
  description = "List of GitHub repository names that can upload plugins to S3 (Traefik plugins only - NHP server plugins are now compiled in)"
  type        = list(string)
  default     = ["traefik-plugins"]
}

# ==================== CloudMap Configuration ====================

variable "nhp_cloudmap_service_name" {
  description = "CloudMap service name for NHP servers. Required. Recommended: 'server'"
  type        = string
  # No default - must be explicitly configured
}

# ==================== QURL Service ====================

variable "deploy_qurl_service" {
  description = "Deploy the QURL API service on ECS Fargate"
  type        = bool
  default     = false
}

variable "qurl_scanner_lambda_enabled" {
  description = "Deploy the scheduled qurl-scanner Lambda + EventBridge cron + scan-gap alarm. Default OFF. Two-apply rollout: ECR repo + SSM image-tag param are created unconditionally with `deploy_qurl_service` so qurl-service CI can publish images BEFORE this flag flips; second apply with this flag ON creates the Lambda (which validates the image at create time). See `modules/qurl-service/scanner_lambda.tf` for the full sequence and gating boundary; prod rollout preconditions are tracked in the prod rollout task ledger."
  type        = bool
  default     = false
}

variable "qurl_scanner_sqs_emit_enabled" {
  description = "Activate the resource-lifecycle SQS data path. See `modules/qurl-service/variables.tf::qurl_scanner_sqs_emit_enabled` for the full rationale (producer/consumer ordering under ECS rollback, operator gates, when to flip)."
  type        = bool
  default     = false
}

variable "qurl_scanner_tombstone_write_enabled" {
  description = "Enable destructive qurl-scanner tombstone writes after the SQS producer/consumer path is active. See `modules/qurl-service/variables.tf::qurl_scanner_tombstone_write_enabled`."
  type        = bool
  default     = false
}

variable "qurl_scanner_active_recheck_enabled" {
  description = "Create the hourly active-resource recheck scheduler after SQS and per-minute tombstone writes have burned in. See `modules/qurl-service/variables.tf::qurl_scanner_active_recheck_enabled`."
  type        = bool
  default     = false
}

variable "qurl_service_domain" {
  description = "Domain for QURL API (e.g., api.qurl.link)"
  type        = string
  default     = null
}

variable "qurl_internal_service_domain" {
  description = "Hostname for the QURL API internal ALB (e.g., internal-api.qurl.layerv.xyz). Served only on the internal=true ALB and resolved via the workload-account private hosted zone — public DNS returns NXDOMAIN. Set to null (default) to disable the internal ALB; the qurl-service module's internal_alb_enabled gate keys off this. The split-horizon design relies on this being a hostname under qurl_hosted_zone (parent zone in mgmt account) so ACM DNS-01 validation can publish a CNAME on the public zone without leaking an A record."
  type        = string
  default     = null

  # RFC1035 label-shape FQDN check: each label starts/ends with an
  # alphanumeric, hyphens allowed only internally, labels separated
  # by dots, at least two labels (FQDN form, no bare label, no
  # leading/trailing dot, no double dot). Catches typos and
  # confused-deputy cases at plan time rather than at ACM apply or
  # smoke probe execution. The hostname flows into smoke-test SSM
  # probe format strings; the reject-list in ssm_probe.go is
  # defense-in-depth, but a structural check on the
  # operator-controlled input is the primary gate.
  validation {
    condition     = var.qurl_internal_service_domain == null || can(regex("^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$", var.qurl_internal_service_domain))
    error_message = "qurl_internal_service_domain must be a valid RFC1035 FQDN (e.g., internal-api.qurl.layerv.xyz): each label 1-63 chars, alphanumeric edges, hyphens only internally, at least two labels, no leading/trailing dot."
  }
}

variable "qurl_enforce_internal_alb_only" {
  description = "When true, removes the legacy in-VPC bypass on the qurl-service ECS task SG (the cidr_blocks=[var.vpc_cidr] ingress rule). Apply with false first to introduce the internal ALB non-disruptively, verify the new path, then flip to true and re-apply to close the bypass. After PR4 of the rollout, the ECS tasks are reachable only from the public-ALB SG and (when internal_alb_enabled) the internal-ALB SG."
  type        = bool
  default     = false
}

variable "qurl_auth0_domain" {
  description = "Auth0 domain for QURL API JWT validation (e.g., 'layerv.us.auth0.com')"
  type        = string
  default     = ""

  validation {
    condition     = var.qurl_auth0_domain == "" || can(regex("^[a-zA-Z0-9][a-zA-Z0-9.-]+[a-zA-Z0-9]$", var.qurl_auth0_domain))
    error_message = "qurl_auth0_domain must be a valid hostname format."
  }
}

variable "qurl_auth0_audience" {
  description = "Auth0 audience for QURL API JWT validation"
  type        = string
  default     = "https://api.layerv.ai"
}

variable "qurl_cookie_domain" {
  description = "Cookie domain for NHP tokens (e.g., .qurl.site)"
  type        = string
  default     = ".qurl.site"
}

variable "qurl_default_ac_id" {
  description = "Default AC identifier for new QURL resources"
  type        = string
  default     = ""

  # Shape fence on the AC identifier. Same threat model as
  # `var.ac_auth_service_id` above — interpolated into the DDB seed
  # row's `ac_id` field (terraform/resources.tf) and used as the AC
  # connection key the server routes against at knock-time.
  # Empty-string is permitted by the regex (variable default; the
  # `terraform_data.frps_preconditions` block in `terraform/main.tf`
  # rejects empty when `deploy_frps = true`), so envs without FRPS
  # pass through without setting this var.
  validation {
    condition     = var.qurl_default_ac_id == "" || can(regex("^[a-z][a-z0-9-]{0,63}$", var.qurl_default_ac_id))
    error_message = "qurl_default_ac_id is interpolated into the DDB seed row's `ac_id` field; it must match `^[a-z][a-z0-9-]{0,63}$` (lowercase letters/digits/dashes, leading letter, ≤64 chars), or empty for envs without FRPS. Today's prod values (`layerv-ac-tf`) conform."
  }
}

variable "deploy_qurl_bootstrap_chain" {
  description = "Wave 5 dark-launch gate for the qurl-service ↔ nhp-server agent bootstrap chain. When true, the qurl-service module injects four env vars on the ECS task def (NHP_SERVER_PUBLIC_KEY_B64, NHP_SERVER_HOST, NHP_SERVER_PORT, QURL_AGENT_BOOTSTRAP_ENABLED) — same wiring shape as NHP_SERVER_INTERNAL_URL, no runtime SSM fetch, no new IAM surface. Values flow from module.compute at the root (server_public_key_b64 for the server-identity pubkey, nlb_dns_name for the host). The QURL_AGENT_BOOTSTRAP_ENABLED env var is driven by a separate `enable_qurl_agent_bootstrap` bool so activation is gated independently from the structural rollout. Requires `deploy_qurl_service = true` (enforced at plan time via a precondition). Default false leaves prod untouched until explicitly enabled per-env."
  type        = bool
  default     = false
}

variable "enable_qurl_agent_bootstrap" {
  description = "Wave 5 activation flag for the qurl-service agent → nhp-server bootstrap chain. Drives the QURL_AGENT_BOOTSTRAP_ENABLED env var on the task def. Default false: the chain stays inert until this is flipped to true per environment. Only consulted when deploy_qurl_bootstrap_chain = true."
  type        = bool
  default     = false
}

variable "retire_http_agent_lifecycle" {
  description = "Delete the obsolete HTTP agent bootstrap, registration, and qurl-service OTP Terraform resources after their runtime consumers have been detached in a separately applied preparation revision. Default false. Set only in the environment undergoing the coordinated UDP-only retirement."
  type        = bool
  default     = false
}

# ==================== Agent registration + email OTP (T1) ====================
#
# Two independent activation flags layered on top of the Wave-5 bootstrap chain,
# both default-dark so an un-opted env (sandbox until burn-in, prod until launch)
# provisions nothing new and its task defs / user_data are byte-unchanged:
#   PATH A — agent_registration_enabled: qurl-service accepts the internal
#     agent-register credential-exchange path (QURL_AGENT_REGISTRATION_ENABLED).
#     qurl-service's boot Config.Validate requires the bootstrap chain enabled +
#     a relay base URL when this is on, enforced here by preconditions on the
#     qurl_service / compute module invocations.
#   PATH B — agent_otp_enabled + agent_otp_registration_enabled: the email-OTP
#     register flow, split across the two services. qurl-service (OTP_ENABLED)
#     sends + verifies the OTP and requires registration + email_from + the pepper
#     secret; the NHP-server QURL plugin (AGENT_OTP_REGISTRATION_ENABLED) accepts
#     the OTP-registered agent. Both flip together.
# The SES sender infra (agent_otp_ses.tf) and the pepper secret are gated on
# agent_otp_enabled, so PATH B is the only flag that creates cloud resources.

variable "agent_registration_enabled" {
  description = "PATH A gate — QURL_AGENT_REGISTRATION_ENABLED on the qurl-service task def. Requires deploy_qurl_bootstrap_chain + enable_qurl_agent_bootstrap = true and a non-empty agent_registration_relay_base_url (enforced by a precondition on module.qurl_service). Default false."
  type        = bool
  default     = false
}

variable "agent_otp_enabled" {
  description = "PATH B gate (qurl-service side) — QURL_AGENT_OTP_ENABLED on the qurl-service task def, AND the create-gate for the SES sender infra (agent_otp_ses.tf) + the QURL_AGENT_OTP_PEPPER secret. Requires agent_registration_enabled = true and a non-empty agent_otp_email_from (enforced by a precondition on module.qurl_service). Flip in lockstep with agent_otp_registration_enabled (NHP-server side). Default false → OTP path inert, SES creates nothing."
  type        = bool
  default     = false
}

variable "agent_otp_ci_send_gate_enabled" {
  description = "Grants the GitHub Actions role ses:SendEmail on the agent-OTP sender identity + configuration set, so qurl-service's per-PR live-email gate can send a real message through real SES before a PR merges. NON-PROD ONLY — a precondition in agent_otp_ses.tf fails the plan if this is true when environment == \"prod\", so prod refuses the grant by constraint rather than by convention. Requires agent_otp_enabled = true (the identity and config set it scopes to are created by that gate). Default false."
  type        = bool
  default     = false
}

variable "agent_otp_registration_enabled" {
  description = "PATH B gate (NHP-server QURL plugin side) — AGENT_OTP_REGISTRATION_ENABLED, rendered into nhp-server user_data only when qurl_config.enabled. Flip in lockstep with agent_otp_enabled (qurl-service side); enabling only one side leaves the OTP register flow half-wired. Default false → user_data byte-unchanged."
  type        = bool
  default     = false
}

variable "agent_otp_ci_mailbox_enabled" {
  description = "Creates the CI receive mailbox for the qurl-go OTP gate (agent_otp_ci_mailbox.tf): a dedicated `ci-otp.<sender domain>` receiving subdomain with its own MX, an SES receipt rule storing raw mail to S3, an SQS arrival queue, and read access for the GitHub Actions role. NON-PROD ONLY — a precondition fails the plan when environment == \"prod\", because this routes OTP mail somewhere CI can read it. Also requires agent_otp_enabled = true (the subdomain derives from the OTP sender domain) and a region where SES email RECEIVING is available. Note this activates an SES receipt rule set, and an account has only one active set. Default false."
  type        = bool
  default     = false
}

variable "agent_otp_email_from" {
  description = "From address qurl-service stamps on OTP emails (QURL_AGENT_OTP_EMAIL_FROM), e.g. `noreply@notify.layerv.ai`. The root derives the SES sender domain from the part after `@` (agent_otp_ses.tf). Required (non-empty) when agent_otp_enabled = true; empty when the OTP path is dark. Do NOT set to an address whose domain is outside the Route53 zone this env manages (hosted_zone_id) — SES DKIM/MAIL-FROM records are written into that zone."
  type        = string
  default     = ""

  validation {
    # Empty (dark) or a bare local@domain addr-spec — the root splits on `@` to
    # derive the SES identity domain, so a display name / angle brackets would
    # break derivation. qurl-service boot config is the authoritative parser.
    condition     = var.agent_otp_email_from == "" || can(regex("^[^@[:space:]]+@[a-z0-9][a-z0-9.-]*[a-z0-9]\\.[a-z]{2,}$", var.agent_otp_email_from))
    error_message = "agent_otp_email_from must be empty (OTP dark) or a bare local@domain address (no display name, angle brackets, or whitespace)."
  }
}

variable "agent_registration_relay_base_url" {
  description = "Base URL of the nhp relay the agent-register flow points clients at (QURL_NHP_RELAY_BASE_URL on the qurl-service task def). Required (non-empty https URL) when agent_registration_enabled = true. Empty when registration is dark."
  type        = string
  default     = ""

  validation {
    condition     = var.agent_registration_relay_base_url == "" || can(regex("^https://", var.agent_registration_relay_base_url))
    error_message = "agent_registration_relay_base_url must be empty (registration dark) or an https:// URL."
  }
}

variable "qurl_default_ac_port" {
  description = "Default AC port for new QURL resources"
  type        = number
  default     = 443
}

variable "qurl_default_token_expire" {
  description = "Default token expiration in seconds"
  type        = number
  default     = 3600
}

variable "qurl_default_open_time" {
  description = "Default firewall open time in seconds"
  type        = number
  default     = 300
}

variable "qurl_link_domain" {
  description = "Domain for QURL access links (e.g., qurl.link)"
  type        = string
  default     = "qurl.link"
}

variable "qurl_site_domain" {
  description = "Domain for QURL protected resources (e.g., qurl.site)"
  type        = string
  default     = "qurl.site"
}

variable "qurl_site_hosted_zone_id" {
  description = "Route53 hosted zone ID for the qurl.site domain wildcard record. For sandbox (qurl.site.layerv.xyz), this is the layerv.xyz zone. For prod (qurl.site), this is the qurl.site zone."
  type        = string
  default     = null

  validation {
    condition     = var.qurl_site_hosted_zone_id == null || can(regex("^Z[A-Z0-9]{8,}$", var.qurl_site_hosted_zone_id))
    error_message = "qurl_site_hosted_zone_id must be a valid Route53 hosted zone ID (uppercase, starts with Z, at least 9 characters)."
  }
}

variable "qurl_ip_rate_limit" {
  description = "Rate limit for IP-based internal routes (requests per minute)"
  type        = number
  default     = 300

  validation {
    condition     = var.qurl_ip_rate_limit > 0 && var.qurl_ip_rate_limit <= 10000
    error_message = "qurl_ip_rate_limit must be between 1 and 10000 requests per minute"
  }
}

variable "qurl_ip_rate_burst" {
  description = "Burst allowance for IP-based internal routes"
  type        = number
  default     = 100

  validation {
    condition     = var.qurl_ip_rate_burst > 0 && var.qurl_ip_rate_burst <= 1000
    error_message = "qurl_ip_rate_burst must be between 1 and 1000"
  }
}

variable "deploy_redis" {
  description = "Deploy ElastiCache Serverless Redis for distributed QURL rate limiting"
  type        = bool
  default     = false
}

variable "qurl_audit_retention_days" {
  description = "Number of days to retain QURL audit logs in DynamoDB"
  type        = number
  default     = 90
}

variable "qurl_cors_allowed_origins" {
  description = "Comma-separated list of allowed CORS origins for QURL API"
  type        = string
  default     = ""
}

variable "qurl_additional_allowed_hosts" {
  description = "Additional allowed hostnames for QURL API. ALB DNS and localhost are always included."
  type        = list(string)
  default     = []
}

variable "qurl_container_cpu" {
  description = "CPU units for QURL container (256 = 0.25 vCPU)"
  type        = number
  default     = 256

  validation {
    condition     = contains([256, 512, 1024, 2048, 4096, 8192, 16384], var.qurl_container_cpu)
    error_message = "qurl_container_cpu must be a valid Fargate CPU value: 256, 512, 1024, 2048, 4096, 8192, or 16384."
  }
}

variable "qurl_container_memory" {
  description = "Memory in MB for QURL container"
  type        = number
  default     = 512

  validation {
    condition     = var.qurl_container_memory >= 512 && var.qurl_container_memory <= 122880
    error_message = "qurl_container_memory must be between 512 and 122880 MB for Fargate."
  }
}

variable "qurl_desired_count" {
  description = "Desired number of QURL ECS tasks"
  type        = number
  default     = 1
}

variable "qurl_container_port" {
  description = "TCP port qurl-service tasks listen on. Threaded into BOTH module.qurl_service (container_port) AND module.bootstrap_alb (target_port) at the env-root call sites so the two cannot drift: bootstrap-alb's target group silently health-checks the wrong port if its target_port disagrees with the qurl-service container_port (modules/bootstrap-alb/variables.tf::target_port description explicitly calls out this footgun). Each module continues to carry its own `default = 8080` so they remain independently usable; this env-root var is the single source of truth WHEN BOTH modules are composed together. Changing this var rolls both attachments to the new port."
  type        = number
  default     = 8080
  nullable    = false

  validation {
    condition     = var.qurl_container_port > 0 && var.qurl_container_port < 65536
    error_message = "qurl_container_port must be a valid TCP port (1–65535)."
  }
}

variable "qurl_autoscaling_min_capacity" {
  description = "Minimum number of QURL ECS tasks for auto-scaling (production only)"
  type        = number
  default     = 2
}

variable "qurl_autoscaling_max_capacity" {
  description = "Maximum number of QURL ECS tasks for auto-scaling (production only)"
  type        = number
  default     = 10
}

variable "qurl_jwt_secret_arn" {
  description = "Secrets Manager ARN for QURL JWT signing secret"
  type        = string
  default     = null
}

variable "qurl_internal_service_token_arn" {
  description = "Secrets Manager ARN for QURL internal service token"
  type        = string
  default     = null
}

variable "qurl_hosted_zone_id" {
  description = "Route53 hosted zone ID for QURL API domain"
  type        = string
  default     = null

  validation {
    condition     = var.qurl_hosted_zone_id == null || can(regex("^Z[A-Z0-9]{8,}$", var.qurl_hosted_zone_id))
    error_message = "qurl_hosted_zone_id must be a valid Route53 hosted zone ID (uppercase, starts with Z, at least 9 characters)."
  }
}

variable "qurl_github_repo" {
  description = "GitHub repository for QURL service (for ECR push permissions)"
  type        = string
  default     = "qurl-service"
}

variable "qurl_go_github_repo" {
  description = "GitHub repository for the qURL Go SDK. Used only to build the two exact OIDC trust subjects for the OTP registration gate's mailbox-read role (agent_otp_ci_mailbox.tf): repo:<github_org>/<this>:pull_request and repo:<github_org>/<this>:ref:refs/heads/main. Note this repo is PUBLIC: the pull_request subject is not itself a fork boundary, so the consumer workflow rejects fork heads before AWS authentication and relies on GitHub withholding its required repository secrets; independently, this role grants nothing but reads of a CI-only OTP mailbox."
  type        = string
  default     = "qurl-go"
}

variable "qurl_reverse_tunnel_server_github_repo" {
  description = "GitHub repository for the qurl-reverse-tunnel-server source. Threaded into the ECR module's github_actions OIDC trust policy. See `modules/ecr/main.tf`'s variable description for the full blast-radius warning — the threaded role is terraform-apply-equivalent, not just ECR push. Empty disables."
  type        = string
  default     = "qurl-reverse-tunnel-server"
}

# ==============================================================================
# Website Email-Capture API DNS
# ==============================================================================
# Route 53 A-alias for the website email-capture API, pointing at an APIGW v2
# custom domain provisioned by the layervai/website CDK stack. The alias lives
# in this repo because the layerv.ai zone is in the layerv-mgmt account and is
# only reachable via the route53_mgmt provider. See layervai/website#188 and
# the resource block in terraform/main.tf for the full rationale.

variable "deploy_website_api_dns" {
  description = "Create the Route 53 A-alias for the website email-capture API. The APIGW custom domain is provisioned in the layervai/website CDK repo (LayerV-production-Api → ApiDomainName); this flag turns on the cross-account DNS record pointing at it. Requires website_api_domain, qurl_hosted_zone_id (mgmt-account layerv.ai zone), and website_api_cfn_stack_name to all be set."
  type        = bool
  default     = false
}

variable "website_api_domain" {
  description = "FQDN for the website email-capture API (e.g. web-api.layerv.ai). Must match apiDomain in layervai/website infra/lib/config.ts. Required when deploy_website_api_dns = true."
  type        = string
  default     = null

  validation {
    condition     = var.website_api_domain == null || can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]\\.[a-z]{2,}$", var.website_api_domain))
    error_message = "website_api_domain must be a valid FQDN (e.g., web-api.layerv.ai)."
  }
}

variable "website_api_cfn_stack_name" {
  description = "Name of the website CDK CloudFormation stack in layerv-prod us-east-1 that provisions the APIGW v2 custom domain (e.g. LayerV-production-Api). The stack's ApiCustomDomainRegionalDomainName and ApiCustomDomainRegionalHostedZoneId outputs are consumed as the A-alias target. Required when deploy_website_api_dns = true."
  type        = string
  default     = null

  validation {
    condition     = var.website_api_cfn_stack_name == null || length(var.website_api_cfn_stack_name) > 0
    error_message = "website_api_cfn_stack_name must be null or a non-empty string."
  }
}

# ==================== QURL Idempotency Cache ====================

variable "qurl_idempotency_cache_ttl_seconds" {
  description = "TTL for idempotency cache entries in seconds"
  type        = number
}

variable "qurl_idempotency_cache_max_size" {
  description = "Maximum number of idempotency cache entries"
  type        = number
}

variable "qurl_idempotency_cleanup_interval_seconds" {
  description = "Interval between idempotency cache cleanup runs in seconds"
  type        = number
}

# ==================== QURL Health Check ====================

variable "qurl_health_check_timeout_seconds" {
  description = "Timeout for QURL health check operations in seconds"
  type        = number
}

variable "qurl_health_startup_timeout_seconds" {
  description = "Timeout for QURL startup health checks in seconds"
  type        = number
}

variable "qurl_customer_cache_ttl_seconds" {
  description = "TTL for customer tier cache in seconds"
  type        = number
  default     = 300
}

variable "qurl_customer_cache_max_size" {
  description = "Maximum entries in the customer tier cache"
  type        = number
  default     = 1000
}

# ==================== QURL Resource Config ====================
# TTL Relationship:
# - qurl_default_expires_in_seconds: How long a QURL is valid (user-facing)
# - qurl_resource_ttl_buffer_seconds: Additional time before DynamoDB cleanup
# - qurl_session_ttl_seconds: How long session records persist

variable "qurl_default_expires_in_seconds" {
  description = "Default QURL lifetime in seconds (60s min, 30 days max)"
  type        = number
  default     = 86400 # 24 hours

  validation {
    condition     = var.qurl_default_expires_in_seconds >= 60 && var.qurl_default_expires_in_seconds <= 2592000
    error_message = "qurl_default_expires_in_seconds must be between 60 (1 minute) and 2592000 (30 days)."
  }
}

variable "qurl_resource_ttl_buffer_seconds" {
  description = "Buffer after expiration for DynamoDB cleanup in seconds (1 hour min, 30 days max)"
  type        = number
  default     = 604800 # 7 days

  validation {
    condition     = var.qurl_resource_ttl_buffer_seconds >= 3600 && var.qurl_resource_ttl_buffer_seconds <= 2592000
    error_message = "qurl_resource_ttl_buffer_seconds must be between 3600 (1 hour) and 2592000 (30 days)."
  }
}

variable "qurl_session_ttl_seconds" {
  description = "Session TTL in seconds (60s min, 30 days max)"
  type        = number
  default     = 3600 # 1 hour — reduced from 24h to limit post-revocation access window

  validation {
    condition     = var.qurl_session_ttl_seconds >= 60 && var.qurl_session_ttl_seconds <= 2592000
    error_message = "qurl_session_ttl_seconds must be between 60 (1 minute) and 2592000 (30 days)."
  }
}

variable "qurl_default_list_limit" {
  description = "Default items per page for list endpoints (1-100)"
  type        = number
  default     = 20

  validation {
    condition     = var.qurl_default_list_limit >= 1 && var.qurl_default_list_limit <= 100
    error_message = "qurl_default_list_limit must be between 1 and 100."
  }
}

# ==================== QURL Auth0 JWKS ====================

variable "qurl_auth0_jwks_cache_ttl_seconds" {
  description = "TTL for Auth0 JWKS cache in seconds"
  type        = number
}

variable "qurl_auth0_jwks_fetch_timeout_seconds" {
  description = "Timeout for fetching Auth0 JWKS in seconds"
  type        = number
}

# ==================== QURL Webhooks ====================

variable "qurl_webhooks_enabled" {
  description = "Enable webhook delivery for QURL service"
  type        = bool
  default     = false
}

variable "qurl_webhooks_worker_count" {
  description = "Number of concurrent webhook delivery workers"
  type        = number
}

variable "qurl_webhooks_max_webhooks_per_owner" {
  description = "Maximum number of webhooks per owner"
  type        = number
}

variable "qurl_webhooks_delivery_timeout_seconds" {
  description = "Timeout for webhook delivery in seconds"
  type        = number
}

variable "qurl_webhooks_max_retries" {
  description = "Maximum number of webhook delivery retries"
  type        = number
}

variable "qurl_webhooks_event_channel_size" {
  description = "Size of the webhook event channel buffer"
  type        = number
}

variable "qurl_webhooks_retry_worker_interval_seconds" {
  description = "Interval between webhook retry worker runs in seconds"
  type        = number
}

variable "qurl_webhooks_drain_timeout_seconds" {
  description = "Timeout for draining webhook events during shutdown in seconds"
  type        = number
}

variable "qurl_webhooks_response_body_limit" {
  description = "Maximum response body size to store from webhook endpoints in bytes"
  type        = number
}

variable "qurl_webhooks_api_version" {
  description = "API version string for webhook payloads"
  type        = string
}

# ==================== QURL Custom Domains ====================

variable "qurl_custom_domain_enabled" {
  description = "Enable custom domain management endpoints in QURL service. ACME suffix and NLB target are derived automatically from hosted_zone and AC module."
  type        = bool
  default     = false
}

variable "qurl_custom_domain_cleanup_topic_arn" {
  description = "SNS topic ARN for domain.cleanup events (nhp#1990). Created by the env and passed in. Ignored unless qurl_custom_domain_cleanup_publish_enabled is true."
  type        = string
  default     = ""

  validation {
    condition     = var.qurl_custom_domain_cleanup_topic_arn == "" || can(regex("^arn:aws:sns:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9_-]+$", var.qurl_custom_domain_cleanup_topic_arn))
    error_message = "qurl_custom_domain_cleanup_topic_arn must be a valid SNS topic ARN or empty."
  }
}

variable "qurl_custom_domain_cleanup_publish_enabled" {
  description = "Static boolean: when true, grants the qurl-service task role sns:Publish on the cleanup topic. Paired with qurl_custom_domain_cleanup_topic_arn — see the module-level variable for the count-depends-on-computed rationale."
  type        = bool
  default     = false
}

variable "deploy_custom_domain_cert" {
  description = "Whether the custom-domain cert lambda is deployed in this env. Gates the #2000 smoke-test surface (SSM discovery params + sns:Publish IAM policy on the CI role) at the root level; the env-level resources (SNS topic, cert lambda module) gate on their own copy of this flag in the env tfvars."
  type        = bool
  default     = false
}

# ==================== QURL GeoIP ====================

variable "qurl_geoip_enabled" {
  description = "Enable GeoIP lookups for geo-restriction policies"
  type        = bool
  default     = false
}

variable "qurl_geoip_db_path" {
  description = "Filesystem path for the GeoIP .mmdb database inside the container"
  type        = string
  default     = "/app/data/GeoLite2-Country.mmdb"
}

variable "qurl_geoip_s3_uri" {
  description = "S3 URI of the GeoLite2-Country .mmdb database. Container downloads on startup when set."
  type        = string
  default     = ""
}

variable "qurl_geoip_s3_kms_key_arn" {
  description = "KMS key ARN used to encrypt the GeoIP S3 bucket. Required if the bucket uses SSE-KMS."
  type        = string
  default     = ""
}

# ==================== QURL Observability (OpenTelemetry) ====================

variable "qurl_otel_enabled" {
  description = "Enable OpenTelemetry instrumentation for QURL service"
  type        = bool
  default     = false
}

variable "qurl_otel_service_name" {
  description = "Service name for OpenTelemetry"
  type        = string
}

variable "qurl_otel_service_version" {
  description = "Service version for OpenTelemetry"
  type        = string
}

variable "qurl_otel_environment" {
  description = "Environment name for OpenTelemetry"
  type        = string
}

variable "qurl_otel_exporter_endpoint" {
  description = "OTLP exporter endpoint (e.g., http://localhost:4317)"
  type        = string
}

variable "qurl_otel_exporter_protocol" {
  description = "OTLP exporter protocol (grpc or http/protobuf)"
  type        = string
}

variable "qurl_otel_exporter_insecure" {
  description = "Use insecure connection to OTLP endpoint (for localhost sidecar)"
  type        = bool
}

variable "qurl_otel_trace_sample_rate" {
  description = "Trace sampling rate (0.0 to 1.0)"
  type        = number
}

variable "qurl_otel_metrics_interval" {
  description = "Metrics export interval in seconds"
  type        = number
}

variable "qurl_otel_metrics_enabled" {
  description = "Enable OpenTelemetry metrics"
  type        = bool
}

variable "qurl_otel_tracing_enabled" {
  description = "Enable OpenTelemetry tracing"
  type        = bool
}

variable "qurl_otel_log_correlation" {
  description = "Enable trace ID correlation in logs"
  type        = bool
}

# ==================== QURL Grafana Cloud (ADOT Sidecar) ====================

variable "qurl_grafana_cloud_enabled" {
  description = "Enable Grafana Cloud OTLP export via ADOT sidecar for QURL service. When enabled, adds an ADOT collector sidecar that exports telemetry to Grafana Cloud."
  type        = bool
  default     = false
}

variable "qurl_grafana_secret_arn" {
  description = <<-EOT
    ARN of Secrets Manager secret containing Grafana Cloud OTLP credentials.
    Required when qurl_grafana_cloud_enabled = true.

    Secret must contain JSON with keys:
    - endpoint: Grafana Cloud OTLP gateway URL
    - auth: Base64-encoded "instance_id:api_token" for Basic authentication
  EOT
  type        = string
  default     = null
}

variable "qurl_adot_collector_image" {
  description = "ADOT Collector container image for QURL service"
  type        = string
  default     = "public.ecr.aws/aws-observability/aws-otel-collector:v0.40.0"
}

# ==================== QURL Connector Auth ====================

variable "qurl_connector_auth_enabled" {
  description = "Enable qurl-service connector-auth endpoint and type=tunnel branches in CreateQurl/CreateResource (qurl-service PR #277 feature gate). Default false keeps the new code paths inert in production until the creation endpoint (qurl-service #405) and per-AZ FRPS assignment (qurl-service #396) are both deployed. Flip per-env via tfvars after the dependent qurl-service work ships and the qurl-service deploy is verified."
  type        = bool
  default     = false
}

# ==================== Grafana Cloud Dashboards ====================

variable "grafana_dashboards_enabled" {
  description = "Enable Grafana Cloud dashboard provisioning"
  type        = bool
  default     = false
}

variable "grafana_url" {
  description = "Grafana Cloud stack URL (e.g., https://layervai.grafana.net)"
  type        = string
  default     = ""
}

variable "grafana_auth" {
  description = "Grafana Cloud API key or service account token with Editor role"
  type        = string
  default     = ""
  sensitive   = true
}

variable "grafana_prometheus_datasource_uid" {
  description = "UID of the Prometheus/Mimir datasource in Grafana Cloud"
  type        = string
  default     = "grafanacloud-prom"
}

variable "grafana_tempo_datasource_uid" {
  description = "UID of the Tempo datasource in Grafana Cloud"
  type        = string
  default     = "grafanacloud-traces"
}

variable "grafana_cloudwatch_enabled" {
  description = "Enable CloudWatch data source in Grafana for NHP Infrastructure dashboard"
  type        = bool
  default     = false
}

variable "grafana_create_dashboards" {
  description = "Create Grafana dashboard and folder resources. Set to false for non-primary environments that only need CloudWatch datasources."
  type        = bool
  default     = true
}

variable "grafana_cloud_aws_account_id" {
  description = "Grafana Cloud's AWS account ID for IAM trust policy (find in Grafana Cloud CloudWatch integration setup)"
  type        = string
  default     = ""
}

variable "grafana_cloud_external_id" {
  description = "External ID for Grafana Cloud IAM assume role"
  type        = string
  default     = null
}

variable "grafana_loki_datasource_uid" {
  description = "UID of the Loki datasource in Grafana Cloud. Used by the qurl-error-logs-spike alert rule."
  type        = string
  default     = "grafanacloud-logs"
}

# ==================== QURL Alerting (Grafana → SNS) ====================
# Grafana alert rules for the qurl-api SLO. Routes alerts through the
# existing CloudWatch SNS topic from the monitoring module so the new
# qurl-api alerts land in the same Slack/email channels as every other
# prod alert. See docs/slo.md and docs/runbooks/qurl-*.md.
#
# Background: 2026-03-24 incident — every POST /v1/qurls returned 500 for
# over a week before any human noticed. The dashboard had burn-rate panels
# but no alert rules. This closes that gap.

variable "qurl_alerts_enabled" {
  description = "Create the Grafana alert rules and SNS contact point for qurl-api. Set true only for prod cells."
  type        = bool
  default     = false
}

variable "qurl_alerts_paused" {
  description = "Ship Grafana alert rules paused so they soak for 24h before going live. Flip to false after the soak period to begin paging."
  type        = bool
  default     = true
}

variable "qurl_alerts_runbook_base_url" {
  description = "Base URL for the alert runbooks. Default points at the layervai/nhp main branch. Consumed unescaped by both the grafana-dashboards module (Grafana alert JSON) and the security module's GuardDuty alert templates, so it must be literal-safe (no double-quote, `<`, `>`, `|`, backslash, or whitespace) and must not end in `/` (consumers append `/<file>.md`). This variable is the single validation point — the consuming modules are internal to this repo and trust this value."
  type        = string
  default     = "https://github.com/layervai/nhp/blob/main/docs/runbooks"

  # SINGLE enforcement point. This value enters the system here and is threaded
  # unescaped to the grafana-dashboards and security modules, where it is
  # concatenated into Grafana alert JSON and the GuardDuty Slack `<url|text>`
  # link. A `"`, `<`, `>`, `|`, backslash, whitespace, or trailing `/` would
  # silently malform that output (a dropped GuardDuty Slack alert is a
  # fail-closed-without-noise monitoring blind spot). Those modules are internal
  # to this repo and only ever receive this validated value, so they deliberately
  # do NOT repeat the check — one guard here beats three hand-synced regexes that
  # rot. If a module is ever extracted for external reuse, add a guard at its new
  # root.
  validation {
    condition     = can(regex("^https://[^\\s\"<>|\\\\]+$", var.qurl_alerts_runbook_base_url))
    error_message = "qurl_alerts_runbook_base_url must be an https:// URL containing no double-quote, <, >, |, backslash, or whitespace — those characters would malform the Grafana alert JSON and the GuardDuty Slack <url|text> link it is concatenated into."
  }
  validation {
    condition     = !endswith(var.qurl_alerts_runbook_base_url, "/")
    error_message = "qurl_alerts_runbook_base_url must not end with a trailing slash — consumers append `/<file>.md`, so a trailing slash yields a `//` in the runbook link."
  }
}

variable "qurl_alerts_slo_target_percent" {
  description = "Availability SLO target as a percentage. Must match the dashboard's slo_target template variable default (qurl-operations.json line 99) so panels and alerts stay in lockstep. A typo here silently changes the burn-rate denominator by orders of magnitude — the validation block guards against that."
  type        = number
  default     = 99.99

  validation {
    condition     = var.qurl_alerts_slo_target_percent >= 90 && var.qurl_alerts_slo_target_percent <= 99.999
    error_message = "qurl_alerts_slo_target_percent must be between 90 and 99.999 (e.g., 99.99 for four nines). Values outside this range produce nonsensical burn-rate denominators and are almost certainly a typo."
  }
}

# ==================== QURL Router Plugin ====================
# Configuration for the Traefik QURL Router plugin that routes *.qurl.site requests

variable "qurl_router_enabled" {
  description = "Enable QURL Router plugin in Traefik (routes *.qurl.site subdomains to target backends)"
  type        = bool
  default     = false
}

variable "qurl_router_cache_ttl" {
  description = "Cache TTL in seconds for successful target URL lookups"
  type        = number
  default     = 60
}

variable "qurl_router_negative_cache_ttl" {
  description = "Cache TTL in seconds for failed lookups (404s)"
  type        = number
  default     = 30
}

variable "qurl_router_max_cache_size" {
  description = "Maximum number of entries in the URL lookup cache"
  type        = number
  default     = 1000
}

variable "qurl_router_api_timeout" {
  description = "Timeout in seconds for QURL Service API calls"
  type        = number
  default     = 5
}

variable "qurl_router_proxy_timeout" {
  description = "Timeout in seconds for proxying requests to target backends"
  type        = number
  default     = 30
}

variable "qurl_router_cache_shards" {
  description = "Number of cache shards for concurrent access"
  type        = number
  default     = 16
}

# ==================== qurl-router HRW (instance-level dispatch) ====================
# traefik-plugins #134 introduced opt-in router-side HRW: when enabled, the
# qurl-router plugin resolves the boundary hostname (per-AZ Cloud Map service)
# to the full set of healthy A records and hashes a resource_id to a specific
# instance IP via the hrw.go package. Off by default — flips to true in PR 4
# once PR 1 (traefik-plugins) and PR 2 (qurl-reverse-tunnel-client) are
# deployed and validated.
#
# Cross-repo HRW contract (consumed by both qurl-router and frpc):
#   - Hash function: sha256(resource_id || "\x00" || instance_endpoint_string)
#   - Score = first 8 bytes of digest, big-endian uint64
#   - Pick: max score, tie-break lexicographically smallest endpoint
#   - Empty instance set → fall back to boundary-level dispatch
# Both router and frpc must use the same algorithm; golden test vectors live
# in the traefik-plugins PR (#134) `hrw_test.go`.
variable "enable_instance_hrw" {
  description = <<-EOT
    Enable router-side HRW dispatch in the qurl-router Traefik plugin.

    When true, the plugin resolves the boundary hostname (per-AZ Cloud Map
    service) to the full set of healthy A records and hashes the
    resource_id to one of them via HRW (highest random weight). When
    false (the default, current behavior), the plugin proxies to the
    boundary hostname and lets DNS pick one A record per query.

    Default false preserves existing behavior. Flip to true in PR 4
    after PR 1 (traefik-plugins #134) and PR 2 (qurl-reverse-tunnel-
    client) are deployed and the matching dial-side HRW is live in
    frpc. PR 3 (this PR) only adds the plumbing — it doesn't flip the
    flag in any tfvars.

    Requires Cloud Map MULTIVALUE routing on the qurl-reverse-tunnel-server services
    (see `var.qurl_reverse_tunnel_server_cloud_map_routing_policy`); otherwise DNS only
    returns one IP per query and HRW degenerates to "always pick the
    same instance".
  EOT
  type        = bool
  default     = false
}

variable "instance_discovery_ttl_seconds" {
  description = <<-EOT
    TTL in seconds for the qurl-router instance-IP allowlist. The plugin
    resolves boundary hostnames into instance IPs and accepts those IPs
    as dialable for this many seconds before re-resolving.

    Default 20 matches the plugin code default (traefik-plugins #134;
    `qurl-router/discovery.go::DefaultDiscoveryTTL`). Lower values mean
    faster reaction to scale events at the cost of more DNS lookups;
    higher values risk dialing IPs that have rotated out of the
    boundary's healthy set.

    Ignored when `enable_instance_hrw = false` — the discovery path only
    runs in HRW mode.
  EOT
  type        = number
  default     = 20

  validation {
    condition     = var.instance_discovery_ttl_seconds >= 1 && var.instance_discovery_ttl_seconds <= 600 && floor(var.instance_discovery_ttl_seconds) == var.instance_discovery_ttl_seconds
    error_message = "instance_discovery_ttl_seconds must be an integer between 1 and 600. Floor 1s catches the typo `0` (no caching at all); ceiling 10min catches a typo that would make HRW resolve against multi-minute-stale IP sets."
  }
}

variable "enable_qurl_site_authz" {
  description = <<-EOT
    Enable the qurl-router L7 per-session authorization gate on the
    *.qurl.site branch. Implemented in layervai/traefik-plugins#146;
    consumer plugin field is `enableQurlSiteAuthz` on the
    qurl-router middleware Config.

    When true, the plugin calls
    GET /internal/v1/resource/:id/authorize on every *.qurl.site
    request and silentDrops requests whose session has expired or
    been revoked. When false (the default), the *.qurl.site branch
    skips the gate and per-session enforcement relies solely on the
    L3 OpenTime clamp at iptables.

    Revoke-to-blocked latency SLO: positive authz results are
    cached for up to `min(authCacheTTL, remaining_seconds)` —
    `authCacheTTL` is currently 15s in the plugin. A server-side
    revoke takes effect at the consumer no later than 15 seconds
    after issue; clients with a recently-cached positive authz can
    see the revoked resource for up to that window. This is the
    accepted trade-off for keeping the gate off the hot path on
    every request. Operators evaluating compliance against
    stricter revocation SLAs should treat the L3 OpenTime clamp
    (still enforced at iptables regardless of this flag) as the
    sub-15s floor.

    Activation cadence: this variable threads through user_data, so
    `terraform apply` bumps the AC launch-template version but does
    NOT replace running AC instances (the AC ASG has no
    `instance_refresh{}` block — by design, to keep TF apply
    light-weight). The flag activates per-instance at the NEXT AC
    instance refresh in each env — driven by the blue/green or
    canary deploy workflow, not by `terraform apply` alone. The
    plugin emits a one-shot startup `Info` line on activation,
    which is the in-band signal that the flag is loaded.

    Producer dependency: the consumer call is to qurl-service's
    `/internal/v1/resource/:id/authorize` endpoint. Verify the
    endpoint is live on every API task (image tag containing the
    producer rollout) before flipping. Reversible — flip back to
    false and re-trigger AC refresh to bypass the gate if a
    producer-side regression surfaces.

    Trust-boundary dependency: the gate's security relies on
    Traefik's `forwardedHeaders.trustedIPs` being pinned to the
    upstream proxy chain so an attacker cannot spoof
    `X-Forwarded-For: <victim-ip>` and ride the victim's authz
    cache. The AC's Traefik config pins this to `vpc_cidr`, while
    the public AC NLB target groups preserve client IP at L3 and do
    NOT inject PROXY protocol. That means external browsers arrive
    with their real TCP peer IP for the plugin's client-IP extractor,
    and external XFF spoofs are still untrusted by Traefik. See
    `terraform/modules/ac/user_data.sh.tpl` (entrypoint config) and
    `extractClientIP` in `layervai/traefik-plugins`'s
    `plugins-local/src/github.com/traefik/qurl-router/qurl_router.go`.
  EOT
  type        = bool
  default     = false
}

variable "require_connector_routing_id" {
  description = <<-EOT
    Require the qurl-router plugin to use the qURL Service-issued
    connector_routing_id for ordinary *.qurl.site Connector traffic.

    Default false keeps the additive producer and consumer rollout dark and
    renders no new user-data bytes, so adding the unset flag is plan-neutral.
    Set true only after qurl-service emits connector_routing_id on every API
    host, the native Connector registers with that exact identity, and the
    matching qurl-router plugin is deployed to every Access Controller.
    With the gate enabled, missing or malformed identities fail closed; there
    is no fallback to the public resource id.

    This is startup-only configuration rendered into AC user data. Applying a
    value change creates a new launch-template version but does not update a
    running AC. Activate or roll back the gate through the normal whole-fleet
    AC restart/rollout, and never admit Connector traffic across a mixed-gate
    fleet. See NHP #3275 and traefik-plugins #246.
  EOT
  type        = bool
  default     = false
}

# ==================== Security Alerting ====================

variable "guardduty_alert_emails" {
  description = "List of email addresses to receive GuardDuty security finding alerts"
  type        = list(string)
  default     = []
}

variable "alert_emails" {
  description = "Email addresses for CloudWatch alarm notifications via SNS. Each email must confirm the subscription."
  type        = list(string)
  default     = []
}

variable "enable_waf_logging" {
  description = "Enable WAF logging to CloudWatch Logs. WAF logs cannot be backfilled — every day without logging is a gap in your security audit trail."
  type        = bool
  default     = true
}

# ==================== Blue/Green Deployment ====================

variable "enable_blue_green" {
  description = "Enable blue/green deployment infrastructure for NHP Server. Creates a second ASG and SSM parameters for instant traffic switching."
  type        = bool
  default     = false
}

variable "green_standby_min_size" {
  description = "Minimum instance count for green ASG in standby mode. 1 = warm standby (instant switch and strict missing-data target-health alarms), 0 = cold standby (requires scale-up before switch; green target-health alarms do not page on missing data while intentionally cold)."
  type        = number
  default     = 1

  validation {
    condition     = var.green_standby_min_size >= 0 && var.green_standby_min_size <= 10
    error_message = "green_standby_min_size must be between 0 and 10."
  }
}

variable "deployment_stale_threshold_days" {
  description = "Number of days without deployments before the stale deployment alarm fires. Set to 0 to disable the alarm."
  type        = number
  default     = 7

  validation {
    condition     = var.deployment_stale_threshold_days >= 0 && var.deployment_stale_threshold_days <= 30
    error_message = "deployment_stale_threshold_days must be between 0 and 30."
  }
}

variable "enable_ac_blue_green" {
  description = "Enable blue/green deployment infrastructure for AC. Creates a second ASG and SSM parameters for instant traffic switching."
  type        = bool
  default     = false
}

variable "enable_secret_reconciliation" {
  description = "Enable scheduled cleanup of orphaned per-instance AC secrets"
  type        = bool
  default     = true
}

variable "ac_green_standby_min_size" {
  description = "Minimum instance count for AC green ASG in standby mode. 1 = warm standby (instant switch), 0 = cold standby (requires scale-up)."
  type        = number
  default     = 1

  validation {
    condition     = var.ac_green_standby_min_size >= 0 && var.ac_green_standby_min_size <= 10
    error_message = "ac_green_standby_min_size must be between 0 and 10."
  }
}

# ==================== Canary Deployment ====================

variable "enable_canary_deployment" {
  description = "Enable Step Functions-based canary deployment for progressive production rollouts."
  type        = bool
  default     = false
}

variable "canary_checkpoint_percentages" {
  description = "Instance refresh checkpoint percentages for canary stages."
  type        = list(number)
  default     = [20, 50, 100]
}

variable "canary_checkpoint_delay_seconds" {
  description = "Seconds to observe at each canary checkpoint before auto-resuming."
  type        = number
  default     = 300
}

variable "canary_instance_warmup_seconds" {
  description = "Instance warmup time in seconds for canary refresh. NLB-disabled canaries also require the ASG capacity-deficit alarm window to stay shorter than canary_checkpoint_delay_seconds."
  type        = number
  default     = 180
}

# ==================== Status Page ====================

variable "deploy_status_page" {
  description = "Deploy the public LayerV status page (Lambda + API Gateway + S3 + CloudFront)"
  type        = bool
  default     = false
}

variable "status_page_domain" {
  description = "Custom domain for the status page (e.g., status.layerv.xyz). If null, CloudFront default domain is used."
  type        = string
  default     = null

  validation {
    condition     = var.status_page_domain == null || can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]$", var.status_page_domain))
    error_message = "status_page_domain must be a valid domain name."
  }
}

variable "status_page_hosted_zone_id" {
  description = "Route53 hosted zone ID for the status page domain. Required when status_page_domain is set."
  type        = string
  default     = null

  validation {
    condition     = var.status_page_hosted_zone_id == null || can(regex("^Z[A-Z0-9]{8,}$", var.status_page_hosted_zone_id))
    error_message = "status_page_hosted_zone_id must be a valid Route53 hosted zone ID (uppercase, starts with Z, at least 9 characters)."
  }
}

variable "status_page_additional_service_urls" {
  description = "Additional public components for the status page (component id => HTTPS health check URL), merged with the built-in qURL API and qURL link checks. Display names for known ids live in the status page frontend."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for url in values(var.status_page_additional_service_urls) : can(regex("^https://", url))])
    error_message = "status_page_additional_service_urls values must be HTTPS URLs."
  }

  validation {
    condition = alltrue([
      for id in keys(var.status_page_additional_service_urls) :
      !contains(["qurl_api", "qurl_link", "nhp_server", "nhp_ac"], id)
    ])
    error_message = "status_page_additional_service_urls cannot use reserved component ids: qurl_api, qurl_link, nhp_server, nhp_ac."
  }
}

variable "status_page_display_only_component_ids" {
  description = "Status page component ids to render and track but exclude from automated component rollup. Use for display-only checks such as the marketing website."
  type        = set(string)
  default     = ["website"]

  validation {
    condition     = alltrue([for id in var.status_page_display_only_component_ids : can(regex("^[a-z0-9_]+$", id))])
    error_message = "status_page_display_only_component_ids values must be lowercase component ids using letters, numbers, and underscores."
  }

  validation {
    condition     = length(setintersection(var.status_page_display_only_component_ids, toset(["nhp_server", "nhp_ac", "qurl_api", "qurl_link"]))) == 0
    error_message = "status_page_display_only_component_ids cannot include core component ids: nhp_server, nhp_ac, qurl_api, qurl_link."
  }
}

# ==================== Status Page NHP Auth ====================

variable "status_page_nhp_auth_enabled" {
  description = "Protect the status page with NHP authentication via QURL (dogfooding). Requires a QURL to be created for the status page URL."
  type        = bool
  default     = false
}

variable "status_page_nhp_auth_qurl_url" {
  description = "QURL link URL for status page login (e.g., https://qurl.link.layerv.xyz/#at_xxx). Required when status_page_nhp_auth_enabled is true. Create via QURL API with target_url set to the status page URL."
  type        = string
  default     = null

  validation {
    condition     = var.status_page_nhp_auth_qurl_url == null || can(regex("^https://", var.status_page_nhp_auth_qurl_url))
    error_message = "status_page_nhp_auth_qurl_url must be a valid HTTPS URL."
  }

  # The URL is templated into the CloudFront Function JavaScript as a single-
  # quoted string literal. Reject characters that would break out of the
  # literal or trigger nested terraform interpolation.
  validation {
    condition = var.status_page_nhp_auth_qurl_url == null || (
      !can(regex("['\\\\\n\r]", var.status_page_nhp_auth_qurl_url)) &&
      !can(regex("\\$\\{", var.status_page_nhp_auth_qurl_url)) &&
      !can(regex("%\\{", var.status_page_nhp_auth_qurl_url))
    )
    error_message = "status_page_nhp_auth_qurl_url must not contain single quotes, backslashes, newlines, or terraform interpolation sequences. These would break the CloudFront Function JavaScript template."
  }

  # Cross-variable check: enforce that a URL is supplied whenever the feature
  # is enabled. The status_page module has its own resource-level
  # precondition, but failing here surfaces the misconfiguration earlier in
  # the plan and at the root variables level where users actually set them.
  validation {
    condition     = !var.status_page_nhp_auth_enabled || (var.status_page_nhp_auth_qurl_url != null && var.status_page_nhp_auth_qurl_url != "")
    error_message = "status_page_nhp_auth_qurl_url is required when status_page_nhp_auth_enabled is true."
  }
}

# ==================== Cost Analytics ====================

variable "deploy_cost_analytics" {
  description = "Deploy AWS cost analytics (Data Export + Athena + Grafana dashboard)"
  type        = bool
  default     = false
}

variable "cross_account_cost_analytics_role_arn" {
  description = "IAM role ARN in mgmt account for cross-account cost analytics"
  type        = string
  default     = null
}

variable "grafana_athena_config" {
  description = "Direct Athena config for cost dashboard when cost_analytics module is not deployed. Allows environments to share a single cost_analytics backend."
  type = object({
    assume_role_arn = string
    workgroup       = string
    database        = string
    region          = optional(string, "us-east-1")
  })
  default = null

  validation {
    condition     = !(var.grafana_athena_config != null && var.deploy_cost_analytics)
    error_message = "grafana_athena_config and deploy_cost_analytics are mutually exclusive. Use deploy_cost_analytics when this environment owns the cost_analytics backend, or grafana_athena_config to point to another environment's backend."
  }
}

# ==================== Developer Portal ====================

variable "deploy_developer_portal" {
  description = "Deploy developer portal infrastructure (playground proxy + credential provisioner)"
  type        = bool
  default     = false
}

variable "developer_portal_m2m_secret_name" {
  description = "Secrets Manager secret name for playground M2M credentials (client_id, client_secret, audience)"
  type        = string
  default     = null
}

variable "developer_portal_auth0_mgmt_secret_name" {
  description = "Secrets Manager secret name for Auth0 management API credentials"
  type        = string
  default     = null
}

variable "developer_portal_auth0_domain" {
  description = "Auth0 domain for developer portal (e.g., auth.layerv.ai)"
  type        = string
  default     = null
}

variable "developer_portal_allowed_origins" {
  description = "CORS allowed origins for developer portal API"
  type        = list(string)
  default     = []
}

variable "developer_portal_custom_domain" {
  description = "Custom domain for developer portal API (e.g., devapi.layerv.xyz). If null, uses default API Gateway URL."
  type        = string
  default     = null
}

variable "developer_portal_hosted_zone_id" {
  description = "Route53 hosted zone ID for developer portal custom domain. Required when developer_portal_custom_domain is set."
  type        = string
  default     = null

  validation {
    condition     = var.developer_portal_hosted_zone_id == null || can(regex("^Z[A-Z0-9]{8,}$", var.developer_portal_hosted_zone_id))
    error_message = "developer_portal_hosted_zone_id must be a valid Route53 hosted zone ID (uppercase, starts with Z, at least 9 characters)."
  }
}

variable "developer_portal_ci_bypass_secret_name" {
  description = "Secrets Manager secret name for CI bypass key. If set, Lambda functions skip rate limiting when X-CI-Key header matches."
  type        = string
  default     = null
}

variable "developer_portal_connector_base_url" {
  description = "Base URL of the qURL S3 connector that the developer-portal Lambda's /playground/upload route forwards multipart bodies + mint_link calls to. Must be https:// with a non-empty host, no trailing slash. Set explicitly per environment so sandbox can't silently coalesce onto the prod connector."
  type        = string

  validation {
    condition     = can(regex("^https://[^/]+", var.developer_portal_connector_base_url))
    error_message = "developer_portal_connector_base_url must use https:// with a non-empty host."
  }

  validation {
    condition     = !endswith(var.developer_portal_connector_base_url, "/")
    error_message = "developer_portal_connector_base_url must not end with '/'."
  }
}

variable "developer_portal_demo_target_url" {
  description = "Exact protected-resource URL the /qurl LiveDemo publishes (e.g. https://hidden-app.layerv.ai). When set with the other developer_portal_demo_* variables, playground creates for exactly this URL mint links for the pre-provisioned demo resource instead of creating a URL resource. Coupled contract: must match the website LiveDemo's published constant byte-for-byte. Empty disables the demo mint path."
  type        = string
  default     = ""

  validation {
    condition     = var.developer_portal_demo_target_url == "" || can(regex("^https://[a-z0-9.-]+(:[0-9]+)?$", var.developer_portal_demo_target_url))
    error_message = "developer_portal_demo_target_url must be https:// with a bare host (no path) — the Lambda matches it by exact string equality."
  }
}

variable "developer_portal_demo_resource_id" {
  description = "qurl-service resource id of the pre-provisioned resource serving the LiveDemo hidden page. Must be owned by the account the playground M2M credentials authenticate as."
  type        = string
  default     = ""

  validation {
    condition     = var.developer_portal_demo_resource_id == "" || can(regex("^[a-zA-Z0-9_-]{1,64}$", var.developer_portal_demo_resource_id))
    error_message = "developer_portal_demo_resource_id must match the Lambda's QURL id pattern (^[a-zA-Z0-9_-]{1,64}$)."
  }
}

variable "developer_portal_demo_qurl_site" {
  description = "qurl_site URL returned verbatim to the LiveDemo for the demo resource (e.g. https://r_abc.qurl.site)."
  type        = string
  default     = ""

  validation {
    condition     = var.developer_portal_demo_qurl_site == "" || can(regex("^https://[A-Za-z0-9._-]+(:[0-9]+)?$", var.developer_portal_demo_qurl_site))
    error_message = "developer_portal_demo_qurl_site must be https:// with a bare host (no path) — it is returned verbatim to the demo client."
  }
}

# ==================== Shared Dashboard CORS ====================

variable "dashboard_allowed_origins" {
  description = "Default CORS origins shared by all dashboard APIs (developer portal, billing). Individual module vars override this when set."
  type        = list(string)
  default     = []
}

# ==================== Billing ====================

variable "deploy_billing" {
  description = "Deploy billing infrastructure (Stripe integration, usage reporting, payment grace)"
  type        = bool
  default     = false
}

variable "billing_stripe_secret_name" {
  description = "Secrets Manager secret name for Stripe API key"
  type        = string
  default     = null
}

variable "billing_stripe_webhook_secret_name" {
  description = "Secrets Manager secret name for Stripe webhook signing secret"
  type        = string
  default     = null
}

variable "billing_stripe_api_base_url" {
  description = "Base URL for Stripe API. Override for testing."
  type        = string
  default     = "https://api.stripe.com"
}

variable "billing_growth_price_id" {
  description = "Stripe Price ID for the Growth plan metered usage component"
  type        = string
  default     = ""
}

variable "billing_base_fee_price_id" {
  description = "Stripe Price ID for the Growth plan base fee (flat monthly)"
  type        = string
  default     = ""
}

variable "billing_success_url" {
  description = "URL to redirect to after successful Stripe Checkout"
  type        = string
  default     = null
}

variable "billing_cancel_url" {
  description = "URL to redirect to when user cancels Stripe Checkout"
  type        = string
  default     = null
}

variable "billing_allowed_origins" {
  description = "List of allowed CORS origins for billing API"
  type        = list(string)
  default     = []
}

variable "billing_from_email" {
  description = "SES verified sender email for grace period notifications"
  type        = string
  default     = null
}

variable "billing_ses_region" {
  description = "AWS region for SES (may differ from deployment region)"
  type        = string
  default     = "us-east-1"
}

variable "billing_grace_period_days" {
  description = "Days after payment failure before account is frozen"
  type        = number
  default     = 7
}

variable "billing_downgrade_after_days" {
  description = "Days after account freeze before downgrade to free tier"
  type        = number
  default     = 30
}

variable "billing_api_throttle_burst_limit" {
  description = "API Gateway default throttle burst limit for billing API"
  type        = number
  default     = 50
}

variable "billing_api_throttle_rate_limit" {
  description = "API Gateway default throttle rate limit for billing API"
  type        = number
  default     = 25
}

# ==================== Auth0 Custom Domain ====================

variable "auth0_custom_domain" {
  description = "Auth0 custom domain for SPA login (e.g., auth.layerv.ai)"
  type        = string
  default     = ""
}

# ==================== E2E Testing ====================

variable "deploy_e2e_echo_server" {
  description = "Deploy E2E echo server Lambda for QURL integration tests"
  type        = bool
  default     = false
}

# ==================== QURL FRP Server ====================

variable "deploy_frps" {
  description = "Deploy the QURL FRP tunnel server for proxying traffic to customer backends. Requires `deploy_ac = true`, `deploy_qurl_service = true`, `qurl_internal_service_token_arn` set, and `qurl_service_domain` set — all four are enforced by `terraform_data.frps_preconditions` at plan time so that FRPS never boots with tunnel auth disabled."
  type        = bool
  default     = false
}

variable "qurl_reverse_tunnel_server_tunnel_auth_mode" {
  description = <<-EOT
    Selects which qurl-reverse-tunnel-server auth mode the deployed FRP server runs in.

      ""             - Module-compat placeholder for envs that have not
                       deployed qurl-reverse-tunnel-server. Current
                       qurl-reverse-tunnel-server images no longer accept
                       unset mode; any env with deploy_frps=true must set
                       "tunnel-auth".

      "tunnel-auth"  - Knock-token-as-identity mode. qurl-reverse-tunnel-server validates
                       the AC-issued knock token with nhp-server, stores the
                       server-resolved owner_id for the FRP run_id, authorizes
                       each NewProxy through qurl-service
                       POST /internal/v1/tunnel/auth-by-owner, and publishes
                       active target rows to qurl-service for router-side
                       active-set dispatch.

    Hard cross-repo prerequisites before flipping a non-sandbox env to
    "tunnel-auth":
      * qurl-reverse-tunnel-server image includes knock-token validation,
        /auth-by-owner authorization, and active registration reporting.
      * qurl-reverse-tunnel-client sends the AC-issued knock token in FRP
        Login metadata.
      * qurl-service tunnel auth is enabled and the active-registration
        write endpoints are deployed. Do not flip qurl-service's active-read
        flag until reporter health is verified.

    See `terraform/modules/qurl-reverse-tunnel-server/variables.tf::qurl_tunnel_auth_mode`
    for the env-shape this drives in user_data.
  EOT
  type        = string
  default     = ""

  validation {
    condition     = var.qurl_reverse_tunnel_server_tunnel_auth_mode == "" || var.qurl_reverse_tunnel_server_tunnel_auth_mode == "tunnel-auth"
    error_message = "qurl_reverse_tunnel_server_tunnel_auth_mode must be \"\" (module-compat placeholder) or \"tunnel-auth\". Other values are rejected at startup by qurl-reverse-tunnel-server; reject here to surface the typo at plan time."
  }
}

variable "qurl_reverse_tunnel_server_min_client_version" {
  description = "Initial qurl-connector minimum version for qurl-reverse-tunnel-server. Empty seeds the runtime SSM parameter as disabled. Values may include the v prefix because qurl-reverse-tunnel-server normalizes it before comparison. After first apply this tfvar is write-once because the SSM value is ignored by Terraform; operators update /<env>/nhp/reverse-tunnel-server/min-client-version directly."
  type        = string
  default     = ""

  validation {
    condition     = var.qurl_reverse_tunnel_server_min_client_version == "" || can(regex("^v?[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?$", var.qurl_reverse_tunnel_server_min_client_version))
    error_message = "qurl_reverse_tunnel_server_min_client_version must be empty or a semantic version like 1.2.3, v1.2.3, or 1.2.3-beta.1; build metadata is not supported by qurl-reverse-tunnel-server."
  }
}

variable "frps_instance_type" {
  description = "EC2 instance type for FRP server"
  type        = string
  default     = "t3.small"
}

variable "frps_image_tag" {
  description = "qurl-reverse-tunnel-server binary version tag. Separate from NHP image_tag since frps has its own release cadence. Defaults to a placeholder tag that CI must overwrite on first deploy — a Terraform-only operator can't accidentally install a moving `latest` that slipped between applies."
  type        = string
  default     = "v0.0.0-bootstrap"
}

variable "frps_bind_port" {
  description = "FRP server control port. Shared between qurl-reverse-tunnel-server module (bind port) and AC module (Traefik route target) so they can't drift."
  type        = number
  default     = 7000
}

variable "connect_layerv_host" {
  # `$${var.…}` escapes prevent Terraform from parsing the doc-string
  # template references as live interpolations — `description` is
  # rendered through HCL's template engine even for descriptive prose,
  # which `${var.frps_bind_port}` would otherwise hit as a context-
  # less variable lookup at `terraform init`. The literal output is
  # `${var.frps_bind_port}` in the rendered description.
  description = <<-EOT
    Customer-facing public DNS name that fronts the FRPS control
    channel. Written into the DDB seed row's `resource_fqdn` field
    (`terraform/resources.tf::aws_dynamodb_table_item.tunnel_server_nhp_resource`);
    the bridge materializes that as `ResourceInfo.Hostname` and the
    agent dials this name instead of the internal Cloud Map host.
    Pre-2026-05-18 the agent dialed
    `frps-{az}.nhp.{env}.internal:$${var.frps_bind_port}` directly — an
    internal-only name no public client could resolve, and the
    FRPS-specific knock had zero L3/L4 effect because the ipset entry
    it rendered was keyed on an internal dst_ip no AC kernel packet
    ever had. Post-redesign the agent dials this public name;
    NLB:$${var.frps_bind_port} → AC kernel → ipset-gated → Traefik TCP
    entrypoint → internal `frps-{az}:$${var.frps_bind_port}`. Set per
    env in tfvars: `connect.layerv.xyz` (sandbox), `connect.layerv.ai`
    (prod). Bare DNS name only (no scheme, port, slashes, whitespace,
    or userinfo) — same shape contract as `var.domain_name`. Per-label
    RFC 1035 validation lives in the per-variable `validation {}`
    blocks below; the `check "tunnel_server_dest_host_shape"` block in
    `terraform/resources.tf` carries the matching defense-in-depth
    fence on the INTERNAL `dest_host` (sourced from upstream-fenced
    inputs).
    Empty value opts out of the FRPS-behind-AC topology — only valid
    for envs without `deploy_frps = true`.
    EOT
  type        = string
  default     = ""

  # Per-label RFC 1035 form: each label starts with a lowercase
  # letter/digit, may contain hyphens, ends with a letter/digit,
  # ≤63 chars per label; multiple dot-separated labels. Tighter
  # than the prior `^[a-z][a-z0-9.-]{0,253}$` which allowed
  # trailing dots, `..`, and per-label `--` overflow. Quote-injection
  # is the load-bearing concern (regex excludes `"` and `\`); the
  # tightening here is defense-in-depth for downstream consumers
  # (Route 53 A-record name, NLB listener routing) that already
  # reject syntactically-broken FQDNs but with cryptic errors at
  # apply time rather than plan time.
  validation {
    condition     = var.connect_layerv_host == "" || can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$", var.connect_layerv_host))
    error_message = "connect_layerv_host must be a bare lowercase DNS name in per-label RFC 1035 form (each label 1-63 chars, alphanumeric with hyphens but not leading/trailing, multiple labels dot-separated; no scheme, port, slashes, whitespace, or userinfo), or empty to opt out of FRPS-behind-AC. Today's values `connect.layerv.{ai,xyz}` conform."
  }

  # Input-shape fence on today's TRANSITIONAL value of this variable.
  # `connect_layerv_host` currently holds the customer-facing public
  # DNS name fronting the AC NLB (because the AC is in the FRPS data
  # plane today — see TRANSITIONAL banner on
  # `aws_vpc_security_group_ingress_rule.ac_frps_control` in
  # `modules/ac/main.tf`). The two checks below reject obvious
  # mis-pointings of the variable to internal/FRPS-shaped names
  # while it serves this role.
  #
  # Both checks are short-lived: when nhp #2019 ("AC out of the FRPS
  # data path") lands and the customer-facing dial target moves off
  # the AC, this variable + every count-gated piece of plumbing it
  # drives is removal work — these validations go with it. Do NOT
  # promote these to a structural invariant about where Hostname
  # "must" point; the L3-only target may use a `frps.*` name, which
  # is correct end-state and would fail the `frps-` prefix check
  # below if kept past the migration.
  # TODO(nhp #2019 — "AC out of the FRPS data path"): both
  # validations below are TRANSITIONAL. When the AC exits the FRPS
  # data plane and Hostname legitimately points at FRPS directly,
  # the `.internal` and `frps-` shape fences become wrong for the
  # end-state. Rip them out in the same PR that lands the L3-only
  # target. See the in-comment doc fence above.
  validation {
    condition     = var.connect_layerv_host == "" || !endswith(var.connect_layerv_host, ".internal")
    error_message = "connect_layerv_host must NOT end in `.internal` — the FRPS-behind-AC redesign (SLACK_QURL_ROLLOUT.md §6) intentionally splits the customer-facing dial target from the internal FRPS Cloud Map host. Use the public AC ingress name (e.g. `connect.layerv.{ai,xyz}`); the AC Traefik TCP entrypoint forwards to the internal `frps-{az}` host via `var.frp_control_upstream_host` separately."
  }
  validation {
    condition     = var.connect_layerv_host == "" || !startswith(var.connect_layerv_host, "frps-")
    error_message = "connect_layerv_host must NOT start with `frps-` — looks like an FRPS Cloud Map name. Use the customer-facing AC ingress name (e.g. `connect.layerv.{ai,xyz}`), distinct from the FRPS host the AC Traefik TCP entrypoint forwards to internally. See SLACK_QURL_ROLLOUT.md §6 (FRPS-behind-AC redesign)."
  }
}

variable "frps_vhost_http_port" {
  description = "FRP vhost HTTP port. Shared between qurl-reverse-tunnel-server module (bind port) and AC module (qurl-router plugin target) so they can't drift."
  type        = number
  default     = 8080
}

# Per-AZ Cloud Map fanout (#1499) decouples tunnel routing from MULTIVALUE
# DNS by putting each ASG instance on its own AZ-keyed service. Sandbox
# and prod both override sizing to length(frps_az_suffixes) (default 3)
# so the steady-state distribution is one instance per AZ. Module defaults
# stay at 1 to keep the module consumable in isolation.

variable "frps_min_size" {
  description = "ASG minimum size for qurl-reverse-tunnel-server. Default 1; production envs set this to length(frps_az_suffixes) for one-instance-per-AZ via the per-AZ Cloud Map fanout."
  type        = number
  default     = 1

  validation {
    # Mirror the module-level validation at the root: a typo like
    # `frps_min_size = 0` while `deploy_frps = false` would otherwise sit
    # unchallenged until the next time frps is deployed. `floor(...) == ...`
    # rejects non-integers (`type = number` on its own accepts 1.5, which
    # would only fail at AWS-API time).
    condition     = var.frps_min_size >= 1 && floor(var.frps_min_size) == var.frps_min_size
    error_message = "frps_min_size must be an integer >= 1 — qurl-reverse-tunnel-server is the only path for tunnel traffic; N=0 means tunnel resources 502."
  }
}

variable "frps_max_size" {
  description = "ASG maximum size for qurl-reverse-tunnel-server. Default 1; production envs match min_size and length(frps_az_suffixes)."
  type        = number
  default     = 1

  validation {
    condition     = var.frps_max_size >= 1 && floor(var.frps_max_size) == var.frps_max_size
    error_message = "frps_max_size must be an integer >= 1 — see frps_min_size."
  }
}

variable "frps_desired_capacity" {
  description = "ASG desired capacity for qurl-reverse-tunnel-server. Default 1; production envs set this to length(frps_az_suffixes) for one-instance-per-AZ steady state."
  type        = number
  default     = 1

  validation {
    condition     = var.frps_desired_capacity >= 1 && floor(var.frps_desired_capacity) == var.frps_desired_capacity
    error_message = "frps_desired_capacity must be an integer >= 1 — see frps_min_size."
  }
}

# FRPS ASG launch-readiness gate (qurl-reverse-tunnel-server#195). Root
# passthroughs for the module knobs so an env can flip CONTINUE->ABANDON and
# tune the timeout from tfvars without a code change. Defaults match the module
# defaults exactly, so leaving them unset is a no-op. See the module's
# variables.tf for the full rationale and the CONTINUE-first rollout phasing.
variable "frps_launch_readiness_default_result" {
  description = "FRPS launch-readiness hook default_result: \"CONTINUE\" (safe default) or \"ABANDON\" (post-sandbox-validation target). Passed to module.qurl_reverse_tunnel_server."
  type        = string
  default     = "CONTINUE"

  validation {
    condition     = contains(["CONTINUE", "ABANDON"], var.frps_launch_readiness_default_result)
    error_message = "frps_launch_readiness_default_result must be \"CONTINUE\" or \"ABANDON\"."
  }
}

variable "frps_launch_readiness_heartbeat_timeout" {
  description = "FRPS launch-readiness hook heartbeat_timeout (seconds); the validator sets this from measured cold-boot. Passed to module.qurl_reverse_tunnel_server."
  type        = number
  default     = 600

  validation {
    condition     = var.frps_launch_readiness_heartbeat_timeout >= 60 && var.frps_launch_readiness_heartbeat_timeout <= 7200
    error_message = "frps_launch_readiness_heartbeat_timeout must be 60-7200 seconds."
  }
}

# Per-AZ sizing form. Default null preserves the legacy explicit triple
# (frps_min_size / frps_max_size / frps_desired_capacity) as the source
# of truth so existing tfvars keep working unchanged. When set, the
# module computes effective sizes as `per_az * length(frps_az_suffixes)`
# and the legacy vars are ignored — see
# `terraform/modules/qurl-reverse-tunnel-server/variables.tf` for the resolution rule.
#
# PR 4 will set `qurl_reverse_tunnel_server_desired_capacity_per_az = 2` in prod tfvars
# to flip steady-state from 1/AZ to 2/AZ once router-side HRW is on.

variable "qurl_reverse_tunnel_server_desired_capacity_per_az" {
  description = <<-EOT
    Per-AZ ASG desired capacity for qurl-reverse-tunnel-server. When set
    (non-null), the module computes effective `desired_capacity` as
    `qurl_reverse_tunnel_server_desired_capacity_per_az * length(frps_az_suffixes)` and the
    legacy `frps_desired_capacity` variable is ignored.

    Default null keeps the legacy triple as the source of truth — same
    effective sizing as before this PR for any existing caller.
  EOT
  type        = number
  default     = null

  validation {
    condition     = var.qurl_reverse_tunnel_server_desired_capacity_per_az == null || (var.qurl_reverse_tunnel_server_desired_capacity_per_az >= 1 && floor(var.qurl_reverse_tunnel_server_desired_capacity_per_az) == var.qurl_reverse_tunnel_server_desired_capacity_per_az)
    error_message = "qurl_reverse_tunnel_server_desired_capacity_per_az must be null or an integer >= 1 — qurl-reverse-tunnel-server must have at least one instance per AZ."
  }
}

variable "qurl_reverse_tunnel_server_min_size_per_az" {
  description = "Per-AZ ASG min size for qurl-reverse-tunnel-server. See qurl_reverse_tunnel_server_desired_capacity_per_az for the resolution rule. Default null keeps the legacy frps_min_size as the source of truth."
  type        = number
  default     = null

  validation {
    condition     = var.qurl_reverse_tunnel_server_min_size_per_az == null || (var.qurl_reverse_tunnel_server_min_size_per_az >= 1 && floor(var.qurl_reverse_tunnel_server_min_size_per_az) == var.qurl_reverse_tunnel_server_min_size_per_az)
    error_message = "qurl_reverse_tunnel_server_min_size_per_az must be null or an integer >= 1 — see qurl_reverse_tunnel_server_desired_capacity_per_az."
  }
}

variable "qurl_reverse_tunnel_server_max_size_per_az" {
  description = "Per-AZ ASG max size for qurl-reverse-tunnel-server. See qurl_reverse_tunnel_server_desired_capacity_per_az for the resolution rule. Default null keeps the legacy frps_max_size as the source of truth."
  type        = number
  default     = null

  validation {
    condition     = var.qurl_reverse_tunnel_server_max_size_per_az == null || (var.qurl_reverse_tunnel_server_max_size_per_az >= 1 && floor(var.qurl_reverse_tunnel_server_max_size_per_az) == var.qurl_reverse_tunnel_server_max_size_per_az)
    error_message = "qurl_reverse_tunnel_server_max_size_per_az must be null or an integer >= 1 — see qurl_reverse_tunnel_server_desired_capacity_per_az."
  }
}

variable "qurl_reverse_tunnel_server_cloud_map_routing_policy" {
  description = <<-EOT
    DNS routing policy for the qurl-reverse-tunnel-server per-AZ Cloud Map services. One of:

      "WEIGHTED"   - (default, backwards compatible) one A record per
                     query. Correct for 1-instance-per-AZ.
      "MULTIVALUE" - full healthy A-record set per query (up to 8).
                     Required when running >1 instance per AZ so router-
                     side HRW (traefik-plugins #134) can hash a resource
                     to a specific instance.

    PR 4 flips this to MULTIVALUE in prod tfvars alongside
    `qurl_reverse_tunnel_server_desired_capacity_per_az = 2`. Sandbox flips earlier as
    part of validation. A precondition in the qurl-reverse-tunnel-server module rejects
    `WEIGHTED + effective_desired > length(frps_az_suffixes)`.

    Replacement semantics: AWS Cloud Map does NOT support in-place
    `routing_policy` updates — the provider marks the field ForceNew.
    The PR 4 flip will produce a REPLACEMENT plan for every per-AZ
    service (and every green service when blue/green is enabled).
    See `terraform/modules/qurl-reverse-tunnel-server/variables.tf`
    for the full sequencing implications.
  EOT
  type        = string
  default     = "WEIGHTED"

  validation {
    condition     = contains(["WEIGHTED", "MULTIVALUE"], var.qurl_reverse_tunnel_server_cloud_map_routing_policy)
    error_message = "qurl_reverse_tunnel_server_cloud_map_routing_policy must be \"WEIGHTED\" or \"MULTIVALUE\"."
  }
}

variable "enable_qurl_reverse_tunnel_server_blue_green" {
  description = <<-EOT
    Enable blue/green deployment for qurl-reverse-tunnel-server. Sandbox-targeted by the
    PR 3 → PR 4 rollout; mirrors `modules/ac/blue_green.tf` adapted for
    Cloud Map routing (no NLB on qurl-reverse-tunnel-server).

    Default false keeps the module a no-op for existing deploys. Mutually
    exclusive with `enable_qurl_reverse_tunnel_server_canary` — a precondition in
    `terraform/main.tf` rejects both true.
  EOT
  type        = bool
  default     = false
}

variable "qurl_reverse_tunnel_server_green_standby_capacity_per_az" {
  description = <<-EOT
    Per-AZ desired capacity for the qurl-reverse-tunnel-server green ASG when in standby.

    Default `null` resolves to "track `min_size_per_az` when set, else
    1" inside the module — so PR 4's `min_size_per_az = 2` flip
    automatically gives `effective_standby = 2` without the operator
    having to keep two knobs in lockstep across files. Set explicitly
    to a non-null value for cold standby (`0`) or other custom shapes.

    Effective green ASG `desired_capacity` is
    `effective_standby_per_az * length(frps_az_suffixes)`.
    Ignored when `enable_qurl_reverse_tunnel_server_blue_green = false`.
  EOT
  type        = number
  default     = null

  validation {
    condition     = var.qurl_reverse_tunnel_server_green_standby_capacity_per_az == null || (var.qurl_reverse_tunnel_server_green_standby_capacity_per_az >= 0 && var.qurl_reverse_tunnel_server_green_standby_capacity_per_az <= 10 && floor(var.qurl_reverse_tunnel_server_green_standby_capacity_per_az) == var.qurl_reverse_tunnel_server_green_standby_capacity_per_az)
    error_message = "qurl_reverse_tunnel_server_green_standby_capacity_per_az must be null (auto-track) or an integer between 0 and 10."
  }
}

variable "enable_qurl_reverse_tunnel_server_canary" {
  description = <<-EOT
    Enable canary deployment for qurl-reverse-tunnel-server via the canary-deployment
    module (instantiated as `module.canary_deployment_qurl_reverse_tunnel_server`).
    Prod-targeted by the PR 3 → PR 4 rollout.

    The canary-deployment module's NLB-keyed alarms are auto-disabled
    for the qurl-reverse-tunnel-server path via `disable_nlb_health_checks = true`
    (qurl-reverse-tunnel-server has no NLB; the orchestrator falls back to ASG-instance
    health). The Cloud Map empty-AZ alarm (#1542) covers the routing-
    layer fault class instead.

    Default false keeps the module a no-op for existing deploys.
    Mutually exclusive with `enable_qurl_reverse_tunnel_server_blue_green` — a
    precondition rejects both true.
  EOT
  type        = bool
  default     = false
}

# Per-AZ Cloud Map services for the qurl-reverse-tunnel-server. Threaded
# into BOTH the qurl-reverse-tunnel-server module (which creates the Cloud Map services)
# and the qurl-service module (whose `QURL_FRPS_AZ_SUFFIXES` env var
# drives the OwnerID-to-AZ hash) from the same source of truth so they
# can't drift.
# See `terraform/modules/qurl-reverse-tunnel-server/main.tf` header for the full cross-repo
# contract — the parallel qurl-service and frpc PRs consume this same set
# of suffixes via their own config surfaces.
variable "frps_az_suffixes" {
  description = "AZ suffix letters that qurl-reverse-tunnel-server creates per-AZ Cloud Map services for, and that qurl-service hashes OwnerID into. Default `[\"a\", \"b\", \"c\"]` matches us-east-{1,2}{a,b,c}. Each entry must be a single lowercase letter."
  type        = list(string)
  default     = ["a", "b", "c"]

  # NOTE: validation logic duplicated from
  # `terraform/modules/qurl-reverse-tunnel-server/variables.tf` (module-level
  # `frps_az_suffixes`). The root copy fences a typo at plan time even when
  # `deploy_frps = false` keeps the module out of the graph; the module
  # copy covers module-direct consumers. Keep both in lockstep with each
  # other and with cloudmap-common.sh's supported service-name regex.
  validation {
    condition     = length(var.frps_az_suffixes) > 0 && alltrue([for s in var.frps_az_suffixes : can(regex("^[a-z]$", s))])
    error_message = "frps_az_suffixes must be a non-empty list of single lowercase letters (e.g., [\"a\", \"b\", \"c\"]) — each entry is the trailing letter of an AWS AZ name."
  }

  validation {
    condition     = length(toset(var.frps_az_suffixes)) == length(var.frps_az_suffixes)
    error_message = "frps_az_suffixes must not contain duplicates (each suffix maps to a distinct Cloud Map service)."
  }
}

# ==================== QURL Integrations DNS ====================
# Cross-account A records for qurl-integrations-infra prod EC2
# instances. Rationale + source-of-truth note in main.tf under
# "QURL Integrations DNS".

variable "deploy_qurl_integrations_dns" {
  description = "Create the cross-account A records for the qurl-integrations-infra prod EC2 instances. When true, requires qurl_hosted_zone_id + all four qurl_{s3_connector,fileviewer}_{domain,eip} inputs (enforced by terraform_data.qurl_integrations_dns_preconditions). Flipping to false after records exist would destroy them — but both records carry lifecycle.prevent_destroy = true, so retiring them requires an explicit terraform state rm in coordination with qurl-integrations-infra."
  type        = bool
  default     = false
}

variable "qurl_s3_connector_domain" {
  description = "FQDN for the qurl-s3-connector upload endpoint (e.g., getqurllink.layerv.ai). Must live under the zone referenced by qurl_hosted_zone_id. Required when deploy_qurl_integrations_dns = true."
  type        = string
  default     = null

  validation {
    condition     = var.qurl_s3_connector_domain == null || can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]\\.[a-z]{2,}$", var.qurl_s3_connector_domain))
    error_message = "qurl_s3_connector_domain must be a valid FQDN (e.g., getqurllink.layerv.ai)."
  }
}

variable "qurl_s3_connector_eip" {
  description = "IPv4 EIP attached to the qurl-s3-connector EC2 instance. Read from qurl-integrations-infra's `instance_public_ip` output or `aws ec2 describe-addresses` in the integrations-prod account — both are authoritative for the same live AWS state. Required when deploy_qurl_integrations_dns = true."
  type        = string
  default     = null

  validation {
    # cidrnetmask rejects octets >255 (a regex-only IPv4 check accepts 999.999.999.999)
    condition     = var.qurl_s3_connector_eip == null || can(cidrnetmask("${var.qurl_s3_connector_eip}/32"))
    error_message = "qurl_s3_connector_eip must be a valid IPv4 address or null."
  }
}

variable "qurl_fileviewer_domain" {
  description = "FQDN for the fileviewer endpoint (e.g., fileviewer.layerv.ai). Must live under the zone referenced by qurl_hosted_zone_id. Required when deploy_qurl_integrations_dns = true."
  type        = string
  default     = null

  validation {
    condition     = var.qurl_fileviewer_domain == null || can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]\\.[a-z]{2,}$", var.qurl_fileviewer_domain))
    error_message = "qurl_fileviewer_domain must be a valid FQDN (e.g., fileviewer.layerv.ai)."
  }
}

variable "qurl_fileviewer_eip" {
  description = "IPv4 EIP attached to the fileviewer EC2 instance. Read from qurl-integrations-infra's `viewer_public_ip` output or `aws ec2 describe-addresses` in the integrations-prod account — both are authoritative for the same live AWS state. Required when deploy_qurl_integrations_dns = true."
  type        = string
  default     = null

  validation {
    condition     = var.qurl_fileviewer_eip == null || can(cidrnetmask("${var.qurl_fileviewer_eip}/32"))
    error_message = "qurl_fileviewer_eip must be a valid IPv4 address or null."
  }
}

# `ecr_replication_check_lookback_hours` — see comment block above
# `variable` declaration for tuning guidance / cost & timeout coupling
# notes. Kept inline so the durable rationale lives next to the variable
# but the `description` field stays one line for terraform-docs / LSP
# hover / console UI render quality.
#
# **Tuning summary**
# - Default 25 sized for daily deploys with a 1h cushion. Raise if
#   deploy cadence drops below daily — see runbook "Adjusting the
#   look-back window".
# - This is the durable control surface; the Lambda's `LOOKBACK_HOURS`
#   env entry is set from this value, so a console edit reverts on the
#   next apply.
# - **Cost scaling:** the dominant per-tick cost is `describe_images`
#   paginating across the *tagged-retention* window (90d), NOT
#   `LOOKBACK_HOURS`. The look-back is a client-side filter applied
#   AFTER pagination, since ECR has no server-side `imagePushedAt`
#   filter. A future bump of tagged-retention (e.g. to 180d) silently
#   2× the per-tick API count without touching this variable; see
#   `terraform/modules/ecr/main.tf::COST-CHECK` for the upstream
#   knob.
# - **Timeout coupling:** at >200h the per-tick API count under
#   sustained throttling can blow the 120s Lambda timeout. Bumping
#   look-back past ~200h should pair with bumping the Lambda's
#   `timeout` past 120s AND the not-invoking alarm's
#   `evaluation_periods` past 3 so long-running ticks don't page.
variable "ecr_replication_check_lookback_hours" {
  description = "Hours of recent pushes the ECR replication-failure probe inspects per invocation. See comment above for tuning + cost coupling."
  type        = number
  default     = 25

  # Lockstep with the Lambda's runtime range fence at
  # `terraform/lambda/ecr_replication_check.py::LOOKBACK_HOURS_{MIN,MAX}`.
  # TF's `validation` block can't reference cross-module values, so the
  # range bounds are duplicated by necessity; both sites must move
  # together, and the Lambda-side test
  # `test_out_of_range_lookback_hours_raises_runtime_error` asserts
  # against the Python constants so a TF-only bump that forgets to
  # update Python surfaces in CI.
  validation {
    condition     = var.ecr_replication_check_lookback_hours >= 1 && var.ecr_replication_check_lookback_hours <= 720
    error_message = "ecr_replication_check_lookback_hours must be between 1 and 720. Effective runtime cap is `< module.ecr.untagged_expiry_hours` (currently 168h), enforced by a precondition on the Lambda. Lockstep with `terraform/lambda/ecr_replication_check.py::LOOKBACK_HOURS_{MIN,MAX}` — bumping this range needs a coordinated change there. See docs/runbooks/ecr-replication-failure.md."
  }
}

# ==================== Common Tags ====================

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}

# ==================== Bootstrap ALB ====================

variable "deploy_bootstrap_alb" {
  description = "Deploy the bootstrap-alb stack (bootstrap.layerv.{xyz,ai}). Default off; flip per-env once the cert is wired (Path 1 / prod: operator pre-provisions cross-account; Path 2 / sandbox: module provisions same-account — see modules/bootstrap-alb/README.md) and qurl-service ECS is ready to register against the new target group."
  type        = bool
  default     = false
}

variable "bootstrap_alb_dns_name" {
  description = "Public DNS name for the bootstrap ALB. Sandbox: `bootstrap.layerv.xyz`. Prod: `bootstrap.layerv.ai`. Only read when `deploy_bootstrap_alb = true`."
  type        = string
  default     = ""

  validation {
    # Mirror the module-side `dns_name` validation so a typo at the
    # root tfvars layer fails plan with a root-pointed error rather
    # than via the module's validation (which produces a less-friendly
    # `module.bootstrap_alb[0].variable.<name>` file pointer). Empty
    # string is allowed because `deploy_bootstrap_alb=false` (the
    # default) doesn't read this variable.
    condition     = var.bootstrap_alb_dns_name == "" || can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", var.bootstrap_alb_dns_name))
    error_message = "bootstrap_alb_dns_name must be empty (when `deploy_bootstrap_alb=false`) or a valid lowercase FQDN like `bootstrap.layerv.xyz`."
  }
}

variable "bootstrap_alb_route53_zone_id" {
  description = "Hosted zone ID for the parent of `bootstrap_alb_dns_name`. Required when `bootstrap_alb_provision_certificate` or `bootstrap_alb_manage_dns_alias` is true. Empty when both are false — typical when the parent zone is cross-account: the cert is operator-pre-provisioned out-of-band and the A-alias is written cross-account by `aws_route53_record.bootstrap_alb_cross_account` (not by this module, so this zone-id stays empty)."
  type        = string
  default     = ""

  validation {
    # Mirror the module-side check. Route53 zone IDs are uppercase
    # alphanumeric starting with `Z`, ≥ 9 chars total.
    condition     = var.bootstrap_alb_route53_zone_id == "" || can(regex("^Z[A-Z0-9]{8,}$", var.bootstrap_alb_route53_zone_id))
    error_message = "bootstrap_alb_route53_zone_id must be empty or a valid Route53 zone ID (uppercase, starts with Z)."
  }
}

variable "bootstrap_alb_manage_dns_alias" {
  description = "Whether the bootstrap-alb *module* writes the A-alias from `bootstrap_alb_dns_name` to the ALB. True when the parent zone is in the same account as the ALB; false when cross-account — in the cross-account case the alias is written by `aws_route53_record.bootstrap_alb_cross_account` in `terraform/main.tf` (via the `aws.route53_mgmt` provider), NOT operator-managed. Sandbox: true (`layerv.xyz` zone in 767397897469, same account; module-managed). Prod: false (`layerv.ai` zone in `layerv-mgmt`; root cross-account record manages it)."
  type        = bool
  default     = false
}

variable "bootstrap_alb_provision_certificate" {
  description = "Whether the bootstrap-alb stack provisions+validates an ACM cert. True only when the parent zone is in the same account as the ALB (DNS validation needs to write CNAMEs there). Sandbox: true (same-account `layerv.xyz`). Prod: false (cross-account `layerv.ai`; operator pre-provisions the cert and supplies the ARN via `bootstrap_alb_existing_certificate_arn`)."
  type        = bool
  default     = false
}

variable "bootstrap_alb_existing_certificate_arn" {
  description = "ACM cert ARN to attach when `bootstrap_alb_provision_certificate=false`. Empty during the first-apply bootstrap window; populated after the operator pre-provisions the cert in this account."
  type        = string
  default     = ""

  validation {
    # Mirror the module-side syntactic check (7 partitions; canonical
    # 8-4-4-4-12 UUID after `certificate/`). The module's
    # listener-side `lifecycle.precondition` is the load-bearing
    # apply-target match (partition + region + account); this is
    # the syntactic shape gate at the root tfvars layer.
    condition     = var.bootstrap_alb_existing_certificate_arn == "" || can(regex("^arn:(aws|aws-us-gov|aws-cn|aws-iso|aws-iso-b|aws-iso-c|aws-iso-e|aws-iso-f):acm:[a-z0-9-]+:[0-9]{12}:certificate/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", var.bootstrap_alb_existing_certificate_arn))
    error_message = "bootstrap_alb_existing_certificate_arn must be empty or a valid ACM ARN: `arn:<partition>:acm:<region>:<12-digit-account>:certificate/<canonical 8-4-4-4-12 UUID>`."
  }
}

variable "bootstrap_alb_waf_count_only_rule_groups" {
  description = "Managed rule-group names from the bootstrap-alb WAF to override to `count` action (vs the default `none` action which honors the group's own block/count actions). Use to bring a new managed group up in count-only mode for a watch period before flipping to enforce. Recommended sandbox-rollout posture is count-only for BOTH `AWSManagedRulesAnonymousIpList` (customer VPN egress class) AND `AWSManagedRulesCommonRuleSet` (CRS body inspection false-positives on PEM-wrapped public keys) for the first 2–4 weeks of sandbox bootstrap traffic."
  type        = list(string)
  default     = []

  validation {
    # Mirror the module-side allowlist check so a typo at the root
    # tfvars layer fails plan with a root-pointed error rather than
    # surfacing as a less-friendly module-side `lifecycle.precondition`
    # error. The module's check (in `aws_wafv2_web_acl.this`) is the
    # actual gate; this is defense-in-depth at the input layer.
    condition = alltrue([for n in var.bootstrap_alb_waf_count_only_rule_groups : contains([
      "AWSManagedRulesAmazonIpReputationList",
      "AWSManagedRulesAnonymousIpList",
      "AWSManagedRulesCommonRuleSet",
      "AWSManagedRulesBotControlRuleSet",
    ], n)])
    error_message = "Each entry must be one of the managed rule groups the bootstrap-alb module enables: AWSManagedRulesAmazonIpReputationList, AWSManagedRulesAnonymousIpList, AWSManagedRulesCommonRuleSet, AWSManagedRulesBotControlRuleSet."
  }
}

variable "bootstrap_alb_cross_account_subscriber_arns" {
  description = "Cross-account IAM principals that may subscribe to the bootstrap-alb alerts SNS topic. Today's pattern is alerts-infra (the org-wide AWS Chatbot home) subscribing from a separate AWS account. **CRITICAL ROLLOUT SEQUENCING**: leave this empty (the default) in the sandbox-flip PR that first sets `deploy_bootstrap_alb=true` (Merge plan step 3 in PR #1886). Between that flip and the paired data-plane PR (step 4), the ALB returns 503 on every probe of `/v1/agent/bootstrap` — populating the cross-account subscriber list here would page alerts-infra during the entire dark-launch window. Populate with the alerts-infra role ARN in a SEPARATE follow-up after step 4 lands and qurl-service is healthy. Empty list skips the cross-account policy entirely (alarms still publish to the topic; just no downstream routing)."
  type        = list(string)
  default     = []
}

variable "bootstrap_alb_alarm_email_subscriptions" {
  description = "Optional email addresses to subscribe to the bootstrap-alb alerts SNS topic. Empty list (default) ships the topic without subscriptions — the canonical alarm-routing path is alerts-infra's cross-account Chatbot subscription (see `bootstrap_alb_cross_account_subscriber_arns`). Email is for interim direct-routing before alerts-infra is wired, or for ops-team accountability copies alongside chat-platform routing. **Subscription confirmation required**: each recipient receives an AWS confirmation email after apply and MUST click the link before alarms deliver — until confirmed, the subscription sits in `PendingConfirmation` and alarms fire silently to that address. See README Step 3 #7 for the `aws sns list-subscriptions-by-topic` verification."
  type        = list(string)
  default     = []
}

variable "bootstrap_alb_elb_5xx_threshold_per_minute" {
  description = "ALB-side 5xx alarm threshold (per minute). **Default `null` defers to the module's own default** (which is `10` — dark-launch-friendly; tolerates the 503-on-empty-TG noise between this stack's first apply and the paired data-plane PR). Env tfvars SHOULD override this down to `1` once the data plane is attached and the surface is live (any ALB-side 5xx is the outage signal at that point). The `null` default keeps the module as the single source of truth for the dark-launch posture — flipping prod live becomes 'set this var to 1' rather than 'remember which layer holds the dark-launch default'."
  type        = number
  default     = null
}

variable "bootstrap_unauthorized_threshold_per_minute" {
  description = "Threshold value for the `bootstrap-unauthorized-spike` alarm in `terraform/qurl_service_outcomes.tf` (counts `agent_bootstrap_completed` slog events whose `outcome=\"unauthorized\"`). The alarm uses `GreaterThanThreshold` so a default of `3` fires when **strictly more than 3** events/min land (i.e., 4+/min), sustained 3-of-5 minutes — same comparator and shape as the existing `alb_target_5xx` alarm so noise behavior stays uniform across the v1 observability surface. A 401 spike during a customer install indicates the customer's `QURL_API_KEY` is wrong or has been revoked — distinct from the 5xx surface that the existing `alb_target_5xx` alarm covers. **Tuning note**: real bootstrap traffic is sparse — 5 sidecars × 1 bootstrap/restart ≈ <1 success/min — so a clustered 401 burst above 3/min is unambiguous noise that warrants paging."
  type        = number
  default     = 3

  validation {
    condition     = var.bootstrap_unauthorized_threshold_per_minute >= 1 && var.bootstrap_unauthorized_threshold_per_minute <= 1000
    error_message = "bootstrap_unauthorized_threshold_per_minute must be 1 ≤ x ≤ 1000. Floor 1: threshold 0 with GreaterThanThreshold pages on the first single 401, too noisy for a key-rotation window. Ceiling 1000: catches typo-class mistakes (e.g., `300` for `30`) that would effectively disable the alarm — bootstrap traffic at steady state is <1 success/min, so any threshold > 1000 is almost certainly wrong."
  }
}

variable "bootstrap_rate_limited_threshold_per_minute" {
  description = "Threshold value for the `bootstrap-rate-limited-spike` alarm in `terraform/qurl_service_outcomes.tf` (counts `agent_bootstrap_completed` slog events whose `outcome=\"rate_limited\"`). The alarm uses `GreaterThanThreshold` so a default of `3` fires at 4+/min sustained 3-of-5 minutes (same shape as `bootstrap_unauthorized_threshold_per_minute`). The bootstrap rate-limiter is 10/hr per-API-key — a 429 spike implies one of: (a) a customer with a runaway sidecar restart loop, (b) a leaked API key being abused, (c) a deliberately probing client. Either is operator-actionable; a single legitimate 429 (developer hammering during smoke test) doesn't page."
  type        = number
  default     = 3

  validation {
    condition     = var.bootstrap_rate_limited_threshold_per_minute >= 1 && var.bootstrap_rate_limited_threshold_per_minute <= 1000
    error_message = "bootstrap_rate_limited_threshold_per_minute must be 1 ≤ x ≤ 1000 (per `bootstrap_unauthorized_threshold_per_minute` rationale — floor catches the 0-trap, ceiling catches typo-class mistakes)."
  }
}

# ── Agent registration + email OTP alarm thresholds (T1) ──
# All feed alarms in `terraform/qurl_service_outcomes.tf` gated on
# agent_registration_enabled / agent_otp_enabled, and all use
# `GreaterThanThreshold` so a default of `N` fires at N+1/min. Same 1..1000
# floor/ceiling rationale as the bootstrap thresholds above: floor 1 avoids
# paging on a single legitimate event during a rollout/smoke window; ceiling
# 1000 catches typo-class mistakes that would effectively disable the alarm
# (agent-register + OTP traffic is sparse at steady state).

variable "agent_otp_send_failed_threshold_per_minute" {
  description = "Threshold for the `agent-otp-send-failed-spike` alarm (counts `agent_otp_completed` slog events whose `outcome=\"send_failed\"`). LAUNCH-BLOCKING: send_failed means SES rejected the OTP email — a silent wire failure the user never sees (they just never get a code). Default 0 so the alarm pages on the FIRST send failure (comparator GreaterThanThreshold → >0 = ≥1); a healthy SES sender never emits send_failed. Set low in prod."
  type        = number
  default     = 0

  validation {
    condition     = var.agent_otp_send_failed_threshold_per_minute >= 0 && var.agent_otp_send_failed_threshold_per_minute <= 1000
    error_message = "agent_otp_send_failed_threshold_per_minute must be 0 ≤ x ≤ 1000. Floor 0 is intentional here (unlike the bootstrap thresholds): send_failed is a silent SES wire failure, so the first one must page. Ceiling 1000 catches typo-class mistakes."
  }
}

variable "agent_otp_bounce_threshold_per_minute" {
  description = "Threshold for the `agent-otp-bounce` alarm (SUM of AWS/SES `Bounce` + `Complaint` + `Reject` per minute on the `<name_prefix>-agent-otp` configuration set). LAUNCH-BLOCKING: these are ASYNC deliverability failures SES reports out-of-band on a message it ACCEPTED at send time — a hard bounce, spam complaint, or filter reject means the user silently never gets the code, the same failure class as send_failed but not caught by the synchronous send_failed alarm. Default 0 so the alarm pages on the FIRST async failure (GreaterThanThreshold → >0 = ≥1); a healthy verified sender emits none. Set low in prod."
  type        = number
  default     = 0

  validation {
    condition     = var.agent_otp_bounce_threshold_per_minute >= 0 && var.agent_otp_bounce_threshold_per_minute <= 1000
    error_message = "agent_otp_bounce_threshold_per_minute must be 0 ≤ x ≤ 1000. Floor 0 is intentional (first async bounce/complaint/reject must page, like send_failed); ceiling 1000 catches typo-class mistakes."
  }
}

variable "agent_otp_rate_limited_threshold_per_minute" {
  description = "Threshold for the `agent-otp-rate-limited-spike` alarm (counts `agent_otp_completed` slog events whose `outcome=\"rate_limited\"`). A sustained OTP rate-limit spike implies an email-bombing / enumeration attempt against the register endpoint, or a client retry loop. Default 5 (fires at 6+/min sustained 3-of-5); tune in prod."
  type        = number
  default     = 5

  validation {
    condition     = var.agent_otp_rate_limited_threshold_per_minute >= 1 && var.agent_otp_rate_limited_threshold_per_minute <= 1000
    error_message = "agent_otp_rate_limited_threshold_per_minute must be 1 ≤ x ≤ 1000 (floor catches the 0-trap, ceiling catches typo-class mistakes)."
  }
}

variable "agent_register_attempts_exceeded_threshold_per_minute" {
  description = "Threshold for the `agent-register-attempts-exceeded-spike` alarm (counts `agent_register_completed` slog events whose `outcome=\"attempts_exceeded\"`). BRUTE-FORCE signal: attempts_exceeded means a caller burned the per-credential attempt budget — a code/credential guessing attack. Default 3 (fires at 4+/min sustained 3-of-5); tune in prod."
  type        = number
  default     = 3

  validation {
    condition     = var.agent_register_attempts_exceeded_threshold_per_minute >= 1 && var.agent_register_attempts_exceeded_threshold_per_minute <= 1000
    error_message = "agent_register_attempts_exceeded_threshold_per_minute must be 1 ≤ x ≤ 1000 (floor catches the 0-trap, ceiling catches typo-class mistakes)."
  }
}

variable "agent_register_credential_invalid_threshold_per_minute" {
  description = "Threshold for the `agent-register-credential-invalid-spike` alarm (counts `agent_register_completed` slog events whose `outcome=\"credential_invalid\"`). Lower-priority companion to attempts_exceeded: a clustered credential_invalid burst can be an early brute-force probe (before the attempt budget is hit) or a broken client sending malformed credentials. Default 10 (fires at 11+/min sustained 3-of-5) — deliberately higher than attempts_exceeded so it's the softer, secondary signal. Tune in prod."
  type        = number
  default     = 10

  validation {
    condition     = var.agent_register_credential_invalid_threshold_per_minute >= 1 && var.agent_register_credential_invalid_threshold_per_minute <= 1000
    error_message = "agent_register_credential_invalid_threshold_per_minute must be 1 ≤ x ≤ 1000 (floor catches the 0-trap, ceiling catches typo-class mistakes)."
  }
}

variable "agent_register_rate_limited_threshold_per_minute" {
  description = "Threshold for the `agent-register-rate-limited-spike` alarm (counts `agent_register_completed` slog events whose `outcome=\"rate_limited\"`). A register rate-limit spike implies a client retry loop or an enumeration attempt against the credential-exchange path. Default 5 (fires at 6+/min sustained 3-of-5); tune in prod."
  type        = number
  default     = 5

  validation {
    condition     = var.agent_register_rate_limited_threshold_per_minute >= 1 && var.agent_register_rate_limited_threshold_per_minute <= 1000
    error_message = "agent_register_rate_limited_threshold_per_minute must be 1 ≤ x ≤ 1000 (floor catches the 0-trap, ceiling catches typo-class mistakes)."
  }
}

variable "relay_otp_reject_rate_limited_threshold_per_minute" {
  description = "Threshold for the `relay-otp-reject-rate-limited` alarm (CloudWatch metric `OTPRejectRateLimited`, namespace `LayerV/NHP`, dim Environment=<env>, emitted from the shared OTP dispatch core in endpoints/server — both the direct-UDP and relayed OTP paths, so despite the relay-cap framing it is NOT relay-only). NOTE: the nhp-server publisher's base dim set is [Environment, Cell], so this alarm's {Environment}-only selection binds ONLY because the server dual-publishes an explicit [Environment]-only BASE stream on the shed path (IncrCounterExplicitDims, the RelayShed pattern) in addition to the [Environment, Cell] breakdown; if that base emit is removed the alarm silently stops binding (INSUFFICIENT_DATA + notBreaching = green). A reject means the fleet-wide GLOBAL 30/min OTP cap was hit and legitimate OTP sends are being shed. Default 0 → pages on the first reject (a healthy fleet under the 30/min cap never rejects), matching the first-event posture. The alarm is gated on `agent_otp_alarms_enabled || deploy_relay`, so with OTP enabled it IS created in prod even while the relay stays dark (the metric still emits on the direct path). Tune in prod once real OTP volume is known relative to the 30/min cap."
  type        = number
  default     = 0

  validation {
    condition     = var.relay_otp_reject_rate_limited_threshold_per_minute >= 0 && var.relay_otp_reject_rate_limited_threshold_per_minute <= 1000
    error_message = "relay_otp_reject_rate_limited_threshold_per_minute must be 0 ≤ x ≤ 1000. Floor 0 is intentional (first-reject page, like the relay shed alarm); ceiling 1000 catches typo-class mistakes against the nhp-server's 30/min global OTP cap."
  }
}

variable "knock_token_reject_threshold_per_minute" {
  description = "Threshold value for the `frps-knock-token-reject-rate` alarm in the qurl-reverse-tunnel-server module (counts `knock_token_invalid` + `knock_token_validator_error` slog events emitted from the FRP-Login knock-token validator). The alarm uses `GreaterThanThreshold` so a default of `3` fires at 4+/min sustained 3-of-5 minutes — same comparator and shape as the bootstrap-ALB `alb_target_5xx` alarm so noise behavior stays uniform across the v1 observability surface. Env tfvars may override to quiet the alarm during a known maintenance window. See `modules/qurl-reverse-tunnel-server/variables.tf::knock_token_reject_threshold_per_minute` for the full operator rationale and customer-install symptom mapping."
  type        = number
  default     = 3

  validation {
    condition     = var.knock_token_reject_threshold_per_minute >= 1 && var.knock_token_reject_threshold_per_minute <= 1000
    error_message = "knock_token_reject_threshold_per_minute must be 1 ≤ x ≤ 1000 (floor catches the 0-trap; ceiling catches typo-class mistakes that would effectively disable the alarm)."
  }
}

variable "owner_missing_reject_threshold" {
  description = "Threshold value for the `frps-owner-missing-rejects` alarm in the qurl-reverse-tunnel-server module (counts frps NewProxy rejections carrying the byte-stable wire string `owner_missing: connector identity missing` — a reverse-tunnel connector stuck registering with no connector identity, tunnel dark). The alarm uses `GreaterThanOrEqualToThreshold` over a single 5-minute Sum so a default of `5` — half the ~10 rejects one stuck connector emits per 5-minute window (it re-knocks ~every 30s) — breaches on a single stuck connector at the next 5-minute period close, but not on a transient single blip. Env tfvars may override to quiet the alarm during a known connector force-restart window. See `modules/qurl-reverse-tunnel-server/variables.tf::owner_missing_reject_threshold` for the full rationale and the wire-string contract."
  type        = number
  default     = 5

  validation {
    condition     = var.owner_missing_reject_threshold >= 1 && var.owner_missing_reject_threshold <= 1000
    error_message = "owner_missing_reject_threshold must be 1 ≤ x ≤ 1000 (floor avoids the always-on trap under GreaterThanOrEqualToThreshold; ceiling catches typo-class mistakes that would effectively disable the alarm)."
  }
}

# ── NHP-Relay (#2208 Phase-2 #5) ──
# Internet-facing relay that forwards browser knocks to the cell's internal
# server endpoint. Ships DARK: until 5c registers the relay pubkey in the server's
# relay.toml, every forward is rejected at the server's Noise layer, so the
# relay is internet-reachable but inert (cannot pivot into the private network).
# DNS/cert vars mirror the bootstrap_alb pattern (same provision-or-existing,
# same-account-vs-cross-account posture).

variable "deploy_relay" {
  description = "Deploy the NHP-Relay stack (autoscaling fleet + internet-facing ALB). Default off; sandbox flips it true for the dark launch. The fleet shares one keypair and authenticates by Noise IK pubkey + relay.toml registration (NOT source IP) once the server runs DisableRelayPeerValidation=true (5c, #2627); baseline one instance per AZ. See modules/relay/variables.tf and the tracking issue #2629."
  type        = bool
  default     = false
}

variable "relay_vpc_cidr" {
  description = "Dedicated relay DMZ VPC CIDR. Read only when deploy_relay=true; sandbox uses 10.101.0.0/16."
  type        = string
  default     = "10.101.0.0/16"

  validation {
    condition     = can(cidrnetmask(var.relay_vpc_cidr)) && cidrnetmask(var.relay_vpc_cidr) == "255.255.0.0"
    error_message = "relay_vpc_cidr must be a valid IPv4 /16 CIDR."
  }
}

# Canonical-key and ordering rules are mirrored by both environment wrappers
# and modules/compute's final trust-set input; keep those contracts in lockstep.
variable "relay_additional_trusted_public_keys_b64" {
  description = "Canonically sorted public-only X25519 keys trusted during guarded relay identity rotation. Never pass private key material here."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for key in var.relay_additional_trusted_public_keys_b64 :
      can(regex("^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$", key))
    ])
    error_message = "Every additional relay public key must be canonical standard Base64 encoding exactly 32 bytes."
  }

  validation {
    condition     = var.relay_additional_trusted_public_keys_b64 == sort(distinct(var.relay_additional_trusted_public_keys_b64))
    error_message = "relay_additional_trusted_public_keys_b64 must already be sorted and duplicate-free."
  }
}

variable "relay_dns_name" {
  description = "Public DNS name for the relay ALB. Sandbox: `relay.qurl.link.layerv.xyz`. Only read when `deploy_relay = true`."
  type        = string
  default     = ""

  validation {
    condition     = var.relay_dns_name == "" || can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", var.relay_dns_name))
    error_message = "relay_dns_name must be empty (when `deploy_relay=false`) or a valid lowercase FQDN like `relay.qurl.link.layerv.xyz`."
  }
}

variable "relay_route53_zone_id" {
  description = "Hosted zone ID for the parent of `relay_dns_name`. Required when `relay_provision_certificate` or `relay_manage_dns_alias` is true. Sandbox: the `layerv.xyz` zone (same account). Empty when both are false (cross-account, operator-managed DNS)."
  type        = string
  default     = ""

  validation {
    condition     = var.relay_route53_zone_id == "" || can(regex("^Z[A-Z0-9]{8,}$", var.relay_route53_zone_id))
    error_message = "relay_route53_zone_id must be empty or a valid Route53 zone ID (uppercase, starts with Z)."
  }
}

variable "relay_provision_certificate" {
  description = "Whether the relay module provisions+validates a regional ACM cert for `relay_dns_name`. True only when the parent zone is same-account (DNS validation writes CNAMEs there). Sandbox: true (same-account `layerv.xyz`). Prod: false (operator pre-provisions cross-account; supply `relay_existing_certificate_arn`)."
  type        = bool
  default     = false
}

variable "relay_manage_dns_alias" {
  description = "Whether the relay module writes the A-alias from `relay_dns_name` to the ALB. True when the parent zone is same-account. Sandbox: true. Prod: false (operator writes the alias cross-account)."
  type        = bool
  default     = false
}

variable "relay_existing_certificate_arn" {
  description = "Regional ACM cert ARN to attach when `relay_provision_certificate=false`. Must be same region+account as the ALB. Empty for the sandbox same-account provision path."
  type        = string
  default     = ""

  validation {
    condition     = var.relay_existing_certificate_arn == "" || can(regex("^arn:(aws|aws-us-gov|aws-cn):acm:[a-z0-9-]+:[0-9]{12}:certificate/[a-f0-9-]{36}$", var.relay_existing_certificate_arn))
    error_message = "relay_existing_certificate_arn must be empty or a valid regional ACM ARN."
  }
}

variable "relay_waf_rate_limit_per_source_ip" {
  description = "Relay WAF per-source-IP rate limit (requests per 5-min window, scoped to `/relay/*`) — the first-line relay DoS control. Surfaced to the env layer so #6 tuning (with real browser traffic; watch NAT/CGNAT concentration) is a tfvars change, not a code change. Default 300."
  type        = number
  default     = 300

  validation {
    condition     = var.relay_waf_rate_limit_per_source_ip >= 100 && var.relay_waf_rate_limit_per_source_ip <= 2000
    error_message = "relay_waf_rate_limit_per_source_ip must be 100-2000 (matches the module floor/ceiling)."
  }
}

variable "relay_scale_requests_per_target" {
  description = "Relay ASG target-tracking threshold: ALB request count per relay target (per-target sum over the metric period). Surfaced to the env layer for #6 tuning. Default 1000."
  type        = number
  default     = 1000

  validation {
    condition     = var.relay_scale_requests_per_target >= 50
    error_message = "relay_scale_requests_per_target must be >= 50."
  }
}

# ==================== qURL v2 (keyed identity) ====================
# Gates for qURL v2. All default false / empty (dark launch). Enabling is a
# coordinated flip across qurl-service (issuance) and the NHP server (admission);
# see modules/qurl-service and modules/compute.
variable "qurl_v2_issuer_key_enabled" {
  description = "Provision the qURL v2 issuer signing KMS key and wire qurl-api issuer config + kms:Sign. Default false."
  type        = bool
  default     = false
}

variable "qurl_v2_resource_keys_enabled" {
  description = "Enable qURL v2 per-resource KMS keys on qurl-api (tag-scoped create/reap). Default false."
  type        = bool
  default     = false
}

variable "qurl_v2_resource_key_software_default" {
  description = "Dark-launch ramp for qURL v2 software key custody. false ⇒ hardware-for-all (KMS CMK per resource) even for unentitled owners; true ⇒ custody chosen per owner (HardwareKeyStorage entitlement ⇒ KMS, else envelope-wrapped software). Only meaningful when qurl_v2_resource_keys_enabled = true. Default false."
  type        = bool
  default     = false
}

variable "qurl_v2_resource_key_reaper_enabled" {
  description = "Run the periodic resource-key reaper in qurl-api (reconcile-and-delete orphaned per-resource CMKs). Requires qurl_v2_resource_keys_enabled. Default false."
  type        = bool
  default     = false
}

variable "qurl_v2_resource_key_reaper_interval_seconds" {
  description = "Resource-key reaper sweep cadence in seconds. Default 21600 (6h); cost granularity is $1/key/month, so tighter cadences buy nothing."
  type        = number
  default     = 21600
}

variable "qurl_v2_issuance_enabled" {
  description = "Enable qURL v2 link minting on qurl-api (requires issuer-key + resource-keys). Default false."
  type        = bool
  default     = false
}

variable "qurl_v2_admission_enabled" {
  description = "Enable the NHP server's qURL v2 signed-claims admission path + issuer trust store. Default false."
  type        = bool
  default     = false
}

variable "qurl_v2_issuer_kid" {
  description = "Issuer key id (kid) stamped into signed claims and used as the NHP-server trust-store key. Required when issuance/admission are enabled."
  type        = string
  default     = ""

  validation {
    condition     = var.qurl_v2_issuer_kid == "" || can(regex("^[A-Za-z0-9._-]+$", var.qurl_v2_issuer_kid))
    error_message = "qurl_v2_issuer_kid must be empty or contain only [A-Za-z0-9._-]."
  }
}

variable "qurl_v2_relay_url" {
  description = "qURL v2 relay endpoint embedded in signed claims (HTTPS, on the allowlist). Required when qurl_v2_issuance_enabled = true."
  type        = string
  default     = ""

  validation {
    condition     = var.qurl_v2_relay_url == "" || can(regex("^https://", var.qurl_v2_relay_url))
    error_message = "qurl_v2_relay_url must be empty or an https:// URL."
  }
}

variable "qurl_v2_relay_allowlist" {
  description = "Comma-separated host[:port] allowlist for qURL v2 relay_url. Required when qurl_v2_issuer_key_enabled = true."
  type        = string
  default     = ""

  validation {
    condition     = var.qurl_v2_relay_allowlist == "" || can(regex("^[A-Za-z0-9.:_-]+(,[A-Za-z0-9.:_-]+)*$", var.qurl_v2_relay_allowlist))
    error_message = "qurl_v2_relay_allowlist must be empty or a comma-separated list of host[:port] entries (no spaces or scheme)."
  }
}

# Control identity plane.
#
# Identity is global, not cell-scoped: a customer exists before any cell
# assignment, may hold resources in several cells, and must outlive the loss of
# any one of them. The Connector Authority validates enrollment credentials for
# every cell and reads only the Control namespace, so a cell that keeps its own
# accounts and API keys is invisible to it -- an agent enrolling with a
# perfectly valid key gets credential_invalid.
#
# Empty keeps this cell on its own identity tables, which is the historical
# behavior. Setting it is a deliberate cutover and REQUIRES the identity rows to
# already exist in Control; flipping first would point every existing customer
# at an empty namespace.
variable "control_identity_environment_id" {
  description = "Control namespace environment id for qurl-service identity (e.g. \"sandbox\"). Empty keeps cell identity tables."
  type        = string
  default     = ""
}

variable "control_identity_home_region" {
  description = "Home region of the Control identity tables. Required when control_identity_environment_id is set."
  type        = string
  default     = ""
}

variable "control_identity_kms_key_arn" {
  description = "KMS key encrypting the Control identity tables. Required when control_identity_environment_id is set."
  type        = string
  default     = ""
}
