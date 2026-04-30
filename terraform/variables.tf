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
  description = "Maximum ASG capacity"
  type        = number
  default     = 10

  validation {
    condition     = var.max_capacity >= 1 && var.max_capacity <= 100
    error_message = "Max capacity must be between 1 and 100."
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

variable "ac_auth_service_id" {
  description = "Authentication service ID for the Access Controller"
  type        = string
  default     = "layerv"
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
    condition     = var.qurl_link_hosted_zone_id == null || can(regex("^Z[A-Z0-9]+$", var.qurl_link_hosted_zone_id))
    error_message = "qurl_link_hosted_zone_id must be a valid Route53 zone ID (starts with Z)"
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

variable "enable_resolve_cloudfront" {
  description = "Enable CloudFront + WAF in front of resolve.qurl.link for ISP compatibility"
  type        = bool
  default     = false
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

variable "qurl_service_domain" {
  description = "Domain for QURL API (e.g., api.qurl.link)"
  type        = string
  default     = null
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
    condition     = var.qurl_site_hosted_zone_id == null || can(regex("^Z[A-Z0-9]+$", var.qurl_site_hosted_zone_id))
    error_message = "qurl_site_hosted_zone_id must be a valid Route53 zone ID (starts with Z)"
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
}

variable "qurl_github_repo" {
  description = "GitHub repository for QURL service (for ECR push permissions)"
  type        = string
  default     = "qurl-service"
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

variable "grafana_nhp_dashboard_url" {
  description = "URL to the NHP Infrastructure Grafana dashboard (shown on status page)"
  type        = string
  default     = ""
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
  description = "Base URL for the alert runbooks. Default points at the layervai/nhp main branch."
  type        = string
  default     = "https://github.com/layervai/nhp/blob/main/docs/runbooks"
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
  description = "Minimum instance count for green ASG in standby mode. 1 = warm standby (instant switch), 0 = cold standby (requires scale-up)."
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
  description = "Instance warmup time in seconds for canary refresh."
  type        = number
  default     = 180
}

# ==================== Status Page ====================

variable "deploy_status_page" {
  description = "Deploy the status page for deployment visibility (Lambda + API Gateway + S3 + CloudFront)"
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
    condition     = var.status_page_hosted_zone_id == null || can(regex("^Z[A-Z0-9]+$", var.status_page_hosted_zone_id))
    error_message = "status_page_hosted_zone_id must be a valid Route53 zone ID (starts with Z)."
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
}

variable "developer_portal_ci_bypass_secret_name" {
  description = "Secrets Manager secret name for CI bypass key. If set, Lambda functions skip rate limiting when X-CI-Key header matches."
  type        = string
  default     = null
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

variable "frps_instance_type" {
  description = "EC2 instance type for FRP server"
  type        = string
  default     = "t3.small"
}

variable "frps_image_tag" {
  description = "qurl-frps binary version tag. Separate from NHP image_tag since frps has its own release cadence. Defaults to a placeholder tag that CI must overwrite on first deploy — a Terraform-only operator can't accidentally install a moving `latest` that slipped between applies."
  type        = string
  default     = "v0.0.0-bootstrap"
}

variable "frps_bind_port" {
  description = "FRP server control port. Shared between qurl-frps module (bind port) and AC module (Traefik route target) so they can't drift."
  type        = number
  default     = 7000
}

variable "frps_vhost_http_port" {
  description = "FRP vhost HTTP port. Shared between qurl-frps module (bind port) and AC module (qurl-router plugin target) so they can't drift."
  type        = number
  default     = 8080
}

# nhp-frps holds tunnel registrations in memory per instance and Cloud Map
# uses MULTIVALUE routing, so scaling beyond 1 today drops ~(N-1)/N of tunnel
# requests. Tracked in #1499 (consistent-hash routing in qurl-router OR shared
# registry in nhp-frps). Leave the defaults at 1 in env tfvars until #1499 is
# resolved; the variables exist now so that the eventual scale-up is a tfvars
# diff and not a module change.

variable "frps_min_size" {
  description = "ASG minimum size for qurl-frps. Default 1; do not raise without resolving #1499."
  type        = number
  default     = 1

  validation {
    # Mirror the module-level validation at the root: a typo like
    # `frps_min_size = 0` while `deploy_frps = false` would otherwise sit
    # unchallenged until the next time frps is deployed. `floor(...) == ...`
    # rejects non-integers (`type = number` on its own accepts 1.5, which
    # would only fail at AWS-API time).
    condition     = var.frps_min_size >= 1 && floor(var.frps_min_size) == var.frps_min_size
    error_message = "frps_min_size must be an integer >= 1 — qurl-frps is the only path for tunnel traffic; N=0 means tunnel resources 502."
  }
}

variable "frps_max_size" {
  description = "ASG maximum size for qurl-frps. Default 1; do not raise without resolving #1499."
  type        = number
  default     = 1

  validation {
    condition     = var.frps_max_size >= 1 && floor(var.frps_max_size) == var.frps_max_size
    error_message = "frps_max_size must be an integer >= 1 — see frps_min_size."
  }
}

variable "frps_desired_capacity" {
  description = "ASG desired capacity for qurl-frps. Default 1; do not raise without resolving #1499."
  type        = number
  default     = 1

  validation {
    condition     = var.frps_desired_capacity >= 1 && floor(var.frps_desired_capacity) == var.frps_desired_capacity
    error_message = "frps_desired_capacity must be an integer >= 1 — see frps_min_size."
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
