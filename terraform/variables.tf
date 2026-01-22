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

# ==================== Server Configuration Options ====================

variable "dev_mode" {
  description = "Enable development mode for the NHP server (enables additional debugging features)"
  type        = bool
  default     = false
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

# ==================== AC Configuration ====================

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
# These are separate from console_ac_* which is for the Console's embedded AC

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

# ==================== RDS Configuration ====================

variable "deploy_rds" {
  description = "Deploy Aurora PostgreSQL Serverless for console application"
  type        = bool
  default     = false
}

variable "rds_database_name" {
  description = "Name of the default database to create"
  type        = string
  default     = "portal"
}

variable "rds_min_capacity" {
  description = "Minimum Aurora Serverless v2 capacity (ACUs)"
  type        = number
  default     = 0.5
}

variable "rds_max_capacity" {
  description = "Maximum Aurora Serverless v2 capacity (ACUs)"
  type        = number
  default     = 4
}

variable "rds_deletion_protection" {
  description = "Enable deletion protection for RDS"
  type        = bool
  default     = true
}

# ==================== Console Configuration ====================

variable "deploy_console" {
  description = "Deploy the Console application as ECS Fargate service"
  type        = bool
  default     = false
}

variable "console_domain" {
  description = "Domain name for console (e.g., console.layerv.xyz)"
  type        = string
  default     = null
}

variable "console_acm_certificate_arn" {
  description = "ACM certificate ARN for console HTTPS"
  type        = string
  default     = null
}

variable "console_cookie_domain" {
  description = "Cookie domain for console portal sites"
  type        = string
  default     = ".layerv.ai"
}

variable "console_admin_password" {
  description = "Admin user password for Console. If not provided, a random password will be generated and logged on first deployment."
  type        = string
  sensitive   = true
  default     = null
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

# ==================== Demo Gateway Configuration ====================

variable "deploy_demo_gateway" {
  description = "Deploy the Demo Gateway for qurl.link routing to NHP Server plugins"
  type        = bool
  default     = false
}

variable "demo_gateway_domain" {
  description = "Domain for Demo Gateway (e.g., qurl.link)"
  type        = string
  default     = null
}

variable "demo_gateway_hosted_zone_id" {
  description = "Route 53 hosted zone ID for Demo Gateway domain (if in different zone than main hosted_zone)"
  type        = string
  default     = null
}

variable "demo_gateway_fallback_url" {
  description = "URL to redirect when accessing Demo Gateway root path"
  type        = string
  default     = "https://layerv.ai/demo"
}

# ==================== Console EC2 Configuration ====================

variable "deploy_console_ec2" {
  description = "Deploy the Console API on EC2 (alternative to ECS Fargate console)"
  type        = bool
  default     = false
}

variable "console_ec2_domain" {
  description = "Domain for Console EC2 API (e.g., console.nhp.layerv.xyz)"
  type        = string
  default     = null
}

variable "console_internal_only" {
  description = "Make Console internal-only (NHP-protected via AC). When true, Console is only accessible through AC after NHP authentication."
  type        = bool
  default     = false
}

variable "console_protected_hostname" {
  description = "NHP-protected Console hostname (e.g., 'console2.apps.layerv.xyz'). Required when console_internal_only=true. This is where users are redirected after successful auth_code knock."
  type        = string
  default     = null
}

variable "console_ac_license_key_hash" {
  description = "Bcrypt hash of the Console AC license key. Generate with: ./terraform/scripts/generate-console-ac-license.sh <environment>. REQUIRED - empty hash will cause AC registration to fail."
  type        = string
  sensitive   = true
  default     = null
}

variable "console_ac_license_key_sha256" {
  description = "SHA256 hash of the Console AC license key. Used as DynamoDB partition key for license lookup. Generate with: ./terraform/scripts/generate-console-ac-license.sh <environment>"
  type        = string
  sensitive   = true
  default     = null
}

variable "console_ac_customer_id" {
  description = "Customer ID (ULID format) for Console's embedded AC. LayerV system uses nil ULID: 00000000000000000000000000"
  type        = string
  default     = "00000000000000000000000000" # Nil ULID for LayerV system customer
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

variable "qurl_default_ac_host" {
  description = "Default AC hostname for new QURL resources"
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

variable "qurl_certificate_arn" {
  description = "ACM certificate ARN for QURL API HTTPS"
  type        = string
  default     = null
}

variable "qurl_github_repo" {
  description = "GitHub repository for QURL service (for ECR push permissions)"
  type        = string
  default     = "qurl-service"
}

# ==================== QURL Router Plugin ====================
# Configuration for the Traefik QURL Router plugin that routes *.qurl.site requests

variable "qurl_router_enabled" {
  description = "Enable QURL Router plugin in Traefik (routes *.qurl.site subdomains to target backends)"
  type        = bool
  default     = false
}

variable "qurl_router_base_domain" {
  description = "Base domain for QURL resources (e.g., qurl.site). Plugin routes {subdomain}.{base_domain} requests."
  type        = string
  default     = "qurl.site"
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

# ==================== Common Tags ====================

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
