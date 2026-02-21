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

variable "deploy_etcd" {
  description = "Deploy etcd infrastructure. Set to false for cloud deployments using DynamoDB backend."
  type        = bool
  default     = null # Defaults to multi_tenant when null

  validation {
    condition     = var.deploy_etcd != true || var.multi_tenant == true
    error_message = "deploy_etcd = true requires multi_tenant = true. etcd is only used in multi-tenant mode."
  }
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

# ==================== NHP Server Assignment Configuration ====================
# These variables configure how Console manages AC-to-NHP-Server assignments.
# All fields are required and must be explicitly configured (no defaults).

variable "nhp_server_assignment_enabled" {
  description = "Enable NHP server assignment for ACs. Required. Recommended: true"
  type        = bool
  # No default - must be explicitly configured
}

variable "nhp_region" {
  description = "AWS region for NHP DynamoDB tables and CloudMap. Required. Recommended: match deployment region."
  type        = string
  # No default - must be explicitly configured
}

variable "nhp_cloudmap_service_name" {
  description = "CloudMap service name for NHP servers. Required. Recommended: 'server'"
  type        = string
  # No default - must be explicitly configured
}

variable "nhp_assignment_servers_per_ac" {
  description = "Number of NHP servers to assign per AC. Required. Recommended: 3 (one per AZ)"
  type        = number
  # No default - must be explicitly configured

  validation {
    condition     = var.nhp_assignment_servers_per_ac >= 1
    error_message = "nhp_assignment_servers_per_ac must be at least 1"
  }
}

variable "nhp_assignment_require_distinct_azs" {
  description = "Require assigned servers to be in different AZs for HA. Required. Recommended: true"
  type        = bool
  # No default - must be explicitly configured
}

variable "nhp_health_monitor_check_interval" {
  description = "Interval in seconds between health checks. Required. Recommended: 60"
  type        = number
  # No default - must be explicitly configured

  validation {
    condition     = var.nhp_health_monitor_check_interval >= 1
    error_message = "nhp_health_monitor_check_interval must be at least 1 second"
  }
}

variable "nhp_health_monitor_operation_timeout" {
  description = "Timeout in seconds for health check operations. Required. Recommended: 30"
  type        = number
  # No default - must be explicitly configured

  validation {
    condition     = var.nhp_health_monitor_operation_timeout >= 1
    error_message = "nhp_health_monitor_operation_timeout must be at least 1 second"
  }
}

variable "nhp_console_ac_enabled" {
  description = "Enable Console's embedded AC self-registration in DynamoDB. Required. Recommended: true"
  type        = bool
  # No default - must be explicitly configured
}

# ==================== Console License Lookup ====================

variable "nhp_dynamodb_licenses_customer_index" {
  description = "GSI name for querying licenses by customer_id. Required for license lookup. Recommended: 'customer_id-index'"
  type        = string
  default     = null
}

variable "nhp_dynamodb_licenses_auth0_subject_index" {
  description = "GSI name for querying licenses by auth0_subject. Required for QURL quota lookup. Recommended: 'auth0_subject-index'"
  type        = string
  default     = null
}

# ==================== Console Internal Service Auth ====================

variable "internal_service_token_secret_arn" {
  description = "ARN of Secrets Manager secret containing the internal service token for Auth0 Actions to call Console API"
  type        = string
  default     = null
}

variable "provisioning_resource_id" {
  description = "Resource ID for auto-provisioned licenses. Recommended: 'qurl-auto-provisioned'"
  type        = string
  default     = null
}

variable "provisioning_default_tier" {
  description = "Default license tier for new customers. Must be: free, pro, enterprise, or system. Recommended: 'free'"
  type        = string
  default     = null

  validation {
    # Use ternary to avoid evaluating contains() when value is null
    condition     = var.provisioning_default_tier == null ? true : contains(["free", "pro", "enterprise", "system"], var.provisioning_default_tier)
    error_message = "provisioning_default_tier must be one of: free, pro, enterprise, system"
  }
}

variable "provisioning_default_max_acs" {
  description = "Default MaxACs limit for new customers. 0 = unlimited. Recommended: 1 (for free tier)"
  type        = number
  default     = null

  validation {
    # Use ternary to avoid evaluating >= when value is null
    condition     = var.provisioning_default_max_acs == null ? true : var.provisioning_default_max_acs >= 0
    error_message = "provisioning_default_max_acs must be non-negative"
  }
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

variable "qurl_owner_rate_limit" {
  description = "Rate limit for authenticated owner routes (requests per minute)"
  type        = number
  default     = 200

  validation {
    condition     = var.qurl_owner_rate_limit > 0 && var.qurl_owner_rate_limit <= 10000
    error_message = "qurl_owner_rate_limit must be between 1 and 10000 requests per minute"
  }
}

variable "qurl_owner_rate_burst" {
  description = "Burst allowance for authenticated owner routes"
  type        = number
  default     = 50

  validation {
    condition     = var.qurl_owner_rate_burst > 0 && var.qurl_owner_rate_burst <= 1000
    error_message = "qurl_owner_rate_burst must be between 1 and 1000"
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

# ==================== QURL License Cache ====================

variable "qurl_license_cache_ttl_seconds" {
  description = "TTL for license cache entries in seconds"
  type        = number
}

variable "qurl_license_cache_max_size" {
  description = "Maximum number of license cache entries"
  type        = number
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
  default     = 86400 # 24 hours

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
  default     = ""
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

# ==================== Common Tags ====================

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
