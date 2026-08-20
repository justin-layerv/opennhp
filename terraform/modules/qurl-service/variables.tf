# QURL Service Module Variables
# ECS Fargate deployment for the QURL API service

# ==================== Environment ====================

variable "environment" {
  description = "Environment name (sandbox, prod)"
  type        = string
}

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "cell_id" {
  description = "Cell identifier for multi-cell deployments (e.g., cell-1)"
  type        = string
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

# ==================== Networking ====================

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for ECS tasks"
  type        = list(string)
}

variable "public_subnet_ids" {
  description = "Subnet IDs for the primary ALB. Public subnets are required when public_ingress_enabled=true; private subnets are required when it is false."
  type        = list(string)
}

variable "resource_name_prefix" {
  description = "Optional physical-resource prefix, excluding cell_id. Defaults to name_prefix. Use when the caller needs an environment-specific SSM namespace but wants cell_id to appear exactly once in ECS/ALB/Lambda/queue/table names."
  type        = string
  default     = null

  validation {
    condition     = var.resource_name_prefix == null || trimspace(var.resource_name_prefix) != ""
    error_message = "resource_name_prefix must be null or a non-empty string."
  }
}

# The primary ALB remains internet-facing by default for the existing cell0
# public API. A private cell-local qurl-service reuses the same task/IAM/data
# module with this flag false; the ALB then lives in the caller-supplied private
# subnets and its security group admits only the exact source SGs below.
variable "public_ingress_enabled" {
  description = "Whether the primary qurl-service ALB is internet-facing. False creates an internal ALB and requires ingress_security_group_ids; it never adds CIDR ingress."
  type        = bool
  default     = true
}

variable "ingress_security_group_ids" {
  description = "Exact caller security groups admitted to the primary ALB when public_ingress_enabled=false. Must be empty in public mode and non-empty in private mode."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for security_group_id in var.ingress_security_group_ids :
      can(regex("^sg-[0-9a-f]+$", security_group_id))
    ])
    error_message = "ingress_security_group_ids entries must be AWS security group IDs."
  }
}

# ==================== Container ====================

variable "ecr_repo_url" {
  description = "ECR repository URL for qurl-api image"
  type        = string
}

variable "image_tag_ssm_param" {
  description = "SSM parameter name containing the image tag (e.g., /nhp-sandbox/qurl-api-image-tag)"
  type        = string
}

variable "image_uri" {
  description = "Optional complete immutable image URI (repository@sha256:digest). When set, ECS uses it verbatim instead of reconstructing an image from the legacy SSM tag. Must be paired with source_revision."
  type        = string
  default     = null

  validation {
    condition = var.image_uri == null || (
      startswith(var.image_uri, "${var.ecr_repo_url}@sha256:")
      && can(regex(
        "^sha256:[0-9a-f]{64}$",
        trimprefix(var.image_uri, "${var.ecr_repo_url}@"),
      ))
    )
    error_message = "image_uri must be null or exactly ecr_repo_url@sha256:<64 lowercase hexadecimal characters>."
  }
}

variable "source_revision" {
  description = "Optional full lowercase 40-hex source commit paired with image_uri and exposed in the task definition for live runtime proof."
  type        = string
  default     = null

  validation {
    condition     = var.source_revision == null || can(regex("^[0-9a-f]{40}$", var.source_revision))
    error_message = "source_revision must be null or a full lowercase 40-hex Git commit."
  }
}

variable "container_cpu" {
  description = "CPU units for container (256 = 0.25 vCPU)"
  type        = number
  default     = 256
}

variable "container_memory" {
  description = "Memory in MB for container"
  type        = number
  default     = 512
}

variable "container_port" {
  description = "Port the container listens on"
  type        = number
  default     = 8080
}

variable "desired_count" {
  description = "Desired number of ECS tasks"
  type        = number
  default     = 1
}

variable "autoscaling_min_capacity" {
  description = "Minimum number of ECS tasks for auto-scaling (production only)"
  type        = number
  default     = 2
}

variable "autoscaling_max_capacity" {
  description = "Maximum number of ECS tasks for auto-scaling (production only)"
  type        = number
  default     = 10
}

# ==================== DynamoDB ====================

variable "dynamodb_table_arns" {
  description = "List of DynamoDB table ARNs for IAM permissions"
  type        = list(string)
}

variable "dynamodb_table_prefix" {
  description = "Prefix for DynamoDB table names (passed to container)"
  type        = string
  default     = ""
}

variable "nhp_resources_table_name" {
  description = "Full NHP-owned resources table name where qurl-service writes dynamic q_ catalog rows"
  type        = string
  default     = ""
}

variable "nhp_resources_table_arn" {
  description = "ARN of the NHP-owned resources table for dynamic q_ catalog row writes"
  type        = string
  default     = ""
}

variable "nhp_resources_customer_id_prefix" {
  description = "Reserved NHP resources table customer_id prefix qurl-service may write dynamic q_ catalog shard rows under"
  type        = string
  default     = ""

  validation {
    condition = (
      var.nhp_resources_customer_id_prefix == ""
      || can(regex("^[0-9A-HJKMNP-TV-Z]{26}$", var.nhp_resources_customer_id_prefix))
    )
    error_message = "nhp_resources_customer_id_prefix must be empty or a 26-character ULID-shaped prefix."
  }
}

variable "qurl_browser_relay_base_url" {
  description = "Browser relay origin embedded by qurl-service into qv1 qURL bootstrap fragments. Empty keeps qurl_link fragments on legacy #at_ form."
  type        = string
  default     = ""
}

# ==================== Auth0 ====================

variable "auth0_domain" {
  description = "Auth0 domain for JWT validation"
  type        = string
}

variable "auth0_audience" {
  description = "Auth0 audience for JWT validation"
  type        = string
  default     = "https://api.layerv.ai"
}

# ==================== Secrets ====================

variable "secrets_kms_key_arn" {
  description = "KMS key ARN for Secrets Manager"
  type        = string
  default     = null
}

variable "jwt_secret_arn" {
  description = "Secrets Manager ARN for JWT signing secret"
  type        = string

  validation {
    condition     = can(regex("^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]+:secret:.+$", var.jwt_secret_arn))
    error_message = "jwt_secret_arn must be a valid Secrets Manager ARN (arn:aws:secretsmanager:REGION:ACCOUNT:secret:NAME)."
  }
}

variable "internal_service_token_arn" {
  description = "Secrets Manager ARN for internal service token"
  type        = string

  validation {
    condition     = can(regex("^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]+:secret:.+$", var.internal_service_token_arn))
    error_message = "internal_service_token_arn must be a valid Secrets Manager ARN (arn:aws:secretsmanager:REGION:ACCOUNT:secret:NAME)."
  }
}

variable "nhp_internal_auth_secret_arn" {
  description = "Secrets Manager ARN for the shared HMAC secret used to sign outbound /nhp/internal/knock requests. Must match the value read by nhp-server."
  type        = string

  validation {
    # arn:aws[-partition]:secretsmanager:<region>:<account>:secret:<name> —
    # accepts commercial (aws), GovCloud (aws-us-gov), and China (aws-cn).
    condition     = can(regex("^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:[0-9]+:secret:.+$", var.nhp_internal_auth_secret_arn))
    error_message = "nhp_internal_auth_secret_arn must be a valid Secrets Manager ARN."
  }
}

variable "feedback_slack_webhook_secret_arn" {
  description = "Secrets Manager ARN for the qURL Desktop feedback Slack incoming webhook"
  type        = string

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:[0-9]+:secret:.+$", var.feedback_slack_webhook_secret_arn))
    error_message = "feedback_slack_webhook_secret_arn must be a valid Secrets Manager ARN."
  }
}

# ==================== KMS ====================

variable "logs_kms_key_arn" {
  description = "KMS key ARN for CloudWatch Logs encryption"
  type        = string
  default     = null
}

variable "alb_access_logs_bucket" {
  description = "S3 bucket name for ALB access logs. Required for production environments for audit compliance."
  type        = string
  default     = null
}

variable "alb_access_logs_prefix" {
  description = "S3 key prefix for ALB access logs"
  type        = string
  default     = "alb-logs"
}

# ==================== QURL Defaults ====================

variable "api_base_url" {
  description = <<-EOT
    Base URL for API responses (Location headers, etc.).
    If not provided, computed automatically:
    - With certificate: https://{domain_name}
    - Without certificate: http://{alb_dns_name}
    Example: https://api.qurl.link
  EOT
  type        = string
  default     = null

  validation {
    condition     = var.api_base_url == null || can(regex("^https?://", var.api_base_url))
    error_message = "api_base_url must start with http:// or https:// when provided."
  }
}

variable "cookie_domain" {
  description = "Cookie domain for NHP tokens (e.g., .qurl.site)"
  type        = string
}

variable "qurl_link_domain" {
  description = "Domain for QURL access links (e.g., qurl.link)"
  type        = string
}

variable "qurl_site_domain" {
  description = "Domain for QURL protected resources (e.g., qurl.site)"
  type        = string
}

variable "default_token_expire" {
  description = "Default JWT token expiration in seconds"
  type        = number
}

variable "default_open_time" {
  description = "Default firewall open time in seconds"
  type        = number
}

# ==================== Rate Limiting ====================

variable "ip_rate_limit" {
  description = "Rate limit for IP-based internal routes (requests per minute)"
  type        = number
}

variable "ip_rate_burst" {
  description = "Burst allowance for IP-based internal routes"
  type        = number
}

# ==================== Audit ====================

variable "audit_retention_days" {
  description = "Number of days to retain audit logs in DynamoDB"
  type        = number
}

# ==================== CORS ====================

variable "cors_allowed_origins" {
  description = "Comma-separated list of allowed CORS origins. Every production deployment requires an explicit non-wildcard value because qurl-service validates it at startup; a private-primary cell may use its exact cell-local internal origin."
  type        = string
}

# ==================== Security ====================

variable "additional_allowed_hosts" {
  description = "Additional allowed hostnames for DNS rebinding protection. ALB DNS and localhost are always included."
  type        = list(string)
  default     = []
}

# ==================== AC Fleet ====================

variable "default_ac_id" {
  description = "Default AC identifier for new resources"
  type        = string
}

variable "default_ac_port" {
  description = "Default AC port for new resources"
  type        = number
  default     = 443
}

# ==================== Domain ====================

variable "domain_name" {
  description = "Domain name for the QURL API (e.g., api.qurl.link)"
  type        = string
  default     = null
}

variable "hosted_zone_id" {
  description = "Route53 hosted zone ID for the domain"
  type        = string
  default     = null
}

variable "certificate_arn" {
  description = "ACM certificate ARN for HTTPS (must be in same region)"
  type        = string
  default     = null
}

# ==================== Internal ALB ====================
# A second, internal-only ALB serves /internal/v1/* to in-VPC consumers
# (NHP server, AC Traefik plugin). The public ALB still serves /v1/*
# from the internet; PR4 of the rollout adds a listener rule that 404s
# /internal/* on the public ALB.
#
# Trust model and multi-PR rollout sequence are documented in the
# nhp PR that introduced these variables (network-isolate qurl-service
# /internal/v1/*, qurl-service #335) and tracked in nhp follow-up
# issues #1589 / #1590 / #1591 / #1592.

variable "internal_alb_enabled" {
  description = "When true, stand up an internal ALB (internal=true, private subnets) that forwards to the same target group as the public ALB. Consumers point at internal_alb_dns_name (or the workload-account private hosted zone alias). Default false so the resource is opt-in and tfvars must be set explicitly per-env."
  type        = bool
  default     = false
}

# Bootstrap-ALB attachment (paired with modules/bootstrap-alb). When the
# env-root instantiates module.bootstrap_alb, it threads its target_group_arn
# and alb_security_group_id outputs through these two vars; the module then
# registers the ECS service against the TG and authorizes ingress from the
# bootstrap-ALB SG. Both null = pre-Wave-5 posture (no attachment, no
# ingress). Wiring is documented on the bootstrap-alb module's
# target_group_arn / alb_security_group_id outputs, which call out this
# module as the paired consumer.
variable "bootstrap_alb_target_group_arn" {
  description = "Target group ARN of the bootstrap-ALB. When non-null, aws_ecs_service.qurl adds a load_balancer block registering task IPs against this TG so POST /v1/agent/bootstrap traffic reaching bootstrap.layerv.<tld> lands on qurl-service. Threaded from env-root as `var.deploy_bootstrap_alb ? module.bootstrap_alb[0].target_group_arn : null` (NOT try() — try() would silently absorb a future output rename and let the precondition pass both-null, quietly regressing the wiring). Must be set together with bootstrap_alb_security_group_id — the both-null-or-both-set invariant is enforced by a precondition on aws_ecs_service.qurl in main.tf (precondition rather than dual variable-level validation because cross-var validation blocks form a cycle when each variable references the other)."
  type        = string
  default     = null

  # Structural ARN validation (regex). Matches the pattern used by other
  # ARN-typed vars in this file (jwt_secret_arn, nhp_internal_auth_secret_arn)
  # and tightens the account-ID segment to [0-9]{12} per the ACM-cert
  # convention at terraform/variables.tf (the stricter pattern in this
  # repo). `aws[a-z-]*` accepts commercial (aws), GovCloud (aws-us-gov),
  # and China (aws-cn). Catches typos and hand-threaded
  # "targetgroup-abc-123"-style mistakes at plan-time rather than mid-apply
  # with a less actionable AWS-side error.
  validation {
    condition     = var.bootstrap_alb_target_group_arn == null || can(regex("^arn:aws[a-z-]*:elasticloadbalancing:[a-z0-9-]+:[0-9]{12}:targetgroup/.+", var.bootstrap_alb_target_group_arn))
    error_message = "bootstrap_alb_target_group_arn must be null (= no attachment) or a valid ELBv2 target-group ARN (arn:aws<-partition>?:elasticloadbalancing:REGION:12-DIGIT-ACCOUNT:targetgroup/NAME/ID)."
  }
}

variable "bootstrap_alb_security_group_id" {
  description = "Security group ID of the bootstrap-ALB. When non-null, aws_security_group.ecs gains an ingress rule on var.container_port from this SG — the actual access control between the bootstrap-ALB ENIs and the qurl-service task ENIs (the bootstrap-ALB's egress is widened to vpc_cidr per modules/bootstrap-alb/security_groups.tf, so the task-SG-side rule is the load-bearing one). Threaded from env-root as `var.deploy_bootstrap_alb ? module.bootstrap_alb[0].alb_security_group_id : null` (NOT try() — same rename-regression rationale as bootstrap_alb_target_group_arn). Must be set together with bootstrap_alb_target_group_arn — invariant enforced by the same precondition referenced on bootstrap_alb_target_group_arn."
  type        = string
  default     = null

  # Structural SG-ID validation (regex). EC2 security-group IDs are
  # `sg-` followed by 8 hex chars (legacy) or 17 hex chars (current).
  # `+` keeps the regex partition-and-length-agnostic; the practical
  # win is rejecting empty / whitespace / typo'd identifiers (e.g.
  # `sgr-abc123`, `sg_abc123`) at plan-time.
  validation {
    condition     = var.bootstrap_alb_security_group_id == null || can(regex("^sg-[a-f0-9]+$", var.bootstrap_alb_security_group_id))
    error_message = "bootstrap_alb_security_group_id must be null (= no attachment) or a valid EC2 security-group ID (sg-XXXXXXXX or sg-XXXXXXXXXXXXXXXXX)."
  }
}

variable "internal_domain_name" {
  description = "Hostname served by the internal ALB (e.g., internal-api.qurl.layerv.xyz). Added to ALLOWED_HOSTS so HostValidation accepts it. Required when internal_alb_enabled = true."
  type        = string
  default     = null

  # RFC1035 label-shape FQDN check: each label starts/ends with an
  # alphanumeric, hyphens allowed only internally, labels separated
  # by dots, at least two labels. Mirrors the root variable
  # qurl_internal_service_domain regex for consistency.
  validation {
    condition     = var.internal_domain_name == null || can(regex("^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$", var.internal_domain_name))
    error_message = "internal_domain_name must be a valid RFC1035 FQDN (e.g., internal-api.qurl.layerv.xyz): each label 1-63 chars, alphanumeric edges, hyphens only internally, at least two labels, no leading/trailing dot."
  }
}

variable "internal_certificate_arn" {
  description = "ACM certificate ARN for the internal ALB HTTPS listener. Required when internal_alb_enabled = true. Must cover internal_domain_name. Independent of the public ALB cert (no SAN coupling)."
  type        = string
  default     = null

  # Structural ACM ARN check: catches the copy-pasted-wrong-cert class
  # at plan time rather than mid-apply when the listener attach fails.
  # Doesn't verify the cert covers internal_domain_name (ACM SAN list is
  # not cleanly available via TF data sources); SNI mismatch surfaces in
  # the smoke fence's TLS leg instead.
  validation {
    condition     = var.internal_certificate_arn == null || can(regex("^arn:aws:acm:[a-z0-9-]+:[0-9]+:certificate/[a-zA-Z0-9-]+$", var.internal_certificate_arn))
    error_message = "internal_certificate_arn must be a valid ACM certificate ARN (e.g., arn:aws:acm:us-east-2:123456789012:certificate/abc-...)."
  }
}

variable "enforce_internal_alb_only" {
  description = "When true, removes the legacy 'HTTP from VPC (cidr_blocks)' ingress rule on the ECS task SG, leaving only ingress from the public-ALB SG and (if internal_alb_enabled) internal-ALB SG. Closes the in-VPC bypass identified in qurl-service #335 architecture review. Apply with `false` first, verify the new path serves traffic, then flip to `true` and apply again."
  type        = bool
  default     = false
}

# ==================== Redis ====================

variable "redis_enabled" {
  description = "Enable Redis for distributed rate limiting"
  type        = bool
  default     = false
}

variable "redis_endpoint" {
  description = "Redis endpoint (host:port)"
  type        = string
  default     = ""
}

variable "redis_security_group_id" {
  description = "Security group ID for Redis access"
  type        = string
  default     = null
}

variable "redis_pool_size" {
  description = "Max connections in the Redis pool (0 = use application default)"
  type        = number
  default     = 0

  validation {
    condition     = var.redis_pool_size >= 0
    error_message = "redis_pool_size must be >= 0"
  }
}

variable "redis_min_idle_conns" {
  description = "Min idle connections kept open in the Redis pool (0 = use application default)"
  type        = number
  default     = 0

  validation {
    condition     = var.redis_min_idle_conns >= 0
    error_message = "redis_min_idle_conns must be >= 0"
  }
}

# ==================== Idempotency ====================

variable "idempotency_table_arn" {
  description = "DynamoDB table ARN for idempotency storage"
  type        = string
  default     = ""
}

variable "idempotency_table_name" {
  description = "DynamoDB table name for idempotency storage"
  type        = string
  default     = ""
}

# Control identity plane.
#
# Identity is not cell-scoped. A customer exists before any cell assignment, may
# hold resources in more than one cell, and must survive the loss of any single
# cell; the Connector Authority is global and validates enrollment credentials
# for every cell, so it reads the Control namespace only and never a cell. These
# variables let this module run its qurl-service against that Control identity
# namespace instead of its own cell tables.
#
# Empty is cell compatibility mode, which is the historical behavior and stays
# the default. Populating them is a deliberate cutover and REQUIRES the identity
# rows to already exist in Control -- switching first would point every existing
# customer at an empty namespace.

variable "control_identity_environment_id" {
  description = "Control namespace environment id (e.g. \"sandbox\"). Empty keeps cell identity mode."
  type        = string
  default     = ""
}

variable "control_identity_home_region" {
  description = "Home region of the Control identity tables. Required when control_identity_environment_id is set."
  type        = string
  default     = ""

  validation {
    condition     = var.control_identity_home_region == "" || can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]$", var.control_identity_home_region))
    error_message = "control_identity_home_region must be a canonical AWS region id."
  }
}

variable "control_identity_kms_key_arn" {
  description = <<-EOT
    KMS key encrypting the Control identity tables. Required when
    control_identity_environment_id is set: DynamoDB reads of an SSE-KMS table
    fail with AccessDeniedException unless the caller can decrypt with the
    table's key, and the Control tables use a different key than the cell ones.
  EOT
  type        = string
  default     = ""
}

variable "control_identity_table_arns" {
  description = <<-EOT
    ARNs of the Control identity tables this service may read and write
    (customers, api-keys, agent-keys, apikey-idempotency). Required when
    control_identity_environment_id is set. Index ARNs are derived, not listed.
  EOT
  type        = list(string)
  default     = []
}

variable "control_device_credential_authority_table_arn" {
  description = <<-EOT
    ARN of the Control Connector Authority table whose permanent device head
    qurl-service reads and atomically revokes with a device API key. Required
    when control_identity_environment_id is set. Kept separate from the broad
    identity table list so the public API task receives only GetItem and
    transaction-enclosed PutItem, fenced to owner partitions. DynamoDB IAM
    cannot constrain the sort-key prefix; the runtime enforces the exact
    device-head key and record shape.
  EOT
  type        = string
  default     = ""
}

variable "apikey_idempotency_table_arn" {
  description = "DynamoDB table ARN for API key mint idempotency storage"
  type        = string
  default     = ""
}

variable "apikey_idempotency_table_name" {
  description = "DynamoDB table name for API key mint idempotency storage"
  type        = string
  default     = ""
}

# ==================== Idempotency Cache ====================

variable "idempotency_cache_ttl_seconds" {
  description = "TTL for idempotency cache entries in seconds"
  type        = number
}

variable "idempotency_cache_max_size" {
  description = "Maximum number of idempotency cache entries"
  type        = number
}

variable "idempotency_cleanup_interval_seconds" {
  description = "Interval between idempotency cache cleanup runs in seconds"
  type        = number
}

# ==================== Health Check ====================

variable "health_check_timeout_seconds" {
  description = "Timeout for health check operations in seconds"
  type        = number
}

variable "health_startup_timeout_seconds" {
  description = "Timeout for startup health checks in seconds"
  type        = number
}

# ==================== Customer Cache Config ====================

variable "customer_cache_ttl_seconds" {
  description = "TTL for customer tier cache in seconds"
  type        = number
  default     = 300
}

variable "customer_cache_max_size" {
  description = "Maximum entries in the customer tier cache"
  type        = number
  default     = 1000
}

# ==================== QURL Resource Config ====================
#
# TTL Relationship:
# - qurl_default_expires_in_seconds: How long a QURL is valid (user-facing)
# - qurl_resource_ttl_buffer_seconds: Additional time before DynamoDB cleanup
#   (allows grace period for analytics, debugging expired resources)
# - qurl_session_ttl_seconds: How long session records persist
#   (should be <= qurl_default_expires_in_seconds + qurl_resource_ttl_buffer_seconds
#    to avoid sessions referencing deleted resources)

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

# ==================== Auth0 JWKS ====================

variable "auth0_jwks_cache_ttl_seconds" {
  description = "TTL for Auth0 JWKS cache in seconds"
  type        = number
}

variable "auth0_jwks_fetch_timeout_seconds" {
  description = "Timeout for fetching Auth0 JWKS in seconds"
  type        = number
}

# ==================== Webhooks ====================

variable "webhooks_enabled" {
  description = "Enable webhook delivery"
  type        = bool
  default     = false
}

variable "webhooks_worker_count" {
  description = "Number of concurrent webhook delivery workers"
  type        = number
}

variable "webhooks_max_webhooks_per_owner" {
  description = "Maximum number of webhooks per owner"
  type        = number
}

variable "webhooks_delivery_timeout_seconds" {
  description = "Timeout for webhook delivery in seconds"
  type        = number
}

variable "webhooks_max_retries" {
  description = "Maximum number of webhook delivery retries"
  type        = number
}

variable "webhooks_event_channel_size" {
  description = "Size of the webhook event channel buffer"
  type        = number
}

variable "webhooks_retry_worker_interval_seconds" {
  description = "Interval between webhook retry worker runs in seconds"
  type        = number
}

variable "webhooks_drain_timeout_seconds" {
  description = "Timeout for draining webhook events during shutdown in seconds"
  type        = number
}

variable "webhooks_response_body_limit" {
  description = "Maximum response body size to store from webhook endpoints in bytes"
  type        = number
}

variable "webhooks_api_version" {
  description = "API version string for webhook payloads"
  type        = string
}

# ==================== Observability (OpenTelemetry) ====================

variable "otel_enabled" {
  description = "Enable OpenTelemetry instrumentation"
  type        = bool
  default     = false
}

variable "otel_service_name" {
  description = "Service name for OpenTelemetry"
  type        = string
}

variable "otel_service_version" {
  description = "Service version for OpenTelemetry"
  type        = string
}

variable "otel_environment" {
  description = "Environment name for OpenTelemetry"
  type        = string
}

variable "otel_exporter_endpoint" {
  description = "OTLP exporter endpoint (e.g., http://localhost:4317)"
  type        = string
}

variable "otel_exporter_protocol" {
  description = "OTLP exporter protocol (grpc or http/protobuf)"
  type        = string
}

variable "otel_exporter_insecure" {
  description = "Use insecure connection to OTLP endpoint (for localhost sidecar)"
  type        = bool
}

variable "otel_trace_sample_rate" {
  description = "Trace sampling rate (0.0 to 1.0)"
  type        = number
}

variable "otel_metrics_interval" {
  description = "Metrics export interval in seconds"
  type        = number
}

variable "otel_metrics_enabled" {
  description = "Enable OpenTelemetry metrics"
  type        = bool
}

variable "otel_tracing_enabled" {
  description = "Enable OpenTelemetry tracing"
  type        = bool
}

variable "otel_log_correlation" {
  description = "Enable trace ID correlation in logs"
  type        = bool
}

# ==================== GeoIP ====================

variable "geoip_enabled" {
  description = "Enable GeoIP lookups for geo-restriction policies. Requires a MaxMind GeoLite2-Country .mmdb database."
  type        = bool
  default     = false
}

variable "geoip_db_path" {
  description = "Filesystem path where the GeoIP .mmdb database is stored inside the container."
  type        = string
  default     = "/app/data/GeoLite2-Country.mmdb"
}

variable "geoip_s3_uri" {
  description = <<-EOT
    S3 URI of the GeoLite2-Country .mmdb database (e.g., s3://my-bucket/geoip/GeoLite2-Country.mmdb).
    When set, the container entrypoint downloads the database from S3 on startup.
    Leave empty if the database is baked into the container image.
  EOT
  type        = string
  default     = ""

  validation {
    condition     = var.geoip_s3_uri == "" || can(regex("^s3://", var.geoip_s3_uri))
    error_message = "geoip_s3_uri must be an S3 URI starting with s3:// or empty."
  }
}

variable "geoip_s3_kms_key_arn" {
  description = "KMS key ARN used to encrypt the GeoIP S3 bucket. Required if the bucket uses SSE-KMS."
  type        = string
  default     = ""
}

# ==================== Grafana Cloud (ADOT Sidecar) ====================

variable "grafana_cloud_enabled" {
  description = "Enable Grafana Cloud OTLP export via ADOT sidecar. When enabled, adds an ADOT collector sidecar container that exports telemetry to Grafana Cloud."
  type        = bool
  default     = false
}

variable "grafana_secret_arn" {
  description = <<-EOT
    ARN of Secrets Manager secret containing Grafana Cloud OTLP credentials.
    Required when grafana_cloud_enabled = true.

    Secret must contain JSON with keys:
    - endpoint: Grafana Cloud OTLP gateway URL (e.g., https://otlp-gateway-prod-us-east-0.grafana.net/otlp)
    - auth: Base64-encoded "instance_id:api_token" for Basic authentication

    Create with:
    aws secretsmanager create-secret --name "layerv-nhp-sandbox/grafana-cloud-otlp" \
      --secret-string '{"endpoint":"https://otlp-gateway-prod-us-east-0.grafana.net/otlp","auth":"BASE64_ENCODED_CREDS"}'
  EOT
  type        = string
  default     = null

  validation {
    condition     = var.grafana_secret_arn == null || can(regex("^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]+:secret:.+$", var.grafana_secret_arn))
    error_message = "grafana_secret_arn must be a valid Secrets Manager ARN or null."
  }
}

variable "stripe_secret_arn" {
  description = "ARN of the Secrets Manager secret containing the Stripe API key"
  type        = string
  default     = ""
}

variable "stripe_growth_price_id" {
  description = "Stripe Price ID for the Growth plan"
  type        = string
  default     = ""
}

variable "stripe_checkout_success_url" {
  description = "Redirect URL after successful Stripe Checkout"
  type        = string
  default     = ""
}

variable "stripe_checkout_cancel_url" {
  description = "Redirect URL when user cancels Stripe Checkout"
  type        = string
  default     = ""
}

# ==================== NHP Integration ====================

variable "nhp_server_internal_url" {
  description = "Internal URL of NHP server for headless resolve knock requests (e.g., http://server.nhp.sandbox.internal:8888). Enables POST /v1/resolve endpoint. Private-primary mode requires the VPC-internal HTTP .internal:8888 origin so egress stays bound to the exact NHP server security group; HTTPS origins remain accepted only for legacy public/direct-module topologies. The .internal suffix matches the private DNS namespace in modules/data/main.tf, and HTTP .internal hostnames are expected to be lowercase Cloud Map/private DNS names."
  type        = string
  default     = ""

  validation {
    # Mirror of root `terraform_data.nhp_server_internal_url_preconditions`
    # and modules/qurl-reverse-tunnel-server/variables.tf::nhp_server_internal_url.
    # Examples: accept "", https://nhp.example.com, http://server.nhp.sandbox.internal:8888;
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

variable "nhp_server_security_group_id" {
  description = "Exact NHP-server security group permitted as the private qurl-service task's internal-API destination. In private-primary mode this must be set iff nhp_server_internal_url is non-empty. Public mode preserves the legacy egress contract and does not require it."
  type        = string
  default     = null

  validation {
    condition     = var.nhp_server_security_group_id == null || can(regex("^sg-[0-9a-f]+$", var.nhp_server_security_group_id))
    error_message = "nhp_server_security_group_id must be null or a valid lowercase AWS security group ID."
  }
}

variable "nhp_knock_timeout_seconds" {
  description = "Timeout for NHP knock requests in seconds"
  type        = number
  default     = 15
}

# ==================== QURL FRPS Integration (tunnel routing, #1499) ====================
# qurl-service hashes OwnerID to one of `frps_az_suffixes` and emits the
# matching `frps-${suffix}.${frps_domain}:${frps_port}` as `upstream_addr` in
# CreateResource / GetResourceTarget responses. frpc and the AC's qurl-router
# both consume this `upstream_addr` so they converge on the same instance.
# The suffix set MUST match the FRPS backends reachable by public FRP control
# ingress. A deployment with a multi-AZ FRPS fleet may intentionally pass a
# single suffix here while control ingress is single-target; widen it only
# when clients can register proxies on the widened set.

variable "frps_az_suffixes" {
  description = "Comma-separated AZ suffixes that qurl-service hashes OwnerID into (e.g., \"a\" or \"a,b,c\"). The qurl-service Go consumer splits on `,` and trims whitespace per entry; each entry must be a single lowercase letter matching the regex `^[a-z]$` (same shape as the qurl-reverse-tunnel-server module's list-form `frps_az_suffixes` validation). Empty disables FRPS env-var threading entirely (the env vars below get omitted), which is the behavior when deploy_frps = false at the root. Must match the FRPS backends reachable by public FRP control ingress; the root module may pass a subset of the physical FRPS fleet while ingress is single-target."
  type        = string
  default     = ""
}

variable "frps_domain" {
  description = "DNS namespace for per-AZ FRPS Cloud Map services (e.g., \"nhp.sandbox.internal\"). qurl-service constructs `frps-$${suffix}.$${frps_domain}:$${frps_port}` per resource. Empty disables FRPS env-var threading. Must agree with the namespace_name passed to qurl-reverse-tunnel-server."
  type        = string
  default     = ""
}

variable "frps_port" {
  description = "FRPS vhost HTTP port qurl-service emits in `upstream_addr`. Must agree with qurl-reverse-tunnel-server module's frps_vhost_http_port. Default 0 disables the env-var threading entirely (paired with the empty-string defaults above for the case where deploy_frps = false at the root)."
  type        = number
  default     = 0
}

variable "usage_events_enabled" {
  description = "Enable sending usage events to billing SQS queue"
  type        = bool
  default     = false
}

variable "usage_events_queue_url" {
  description = "SQS queue URL for billing usage events"
  type        = string
  default     = ""
}

variable "usage_events_queue_arn" {
  description = "SQS queue ARN for IAM permissions"
  type        = string
  default     = ""
}

# ==================== Custom Domains ====================

variable "custom_domain_enabled" {
  description = "Enable custom domain management endpoints (GET/POST/DELETE /v1/domains)"
  type        = bool
  default     = false
}

variable "custom_domain_acme_suffix" {
  description = "ACME CNAME target suffix for DNS-01 challenge delegation (e.g., acme.layerv.xyz)"
  type        = string
  default     = ""
}

variable "custom_domain_nlb_target" {
  description = "AC NLB hostname for custom domain traffic routing verification"
  type        = string
  default     = ""
}

variable "custom_domain_cleanup_topic_arn" {
  description = "SNS topic ARN that DeleteDomain publishes domain.cleanup events to. Consumed by the cert Lambda in nhp; see nhp#1990 / qurl-service#148. Ignored unless custom_domain_cleanup_publish_enabled is true."
  type        = string
  default     = ""

  validation {
    condition     = var.custom_domain_cleanup_topic_arn == "" || can(regex("^arn:aws:sns:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9_-]+$", var.custom_domain_cleanup_topic_arn))
    error_message = "custom_domain_cleanup_topic_arn must be a valid SNS topic ARN or empty."
  }
}

variable "custom_domain_cleanup_publish_enabled" {
  description = "Static boolean: when true, the ECS task role is granted sns:Publish on custom_domain_cleanup_topic_arn. Paired with custom_domain_cleanup_topic_arn (which is the env's `aws_sns_topic.custom_domain_cleanup[0].arn` — a computed value, unknown at plan time, so a `count = var.custom_domain_cleanup_topic_arn != \"\" ? 1 : 0` would fail with 'Invalid count argument'). Container env injection still keys on the arn-non-empty check because env values may be apply-time computed without breaking plan."
  type        = bool
  default     = false
}

variable "adot_collector_image" {
  description = "ADOT Collector container image. Uses AWS public ECR for the official ADOT image."
  type        = string
  default     = "public.ecr.aws/aws-observability/aws-otel-collector:v0.40.0"
}

# ==================== Connector Auth ====================

variable "connector_auth_enabled" {
  description = "Enable the qurl-service connector-auth code paths (POST /internal/v1/tunnel/auth + type=tunnel branches in CreateQurl/CreateResource). Default false keeps the new surface inert in prod until the creation endpoint (qurl-service #405) and per-AZ FRPS assignment (qurl-service #396) are both deployed. See PR #277 for the gate; flip per-env via tfvars after the dependent qurl-service work ships."
  type        = bool
  default     = false
}

variable "connector_active_registrations_enabled" {
  description = "Enable authoritative active tunnel target reads from qurl-reverse-tunnel-server registration rows. When false, qurl-service continues to emit only legacy per-AZ upstream_addr values even if registration writes are arriving. Flip after reporter and router active-target support are deployed and observed healthy."
  type        = bool
  default     = false
}

# ==================== QURL agent → nhp-server bootstrap chain (Wave 5) ====================

variable "deploy_qurl_bootstrap_chain" {
  description = "Structural-only gate for the qurl-service ↔ nhp-server agent bootstrap chain — agent activation is gated separately via `enable_qurl_agent_bootstrap`. When true, injects four env vars on the ECS task def (NHP_SERVER_PUBLIC_KEY_B64, NHP_SERVER_HOST, NHP_SERVER_PORT, QURL_AGENT_BOOTSTRAP_ENABLED) alongside the existing NHP_SERVER_INTERNAL_URL. Same wiring shape (TF-injected env vars, no runtime SSM fetch). Default false leaves prod and any environment that hasn't opted in untouched. Enable per-env via tfvars."
  type        = bool
  default     = false
}

variable "enable_qurl_agent_bootstrap" {
  description = "Wave 5 activation flag for the qurl-service agent → nhp-server bootstrap chain. Drives the QURL_AGENT_BOOTSTRAP_ENABLED env var on the task def. Default false: the chain stays inert until this is flipped to true per environment. Only consulted when deploy_qurl_bootstrap_chain = true."
  type        = bool
  default     = false
}

variable "retire_http_agent_lifecycle" {
  description = "Delete the qurl-service-owned Terraform sentinels and IAM grant for the retired HTTP agent lifecycle after runtime consumers have been detached."
  type        = bool
  default     = false
}

variable "nhp_server_public_key_b64" {
  description = "NHP server-identity public key (base64; raw 32-byte X25519 key). Threaded from `module.compute.server_public_key_b64` at the root — the key the running NHP server actually signs NHP packets with. NOT `module.nhp_keypair.registration_public_key` (which is the shared AC↔server registration key — a different role; wiring that here silently breaks every agent knock with a server-HMAC-validation failure). Consumed only when deploy_qurl_bootstrap_chain = true; pass empty string when the gate is off."
  type        = string
  default     = ""

  # Catch keypair-output shape drift at plan time. Allows empty when the
  # gate is off; otherwise requires the encoded shape of a base64'd
  # 32-byte value — 43 base64 chars + 1 `=` padding char = 44 chars
  # total. Defends against producer-side changes that wrap the key in
  # PEM, add leading whitespace from a Lambda JSON re-encode, etc. —
  # qurl-service would otherwise blow up at consume time with no
  # plan-time signal.
  #
  # Why a regex on the encoded value and not `base64decode(...)` +
  # `length(...)`? Terraform's `base64decode` interprets the decoded
  # bytes as UTF-8 and errors out if they aren't valid UTF-8 — random
  # X25519 key bytes almost always contain a byte outside the valid
  # UTF-8 leading-byte range (e.g. the live sandbox key starts with
  # 0x9c, a continuation byte). The prior `can(base64decode(...))`
  # form returned false for every real key it was meant to admit.
  # Even if the decoded bytes happen to be valid UTF-8, `length()` on
  # a string returns codepoint count rather than byte count, so the
  # `== 32` comparison is a different check than intended. Validating
  # the encoded shape sidesteps both issues.
  #
  # Greenfield caveat: on a fresh env where `module.nhp_keypair` hasn't
  # yet applied, the threaded value resolves through
  # `aws_lambda_invocation.keygen.result` and is "known after apply".
  # Terraform 1.5+ defers `validation` blocks against unknown values to
  # apply time, so the shape-check still runs — just at apply, not at
  # plan. Same posture as the module-side `terraform_data` precondition;
  # a fail-loud apply error is strictly better than runtime agent
  # failure either way.
  validation {
    condition     = var.nhp_server_public_key_b64 == "" || can(regex("^[A-Za-z0-9+/]{43}=$", var.nhp_server_public_key_b64))
    error_message = "nhp_server_public_key_b64 must be empty (gate off) or a base64-encoded 32-byte X25519 public key (44 chars total: 43 base64 chars + `=` padding). Got a malformed value — check module.compute.server_public_key_b64's output shape."
  }
}

variable "nhp_server_host" {
  description = "NHP server NLB DNS name (intentionally a DNS name rather than an IP — NLB DNS resolution and TTL semantics are the consumer's responsibility at the agent). Threaded from `module.compute.nlb_dns_name` at the root. Consumed only when deploy_qurl_bootstrap_chain = true; pass empty string when the gate is off."
  type        = string
  default     = ""

  # Bare-hostname shape check. `module.compute.nlb_dns_name` returns
  # a bare DNS name today (e.g.
  # `nhp-sandbox-<...>.elb.us-east-1.amazonaws.com`); this fence catches
  # a future producer change that wraps a scheme, path, or port around
  # the value before the agent fails the NHP/UDP handshake at runtime.
  # Same greenfield "known after apply" caveat applies as on the
  # public-key validation — Terraform 1.5+ defers to apply when the
  # value is unknown at plan time.
  #
  # Narrower than RFC 1035 on purpose: the regex accepts lowercase
  # ASCII labels with `[a-z]{2,}` TLDs only, so it would reject an IDN
  # A-label TLD (e.g. `.xn--p1ai`). NLB DNS names are lowercase ASCII
  # by AWS spec, and the upstream `nhp_keypair` + `compute` producers
  # have no IDN code paths — this is the deliberate tradeoff. Don't
  # loosen without checking what edge case prompted it.
  validation {
    condition     = var.nhp_server_host == "" || can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]\\.[a-z]{2,}$", var.nhp_server_host))
    error_message = "nhp_server_host must be empty (gate off) or a bare DNS name — no scheme, path, port, or whitespace. Got an unparseable value; check `module.compute.nlb_dns_name`'s output shape."
  }
}

variable "nhp_server_port" {
  description = "Public NHP client-edge UDP port advertised to agents via NHP_SERVER_PORT. This is the cell NLB's listener port (443), NOT the server's own 62206 bind — the NLB translates between them, so this must track `aws_lb_listener.udp` in `modules/compute` and `endpoints/ac.DefaultServerPort`, not the UDP target group. Consumed only when deploy_qurl_bootstrap_chain = true."
  type        = string
  default     = "443"

  # No leading zeros — `"0443"` would validate as 443 but inject the
  # literal `"0443"` into the env var, which a strict consumer parser
  # would reject at task startup. Anchor with `^[1-9][0-9]*$` so the
  # string representation matches what the consumer expects.
  validation {
    condition     = can(regex("^[1-9][0-9]*$", var.nhp_server_port)) && tonumber(var.nhp_server_port) <= 65535
    error_message = "nhp_server_port must be a numeric string in [1, 65535] with no leading zeros (e.g., \"443\")."
  }
}

# ==================== Scanner Lambda ====================
#
# Drives `scanner_lambda.tf`. The repo + SSM image-tag param gate on
# `deploy_qurl_service` (so qurl-service CI can publish images regardless
# of the Lambda enable flag); the Lambda + cron + alarm gate on
# `qurl_scanner_lambda_enabled`. See `scanner_lambda.tf` for the full
# rollout sequence and the resource list each gate covers.

variable "qurl_scanner_lambda_enabled" {
  description = "Create the scheduled qurl-scanner Lambdas + EventBridge schedules + scan-gap alarms. Default OFF. Setting true on a greenfield env fails with `InvalidParameterValueException: Source image ... does not exist` until qurl-service CI has published its first image — the two-apply rollout sequences this. Sandbox-only on first applies; prod rollout preconditions are tracked in the prod rollout task ledger."
  type        = bool
  default     = false
}

# CANONICAL RATIONALE for the activation flag — all other-layer
# declarations of `qurl_scanner_sqs_emit_enabled` (root,
# sandbox/prod env vars, sandbox tfvars) cross-reference this block.
#
# # What it does
#
# Flips the producer (scanner Lambda) AND consumer (qurl-api ECS task)
# wiring of the `resource_lifecycle_queue`. When true:
#
#   - Scanner Lambda gets `QURL_SCANNER_EMIT_MODE=sqs` +
#     `QURL_SCANNER_SQS_QUEUE_URL=<resource-lifecycle queue URL>`
#     (binary publishes `qurl.expired` / `resource.closed` envelopes
#     via SQS SendMessage instead of slog-only).
#   - qurl-api task def gets `WEBHOOK_EVENTS_CONSUMER_ENABLED=true` +
#     `WEBHOOK_EVENTS_SQS_QUEUE_URL=<same URL>` (qurl-service PR #874
#     drainer goroutine wakes up and starts dequeueing).
#
# # Ordering (NOT atomic in one apply — important nuance)
#
# Conceptually a "both-at-once" flip, but the CI workflow splits the
# apply into stages — producer flips during `deploy-sandbox-infra` (a
# plain Lambda env update with no rollback), consumer flips during the
# LATER `deploy-sandbox-qurl` ECS roll (circuit-breaker protected).
# So there's an inherent producer-first ordering, plus a short window
# where a scheduled scanner tick could publish to SQS before the
# consumer is draining. While the consumer is starting up, accumulated
# messages stay in the MAIN queue (consumer not yet receiving, so
# `maxReceiveCount` doesn't trip and the DLQ stays empty); the window
# is bounded by `message_retention_seconds = 345600` (4 days) and
# alarmed via `resource_lifecycle_queue_backlog` (`Sum > 1000 for
# 3 × 5min`). Harmless in normal operation.
#
# # Rollback de-atomization risk
#
# If the qurl-api task def fails `/health/live` on the new revision,
# ECS `deployment_circuit_breaker { rollback = true }` reverts to the
# prior task def — which does NOT carry the consumer env vars. The
# scanner Lambda's config update, however, has no rollback. Net:
# producer ON, consumer OFF → main-queue backlog accumulates (NOT
# DLQ — consumer isn't receiving, so retries never trip; bounded by
# `message_retention_seconds = 345600` / 4 days, watched by
# `resource_lifecycle_queue_backlog` alarm). This is the exact
# unsafe direction the design tried to avoid. The DLQ + redrive
# policy bound the orthogonal consumer-running-but-failing case.
#
# # When to flip
#
# `build-and-push.yml` triggers on push to main with paths
# `terraform/**`, so MERGING a tfvar flip auto-applies — there is no
# manual dispatch to hold. The safe rollout is:
#
#   1. Land the variable plumbing with `qurl_scanner_sqs_emit_enabled
#      = false` everywhere (this PR).
#   2. Verify qurl-service main has shipped a confirmed-healthy
#      qurl-api image (the current 7791fcc-class image fails
#      `/health/live` per the dispatched run that landed the scanner
#      Lambda). `aws ssm get-parameter --name
#      /layerv-nhp-sandbox/qurl-api-image-tag --query
#      'Parameter.Value' --output text` should return that SHA, and
#      its `/health/live` should be green when the task boots.
#   3. Flip the sandbox tfvar to true in a tiny follow-up PR. The
#      merge auto-applies; the apply lands the env-var changes
#      cleanly because the upstream image boots.
#   4. POST-APPLY: verify the active task def revision is the new one
#      (not a rolled-back prior) — `aws ecs describe-services ...
#      --query 'services[].deployments[?status==\`PRIMARY\`].taskDefinition'`.
#      If it returns a rolled-back prior, the producer is ON but
#      consumer is OFF — flip the tfvar back to false + re-apply to
#      close the skew gap.
#
# # Default + prod
#
# Default false: the queue + DLQ exist (gated on
# `qurl_scanner_lambda_enabled`) but are unused. Setting true requires
# `qurl_scanner_lambda_enabled = true` — without the Lambda, there's
# nothing to emit, so the `resource_lifecycle_queue` resource doesn't
# exist (count=0). Enforcement: the qurl-api task def's `lifecycle {
# precondition }` block in `main.tf` covers BOTH the producer and
# consumer sides with a single check (the task def is always planned,
# unlike the count-gated scanner Lambda). Belt-and-suspenders on top:
# both env-var conditionals AND `qurl_scanner_lambda_enabled` so the
# `[0]` lookups against the queue resource are structurally unreachable
# under the operator-misconfig case (`emit=true, lambda=false`).
#
# Prod: stays false until sandbox e2e + load-test gates clear. The
# #2326 ledger entry tracks the prod preconditions.
variable "qurl_scanner_sqs_emit_enabled" {
  description = "Activate the resource-lifecycle SQS data path — flips scanner Lambda emit-mode to `sqs` + wakes the qurl-api consumer goroutine. Requires `qurl_scanner_lambda_enabled = true`. Default false (queue + DLQ exist but are unused). See `scanner_lambda.tf`'s `environment.variables` merge for the producer wiring, `main.tf`'s `local.container_env` for the consumer wiring."
  type        = bool
  default     = false
}

variable "qurl_scanner_tombstone_write_enabled" {
  description = "Enable destructive scanner tombstone writes (`QURL_SCANNER_ENABLE_TOMBSTONE_WRITE=true`). Requires `qurl_scanner_sqs_emit_enabled = true` so resource.closed is delivered to the SQS consumer before any resource is flipped to 410-Gone. The active-resource recheck scheduler has its own later flag so this per-minute tombstone-write phase can burn in first."
  type        = bool
  default     = false
}

variable "qurl_scanner_active_recheck_enabled" {
  description = "Create the hourly active-resource recheck scheduler. Requires `qurl_scanner_tombstone_write_enabled = true` so each broad status-index sweep can tombstone close-eligible resources instead of repeatedly re-emitting them. Keep false while SQS and per-minute tombstone writes burn in."
  type        = bool
  default     = false
}

variable "qurl_scanner_lambda_ecr_repo_url" {
  description = "ECR repository URL for the qurl-scanner Lambda image (e.g. `<acct>.dkr.ecr.<region>.amazonaws.com/layerv/qurl-scanner-lambda`). Threaded from `module.ecr.qurl_scanner_lambda_repo_url`. Empty is the gate-OFF default; the Lambda's `lifecycle { precondition }` block fails plan with a copy-pasteable error if `qurl_scanner_lambda_enabled = true` and this is empty (so an enabled Lambda can never reference a malformed `image_uri`)."
  type        = string
  default     = ""
}

variable "qurl_scanner_lambda_ecr_repo_arn" {
  description = "ECR repository ARN for the qurl-scanner Lambda image (threaded from `module.ecr.qurl_scanner_lambda_repo_arn`). Consumed as the `input` of `terraform_data.scanner_ecr_ready`; see the COUNT GATE block on that resource in `scanner_lambda.tf` for the apply-time ordering rationale and the regression trail (#2326 -> #2327, lint follow-up #2328)."
  type        = string
  default     = ""
}

variable "qurl_scanner_lambda_image_tag_ssm_param" {
  description = "SSM parameter name carrying the qurl-scanner Lambda image tag (e.g. `/layerv-nhp-sandbox/qurl-scanner-lambda-image-tag`). Must match the path qurl-service `build-and-deploy.yml` writes to (`SSM_SCANNER_LAMBDA_IMAGE_TAG_SANDBOX`). This module creates the param seeded `\"latest\"` with `ignore_changes = [value]` and reads its CURRENT value via `data.aws_ssm_parameter` at plan time so each apply picks up the latest CI-written SHA."
  type        = string
  default     = ""

  validation {
    condition     = var.qurl_scanner_lambda_image_tag_ssm_param == "" || can(regex("^/[A-Za-z0-9._/-]+$", var.qurl_scanner_lambda_image_tag_ssm_param))
    error_message = "qurl_scanner_lambda_image_tag_ssm_param must be empty (gate off) or a leading-slash SSM parameter name (e.g., \"/layerv-nhp-sandbox/qurl-scanner-lambda-image-tag\")."
  }
}

variable "qurl_resources_table_arn" {
  description = "ARN of the qurl-resources DynamoDB table (UpdateItem + GetItem + DeleteItem from the scanner Lambdas, plus Query on `status-index` for active-resource rechecks). Threaded from `module.dynamodb.qurl_resources_table_arn`. Empty is the gate-OFF default; the Lambda precondition fails plan if `qurl_scanner_lambda_enabled = true` and this is empty."
  type        = string
  default     = ""
}

variable "qurl_access_tokens_table_arn" {
  description = "ARN of the qurl-access-tokens DynamoDB table (Query on `time-bucket-index` GSI for the per-minute scan, Query on `resource-token-index` for active-qurl precondition, UpdateItem to set per-qurl `expired_webhook_fired_at`). Threaded from `module.dynamodb.qurl_access_tokens_table_arn`. Empty is the gate-OFF default; the Lambda precondition fails plan if `qurl_scanner_lambda_enabled = true` and this is empty."
  type        = string
  default     = ""
}

variable "qurl_sessions_table_arn" {
  description = "ARN of the qurl-sessions DynamoDB table (Query by `resource_id` PK with TTL filter for the session-active precondition — the session counter has a documented TTL-drift bug that rules out the simpler counter-based check). Threaded from `module.dynamodb.qurl_sessions_table_arn`. Empty is the gate-OFF default; the Lambda precondition fails plan if `qurl_scanner_lambda_enabled = true` and this is empty."
  type        = string
  default     = ""
}

variable "scanner_lambda_memory_mb" {
  description = "Memory size for the qurl-scanner Lambda. 512 MB matches the per-tick working set of ~16 parallel shard Queries + JSON marshal of up to MaxEventsPerShard events; no measured pressure to raise it. Set higher only if CloudWatch shows OOM kills."
  type        = number
  default     = 512

  validation {
    condition     = var.scanner_lambda_memory_mb >= 128 && var.scanner_lambda_memory_mb <= 10240
    error_message = "scanner_lambda_memory_mb must be in [128, 10240] per the Lambda quota for the `provided.al2023` runtime."
  }
}

variable "scanner_lambda_timeout_seconds" {
  description = "Per-invocation timeout (seconds) for the qurl-scanner Lambda. Defaulted to 50s — gives a ~10s headroom under the EventBridge `rate(1 minute)` cadence so a long-running tick aborts and frees the reserved-concurrency slot BEFORE the next cron fire (a tick that ran the full 60s under `reserved_concurrent_executions = 1` would race the next invocation and throttle it). The binary's carry-over cursor recovers the aborted bucket on the next tick. Cap is 60 (would collide with the next tick on every run)."
  type        = number
  default     = 50

  validation {
    condition     = var.scanner_lambda_timeout_seconds >= 1 && var.scanner_lambda_timeout_seconds <= 60
    error_message = "scanner_lambda_timeout_seconds must be in [1, 60] to stay under the rate(1 minute) cadence."
  }
}

variable "scanner_active_recheck_timeout_seconds" {
  description = "Per-invocation timeout (seconds) for the hourly active-resource recheck Lambda. Default 300s gives the status-index sweep room to close session-drained resources without sharing the per-minute expiry scanner's strict 60s cadence budget. Keep below the hourly schedule interval; raise only with measured CloudWatch duration data."
  type        = number
  default     = 300

  validation {
    condition     = var.scanner_active_recheck_timeout_seconds >= 1 && var.scanner_active_recheck_timeout_seconds <= 900
    error_message = "scanner_active_recheck_timeout_seconds must be in [1, 900] per the Lambda maximum timeout."
  }
}

variable "scanner_lambda_log_retention_days" {
  description = "CloudWatch Logs retention (days) for the qurl-scanner Lambda's log group. Null (default) lets the module pick `local.is_prod ? 365 : 30`, mirroring the ECS task log group's per-env shape. Override only to pin a specific retention in a multi-tenant test env."
  type        = number
  default     = null

  validation {
    condition     = var.scanner_lambda_log_retention_days == null || contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 2192, 2557, 2922, 3288, 3653], var.scanner_lambda_log_retention_days == null ? 30 : var.scanner_lambda_log_retention_days)
    error_message = "scanner_lambda_log_retention_days must be null (auto) or one of the CloudWatch-Logs-supported retention values (see aws_cloudwatch_log_group.retention_in_days docs)."
  }
}

variable "qurl_service_alarm_sns_topic_arn" {
  description = "SNS topic ARN for qurl-service CloudWatch alarm actions (qurl-api, scanner Lambda, and resource-lifecycle queue). The root module wires this to the cell-wide alerts topic (`module.monitoring.sns_topic_arn`), the same topic every other alarm in the cell routes to (#2491). Empty string keeps the safe-degrade seam — the alarm still fires + appears in CloudWatch, but publishes no notification — so the module stays reusable by a caller with no alerts topic."
  type        = string
  default     = ""

  validation {
    condition     = var.qurl_service_alarm_sns_topic_arn == "" || can(regex("^arn:aws:sns:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9._-]+$", var.qurl_service_alarm_sns_topic_arn))
    error_message = "qurl_service_alarm_sns_topic_arn must be empty or a standard SNS topic ARN (arn:aws:sns:<region>:<account>:<name>)."
  }
}

variable "target_health_alarm_enabled" {
  description = "Create a fail-closed HealthyHostCount alarm for the primary ALB target group. Enable for private cell services that must have at least one routable task before activation."
  type        = bool
  default     = false
}

# ==================== qURL v2 (keyed identity) ====================
# Feature gates for qURL v2 issuance. All default false (dark launch). Dependency
# order is enforced fail-closed by qurl-service's own Config.Validate at boot:
# issuance requires issuer-key + resource-keys, so flip them together in tfvars.

variable "qurl_v2_issuer_key_enabled" {
  description = "Emit QURL_V2_ISSUER_KEY_ENABLED + issuer key ARN/kid/role env on qurl-api and grant kms:Sign on the issuer key. Requires qurl_v2_issuer_key_arn. Default false."
  type        = bool
  default     = false
}

variable "qurl_v2_resource_keys_enabled" {
  description = "Emit QURL_V2_RESOURCE_KEYS_ENABLED and grant the tag-scoped per-resource KMS create/reap policy so qurl-service mints a P-256 key per protected resource. Default false."
  type        = bool
  default     = false
}

variable "qurl_v2_resource_key_envelope_key_arn" {
  description = "ARN of the single shared envelope CMK (from module.kms.qurl_v2_resource_key_envelope_key_arn) used to wrap SOFTWARE-custody resource private keys. Must be a key ARN, never an alias ARN (the validation rejects aliases). Emitted as QURL_V2_RESOURCE_KEY_ENVELOPE_KMS_ARN and granted kms:GenerateDataKey only (Decrypt lands with the delegation-proof read path). Required (non-empty) when qurl_v2_resource_keys_enabled = true."
  type        = string
  default     = ""

  validation {
    condition     = var.qurl_v2_resource_key_envelope_key_arn == "" || can(regex("^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[a-z0-9-]+$", var.qurl_v2_resource_key_envelope_key_arn))
    error_message = "qurl_v2_resource_key_envelope_key_arn must be empty or a valid KMS key ARN."
  }
}

variable "qurl_v2_resource_key_software_default" {
  description = "Dark-launch ramp for software key custody. false ⇒ hardware-for-all (KMS CMK per resource, byte-identical to pre-software behavior) even for unentitled owners; true ⇒ custody chosen per owner (HardwareKeyStorage entitlement ⇒ KMS, else software). Emitted as QURL_V2_RESOURCE_KEY_SOFTWARE_DEFAULT. Default false."
  type        = bool
  default     = false
}

variable "qurl_v2_resource_key_reaper_enabled" {
  description = "Run the periodic resource-key reaper in qurl-api: reconciles per-resource KMS CMKs against live resources and schedules deletion of orphans (dead/revoked/tombstoned owners), which otherwise bill ~$1/month each forever. Emits QURL_V2_RESOURCE_KEY_REAPER_* env and grants tag:GetResources. Requires qurl_v2_resource_keys_enabled. Default false."
  type        = bool
  default     = false
}

variable "qurl_v2_resource_key_reaper_interval_seconds" {
  description = "Resource-key reaper sweep cadence in seconds. Default 21600 (6h) — cost granularity is $1/key/month, so tighter cadences buy nothing."
  type        = number
  default     = 21600

  validation {
    condition     = var.qurl_v2_resource_key_reaper_interval_seconds >= 300
    error_message = "qurl_v2_resource_key_reaper_interval_seconds must be >= 300 (matches the service-side config floor)."
  }
}

variable "qurl_v2_issuance_enabled" {
  description = "Emit QURL_V2_ISSUANCE_ENABLED + QURL_V2_RELAY_URL so createQurl mints v2 signed-claims links (and mounts the admission surface). Requires issuer-key + resource-keys enabled. Default false."
  type        = bool
  default     = false
}

variable "qurl_v2_issuer_key_arn" {
  description = "ARN of the qURL v2 issuer signing KMS key (from module.kms.qurl_v2_issuer_key_arn). Required when qurl_v2_issuer_key_enabled = true."
  type        = string
  default     = ""

  validation {
    # arn:aws[a-z-]*: matches the aws / aws-us-gov / aws-cn partitions; key/[a-z0-9-]+
    # accepts both UUID key ids and multi-Region key ids (mrk-...).
    condition     = var.qurl_v2_issuer_key_arn == "" || can(regex("^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[a-z0-9-]+$", var.qurl_v2_issuer_key_arn))
    error_message = "qurl_v2_issuer_key_arn must be empty or a valid KMS key ARN."
  }
}

variable "qurl_v2_issuer_kid" {
  description = "Key id (kid) stamped into signed claims and used as the trust-store key on both verifiers. Must match the NHP server's QURL_V2_ISSUER_TRUST_STORE key. Required when qurl_v2_issuer_key_enabled = true."
  type        = string
  default     = ""

  validation {
    # The kid is both a JSON object key in the computed trust store and the
    # QURL_V2_ISSUER_KEY_KID env value; a stray char (space, newline, =) would break
    # signer/verifier kid matching -> ErrUnknownKID -> every admission denies. Pin it.
    condition     = var.qurl_v2_issuer_kid == "" || can(regex("^[A-Za-z0-9._-]+$", var.qurl_v2_issuer_kid))
    error_message = "qurl_v2_issuer_kid must be empty or contain only [A-Za-z0-9._-]."
  }
}

variable "qurl_v2_relay_url" {
  description = "Deployment relay endpoint embedded in signed claims as relay_url (HTTPS, must be on the relay allowlist). Required when qurl_v2_issuance_enabled = true."
  type        = string
  default     = ""

  validation {
    condition     = var.qurl_v2_relay_url == "" || can(regex("^https://", var.qurl_v2_relay_url))
    error_message = "qurl_v2_relay_url must be empty or an https:// URL."
  }
}

variable "qurl_v2_relay_allowlist" {
  description = "Comma-separated host[:port] allowlist a qURL v2 relay_url may target (QURL_V2_RELAY_ALLOWLIST). Required when qurl_v2_issuer_key_enabled = true."
  type        = string
  default     = ""

  validation {
    # Comma-separated host[:port] tokens — no spaces and no scheme. Catches a
    # fat-fingered "https://..." or space-separated value at plan time; qurl-service
    # boot Config.Validate remains the authoritative parser.
    condition     = var.qurl_v2_relay_allowlist == "" || can(regex("^[A-Za-z0-9.:_-]+(,[A-Za-z0-9.:_-]+)*$", var.qurl_v2_relay_allowlist))
    error_message = "qurl_v2_relay_allowlist must be empty or a comma-separated list of host[:port] entries (no spaces or scheme)."
  }
}

variable "qurl_v2_resource_key_protected_kms_arns" {
  description = "KMS key ARNs the per-resource-key policy explicitly Denies destructive actions on (the account encryption CMKs + the issuer key), threaded from the root's module.kms outputs. Must be non-empty when qurl_v2_resource_keys_enabled = true — the Deny is a required safety guard, not optional hardening."
  type        = list(string)
  default     = []
}

# ==================== Agent registration + email OTP (T1) ====================
#
# Two independent flags with a dependency order enforced by qurl-service's own
# boot-time Config.Validate (fail-closed), mirrored here in env-var emission so a
# dark env's task def is byte-unchanged:
#   OTP_ENABLED   ⇒ REGISTRATION_ENABLED + EMAIL_FROM + PEPPER
#   REGISTRATION_ENABLED ⇒ bootstrap-enabled + a relay URL
# The pepper is the only secret — it rides `container_secrets` (valueFrom the
# Secrets Manager ARN), everything else is a plain env var.

variable "agent_registration_enabled" {
  description = "PATH A gate — drives QURL_AGENT_REGISTRATION_ENABLED on the qurl-service task def. When true qurl-service accepts the internal agent-register credential-exchange path. qurl-service's Config.Validate requires the agent bootstrap chain to be enabled and a relay base URL to be set when this is on; the root wires QURL_NHP_RELAY_BASE_URL alongside it. Default false leaves prod/any un-opted env byte-unchanged."
  type        = bool
  default     = false
}

variable "agent_otp_enabled" {
  description = "PATH B gate — drives QURL_AGENT_OTP_ENABLED on the qurl-service task def. When true qurl-service serves the email-OTP register flow (send OTP via SES, then verify). qurl-service's Config.Validate requires agent_registration_enabled + a non-empty email_from + the pepper secret when this is on. Default false: the OTP path stays inert (and the SES infra at the root creates nothing) until flipped per-env."
  type        = bool
  default     = false
}

variable "agent_otp_email_from" {
  description = "Envelope/From address qurl-service stamps on OTP emails (QURL_AGENT_OTP_EMAIL_FROM), e.g. `noreply@notify.layerv.ai`. The root derives the SES sender domain from this value. Required (non-empty) when agent_otp_enabled = true; leave empty when the OTP path is dark."
  type        = string
  default     = ""

  validation {
    # Empty (dark) or a bare RFC5322-ish addr-spec — no display name, no angle
    # brackets, no whitespace — because the root's `split(\"@\", ...)` derives the
    # SES identity domain from the part after the single `@`. qurl-service's boot
    # config remains the authoritative parser; this only fences the shape the
    # root's domain-derivation relies on.
    condition     = var.agent_otp_email_from == "" || can(regex("^[^@[:space:]]+@[a-z0-9][a-z0-9.-]*[a-z0-9]\\.[a-z]{2,}$", var.agent_otp_email_from))
    error_message = "agent_otp_email_from must be empty (OTP dark) or a bare local@domain address (no display name, angle brackets, or whitespace) — the root derives the SES sender domain from the part after `@`."
  }
}

variable "agent_otp_relay_base_url" {
  description = "Base URL of the nhp relay the agent-register flow points clients at (QURL_NHP_RELAY_BASE_URL). Required (non-empty https URL) when agent_registration_enabled = true — qurl-service's Config.Validate rejects registration-on with no relay URL. Empty when registration is dark."
  type        = string
  default     = ""

  validation {
    condition     = var.agent_otp_relay_base_url == "" || can(regex("^https://", var.agent_otp_relay_base_url))
    error_message = "agent_otp_relay_base_url must be empty (registration dark) or an https:// URL."
  }
}

variable "agent_otp_pepper_secret_arn" {
  description = "Secrets Manager ARN of the QURL_AGENT_OTP_PEPPER secret (32+ chars), created + seeded at the root and gated on agent_otp_enabled. Added to container_secrets (valueFrom) and to the execution role's GetSecretValue statement only when non-empty. Empty when the OTP path is dark → no secret is referenced and no IAM grant is added."
  type        = string
  default     = ""

  validation {
    # Empty (dark) or a Secrets Manager ARN — accepts commercial (aws), GovCloud
    # (aws-us-gov), and China (aws-cn) partitions. Mirrors nhp_internal_auth_secret_arn.
    condition     = var.agent_otp_pepper_secret_arn == "" || can(regex("^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:[0-9]+:secret:.+$", var.agent_otp_pepper_secret_arn))
    error_message = "agent_otp_pepper_secret_arn must be empty (OTP dark) or a valid Secrets Manager ARN."
  }
}

variable "agent_otp_config_set_name" {
  description = "Name of the SES v2 configuration set qurl-service passes as configuration_set_name on every OTP SendEmail — created at the ROOT (agent_otp_ses.tf) as `<name_prefix>-agent-otp` and wired in from there. SESv2 SendEmail WITH a configuration set authorizes ses:SendEmail against BOTH the sender identity AND the config-set resource, so the task-role send grant (task_agent_otp_ses) must list this config-set ARN alongside the identity ARN — omitting it yields AccessDenied on ses:SendEmail for the config-set. Empty when the OTP path is dark: the send grant is count-gated on agent_otp_enabled, so this stays unreferenced (empty-safe)."
  type        = string
  default     = ""
}
