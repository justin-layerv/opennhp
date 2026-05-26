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
  description = "Public subnet IDs for ALB"
  type        = list(string)
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
  description = "Comma-separated list of allowed CORS origins. Production requires explicit origins (validated in task definition)."
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
  description = "Internal URL of NHP server for headless resolve knock requests (e.g., http://server.nhp.sandbox.internal:8888). Enables POST /v1/resolve endpoint."
  type        = string
  default     = ""
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

# ==================== Tunnel Auth ====================

variable "tunnel_auth_enabled" {
  description = "Enable the qurl-service tunnel-auth code paths (POST /internal/v1/tunnel/auth + type=tunnel branches in CreateQurl/CreateResource). Default false keeps the new surface inert in prod until the creation endpoint (qurl-service #405) and per-AZ FRPS assignment (qurl-service #396) are both deployed. See PR #277 for the gate; flip per-env via tfvars after the dependent qurl-service work ships."
  type        = bool
  default     = false
}

variable "tunnel_active_registrations_enabled" {
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
  description = "NHP UDP listener port. Conventionally 62206 — matches the UDP TG / SG rules in `modules/compute` and the AC ConnectorClient in `modules/ac` (grep `62206`; #2027 tracks consolidating all three sites into a shared local). Consumed only when deploy_qurl_bootstrap_chain = true."
  type        = string
  default     = "62206"

  # No leading zeros — `"062206"` would validate as 62206 but inject the
  # literal `"062206"` into the env var, which a strict consumer parser
  # would reject at task startup. Anchor with `^[1-9][0-9]*$` so the
  # string representation matches what the consumer expects.
  validation {
    condition     = can(regex("^[1-9][0-9]*$", var.nhp_server_port)) && tonumber(var.nhp_server_port) <= 65535
    error_message = "nhp_server_port must be a numeric string in [1, 65535] with no leading zeros (e.g., \"62206\")."
  }
}
