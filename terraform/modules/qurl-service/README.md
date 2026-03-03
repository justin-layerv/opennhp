# QURL Service Module

ECS Fargate deployment for the QURL API service.

## Architecture

```
Internet → ALB (HTTPS 443) → ECS Fargate (port 8080) → DynamoDB
                                    ↓
                              Auth0 (JWT validation)
```

The QURL API handles:
- **Public API**: QURL management (Auth0 JWT protected)
- **Internal API**: Token resolution for NHP plugin, target lookup for Traefik

## Usage

```hcl
module "qurl_service" {
  source = "./modules/qurl-service"

  environment = "sandbox"
  name_prefix = "nhp-sandbox"
  cell_id     = "cell-1"

  # Networking
  vpc_id             = module.networking.vpc_id
  vpc_cidr           = module.networking.vpc_cidr
  private_subnet_ids = module.networking.private_subnet_ids
  public_subnet_ids  = module.networking.public_subnet_ids

  # Container
  ecr_repo_url        = module.ecr.qurl_repo_url
  image_tag_ssm_param = "/nhp-sandbox/qurl-api-image-tag"

  # ... see variables below
}
```

## Variables Reference

### Environment

| Variable | Description | Type | Required |
|----------|-------------|------|----------|
| `environment` | Environment name (sandbox, prod) | `string` | Yes |
| `name_prefix` | Prefix for resource names | `string` | Yes |
| `cell_id` | Cell identifier for multi-cell deployments | `string` | Yes |
| `tags` | Tags to apply to all resources | `map(string)` | No |

### Networking

| Variable | Description | Type | Required |
|----------|-------------|------|----------|
| `vpc_id` | VPC ID | `string` | Yes |
| `vpc_cidr` | VPC CIDR block | `string` | Yes |
| `private_subnet_ids` | Private subnet IDs for ECS tasks | `list(string)` | Yes |
| `public_subnet_ids` | Public subnet IDs for ALB | `list(string)` | Yes |

### Container

| Variable | Description | Type | Default |
|----------|-------------|------|---------|
| `ecr_repo_url` | ECR repository URL for qurl-api image | `string` | Required |
| `image_tag_ssm_param` | SSM parameter name containing the image tag | `string` | Required |
| `container_cpu` | CPU units (256 = 0.25 vCPU) | `number` | `256` |
| `container_memory` | Memory in MB | `number` | `512` |
| `container_port` | Port the container listens on | `number` | `8080` |
| `desired_count` | Desired number of ECS tasks | `number` | `1` |
| `autoscaling_min_capacity` | Min tasks for auto-scaling (prod only) | `number` | `2` |
| `autoscaling_max_capacity` | Max tasks for auto-scaling (prod only) | `number` | `10` |

### DynamoDB

| Variable | Description | Type | Required |
|----------|-------------|------|----------|
| `dynamodb_table_arns` | List of DynamoDB table ARNs for IAM | `list(string)` | Yes |
| `dynamodb_table_prefix` | Prefix for DynamoDB table names | `string` | No |
| `licenses_table_arn` | ARN of nhp_licenses table | `string` | Yes |
| `licenses_table_name` | Name of nhp_licenses table | `string` | Yes |

### Auth0

| Variable | Description | Type | Default |
|----------|-------------|------|---------|
| `auth0_domain` | Auth0 domain for JWT validation | `string` | Required |
| `auth0_audience` | Auth0 audience for JWT validation | `string` | `https://api.layerv.ai` |
| `auth0_jwks_cache_ttl_seconds` | JWKS cache TTL in seconds | `number` | Required |
| `auth0_jwks_fetch_timeout_seconds` | JWKS fetch timeout in seconds | `number` | Required |

### Secrets

| Variable | Description | Type | Required |
|----------|-------------|------|----------|
| `secrets_kms_key_arn` | KMS key ARN for Secrets Manager | `string` | No |
| `jwt_secret_arn` | Secrets Manager ARN for JWT signing secret | `string` | Yes |
| `internal_service_token_arn` | Secrets Manager ARN for internal service token | `string` | Yes |

### QURL Defaults

| Variable | Description | Type | Required |
|----------|-------------|------|----------|
| `cookie_domain` | Cookie domain for NHP tokens (e.g., `.qurl.site`) | `string` | Yes |
| `qurl_link_domain` | Domain for QURL access links (e.g., `qurl.link`) | `string` | Yes |
| `qurl_site_domain` | Domain for QURL protected resources (e.g., `qurl.site`) | `string` | Yes |
| `default_token_expire` | Default JWT token expiration in seconds | `number` | Yes |
| `default_open_time` | Default firewall open time in seconds | `number` | Yes |

### Rate Limiting

| Variable | Description | Type | Required |
|----------|-------------|------|----------|
| `ip_rate_limit` | Rate limit for IP-based internal routes (req/min) | `number` | Yes |
| `ip_rate_burst` | Burst allowance for IP-based internal routes | `number` | Yes |

### Audit

| Variable | Description | Type | Required |
|----------|-------------|------|----------|
| `audit_retention_days` | Days to retain audit logs in DynamoDB | `number` | Yes |

### AC Fleet

| Variable | Description | Type | Default |
|----------|-------------|------|---------|
| `default_ac_id` | Default AC identifier for new resources | `string` | Required |
| `default_ac_port` | Default AC port for new resources | `number` | `443` |

### Idempotency Cache

| Variable | Description | Type | Recommended |
|----------|-------------|------|-------------|
| `idempotency_cache_ttl_seconds` | TTL for cache entries | `number` | `300` (5 min) |
| `idempotency_cache_max_size` | Maximum cache entries | `number` | `1000` |
| `idempotency_cleanup_interval_seconds` | Cleanup interval | `number` | `60` |

### Health Check

| Variable | Description | Type | Recommended |
|----------|-------------|------|-------------|
| `health_check_timeout_seconds` | Health check timeout | `number` | `10` |
| `health_startup_timeout_seconds` | Startup timeout | `number` | `30` |

### License Cache

| Variable | Description | Type | Recommended |
|----------|-------------|------|-------------|
| `license_cache_ttl_seconds` | Cache TTL | `number` | `300` (5 min) |
| `license_cache_max_size` | Maximum cache entries | `number` | `1000` |

### Webhooks (Optional)

| Variable | Description | Type | Default |
|----------|-------------|------|---------|
| `webhooks_enabled` | Enable webhook delivery | `bool` | `false` |
| `webhooks_max_webhooks_per_owner` | Max webhooks per owner | `number` | Required if enabled |
| `webhooks_delivery_timeout_seconds` | Delivery timeout | `number` | `30` |
| `webhooks_max_retries` | Max delivery retries | `number` | `5` |
| `webhooks_event_channel_size` | Event channel buffer | `number` | `1000` |
| `webhooks_retry_worker_interval_seconds` | Retry worker interval | `number` | `30` |
| `webhooks_drain_timeout_seconds` | Shutdown drain timeout | `number` | `30` |
| `webhooks_response_body_limit` | Max response body bytes | `number` | `8192` |
| `webhooks_api_version` | API version for payloads | `string` | `2024-01-01` |

### Observability (Optional)

| Variable | Description | Type | Default |
|----------|-------------|------|---------|
| `otel_enabled` | Enable OpenTelemetry | `bool` | `false` |
| `otel_service_name` | Service name | `string` | `qurl-api` |
| `otel_service_version` | Service version | `string` | Required if enabled |
| `otel_environment` | Environment name | `string` | Required if enabled |
| `otel_exporter_endpoint` | OTLP endpoint | `string` | `http://localhost:4317` |
| `otel_exporter_protocol` | OTLP protocol | `string` | `grpc` |
| `otel_exporter_insecure` | Use insecure connection | `bool` | `true` |
| `otel_trace_sample_rate` | Trace sampling rate (0.0-1.0) | `number` | `1.0` |
| `otel_metrics_interval` | Metrics export interval | `number` | `60` |
| `otel_metrics_enabled` | Enable metrics | `bool` | `true` |
| `otel_tracing_enabled` | Enable tracing | `bool` | `true` |
| `otel_log_correlation` | Add trace IDs to logs | `bool` | `true` |

### Domain (Optional)

| Variable | Description | Type | Default |
|----------|-------------|------|---------|
| `domain_name` | Domain name for the QURL API | `string` | `null` |
| `hosted_zone_id` | Route53 hosted zone ID | `string` | `null` |
| `certificate_arn` | ACM certificate ARN for HTTPS | `string` | `null` |

### Redis (Optional)

| Variable | Description | Type | Default |
|----------|-------------|------|---------|
| `redis_enabled` | Enable Redis for distributed rate limiting | `bool` | `false` |
| `redis_endpoint` | Redis endpoint (host:port) | `string` | `""` |
| `redis_security_group_id` | Security group ID for Redis access | `string` | `null` |

## Outputs

| Output | Description |
|--------|-------------|
| `alb_dns_name` | ALB DNS name for routing |
| `alb_zone_id` | ALB hosted zone ID for Route53 alias |
| `ecs_cluster_name` | ECS cluster name |
| `ecs_service_name` | ECS service name |
| `security_group_id` | ECS task security group ID |

## Health Checks

The module configures two types of health checks following Kubernetes semantics:

- **Liveness** (`/health/live`): Used by ECS container health check. Fast check that the service is running.
- **Readiness** (`/health/ready`): Used by ALB target group. Deep check that all dependencies are healthy.

## Notes

- In production (`environment = "prod"`), auto-scaling is enabled with the configured min/max capacity
- Container Insights is enabled in production for enhanced monitoring
- The module uses Fargate launch type for serverless container management
- All secrets are fetched from AWS Secrets Manager at container start
