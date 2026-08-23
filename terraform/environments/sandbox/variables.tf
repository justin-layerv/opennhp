# Variables for sandbox environment
# Values are set in terraform.tfvars

variable "environment" {
  type = string
}

variable "cell_id" {
  description = "Cell identifier for resource naming, tags, and per-cell alarm dimensions."
  type        = string
  default     = "cell0"
  # Validation is enforced at module input boundaries; keep env files free of
  # duplicate regex blocks.
}

variable "connector_authority_cell_config" {
  description = "Optional exact cell0 Connector Authority caller graph. Dark by default; activate only after the Control runtime has been applied and verified."
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
  default = null
}

variable "aws_region" {
  type = string
}

variable "aws_account_id" {
  type = string
}

variable "domain_name" {
  type = string
}

variable "hosted_zone" {
  type    = string
  default = null
}

variable "multi_tenant" {
  type = bool
}

variable "deploy_etcd" {
  description = "Deploy etcd infrastructure. Set to false for cloud deployments using DynamoDB backend."
  type        = bool
  default     = null
}

variable "server_ami_id" {
  description = "Docker-optimized AMI ID for NHP Server. If null, compute module reads from /sandbox/nhp/server/ami-id SSM parameter."
  type        = string
  default     = null
}

variable "ac_ami_id" {
  description = "Runtime-baked AMI ID for NHP AC. If null, AC module reads from /sandbox/nhp/ac/ami-id SSM parameter."
  type        = string
  default     = null
}

variable "min_capacity" {
  type = number
}

variable "max_capacity" {
  type = number
}

variable "enable_termination_cleanup" {
  description = "Enable ASG lifecycle hook for immediate DynamoDB cleanup on server termination"
  type        = bool
}

variable "enable_secret_reconciliation" {
  description = "Enable scheduled cleanup of orphaned per-instance AC secrets"
  type        = bool
  default     = true
}

variable "vpc_cidr" {
  type = string
}

variable "tags" {
  type = map(string)
}

variable "is_primary_account" {
  type    = bool
  default = true
}

variable "primary_account_id" {
  type    = string
  default = ""
}

variable "secondary_account_ids" {
  description = "AWS account IDs that need cross-account ECR pull access"
  type        = list(string)
  default     = []
}

variable "enable_replication" {
  description = "Enable ECR cross-account replication to secondary accounts"
  type        = bool
  default     = false
}

variable "github_org" {
  type    = string
  default = "layervai"
}

variable "github_repo" {
  type    = string
  default = "nhp"
}

variable "deploy_ac" {
  type    = bool
  default = true
}

variable "acme_email" {
  type    = string
  default = ""
}

variable "terraform_state_bucket" {
  type    = string
  default = ""
}

variable "terraform_lock_table" {
  type    = string
  default = "terraform-state-lock"
}

# AC configuration
variable "ac_auth_service_id" {
  type    = string
  default = "agent"
}

variable "ac_resource_ids" {
  type    = list(string)
  default = ["default"]
}

variable "ac_min_capacity" {
  description = "Minimum number of AC instances. Overrides the module default (2 for prod, 1 otherwise)."
  type        = number
  default     = null
}

variable "ac_filter_mode" {
  description = "AC datapath FilterMode for sandbox: 0=iptables/ipset, 1=eBPF/XDP."
  type        = number
  default     = 0

  validation {
    condition     = contains([0, 1], var.ac_filter_mode)
    error_message = "ac_filter_mode must be 0 (iptables/ipset) or 1 (eBPF/XDP)."
  }
}

variable "enable_l3_flush_on_expiry" {
  description = "Sandbox AC L3 flush-on-expiry scheduler: actively tear down kernel allow-state (ipset/BPF map + conntrack) at session end. Off by default (pre-flush baseline). Full semantics in modules/ac/variables.tf, rollout in docs/runbooks/l3-flush-*.md."
  type        = bool
  default     = false
}

variable "l3_flush_dry_run" {
  description = "Gate the sandbox L3 flush scheduler into log-only mode (default true); no effect unless enable_l3_flush_on_expiry=true. Full semantics + the first-load dry-run safety in modules/ac/variables.tf."
  type        = bool
  default     = true
}

variable "l3_flush_real_mode_acknowledged" {
  description = "Sandbox durable acknowledgement for direct real-flush boot after the dry-run soak gates have passed."
  type        = bool
  default     = false
}

variable "l3_flush_conntrack_backend" {
  description = "AC conntrack teardown backend for sandbox L3 flush: exec or netlink."
  type        = string
  default     = "exec"

  validation {
    condition     = contains(["exec", "netlink"], lower(var.l3_flush_conntrack_backend))
    error_message = "l3_flush_conntrack_backend must be either \"exec\" or \"netlink\"."
  }
}

variable "l3_flush_conntrack_pool_size" {
  description = "Sandbox AC netlink conntrack socket pool size. 0 preserves the AC default (currently 16)."
  type        = number
  default     = 0

  # Keep this bound aligned with the AC module and the Go-side
  # maxConntrackNetlinkPoolSize/defaultConntrackNetlinkPoolSize constants.
  validation {
    condition     = var.l3_flush_conntrack_pool_size >= 0 && var.l3_flush_conntrack_pool_size <= 128 && floor(var.l3_flush_conntrack_pool_size) == var.l3_flush_conntrack_pool_size
    error_message = "l3_flush_conntrack_pool_size must be an integer between 0 and 128; use 0 for the AC default."
  }
}

variable "enable_egress_eips" {
  description = "Allocate Elastic IPs for AC instances for stable egress IPs (2x when blue/green enabled). Customers whitelist these on their origin firewalls."
  type        = bool
  default     = false
}

# Security services
variable "enable_cloudtrail" {
  description = "Enable AWS CloudTrail. Set to false if SCP blocks cloudtrail operations."
  type        = bool
  default     = true
}

variable "config_recording_frequency" {
  description = "AWS Config recording frequency: CONTINUOUS or DAILY"
  type        = string
  default     = "DAILY"
}

variable "config_resource_types" {
  description = "Specific AWS resource types to record. Empty list uses module defaults."
  type        = list(string)
  default     = []
}

# GitHub OIDC
variable "create_oidc_provider" {
  description = "Create GitHub OIDC provider. Set to false if org manages centrally or SCP blocks creation."
  type        = bool
  default     = true
}

# Server configuration
variable "log_level" {
  description = "NHP log level for all components: 0=silent, 1=error, 2=info, 3=audit, 4=debug, 5=trace"
  type        = number
  default     = 4 # Debug for sandbox

  validation {
    condition     = var.log_level >= 0 && var.log_level <= 5
    error_message = "log_level must be between 0 (silent) and 5 (trace)."
  }
}

variable "dev_mode" {
  type    = bool
  default = false
}

variable "nhp_cors_allowed_origins" {
  description = "Comma-separated list of allowed CORS origins for NHP HTTP server"
  type        = string
  default     = ""
}

variable "nhp_knock_headertype_verify_require" {
  description = "Wrapper passthrough for the root nhp_knock_headertype_verify_require — see ../../variables.tf and ../../modules/compute/variables.tf for gate semantics and burn-in criteria."
  type        = bool
  default     = false
}

variable "nhp_internal_auth_require" {
  description = "Wrapper passthrough for the root nhp_internal_auth_require — see ../../variables.tf and ../../modules/compute/variables.tf for gate semantics and burn-in criteria."
  type        = bool
  default     = false
}

variable "nhp_revocation_retry_enabled" {
  description = "Wrapper passthrough for the root nhp_revocation_retry_enabled (#2793). Default false keeps new/unset environments conservative; sandbox opts in explicitly in terraform.tfvars after ACK support."
  type        = bool
  default     = false
}

variable "nhp_revocation_retry_interval_seconds" {
  description = "Wrapper passthrough for the root nhp_revocation_retry_interval_seconds (#2793)."
  type        = number
  default     = 5

  validation {
    condition     = var.nhp_revocation_retry_interval_seconds >= 1 && floor(var.nhp_revocation_retry_interval_seconds) == var.nhp_revocation_retry_interval_seconds
    error_message = "nhp_revocation_retry_interval_seconds must be a whole number of seconds >= 1."
  }
}

variable "nhp_revocation_retry_age_out_seconds" {
  description = "Wrapper passthrough for the root nhp_revocation_retry_age_out_seconds (#2793)."
  type        = number
  default     = 60

  validation {
    condition     = var.nhp_revocation_retry_age_out_seconds >= 1 && floor(var.nhp_revocation_retry_age_out_seconds) == var.nhp_revocation_retry_age_out_seconds
    error_message = "nhp_revocation_retry_age_out_seconds must be a positive whole number of seconds."
  }
}

variable "nhp_overload_cookie_time_window_seconds" {
  description = "Wrapper passthrough for the root nhp_overload_cookie_time_window_seconds. Default 60s; tune only with NTP/clock-skew evidence."
  type        = number
  default     = 60

  validation {
    condition     = var.nhp_overload_cookie_time_window_seconds > 0
    error_message = "nhp_overload_cookie_time_window_seconds must be positive."
  }
}

variable "nhp_knock_global_rate_limit_pps" {
  description = "Wrapper passthrough for the root nhp_knock_global_rate_limit_pps (#1159). Aggregate UDP knock pps cap."
  type        = number
  default     = 5000
}

variable "nhp_knock_global_rate_limit_burst" {
  description = "Wrapper passthrough for the root nhp_knock_global_rate_limit_burst (#1159). Burst allowance for the aggregate cap."
  type        = number
  default     = 10000
}

variable "nhp_udp_recv_buffer_bytes" {
  description = "Wrapper passthrough for the root nhp_udp_recv_buffer_bytes (#1159). Target SO_RCVBUF for the NHP knock listen socket."
  type        = number
  default     = 8388608
}

variable "public_nhp_udp_ingress_cidrs" {
  description = <<-EOT
    Sources allowed at the sandbox cell0 public UDP NLB. A non-null list also
    enables the NLB security-group attachment. Sandbox is open to developers
    inside and outside the company (qurl-go ADR 0001), so this is the open-edge
    value, matching the open Hub: an agent that clears the Hub has to be able to
    register against its assigned cell.

    This replaces the previous proof-runner /32, which 0.0.0.0/0 subsumes. The
    seven managed AC EIP /32 rules on the same security group are emitted by the
    ac module (aws_vpc_security_group_ingress_rule.server_nlb_registration) and
    are unaffected; they become redundant but are left to that module to own.
  EOT
  type        = list(string)
  default     = ["0.0.0.0/0"]

  validation {
    condition     = length(var.public_nhp_udp_ingress_cidrs) == 1 && var.public_nhp_udp_ingress_cidrs[0] == "0.0.0.0/0"
    error_message = "Sandbox cell0 UDP ingress is open by decision (qurl-go ADR 0001) and must remain exactly [\"0.0.0.0/0\"]; changing sandbox access requires superseding that ADR."
  }
}

variable "resource_mode" {
  type    = string
  default = "local"
}

variable "auth_url" {
  type    = string
  default = null
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

# Monitoring
variable "enable_slack_notifications" {
  type    = bool
  default = false
}

variable "slack_workspace_id" {
  type    = string
  default = ""
}

variable "slack_channel_id" {
  type    = string
  default = ""
}

variable "chatbot_owned_externally" {
  description = "Sandbox's #alerts-sandbox Chatbot config is owned by alerts-infra's sandbox-alerts-sandbox module, which subscribes our layerv-nhp-sandbox-cell0-alerts SNS topic. Default true keeps NHP from re-colliding on the (workspace, channel) pair."
  type        = bool
  default     = true
}

variable "qurl_browser_rejected_alarm_actions_enabled" {
  description = "Enable SNS actions for the qURL browser timing rejected-ratio alarms. Default false keeps the initial #1840 rollout report-only while thresholds bake."
  type        = bool
  default     = false
}

# Production domains
variable "production_domains" {
  type    = list(string)
  default = []
}

variable "production_zone_ids" {
  type    = list(string)
  default = []
}

# Deployment configuration
variable "image_tag" {
  description = "Docker image tag for NHP server and AC"
  type        = string
  default     = "latest"
}

# NHP Server plugins - statically compiled into server binary
variable "server_plugins" {
  description = "List of NHP Server plugins to enable (plugins are compiled into the server)"
  type        = list(string)
  default     = []
}

# QURL plugin configuration
variable "qurl_config" {
  description = "QURL plugin configuration for token resolution (qurl.link → qurl.site flow)"
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
}

variable "qurl_service_token_secret_arn" {
  description = "ARN of Secrets Manager secret containing the QURL service token"
  type        = string
  default     = null
}

# QURL Link redirect page (CloudFront + S3)
variable "deploy_qurl_link" {
  description = "Deploy the QURL link redirect page"
  type        = bool
  default     = false
}

variable "qurl_link_frontend_domain" {
  description = "Domain for the QURL link redirect page (e.g., link.nhp.layerv.xyz)"
  type        = string
  default     = null
}

variable "qurl_link_hosted_zone_id" {
  description = "Route53 hosted zone ID for the QURL link domain"
  type        = string
  default     = null

  validation {
    condition     = var.qurl_link_hosted_zone_id == null || can(regex("^Z[A-Z0-9]{8,}$", var.qurl_link_hosted_zone_id))
    error_message = "qurl_link_hosted_zone_id must be a valid Route53 hosted zone ID (uppercase, starts with Z, at least 9 characters)."
  }
}

variable "qurl_link_external_dns" {
  description = "When true, Route53 records for qurl_link are managed externally (e.g., via AWS CLI in layerv-mgmt)"
  type        = bool
  default     = false
}

variable "qurl_link_enable_access_logs" {
  description = "Enable CloudFront access logging for QURL link redirect page"
  type        = bool
  default     = false
}

variable "qurl_link_js_agent_enabled" {
  description = "Upload the browser NHP JS-agent bundle to qurl.link, render relay bootstrap config, and disable browser resolve ingress during sandbox relay cutover staging (#2208/#2680). Requires deploy_relay and relay_dns_name when true."
  type        = bool
  default     = false
}

variable "enable_resolve_cloudfront" {
  description = "Enable CloudFront + WAF in front of resolve.qurl.link for ISP compatibility"
  type        = bool
  default     = false
}

variable "resolve_waf_ip_reputation_block" {
  description = "Block (true) vs. count (false) the resolve WAF's IP-reputation rule. See root module variable for rationale."
  type        = bool
  default     = false
}

variable "enable_resolve_waf_logging" {
  description = "Enable WAF request logging for the resolve CloudFront WebACL. See root module variable for rationale."
  type        = bool
  default     = true
}

variable "enable_resolve_access_logs" {
  description = "Enable CloudFront access logging (v2 -> S3) for the resolve distribution. See root module variable for rationale (token never logged; #1799)."
  type        = bool
  default     = true
}

# QURL Service deployment
variable "deploy_qurl_service" {
  description = "Deploy the QURL API service on ECS Fargate"
  type        = bool
}

variable "qurl_scanner_lambda_enabled" {
  description = "Deploy the scheduled qurl-scanner Lambda + EventBridge cron + scan-gap alarm (sibling to the qurl-service ECS task). Default OFF — see root variable for the two-apply rollout sequence."
  type        = bool
  default     = false
}

variable "qurl_scanner_sqs_emit_enabled" {
  description = "Activate the resource-lifecycle SQS data path (sandbox). See `modules/qurl-service/variables.tf::qurl_scanner_sqs_emit_enabled` for the canonical rationale."
  type        = bool
  default     = false
}

variable "qurl_scanner_tombstone_write_enabled" {
  description = "Enable destructive qurl-scanner tombstone writes in sandbox after the SQS producer/consumer path is active. See `modules/qurl-service/variables.tf::qurl_scanner_tombstone_write_enabled`."
  type        = bool
  default     = false
}

variable "qurl_scanner_active_recheck_enabled" {
  description = "Create the hourly active-resource recheck scheduler in sandbox after SQS and per-minute tombstone writes have burned in. See `modules/qurl-service/variables.tf::qurl_scanner_active_recheck_enabled`."
  type        = bool
  default     = false
}

# Wave 5 dark-launch gate for the qurl-service ↔ nhp-server agent
# bootstrap chain (NHP_SERVER_PUBLIC_KEY_B64 / NHP_SERVER_HOST /
# NHP_SERVER_PORT / QURL_AGENT_BOOTSTRAP_ENABLED). See root variable
# of the same name for the full contract.
variable "deploy_qurl_bootstrap_chain" {
  description = "Inject the four bootstrap-chain env vars (NHP_SERVER_PUBLIC_KEY_B64, NHP_SERVER_HOST, NHP_SERVER_PORT, QURL_AGENT_BOOTSTRAP_ENABLED) on the qurl-service ECS task def. Default false; flip to true to land the chain. The agent-enabled flag itself is gated separately via `enable_qurl_agent_bootstrap` so activation is a focused one-line tfvars flip per environment."
  type        = bool
  default     = false
}

variable "enable_qurl_agent_bootstrap" {
  description = "Wave 5 activation flag for the qurl-service agent → nhp-server bootstrap chain. Drives the QURL_AGENT_BOOTSTRAP_ENABLED env var on the task def. Default false: the chain stays inert until this is flipped to true per environment. Only consulted when deploy_qurl_bootstrap_chain = true."
  type        = bool
  default     = false
}

variable "retire_http_agent_lifecycle" {
  description = "Delete the obsolete HTTP agent lifecycle Terraform resources after the preparation revision has been applied."
  type        = bool
  default     = false
}

# ── Agent registration + email OTP (T1) — pass-through to module "nhp" ──
# See the root terraform/variables.tf for full rationale. PATH A (registration),
# PATH B (OTP, split across qurl-service + nhp-server), email_from, relay URL, and
# the alarm thresholds. All default dark so an env stays dark until tfvars opts in.

variable "agent_registration_enabled" {
  description = "PATH A gate — QURL_AGENT_REGISTRATION_ENABLED on qurl-service. Requires enable_qurl_agent_bootstrap + a relay URL (enforced at the root). Default false."
  type        = bool
  default     = false
}

variable "agent_otp_enabled" {
  description = "PATH B gate (qurl-service side) — QURL_AGENT_OTP_ENABLED + the create-gate for SES infra + the pepper secret. Requires agent_registration_enabled + email_from + agent_otp_registration_enabled. Default false."
  type        = bool
  default     = false
}

variable "agent_otp_registration_enabled" {
  description = "PATH B gate (nhp-server QURL plugin side) — AGENT_OTP_REGISTRATION_ENABLED in user_data. Flip in lockstep with agent_otp_enabled. Default false."
  type        = bool
  default     = false
}

variable "agent_otp_ci_send_gate_enabled" {
  description = "Creates the dedicated ses:SendEmail role qurl-service's per-PR live-email gate assumes (module nhp, agent_otp_ses.tf). Must be DECLARED here and PASSED THROUGH module.nhp below — setting it only in terraform.tfvars makes it an undeclared variable this root ignores, so the module keeps its false default and the role is silently never created. Non-prod only; a precondition in the module fails the plan otherwise. Default false."
  type        = bool
  default     = false
}

variable "agent_otp_email_from" {
  description = "From address for OTP emails (QURL_AGENT_OTP_EMAIL_FROM); the root derives the SES sender domain from it. Required when agent_otp_enabled. Empty when dark."
  type        = string
  default     = ""

  validation {
    condition     = var.agent_otp_email_from == "" || can(regex("^[^@[:space:]]+@[a-z0-9][a-z0-9.-]*[a-z0-9]\\.[a-z]{2,}$", var.agent_otp_email_from))
    error_message = "agent_otp_email_from must be empty (OTP dark) or a bare local@domain address (no display name, angle brackets, or whitespace)."
  }
}

variable "agent_otp_ci_mailbox_enabled" {
  description = "Creates the CI receive mailbox (SES inbound -> S3 -> SQS) the qurl-go OTP registration gate reads, in module nhp's agent_otp_ci_mailbox.tf. Must be DECLARED here and PASSED THROUGH module.nhp below — setting it only in terraform.tfvars makes it an undeclared variable this root ignores, so the module keeps its false default and the mailbox is silently never created (exactly how the sibling send-gate flag shipped inert). Non-prod only; a precondition in the module fails the plan otherwise. Default false."
  type        = bool
  default     = false
}

variable "agent_registration_relay_base_url" {
  description = "Relay base URL the register flow advertises (QURL_NHP_RELAY_BASE_URL). Required (https) when agent_registration_enabled. Empty when dark."
  type        = string
  default     = ""

  validation {
    condition     = var.agent_registration_relay_base_url == "" || can(regex("^https://", var.agent_registration_relay_base_url))
    error_message = "agent_registration_relay_base_url must be empty (registration dark) or an https:// URL."
  }
}

variable "agent_otp_send_failed_threshold_per_minute" {
  description = "Threshold for the agent-otp-send-failed-spike alarm (LAUNCH-BLOCKING; SES rejecting sends). Default 0 → page on first failure."
  type        = number
  default     = 0

  validation {
    condition     = var.agent_otp_send_failed_threshold_per_minute >= 0 && var.agent_otp_send_failed_threshold_per_minute <= 1000
    error_message = "agent_otp_send_failed_threshold_per_minute must be 0 ≤ x ≤ 1000."
  }
}

variable "agent_otp_bounce_threshold_per_minute" {
  description = "Threshold for the agent-otp-bounce alarm (LAUNCH-BLOCKING; SUM of AWS/SES Bounce+Complaint+Reject on the OTP config set — async deliverability failures send_failed misses). Default 0 → page on first async failure."
  type        = number
  default     = 0

  validation {
    condition     = var.agent_otp_bounce_threshold_per_minute >= 0 && var.agent_otp_bounce_threshold_per_minute <= 1000
    error_message = "agent_otp_bounce_threshold_per_minute must be 0 ≤ x ≤ 1000."
  }
}

variable "agent_otp_rate_limited_threshold_per_minute" {
  description = "Threshold for the agent-otp-rate-limited-spike alarm. Default 5."
  type        = number
  default     = 5

  validation {
    condition     = var.agent_otp_rate_limited_threshold_per_minute >= 1 && var.agent_otp_rate_limited_threshold_per_minute <= 1000
    error_message = "agent_otp_rate_limited_threshold_per_minute must be 1 ≤ x ≤ 1000."
  }
}

variable "agent_register_attempts_exceeded_threshold_per_minute" {
  description = "Threshold for the agent-register-attempts-exceeded-spike alarm (brute-force). Default 3."
  type        = number
  default     = 3

  validation {
    condition     = var.agent_register_attempts_exceeded_threshold_per_minute >= 1 && var.agent_register_attempts_exceeded_threshold_per_minute <= 1000
    error_message = "agent_register_attempts_exceeded_threshold_per_minute must be 1 ≤ x ≤ 1000."
  }
}

variable "agent_register_credential_invalid_threshold_per_minute" {
  description = "Threshold for the agent-register-credential-invalid-spike alarm (lower-priority brute-force companion). Default 10."
  type        = number
  default     = 10

  validation {
    condition     = var.agent_register_credential_invalid_threshold_per_minute >= 1 && var.agent_register_credential_invalid_threshold_per_minute <= 1000
    error_message = "agent_register_credential_invalid_threshold_per_minute must be 1 ≤ x ≤ 1000."
  }
}

variable "agent_register_rate_limited_threshold_per_minute" {
  description = "Threshold for the agent-register-rate-limited-spike alarm. Default 5."
  type        = number
  default     = 5

  validation {
    condition     = var.agent_register_rate_limited_threshold_per_minute >= 1 && var.agent_register_rate_limited_threshold_per_minute <= 1000
    error_message = "agent_register_rate_limited_threshold_per_minute must be 1 ≤ x ≤ 1000."
  }
}

variable "relay_otp_reject_rate_limited_threshold_per_minute" {
  description = "Threshold for the relay-otp-reject-rate-limited alarm (nhp-server global ~30/min OTP cap, fleet-wide; the metric emits from the shared OTP dispatch core so it spans the direct-UDP and relayed paths — the 'relay' name is legacy). Gated on agent_otp_alarms_enabled || deploy_relay, so it is created in prod with OTP on even while the relay stays dark. Default 0 → page on first reject."
  type        = number
  default     = 0

  validation {
    condition     = var.relay_otp_reject_rate_limited_threshold_per_minute >= 0 && var.relay_otp_reject_rate_limited_threshold_per_minute <= 1000
    error_message = "relay_otp_reject_rate_limited_threshold_per_minute must be 0 ≤ x ≤ 1000."
  }
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

variable "qurl_internal_service_domain" {
  description = "Hostname for the QURL API internal ALB (e.g., internal-api.qurl.layerv.xyz). See canonical doc + RFC1035 validation on the root variable of the same name."
  type        = string
  default     = null
}

variable "qurl_cookie_domain" {
  description = "Cookie domain for NHP tokens (must match qurl_site_domain with leading dot)"
  type        = string
  default     = ".qurl.site"
}

variable "qurl_link_domain" {
  description = "Domain for QURL access links (e.g., qurl.link)"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]\\.[a-z]{2,}$", var.qurl_link_domain))
    error_message = "qurl_link_domain must be a valid domain name (e.g., qurl.link)"
  }
}

variable "qurl_site_domain" {
  description = "Domain for QURL protected resources (e.g., qurl.site)"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]*[a-z0-9]\\.[a-z]{2,}$", var.qurl_site_domain))
    error_message = "qurl_site_domain must be a valid domain name (e.g., qurl.site)"
  }
}

variable "qurl_site_hosted_zone_id" {
  description = "Route53 hosted zone ID for the qurl.site domain wildcard record"
  type        = string
  default     = null

  validation {
    condition     = var.qurl_site_hosted_zone_id == null || can(regex("^Z[A-Z0-9]{8,}$", var.qurl_site_hosted_zone_id))
    error_message = "qurl_site_hosted_zone_id must be a valid Route53 hosted zone ID (uppercase, starts with Z, at least 9 characters)."
  }
}

variable "qurl_audit_retention_days" {
  description = "Number of days to retain QURL audit logs in DynamoDB"
  type        = number

  validation {
    condition     = var.qurl_audit_retention_days > 0 && var.qurl_audit_retention_days <= 3650
    error_message = "qurl_audit_retention_days must be between 1 and 3650 days (10 years max)"
  }
}

variable "qurl_cors_allowed_origins" {
  description = "Comma-separated list of allowed CORS origins for QURL API"
  type        = string
}

variable "qurl_additional_allowed_hosts" {
  description = "Additional allowed hostnames for DNS rebinding protection. ALB DNS and localhost are always included."
  type        = list(string)
  default     = []
}

# QURL Rate Limiting
variable "qurl_ip_rate_limit" {
  description = "Rate limit for IP-based internal routes (requests per minute)"
  type        = number

  validation {
    condition     = var.qurl_ip_rate_limit > 0 && var.qurl_ip_rate_limit <= 10000
    error_message = "qurl_ip_rate_limit must be between 1 and 10000 requests per minute"
  }
}

variable "qurl_ip_rate_burst" {
  description = "Burst allowance for IP-based internal routes"
  type        = number

  validation {
    condition     = var.qurl_ip_rate_burst > 0 && var.qurl_ip_rate_burst <= 1000
    error_message = "qurl_ip_rate_burst must be between 1 and 1000"
  }
}

# QURL Router plugin configuration
variable "qurl_router_enabled" {
  description = "Enable QURL Router plugin in Traefik"
  type        = bool
  default     = false
}

variable "qurl_router_cache_ttl" {
  description = "Cache TTL in seconds for successful lookups"
  type        = number
  default     = 60

  validation {
    condition     = var.qurl_router_cache_ttl >= 0 && var.qurl_router_cache_ttl <= 86400
    error_message = "qurl_router_cache_ttl must be between 0 and 86400 seconds (24 hours max)"
  }
}

variable "qurl_router_negative_cache_ttl" {
  description = "Cache TTL in seconds for failed lookups"
  type        = number
  default     = 30

  validation {
    condition     = var.qurl_router_negative_cache_ttl >= 0 && var.qurl_router_negative_cache_ttl <= 3600
    error_message = "qurl_router_negative_cache_ttl must be between 0 and 3600 seconds (1 hour max)"
  }
}

variable "qurl_router_max_cache_size" {
  description = "Maximum cache entries"
  type        = number
  default     = 1000

  validation {
    condition     = var.qurl_router_max_cache_size > 0 && var.qurl_router_max_cache_size <= 100000
    error_message = "qurl_router_max_cache_size must be between 1 and 100000 entries"
  }
}

variable "qurl_router_api_timeout" {
  description = "Timeout in seconds for QURL API calls"
  type        = number
  default     = 5

  validation {
    condition     = var.qurl_router_api_timeout > 0 && var.qurl_router_api_timeout <= 300
    error_message = "qurl_router_api_timeout must be between 1 and 300 seconds"
  }
}

variable "qurl_router_proxy_timeout" {
  description = "Timeout in seconds for proxying to backends"
  type        = number
  default     = 30

  validation {
    condition     = var.qurl_router_proxy_timeout > 0 && var.qurl_router_proxy_timeout <= 600
    error_message = "qurl_router_proxy_timeout must be between 1 and 600 seconds"
  }
}

variable "qurl_router_cache_shards" {
  description = "Number of cache shards"
  type        = number
  default     = 16

  validation {
    condition     = var.qurl_router_cache_shards > 0 && var.qurl_router_cache_shards <= 256
    error_message = "qurl_router_cache_shards must be between 1 and 256"
  }
}

# ==================== qurl-router HRW (traefik-plugins #134) ====================

variable "enable_instance_hrw" {
  description = "Enable router-side HRW dispatch in qurl-router. Default false; PR 4 flips to true in prod tfvars after sandbox validation. See terraform/variables.tf for the full description."
  type        = bool
  default     = false
}

variable "instance_discovery_ttl_seconds" {
  description = "TTL in seconds for the qurl-router instance-IP allowlist. Default 20 matches the plugin's DefaultDiscoveryTTL; ignored when enable_instance_hrw=false. Range validation lives at the root (terraform/variables.tf) and on the AC module's qurl_router_config — duplicating it here would be a future inconsistency vector."
  type        = number
  default     = 20
}

variable "enable_qurl_site_authz" {
  description = "Enable the qurl-router L7 per-session authz gate on *.qurl.site. See terraform/variables.tf for the full description (activation cadence, producer dependency, trust-boundary requirements)."
  type        = bool
  default     = false
}

variable "require_connector_routing_id" {
  description = "Require qurl-router to use the producer-issued connector_routing_id for ordinary *.qurl.site Connector traffic. Default false keeps the cutover dark; changing it requires the normal whole-fleet AC restart/rollout. See terraform/variables.tf and NHP #3275."
  type        = bool
  default     = false
}

# ==================== qurl-reverse-tunnel-server deploy + sizing (per-AZ + blue/green) ====================
# PR 3 only declares the NEW per-AZ / blue/green / canary variables here.
# The existing tfvars values for `deploy_frps` / `frps_*` are already
# latent no-ops in env tfvars (the env main.tf never forwarded them);
# PR 3 leaves that pre-existing gap untouched to avoid changing deploy
# state. PR 4 wires the legacy passthrough at the same time as the
# value flip.

variable "qurl_reverse_tunnel_server_min_size_per_az" {
  description = "Per-AZ ASG min size for qurl-reverse-tunnel-server. Default null keeps the legacy frps_min_size as the source of truth. PR 4 may set this in prod tfvars."
  type        = number
  default     = null
}

variable "qurl_reverse_tunnel_server_max_size_per_az" {
  description = "Per-AZ ASG max size for qurl-reverse-tunnel-server. Default null keeps the legacy frps_max_size as the source of truth."
  type        = number
  default     = null
}

variable "qurl_reverse_tunnel_server_desired_capacity_per_az" {
  description = "Per-AZ ASG desired capacity for qurl-reverse-tunnel-server. Default null keeps the legacy frps_desired_capacity as the source of truth. PR 4 will set this to 2 in prod tfvars to flip 1/AZ → 2/AZ."
  type        = number
  default     = null
}

variable "qurl_reverse_tunnel_server_cloud_map_routing_policy" {
  description = "Cloud Map routing policy for qurl-reverse-tunnel-server per-AZ services. Default WEIGHTED matches current 1/AZ behavior; PR 4 flips to MULTIVALUE for router-side HRW dispatch."
  type        = string
  default     = "WEIGHTED"
}

variable "enable_qurl_reverse_tunnel_server_blue_green" {
  description = "Enable blue/green deployment for qurl-reverse-tunnel-server. Sandbox-targeted; mutually exclusive with enable_qurl_reverse_tunnel_server_canary."
  type        = bool
  default     = false
}

variable "qurl_reverse_tunnel_server_green_standby_capacity_per_az" {
  description = "Per-AZ desired capacity for the qurl-reverse-tunnel-server green ASG when in standby. Default null = auto-track min_size_per_az when set, else 1. Set explicitly for cold standby (0) or custom values."
  type        = number
  default     = null
}

variable "enable_qurl_reverse_tunnel_server_canary" {
  description = "Enable canary deployment for qurl-reverse-tunnel-server via the canary-deployment module. Prod-targeted; mutually exclusive with enable_qurl_reverse_tunnel_server_blue_green."
  type        = bool
  default     = false
}

variable "qurl_reverse_tunnel_server_tunnel_auth_mode" {
  description = <<-EOT
    Env-root pass-through for the root module's `qurl_reverse_tunnel_server_tunnel_auth_mode`
    variable. Required because the sandbox env wrapper is a self-contained TF root
    that re-declares every variable it forwards to `module "nhp"`. Without this
    declaration, the matching tfvars line is silently ignored (terraform applies
    the root module with the parent variable's "" default, so FRPS never enters
    tunnel-auth regardless of what sandbox tfvars says). See
    `terraform/variables.tf::qurl_reverse_tunnel_server_tunnel_auth_mode` for the
    full env-shape contract and `terraform/modules/qurl-reverse-tunnel-server/variables.tf::qurl_tunnel_auth_mode`
    for the per-mode user_data branches.
  EOT
  type        = string
  default     = ""

  validation {
    condition     = var.qurl_reverse_tunnel_server_tunnel_auth_mode == "" || var.qurl_reverse_tunnel_server_tunnel_auth_mode == "tunnel-auth"
    error_message = "qurl_reverse_tunnel_server_tunnel_auth_mode must be \"\" (module-compat placeholder) or \"tunnel-auth\"."
  }
}

variable "qurl_reverse_tunnel_server_min_client_version" {
  description = "Env-root pass-through for the qurl-reverse-tunnel-server runtime min-client-version SSM seed. Empty seeds the parameter as disabled. Values may include the v prefix because qurl-reverse-tunnel-server normalizes it before comparison. After first apply this tfvar is write-once; operators update the SSM value directly for hot changes."
  type        = string
  default     = ""

  validation {
    condition     = var.qurl_reverse_tunnel_server_min_client_version == "" || can(regex("^v?[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?$", var.qurl_reverse_tunnel_server_min_client_version))
    error_message = "qurl_reverse_tunnel_server_min_client_version must be empty or a semantic version like 1.2.3, v1.2.3, or 1.2.3-beta.1; build metadata is not supported by qurl-reverse-tunnel-server."
  }
}

# ==================== FRPS passthroughs (parent variables, env-root mirror) ====================
# Closes the gap noted by #1745: tfvars values for `deploy_frps`,
# `connect_layerv_host`, `frps_az_suffixes`, and the legacy
# `frps_min_size` / `frps_max_size` / `frps_desired_capacity` triple
# (plus `frps_image_tag`, `frps_bind_port`, and `frps_vhost_http_port`
# threaded preemptively against the same trap) were previously declared
# in the parent module but NOT in the env root, so the env tfvars
# entries surfaced as "Value for undeclared variable" warnings at plan
# time and silently no-op'd at apply. Declaring + threading them
# through to `module "nhp"` is what lets #1977's FRPS-behind-AC
# topology actually apply in sandbox.
#
# Descriptions/types/defaults/validations are copied from
# `terraform/variables.tf` to keep the env-root fence in lockstep with
# the parent. Where the parent uses a multi-paragraph HEREDOC
# description (today: `connect_layerv_host`), the env-root copy is
# pragmatically condensed to a one-liner that points back at the
# parent for the full doc — the parent stays the source of truth so
# rationale doesn't drift. Validations are mirrored verbatim because
# their wording is the user-facing error text on a malformed input.
#
# Lockstep is enforced today only for `frps_az_suffixes` by
# `scripts/check-frps-az-suffixes-validation-drift.sh` (root + module +
# this env-root copy, three-way). #2037 tracks extending that lint to
# the four remaining mirrored variable families: `connect_layerv_host`,
# `frps_min_size`, `frps_max_size`, and `frps_desired_capacity`. Until
# that lands, edits to a parent validation block MUST be mirrored here
# in the same PR — particularly important for the `connect_layerv_host`
# `.internal` / `frps-` shape fences, which are transitional and slated
# for removal alongside #2019. The whole class of "tfvars value,
# env-root undeclared" misapply that motivated this section is tracked
# in #2038.
#
# Manual-lockstep also applies to the variables WITHOUT `validation {}`
# blocks (`deploy_frps`, `frps_image_tag`, `frps_bind_port`,
# `frps_vhost_http_port`) — a parent `default` bump won't be caught by
# any current lint, so a tfvars-not-set port flip would land on a stale
# env-root default. And the condensed `connect_layerv_host` description
# inlines the wire-flow narrative (`NLB → AC → ipset → Traefik → frps-{az}`);
# if #2019 changes that topology, mirror the wording change here too.
# Both gaps are tracked in #2037's expanded scope.

variable "deploy_frps" {
  description = "Deploy the QURL FRP tunnel server for proxying traffic to customer backends. Requires `deploy_ac = true`, `deploy_qurl_service = true`, `qurl_internal_service_token_arn` set, and `qurl_service_domain` set — all four are enforced by `terraform_data.frps_preconditions` at plan time so that FRPS never boots with tunnel auth disabled."
  type        = bool
  default     = false
}

variable "connect_layerv_host" {
  description = "Customer-facing public DNS name that fronts the FRPS control channel (sandbox: `connect.layerv.xyz`, prod: `connect.layerv.ai`). Written into the DDB seed row's `resource_fqdn` field; the bridge materializes that as `ResourceInfo.Hostname` so the agent dials this name instead of the internal Cloud Map host; NLB:frps_bind_port → AC kernel → ipset-gated → Traefik TCP entrypoint → internal `frps-{az}`. Bare DNS name only (no scheme, port, slashes, whitespace, or userinfo); empty value opts out of the FRPS-behind-AC topology and is only valid for envs without `deploy_frps = true`. Validation duplicated from terraform/variables.tf so a malformed value attributes to the env root rather than the parent module; see the parent for the full migration narrative (why the `.internal` and `frps-` shape fences exist transitionally)."
  type        = string
  default     = ""

  # Validations duplicated from terraform/variables.tf — the root copy
  # fences malformed values regardless of `deploy_frps`; this env copy
  # gives earlier/clearer attribution when a tfvars-driven typo hits
  # the env root first (parent validation still fires too).
  #
  # RFC 1035 per-label form is the load-bearing fence (quote-injection
  # exclusion); the `.internal` and `frps-` checks are transitional
  # input-shape fences against the current customer-facing role of this
  # variable. Keep wording identical to the parent so error messages
  # don't drift across layers.
  # TODO(nhp #2019 — "AC out of the FRPS data path"): both the
  # `!endswith(".internal")` and `!startswith("frps-")` validations
  # below are TRANSITIONAL — mirror of the parent's TODO marker at
  # terraform/variables.tf:2076. When the AC exits the FRPS data plane
  # and Hostname legitimately points at FRPS directly, the `.internal`
  # and `frps-` shape fences become wrong for the end-state. Rip them
  # out HERE in the same PR that rips the parent's copy. Grep for
  # `TODO(nhp #2019` to find every site that needs the lockstep
  # removal.
  validation {
    condition     = var.connect_layerv_host == "" || can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$", var.connect_layerv_host))
    error_message = "connect_layerv_host must be a bare lowercase DNS name in per-label RFC 1035 form (each label 1-63 chars, alphanumeric with hyphens but not leading/trailing, multiple labels dot-separated; no scheme, port, slashes, whitespace, or userinfo), or empty to opt out of FRPS-behind-AC. Today's values `connect.layerv.{ai,xyz}` conform."
  }

  validation {
    condition     = var.connect_layerv_host == "" || !endswith(var.connect_layerv_host, ".internal")
    error_message = "connect_layerv_host must NOT end in `.internal` — the FRPS-behind-AC redesign (SLACK_QURL_ROLLOUT.md §6) intentionally splits the customer-facing dial target from the internal FRPS Cloud Map host. Use the public AC ingress name (e.g. `connect.layerv.{ai,xyz}`); the AC Traefik TCP entrypoint forwards to the internal `frps-{az}` host via `var.frp_control_upstream_host` separately."
  }

  validation {
    condition     = var.connect_layerv_host == "" || !startswith(var.connect_layerv_host, "frps-")
    error_message = "connect_layerv_host must NOT start with `frps-` — looks like an FRPS Cloud Map name. Use the customer-facing AC ingress name (e.g. `connect.layerv.{ai,xyz}`), distinct from the FRPS host the AC Traefik TCP entrypoint forwards to internally. See SLACK_QURL_ROLLOUT.md §6 (FRPS-behind-AC redesign)."
  }
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

variable "frps_vhost_http_port" {
  description = "FRP vhost HTTP port. Shared between qurl-reverse-tunnel-server module (bind port) and AC module (qurl-router plugin target) so they can't drift."
  type        = number
  default     = 8080
}

variable "frps_az_suffixes" {
  description = "AZ suffix letters that qurl-reverse-tunnel-server creates per-AZ Cloud Map services for, and that qurl-service hashes OwnerID into. Default `[\"a\", \"b\", \"c\"]` matches us-east-{1,2}{a,b,c}. Each entry must be a single lowercase letter."
  type        = list(string)
  default     = ["a", "b", "c"]

  # Validation duplicated from terraform/variables.tf — the root copy
  # fences a typo at plan time even when `deploy_frps = false` keeps the
  # module out of the graph. Terraform validates root inputs before
  # propagating them to children, so both copies fire; this env copy
  # gives earlier/clearer attribution (env root rather than parent
  # module) when tfvars-driven inputs are malformed. Lockstep with the
  # root + module copies is enforced by
  # `scripts/check-frps-az-suffixes-validation-drift.sh`.
  validation {
    condition     = length(var.frps_az_suffixes) > 0 && alltrue([for s in var.frps_az_suffixes : can(regex("^[a-z]$", s))])
    error_message = "frps_az_suffixes must be a non-empty list of single lowercase letters (e.g., [\"a\", \"b\", \"c\"]) — each entry is the trailing letter of an AWS AZ name."
  }

  validation {
    condition     = length(toset(var.frps_az_suffixes)) == length(var.frps_az_suffixes)
    error_message = "frps_az_suffixes must not contain duplicates (each suffix maps to a distinct Cloud Map service)."
  }
}

variable "frps_min_size" {
  description = "ASG minimum size for qurl-reverse-tunnel-server. Default 1; production envs set this to length(frps_az_suffixes) for one-instance-per-AZ via the per-AZ Cloud Map fanout."
  type        = number
  default     = 1

  validation {
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

# QURL Idempotency Cache
variable "qurl_idempotency_cache_ttl_seconds" {
  description = "TTL for idempotency cache entries in seconds"
  type        = number

  validation {
    condition     = var.qurl_idempotency_cache_ttl_seconds > 0 && var.qurl_idempotency_cache_ttl_seconds <= 86400
    error_message = "qurl_idempotency_cache_ttl_seconds must be between 1 and 86400 seconds (24 hours max)"
  }
}

variable "qurl_idempotency_cache_max_size" {
  description = "Maximum number of idempotency cache entries"
  type        = number

  validation {
    condition     = var.qurl_idempotency_cache_max_size > 0 && var.qurl_idempotency_cache_max_size <= 1000000
    error_message = "qurl_idempotency_cache_max_size must be between 1 and 1000000 entries"
  }
}

variable "qurl_idempotency_cleanup_interval_seconds" {
  description = "Interval between idempotency cache cleanup runs in seconds"
  type        = number

  validation {
    condition     = var.qurl_idempotency_cleanup_interval_seconds > 0 && var.qurl_idempotency_cleanup_interval_seconds <= 3600
    error_message = "qurl_idempotency_cleanup_interval_seconds must be between 1 and 3600 seconds"
  }
}

# QURL Health Check
variable "qurl_health_check_timeout_seconds" {
  description = "Timeout for QURL health check operations in seconds"
  type        = number

  validation {
    condition     = var.qurl_health_check_timeout_seconds > 0 && var.qurl_health_check_timeout_seconds <= 300
    error_message = "qurl_health_check_timeout_seconds must be between 1 and 300 seconds"
  }
}

variable "qurl_health_startup_timeout_seconds" {
  description = "Timeout for QURL startup health checks in seconds"
  type        = number

  validation {
    condition     = var.qurl_health_startup_timeout_seconds > 0 && var.qurl_health_startup_timeout_seconds <= 600
    error_message = "qurl_health_startup_timeout_seconds must be between 1 and 600 seconds"
  }
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

# QURL Resource Config
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

# QURL API Domain Configuration
variable "qurl_service_domain" {
  description = "Custom domain for QURL API (e.g., api.layerv.xyz). When set, creates ACM certificate."
  type        = string
  default     = null
}

variable "qurl_hosted_zone_id" {
  description = "Route53 hosted zone ID for qurl_service_domain DNS records"
  type        = string
  default     = null

  validation {
    condition     = var.qurl_hosted_zone_id == null || can(regex("^Z[A-Z0-9]{8,}$", var.qurl_hosted_zone_id))
    error_message = "qurl_hosted_zone_id must be a valid Route53 hosted zone ID (uppercase, starts with Z, at least 9 characters)."
  }
}

# QURL Auth0 Configuration
variable "qurl_auth0_domain" {
  description = "Auth0 domain for JWKS validation (custom domain, e.g., auth.layerv.ai)"
  type        = string
}

variable "qurl_auth0_audience" {
  description = "Auth0 API audience/identifier (e.g., https://api.layerv.xyz)"
  type        = string

  validation {
    condition     = can(regex("^https://", var.qurl_auth0_audience))
    error_message = "qurl_auth0_audience must be an HTTPS URL"
  }
}

# QURL Auth0 JWKS
variable "qurl_auth0_jwks_cache_ttl_seconds" {
  description = "TTL for Auth0 JWKS cache in seconds"
  type        = number

  validation {
    condition     = var.qurl_auth0_jwks_cache_ttl_seconds > 0 && var.qurl_auth0_jwks_cache_ttl_seconds <= 86400
    error_message = "qurl_auth0_jwks_cache_ttl_seconds must be between 1 and 86400 seconds (24 hours max)"
  }
}

variable "qurl_auth0_jwks_fetch_timeout_seconds" {
  description = "Timeout for fetching Auth0 JWKS in seconds"
  type        = number

  validation {
    condition     = var.qurl_auth0_jwks_fetch_timeout_seconds > 0 && var.qurl_auth0_jwks_fetch_timeout_seconds <= 60
    error_message = "qurl_auth0_jwks_fetch_timeout_seconds must be between 1 and 60 seconds"
  }
}

# QURL AC Fleet defaults
variable "qurl_default_ac_id" {
  description = "Default AC identifier for new QURL resources"
  type        = string
}

variable "qurl_default_ac_port" {
  description = "Default AC port for new QURL resources"
  type        = number
  default     = 443

  validation {
    condition     = var.qurl_default_ac_port > 0 && var.qurl_default_ac_port <= 65535
    error_message = "qurl_default_ac_port must be a valid port number (1-65535)"
  }
}

# QURL Webhooks
variable "qurl_webhooks_enabled" {
  description = "Enable webhook delivery for QURL service"
  type        = bool
  default     = false
}

variable "qurl_webhooks_worker_count" {
  description = "Number of concurrent webhook delivery workers"
  type        = number

  validation {
    condition     = var.qurl_webhooks_worker_count > 0 && var.qurl_webhooks_worker_count <= 100
    error_message = "qurl_webhooks_worker_count must be between 1 and 100"
  }
}

variable "qurl_webhooks_max_webhooks_per_owner" {
  description = "Maximum number of webhooks per owner"
  type        = number

  validation {
    condition     = var.qurl_webhooks_max_webhooks_per_owner > 0 && var.qurl_webhooks_max_webhooks_per_owner <= 100
    error_message = "qurl_webhooks_max_webhooks_per_owner must be between 1 and 100"
  }
}

variable "qurl_webhooks_delivery_timeout_seconds" {
  description = "Timeout for webhook delivery in seconds"
  type        = number

  validation {
    condition     = var.qurl_webhooks_delivery_timeout_seconds > 0 && var.qurl_webhooks_delivery_timeout_seconds <= 300
    error_message = "qurl_webhooks_delivery_timeout_seconds must be between 1 and 300 seconds"
  }
}

variable "qurl_webhooks_max_retries" {
  description = "Maximum number of webhook delivery retries"
  type        = number

  validation {
    condition     = var.qurl_webhooks_max_retries >= 0 && var.qurl_webhooks_max_retries <= 10
    error_message = "qurl_webhooks_max_retries must be between 0 and 10"
  }
}

variable "qurl_webhooks_event_channel_size" {
  description = "Size of the webhook event channel buffer"
  type        = number

  validation {
    condition     = var.qurl_webhooks_event_channel_size > 0 && var.qurl_webhooks_event_channel_size <= 10000
    error_message = "qurl_webhooks_event_channel_size must be between 1 and 10000"
  }
}

variable "qurl_webhooks_retry_worker_interval_seconds" {
  description = "Interval between webhook retry worker runs in seconds"
  type        = number

  validation {
    condition     = var.qurl_webhooks_retry_worker_interval_seconds > 0 && var.qurl_webhooks_retry_worker_interval_seconds <= 3600
    error_message = "qurl_webhooks_retry_worker_interval_seconds must be between 1 and 3600 seconds"
  }
}

variable "qurl_webhooks_drain_timeout_seconds" {
  description = "Timeout for draining webhook events during shutdown in seconds"
  type        = number

  validation {
    condition     = var.qurl_webhooks_drain_timeout_seconds > 0 && var.qurl_webhooks_drain_timeout_seconds <= 300
    error_message = "qurl_webhooks_drain_timeout_seconds must be between 1 and 300 seconds"
  }
}

variable "qurl_webhooks_response_body_limit" {
  description = "Maximum response body size to store from webhook endpoints in bytes"
  type        = number

  validation {
    condition     = var.qurl_webhooks_response_body_limit > 0 && var.qurl_webhooks_response_body_limit <= 1048576
    error_message = "qurl_webhooks_response_body_limit must be between 1 and 1048576 bytes (1MB max)"
  }
}

variable "qurl_webhooks_api_version" {
  description = "API version string for webhook payloads"
  type        = string
}

# QURL Custom Domains
variable "qurl_custom_domain_enabled" {
  description = "Enable custom domain management endpoints in QURL service"
  type        = bool
  default     = false
}

# QURL GeoIP
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
  description = "S3 URI of the GeoLite2-Country .mmdb database"
  type        = string
  default     = ""
}

variable "qurl_geoip_s3_kms_key_arn" {
  description = "KMS key ARN used to encrypt the GeoIP S3 bucket"
  type        = string
  default     = ""
}

# QURL Observability (OpenTelemetry)
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

  validation {
    condition     = var.qurl_otel_trace_sample_rate >= 0 && var.qurl_otel_trace_sample_rate <= 1
    error_message = "qurl_otel_trace_sample_rate must be between 0.0 and 1.0"
  }
}

variable "qurl_otel_metrics_interval" {
  description = "Metrics export interval in seconds"
  type        = number

  validation {
    condition     = var.qurl_otel_metrics_interval > 0 && var.qurl_otel_metrics_interval <= 3600
    error_message = "qurl_otel_metrics_interval must be between 1 and 3600 seconds"
  }
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

# QURL Container Sizing
variable "qurl_container_cpu" {
  description = "CPU units for QURL container (256, 512, 1024, 2048, 4096, 8192, 16384)"
  type        = number
  default     = 256

  validation {
    condition     = contains([256, 512, 1024, 2048, 4096, 8192, 16384], var.qurl_container_cpu)
    error_message = "qurl_container_cpu must be a valid Fargate CPU value."
  }
}

variable "qurl_container_memory" {
  description = "Memory in MB for QURL container. When grafana_cloud_enabled=true, effective memory is container_memory + 256."
  type        = number
  default     = 512

  validation {
    condition     = var.qurl_container_memory >= 512 && var.qurl_container_memory <= 122880
    error_message = "qurl_container_memory must be between 512 and 122880 MB."
  }
}

variable "qurl_container_port" {
  description = "TCP port qurl-service tasks listen on. Threaded into BOTH module.qurl_service (container_port) AND module.bootstrap_alb (target_port) at the nhp module level so the two cannot drift (modules/bootstrap-alb/variables.tf::target_port explicitly calls out this footgun). Default 8080 — operators rarely override; only meaningful when the qurl-service container exposes a non-default port."
  type        = number
  default     = 8080
  nullable    = false

  validation {
    condition     = var.qurl_container_port > 0 && var.qurl_container_port < 65536
    error_message = "qurl_container_port must be a valid TCP port (1–65535)."
  }
}

variable "qurl_desired_count" {
  description = "Desired number of QURL ECS tasks"
  type        = number
  default     = 1
}

variable "qurl_autoscaling_min_capacity" {
  description = "Minimum number of QURL ECS tasks for auto-scaling"
  type        = number
  default     = 1
}

# QURL Grafana Cloud (ADOT Sidecar)
variable "qurl_grafana_cloud_enabled" {
  description = "Enable Grafana Cloud OTLP export via ADOT sidecar for QURL service"
  type        = bool
  default     = false
}

variable "qurl_grafana_secret_arn" {
  description = "ARN of Secrets Manager secret containing Grafana Cloud OTLP credentials"
  type        = string
  default     = null
}

variable "qurl_adot_collector_image" {
  description = "ADOT Collector container image for QURL service"
  type        = string
  default     = "public.ecr.aws/aws-observability/aws-otel-collector:v0.40.0"
}

# Grafana Cloud Dashboards
variable "grafana_dashboards_enabled" {
  description = "Enable Grafana Cloud dashboard provisioning"
  type        = bool
  default     = true
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

variable "grafana_cloudwatch_enabled" {
  description = "Enable CloudWatch data source in Grafana for NHP Infrastructure dashboard"
  type        = bool
  default     = true
}

variable "grafana_cloud_aws_account_id" {
  description = "Grafana Cloud's AWS account ID for IAM trust policy"
  type        = string
  default     = "008923505280"
}

variable "grafana_cloud_external_id" {
  description = "External ID for Grafana Cloud IAM assume role"
  type        = string
  default     = null
}

variable "grafana_create_dashboards" {
  description = "Create Grafana dashboard and folder resources. Set to false for non-primary environments."
  type        = bool
  default     = true
}

# Cost analytics
# Role in LayerV mgmt/payer account (165115313779) for consolidated billing access.
# Same cross-account pattern as cross_account_route53_role_arn above.
variable "cross_account_cost_analytics_role_arn" {
  description = "IAM role ARN in mgmt account for cost analytics resources"
  type        = string
  default     = "arn:aws:iam::165115313779:role/nhp-cost-analytics-access"
}

variable "deploy_cost_analytics" {
  description = "Deploy AWS cost analytics (Data Export + Athena + Grafana dashboard)"
  type        = bool
  default     = true
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

# Traefik plugins
variable "traefik_plugins" {
  description = "Map of Traefik plugins to deploy"
  type = map(object({
    version = string
    config  = optional(map(string), {})
  }))
  default = {}
}

# Traefik plugins deploy bucket (for traefik-plugins CI/CD SSM-based deployment)
variable "traefik_plugins_deploy_bucket_arn" {
  description = "ARN of the S3 bucket used by traefik-plugins CI/CD for SSM-based plugin deployment"
  type        = string
  default     = null
}

# Plugin repos - repos that can assume the GitHub Actions role
variable "plugin_repos" {
  description = "Additional GitHub repos that can assume the GitHub Actions role"
  type        = list(string)
  default     = []
}

variable "cross_account_route53_role_arn" {
  description = "IAM role ARN for cross-account Route 53 access"
  type        = string
  default     = null
}

# CloudMap configuration
variable "nhp_cloudmap_service_name" {
  description = "CloudMap service name for NHP servers. Required. Recommended: 'server'"
  type        = string
}

# Standalone AC license credentials (for cloud mode registration)
variable "ac_customer_id" {
  description = "Customer ID for standalone AC license (ULID format)"
  type        = string
  default     = null
}

variable "ac_license_key" {
  description = "License key for standalone AC registration (plaintext, passed via TF_VAR_ac_license_key)"
  type        = string
  sensitive   = true
  default     = null
}

variable "ac_license_key_hash" {
  description = "Bcrypt hash of standalone AC license key for validation"
  type        = string
  sensitive   = true
  default     = null
}

variable "ac_license_key_sha256" {
  description = "SHA256 hash of standalone AC license key for DynamoDB lookup"
  type        = string
  sensitive   = true
  default     = null
}

# TLS certificate configuration
variable "additional_tls_domains" {
  description = "Additional domains for TLS certificates in same account"
  type        = list(string)
  default     = []
}

variable "use_production_acme" {
  description = "Use production Let's Encrypt (true) or staging (false)"
  type        = bool
  default     = null
}

# Security alerting
variable "guardduty_alert_emails" {
  description = "List of email addresses to receive GuardDuty security finding alerts"
  type        = list(string)
  default     = []
}

# ==============================================================================
# Auth0 Configuration
# ==============================================================================

variable "auth0_domain" {
  description = "Auth0 tenant domain for Management API (e.g., dev-xxx.us.auth0.com). Required when using Auth0 module."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9-]+\\.(us|eu|au|jp)\\.auth0\\.com$", var.auth0_domain))
    error_message = "auth0_domain must be a valid Auth0 tenant domain (e.g., dev-xxx.us.auth0.com)"
  }
}

# ==============================================================================
# Auth0 Secret Rotation Configuration
# ==============================================================================

variable "auth0_manage_tenant_resources" {
  description = "Whether this environment manages shared Auth0 tenant resources (roles, branding, attack protection, email, social connections). Only one environment should set this to true per shared tenant."
  type        = bool
  default     = true
}

variable "auth0_enable_rotation" {
  description = "Enable automatic rotation for Auth0 M2M credentials"
  type        = bool
  default     = false
}

variable "auth0_rotation_days" {
  description = "Rotate Auth0 M2M credentials every N days"
  type        = number
  default     = 30
}

variable "auth0_management_secret_arn" {
  description = "Secrets Manager ARN containing Auth0 Management API credentials for rotation Lambda. Required when auth0_enable_rotation is true."
  type        = string
  default     = null
}

# ==============================================================================
# Centralized TLS Certificate Management
# ==============================================================================
# When enabled, ACs fetch TLS certificates from Secrets Manager instead of
# requesting individual certificates via ACME. This scales to thousands of ACs
# without hitting Let's Encrypt rate limits.
#
# NOTE: This is an interim solution. For production at scale, consider migrating
# to HashiCorp Vault PKI for short-lived certificates and better revocation.

variable "centralized_cert_enabled" {
  description = "Enable centralized certificate management for AC fleet"
  type        = bool
  default     = false
}

variable "centralized_cert_domains" {
  description = "Domains for centralized TLS certificate (e.g., ['nhp.layerv.xyz', '*.nhp.layerv.xyz'])"
  type        = list(string)
  default     = []
}

variable "deploy_custom_domain_cert" {
  description = "Deploy the custom domain certificate manager Lambda for QURL custom domains"
  type        = bool
  default     = false
}

# ==============================================================================
# Blue/Green Deployment Configuration
# ==============================================================================

variable "enable_blue_green" {
  description = "Enable blue/green deployment infrastructure for NHP Server"
  type        = bool
  default     = false
}

variable "green_standby_min_size" {
  description = "Min instances for green ASG in standby (1=warm with strict target-health alarms, 0=cold with missing-data pages suppressed until warmed)"
  type        = number
  default     = 1
}

variable "deployment_stale_threshold_days" {
  description = "Days without deployments before stale alarm fires (0=disable)"
  type        = number
  default     = 7
}

variable "enable_ac_blue_green" {
  description = "Enable blue/green deployment infrastructure for AC. Creates a second ASG and SSM parameters for instant traffic switching."
  type        = bool
  default     = false
}

variable "ac_green_standby_min_size" {
  description = "Minimum instance count for AC green ASG in standby mode. 1 = warm standby (instant switch), 0 = cold standby (requires scale-up)."
  type        = number
  default     = 1
}

# ==============================================================================
# Canary Deployment Configuration
# ==============================================================================

variable "enable_canary_deployment" {
  description = "Enable Step Functions-based canary deployment for progressive production rollouts"
  type        = bool
  default     = false
}

variable "canary_checkpoint_percentages" {
  description = "Instance refresh checkpoint percentages for canary stages"
  type        = list(number)
  default     = [20, 50, 100]
}

variable "canary_checkpoint_delay_seconds" {
  description = "Seconds to observe at each canary checkpoint before auto-resuming"
  type        = number
  default     = 300
}

variable "canary_instance_warmup_seconds" {
  description = "Instance warmup time in seconds for canary refresh. NLB-disabled canaries also require the ASG capacity-deficit alarm window to stay shorter than canary_checkpoint_delay_seconds."
  type        = number
  default     = 180
}

# ==============================================================================
# Status Page Configuration
# ==============================================================================

variable "deploy_status_page" {
  description = "Deploy the deployment status page (Lambda + API Gateway + S3 + CloudFront)"
  type        = bool
  default     = false
}

variable "status_page_domain" {
  description = "Custom domain for the status page (e.g., status.layerv.xyz)"
  type        = string
  default     = null
}

variable "status_page_hosted_zone_id" {
  description = "Route53 hosted zone ID for the status page custom domain"
  type        = string
  default     = null

  validation {
    condition     = var.status_page_hosted_zone_id == null || can(regex("^Z[A-Z0-9]{8,}$", var.status_page_hosted_zone_id))
    error_message = "status_page_hosted_zone_id must be a valid Route53 hosted zone ID (uppercase, starts with Z, at least 9 characters)."
  }
}

variable "status_page_additional_service_urls" {
  description = "Additional public components for the status page (component id => HTTPS health check URL)"
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
  description = "Status page component ids to render and track but exclude from automated component rollup."
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

variable "status_page_nhp_auth_enabled" {
  description = "Protect the status page with NHP authentication (dogfooding)"
  type        = bool
  default     = false
}

variable "status_page_nhp_auth_qurl_url" {
  description = "QURL link URL for status page authentication. Required when status_page_nhp_auth_enabled is true."
  type        = string
  default     = null
}

# Developer Portal
variable "deploy_developer_portal" {
  description = "Deploy developer portal infrastructure (playground proxy + credential provisioner)"
  type        = bool
  default     = false
}

variable "developer_portal_m2m_secret_name" {
  description = "Secrets Manager secret name for playground M2M credentials"
  type        = string
  default     = null
}

variable "developer_portal_auth0_mgmt_secret_name" {
  description = "Secrets Manager secret name for Auth0 management API credentials"
  type        = string
  default     = null
}

variable "developer_portal_auth0_domain" {
  description = "Auth0 domain for developer portal"
  type        = string
  default     = null
}

variable "developer_portal_allowed_origins" {
  description = "CORS allowed origins for developer portal API"
  type        = list(string)
  default     = []
}

variable "developer_portal_custom_domain" {
  description = "Custom domain for developer portal API"
  type        = string
  default     = null
}

variable "developer_portal_hosted_zone_id" {
  description = "Route53 hosted zone ID for developer portal custom domain"
  type        = string
  default     = null

  validation {
    condition     = var.developer_portal_hosted_zone_id == null || can(regex("^Z[A-Z0-9]{8,}$", var.developer_portal_hosted_zone_id))
    error_message = "developer_portal_hosted_zone_id must be a valid Route53 hosted zone ID (uppercase, starts with Z, at least 9 characters)."
  }
}

variable "developer_portal_ci_bypass_secret_name" {
  description = "Secrets Manager secret name for CI bypass key"
  type        = string
  default     = null
}

variable "developer_portal_connector_base_url" {
  description = "Base URL of the qURL S3 connector for /playground/upload."
  type        = string
}

# ==============================================================================
# Auth0 SPA Dashboard Configuration
# ==============================================================================

variable "enable_auth0_spa_dashboard" {
  description = "Enable Auth0 SPA client for dashboard login"
  type        = bool
  default     = false
}

variable "auth0_custom_domain" {
  description = "Auth0 custom domain for SPA login (e.g., auth.layerv.ai). If null, falls back to auth0_domain."
  type        = string
  default     = null
}

# ==============================================================================
# Auth0 Slack OAuth Configuration
# ==============================================================================

variable "enable_auth0_slack_oauth_client" {
  description = "Enable the Auth0 regular_web client for qurl-bot-slack workspace-install OAuth flow. The callback URL is derived in main.tf from `local.slack_bot_domain` (in `qurl_bot_dns.tf`) + the fixed `/oauth/qurl/callback` path — single source of truth, no env-level callback override."
  type        = bool
  default     = false
}

# ==============================================================================
# Billing Configuration
# ==============================================================================

variable "deploy_billing" {
  description = "Deploy billing infrastructure (Stripe integration)"
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
  description = "Base URL for Stripe API"
  type        = string
  default     = "https://api.stripe.com"
}

variable "billing_growth_price_id" {
  description = "Stripe Price ID for the Growth plan metered usage component"
  type        = string
  default     = ""
}

variable "billing_base_fee_price_id" {
  description = "Stripe Price ID for the Growth plan base fee"
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

variable "dashboard_allowed_origins" {
  description = "Default CORS origins shared by all dashboard APIs (developer portal, billing)"
  type        = list(string)
  default     = []
}

variable "billing_from_email" {
  description = "SES verified sender email for grace period notifications"
  type        = string
  default     = null
}

variable "billing_ses_region" {
  description = "AWS region for SES"
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
  description = "API Gateway throttle burst limit for billing API"
  type        = number
  default     = 50
}

variable "billing_api_throttle_rate_limit" {
  description = "API Gateway throttle rate limit for billing API"
  type        = number
  default     = 25
}

variable "deploy_redis" {
  description = "Deploy ElastiCache Serverless Redis for distributed QURL rate limiting"
  type        = bool
  default     = false
}

variable "deploy_vpc_endpoints" {
  description = "Deploy additional VPC endpoints for QURL service AWS dependencies (DynamoDB gateway, SQS interface)"
  type        = bool
  default     = false
}

# ==================== Bootstrap ALB ====================
# Closes the second class of env-root gap noted in the body of #2035 (the
# FRPS passthrough PR): `bootstrap_alb_*` and `qurl_connector_auth_enabled`
# (below) are set in env tfvars but were never declared at the env root,
# so they surfaced as "Value for undeclared variable" warnings at plan
# time and silently no-op'd at apply — leaving the bootstrap-alb module
# uninstantiated (no `bootstrap.layerv.xyz` Route53 record, no ACM cert,
# no qurl-service target group) and `CONNECTOR_AUTH_ENABLED=false` on the
# qurl-service ECS task def. Threading them here closes that gap so the
# Wave 5 connector-auth + agent-bootstrap chain can actually apply in
# sandbox. Same wiring pattern as #2035.
#
# All 10 `bootstrap_alb_*` vars are declared here even though sandbox
# tfvars only sets 5 — the other 5 fall back to parent defaults.
# Declaring them all forecloses the same gap on future operator flips
# (e.g. `bootstrap_alb_elb_5xx_threshold_per_minute = 1` once the data
# plane is healthy, or `bootstrap_alb_cross_account_subscriber_arns`
# once alerts-infra is wired).
#
# Descriptions + validations mirrored from terraform/variables.tf for
# root-pointed error attribution; keep in lockstep with terraform/variables.tf.

variable "deploy_bootstrap_alb" {
  description = "Deploy the bootstrap-alb stack (bootstrap.layerv.{xyz,ai}). Default off; flip per-env once the cert is wired (Path 1 / prod: operator pre-provisions cross-account; Path 2 / sandbox: module provisions same-account — see modules/bootstrap-alb/README.md) and qurl-service ECS is ready to register against the new target group."
  type        = bool
  default     = false
}

variable "bootstrap_alb_dns_name" {
  description = "Public DNS name for the bootstrap ALB. Sandbox: `bootstrap.layerv.xyz`. Prod: `bootstrap.layerv.ai`. Only read when `deploy_bootstrap_alb = true`."
  type        = string
  default     = ""

  # Mirrored from parent for root-pointed error attribution; keep in lockstep with terraform/variables.tf.
  validation {
    condition     = var.bootstrap_alb_dns_name == "" || can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", var.bootstrap_alb_dns_name))
    error_message = "bootstrap_alb_dns_name must be empty (when `deploy_bootstrap_alb=false`) or a valid lowercase FQDN like `bootstrap.layerv.xyz`."
  }
}

variable "bootstrap_alb_route53_zone_id" {
  description = "Hosted zone ID for the parent of `bootstrap_alb_dns_name`. Required when `bootstrap_alb_provision_certificate` or `bootstrap_alb_manage_dns_alias` is true. Empty when both are false (operator-managed out-of-band — typical when the parent zone is cross-account, but also valid for any same-account env that chooses to operator-manage cert + alias)."
  type        = string
  default     = ""

  # Mirrored from parent for root-pointed error attribution; keep in lockstep with terraform/variables.tf.
  validation {
    condition     = var.bootstrap_alb_route53_zone_id == "" || can(regex("^Z[A-Z0-9]{8,}$", var.bootstrap_alb_route53_zone_id))
    error_message = "bootstrap_alb_route53_zone_id must be empty or a valid Route53 zone ID (uppercase, starts with Z)."
  }
}

variable "bootstrap_alb_manage_dns_alias" {
  description = "Whether the bootstrap-alb stack writes the A-alias from `bootstrap_alb_dns_name` to the ALB. True when the parent zone is in the same account as the ALB; false when cross-account (alias is operator-managed in the zone's account). Sandbox: true (`layerv.xyz` zone in 767397897469, same account). Prod: false (`layerv.ai` zone in `layerv-mgmt`)."
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

  # Mirrored from parent for root-pointed error attribution; keep in lockstep with terraform/variables.tf.
  validation {
    condition     = var.bootstrap_alb_existing_certificate_arn == "" || can(regex("^arn:(aws|aws-us-gov|aws-cn|aws-iso|aws-iso-b|aws-iso-c|aws-iso-e|aws-iso-f):acm:[a-z0-9-]+:[0-9]{12}:certificate/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", var.bootstrap_alb_existing_certificate_arn))
    error_message = "bootstrap_alb_existing_certificate_arn must be empty or a valid ACM ARN: `arn:<partition>:acm:<region>:<12-digit-account>:certificate/<canonical 8-4-4-4-12 UUID>`."
  }
}

variable "bootstrap_alb_waf_count_only_rule_groups" {
  description = "Managed rule-group names from the bootstrap-alb WAF to override to `count` action (vs the default `none` action which honors the group's own block/count actions). Use to bring a new managed group up in count-only mode for a watch period before flipping to enforce. Recommended sandbox-rollout posture is count-only for BOTH `AWSManagedRulesAnonymousIpList` (customer VPN egress class) AND `AWSManagedRulesCommonRuleSet` (CRS body inspection false-positives on PEM-wrapped public keys) for the first 2–4 weeks of sandbox bootstrap traffic."
  type        = list(string)
  default     = []

  # Mirrored from parent for root-pointed error attribution; keep in lockstep with terraform/variables.tf.
  validation {
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

# Description + validation mirrored from terraform/variables.tf for
# root-pointed error attribution; keep both copies in lockstep.
variable "bootstrap_unauthorized_threshold_per_minute" {
  description = "Threshold value for the `bootstrap-unauthorized-spike` alarm in `terraform/qurl_service_outcomes.tf`. The alarm uses `GreaterThanThreshold` so a default of `3` fires at 4+/min sustained 3-of-5 minutes (same shape as `bootstrap_alb_5xx`). Env tfvars may override to quiet the alarm during a known operator probe / load test. See description in terraform/variables.tf for the full rationale."
  type        = number
  default     = 3

  validation {
    condition     = var.bootstrap_unauthorized_threshold_per_minute >= 1 && var.bootstrap_unauthorized_threshold_per_minute <= 1000
    error_message = "bootstrap_unauthorized_threshold_per_minute must be 1 ≤ x ≤ 1000. Floor 1: threshold 0 with GreaterThanThreshold pages on the first single 401, too noisy for a key-rotation window. Ceiling 1000: catches typo-class mistakes (e.g., `300` for `30`) that would effectively disable the alarm — bootstrap traffic at steady state is <1 success/min, so any threshold > 1000 is almost certainly wrong."
  }
}

# Description + validation mirrored from terraform/variables.tf for
# root-pointed error attribution; keep both copies in lockstep.
variable "bootstrap_rate_limited_threshold_per_minute" {
  description = "Threshold value for the `bootstrap-rate-limited-spike` alarm in `terraform/qurl_service_outcomes.tf`. The alarm uses `GreaterThanThreshold` so a default of `3` fires at 4+/min sustained 3-of-5 minutes (mirrors the unauthorized threshold). Env tfvars may override. See description in terraform/variables.tf for the full rationale."
  type        = number
  default     = 3

  validation {
    condition     = var.bootstrap_rate_limited_threshold_per_minute >= 1 && var.bootstrap_rate_limited_threshold_per_minute <= 1000
    error_message = "bootstrap_rate_limited_threshold_per_minute must be 1 ≤ x ≤ 1000 (per `bootstrap_unauthorized_threshold_per_minute` rationale — floor catches the 0-trap, ceiling catches typo-class mistakes)."
  }
}

# Description + validation mirrored from terraform/variables.tf for
# root-pointed error attribution; keep both copies in lockstep.
variable "knock_token_reject_threshold_per_minute" {
  description = "Threshold value for the `frps-knock-token-reject-rate` alarm in the qurl-reverse-tunnel-server module. The alarm uses `GreaterThanThreshold` so a default of `3` fires at 4+/min sustained 3-of-5 minutes (same shape as the bootstrap-outcome thresholds). Env tfvars may override. See description in terraform/variables.tf for the full rationale."
  type        = number
  default     = 3

  validation {
    condition     = var.knock_token_reject_threshold_per_minute >= 1 && var.knock_token_reject_threshold_per_minute <= 1000
    error_message = "knock_token_reject_threshold_per_minute must be 1 ≤ x ≤ 1000 (floor catches the 0-trap; ceiling catches typo-class mistakes that would effectively disable the alarm)."
  }
}

# Validation mirrored from terraform/variables.tf for root-pointed error
# attribution; the description is condensed here (see that file for the
# full rationale). Keep the validation in lockstep.
variable "owner_missing_reject_threshold" {
  description = "Threshold value for the `frps-owner-missing-rejects` alarm in the qurl-reverse-tunnel-server module. The alarm uses `GreaterThanOrEqualToThreshold` over a single 5-minute Sum, so a default of `5` — half the ~10 rejects one stuck connector emits per 5-minute window — breaches on a single stuck connector but not on a transient 1-2 blip. Env tfvars may override to quiet the alarm during a known connector force-restart window. See description in terraform/variables.tf for the full rationale."
  type        = number
  default     = 5

  validation {
    condition     = var.owner_missing_reject_threshold >= 1 && var.owner_missing_reject_threshold <= 1000
    error_message = "owner_missing_reject_threshold must be 1 ≤ x ≤ 1000 (floor avoids the always-on trap under GreaterThanOrEqualToThreshold; ceiling catches typo-class mistakes that would effectively disable the alarm)."
  }
}

# ==================== QURL Connector Auth ====================
# Same env-root-gap class as the Bootstrap ALB section above.

variable "qurl_connector_auth_enabled" {
  description = "Enable qurl-service connector-auth endpoint and type=tunnel branches in CreateQurl/CreateResource (qurl-service PR #277 feature gate). Default false keeps the new code paths inert in production until the creation endpoint (qurl-service #405) and per-AZ FRPS assignment (qurl-service #396) are both deployed. Flip per-env via tfvars after the dependent qurl-service work ships and the qurl-service deploy is verified."
  type        = bool
  default     = false
}

# ── NHP-Relay (#2208) — mirrored from parent terraform/variables.tf ──
variable "deploy_relay" {
  description = "Deploy the NHP-Relay stack (autoscaling fleet + internet-facing ALB). Default off; sandbox enables for the dark launch. The fleet shares one keypair and authenticates by pubkey + relay.toml registration (not source IP) once the server runs DisableRelayPeerValidation=true (5c, #2627); baseline one instance per AZ. See #2629."
  type        = bool
  default     = false
}

variable "relay_vpc_cidr" {
  description = "Dedicated relay DMZ VPC CIDR."
  type        = string
  default     = "10.101.0.0/16"

  validation {
    condition     = can(cidrnetmask(var.relay_vpc_cidr)) && cidrnetmask(var.relay_vpc_cidr) == "255.255.0.0"
    error_message = "relay_vpc_cidr must be a valid IPv4 /16 CIDR."
  }
}

# Keep canonical-key and ordering rules in lockstep with terraform/variables.tf,
# the prod wrapper, and modules/compute/variables.tf.
variable "relay_additional_trusted_public_keys_b64" {
  description = "Sorted, duplicate-free public X25519 keys trusted temporarily during relay identity rotation."
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
  description = "Hosted zone ID for the parent of `relay_dns_name`. Required when `relay_provision_certificate` or `relay_manage_dns_alias` is true. Empty otherwise."
  type        = string
  default     = ""

  validation {
    condition     = var.relay_route53_zone_id == "" || can(regex("^Z[A-Z0-9]{8,}$", var.relay_route53_zone_id))
    error_message = "relay_route53_zone_id must be empty or a valid Route53 zone ID (uppercase, starts with Z)."
  }
}

variable "relay_provision_certificate" {
  description = "Whether the relay module provisions+validates a regional ACM cert for `relay_dns_name`. Sandbox: true (same-account). Prod: false (operator pre-provisions cross-account)."
  type        = bool
  default     = false
}

variable "relay_manage_dns_alias" {
  description = "Whether the relay module writes the A-alias from `relay_dns_name` to the ALB. Sandbox: true. Prod: false."
  type        = bool
  default     = false
}

variable "relay_existing_certificate_arn" {
  description = "Regional ACM cert ARN to attach when `relay_provision_certificate=false`. Same region+account as the ALB."
  type        = string
  default     = ""

  validation {
    condition     = var.relay_existing_certificate_arn == "" || can(regex("^arn:(aws|aws-us-gov|aws-cn):acm:[a-z0-9-]+:[0-9]{12}:certificate/[a-f0-9-]{36}$", var.relay_existing_certificate_arn))
    error_message = "relay_existing_certificate_arn must be empty or a valid regional ACM ARN."
  }
}

variable "relay_waf_rate_limit_per_source_ip" {
  description = "Relay WAF per-source-IP rate limit (req/5min on /relay/*) — env-tunable for #6. Default 300."
  type        = number
  default     = 300

  validation {
    condition     = var.relay_waf_rate_limit_per_source_ip >= 100 && var.relay_waf_rate_limit_per_source_ip <= 2000
    error_message = "relay_waf_rate_limit_per_source_ip must be 100-2000."
  }
}

variable "relay_scale_requests_per_target" {
  description = "Relay ASG target-tracking threshold (ALB request count per target) — env-tunable for #6. Default 1000."
  type        = number
  default     = 1000

  validation {
    condition     = var.relay_scale_requests_per_target >= 50
    error_message = "relay_scale_requests_per_target must be >= 50."
  }
}

# ==================== qURL v2 (keyed identity) ====================
# Gates for qURL v2. All default false / empty (dark launch). Enabling is a
# coordinated flip across qurl-service (issuance) and the NHP server (admission).
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

# ==============================================================================
# Auth0 client IDs (#3284)
# ==============================================================================
# The Auth0 Terraform provider is retired — tenant configuration lives in the
# Auth0 dashboard. These IDs are inputs to the AWS-side resources that publish
# and reference them. Auth0 client IDs are PUBLIC identifiers, not secrets: the
# dashboard client ID is already a plaintext SSM parameter and ships to browsers
# as NEXT_PUBLIC_AUTH0_CLIENT_ID. Client SECRETS are never Terraform inputs.

variable "auth0_backend_service_client_id" {
  description = "Auth0 client ID of the Website Playground M2M application. Public identifier."
  type        = string
  default     = null
}

variable "auth0_smoke_test_client_id" {
  description = "Auth0 client ID of the smoke-test M2M application. Public identifier."
  type        = string
  default     = null
}

variable "auth0_spa_dashboard_client_id" {
  description = "Auth0 client ID of the dashboard SPA. Public identifier, published to SSM for the website build."
  type        = string
  default     = null
}

variable "auth0_slack_oauth_client_id" {
  description = "Auth0 client ID of the qurl-bot-slack workspace-install application. Public identifier."
  type        = string
  default     = null
}

# Control identity plane for qurl-service. See terraform/variables.tf for why
# identity is global rather than cell-scoped. Empty keeps cell identity tables.
variable "control_identity_environment_id" {
  description = "Control namespace environment id for qurl-service identity. Empty keeps cell identity tables."
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
