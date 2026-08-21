variable "environment" {
  description = "Infrastructure namespace used for resource names, tags, logs, and SSM paths."
  type        = string
}

variable "protocol_environment" {
  description = "Logical NHP/Authority environment placed in NHP_ENVIRONMENT. null inherits environment; a secondary sandbox cell sets sandbox while retaining a distinct infrastructure namespace."
  type        = string
  default     = null

  validation {
    condition     = var.protocol_environment == null || contains(["sandbox", "prod"], var.protocol_environment)
    error_message = "protocol_environment must be null, sandbox, or prod."
  }
}

# =============================================================================
# AMI Configuration
# =============================================================================

variable "server_ami_id" {
  description = <<-EOT
    Docker-optimized AMI ID for NHP Server instances.

    If not set, reads from SSM parameter: /{environment}/nhp/server/ami-id
    If neither exists, Terraform fails at plan time (no fallback to vanilla Ubuntu).

    Build and publish AMI:
      cd packer && packer build -var 'environment=sandbox' nhp-server-docker.pkr.hcl
      aws ssm put-parameter --name "/sandbox/nhp/server/ami-id" \
        --value "ami-xxx" --type String --overwrite

    Instance startup: ~30s (vs ~5-6 min without custom AMI)
  EOT
  type        = string
  default     = null

  # NOTE: there is intentionally no `validation` block rejecting the
  # PR-validation placeholder ("ami-0000000000000abcd"). An earlier round of
  # this PR added one and it self-defeats: variable validation fires at PLAN
  # time, and the PR-validation step in build-and-push.yml IS a `terraform
  # plan` run. A validation that rejected the placeholder rejected exactly
  # the flow it was meant to coexist with, breaking CI on this branch.
  #
  # The actual safeguards against the placeholder reaching apply are
  # structural and live outside this file:
  #
  #   1. The placeholder is hardcoded in exactly ONE place
  #      (.github/workflows/build-and-push.yml::terraform-plan, the
  #      TF_VAR_server_ami_id env var) and nothing else passes it. Anyone
  #      wanting to misuse it would have to copy-paste from there.
  #   2. That step runs `terraform plan` only, never `terraform apply`.
  #   3. The actual deploy steps (deploy-sandbox-*, promote-to-prod) do NOT
  #      pass TF_VAR_server_ami_id at all. With var.server_ami_id == null,
  #      the compute module reads from SSM
  #      (data.aws_ssm_parameter.server_ami in main.tf). The placeholder
  #      cannot reach those code paths.
  #   4. promote-to-prod additionally verifies the SSM value matches
  #      ^ami-[0-9a-f]+$ AND the AMI is Available before any apply runs
  #      (.github/workflows/promote-to-prod.yml::"Verify prod NHP Server
  #      AMI is published to SSM"), so even an explicitly-bad SSM value
  #      can't reach prod apply.
  #
  # If you ever need to add another path that passes a TF_VAR_server_ami_id
  # value, audit it against the four safeguards above before merging.
}

variable "cell_id" {
  description = "Cell identifier for multi-cell deployments (e.g., cell0, cell1)"
  type        = string
  default     = "cell0"
}

variable "connector_authority_cell_config" {
  description = "Nullable assigned-cell Connector Authority target/config bundle. The resource alias is null only for the exact pre-creso rollout predecessor; null config keeps all cell operations, the Lambda VPC endpoint, and its IAM grant dark."
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

variable "domain_name" {
  description = "Domain name for NHP server"
  type        = string
}

variable "multi_tenant" {
  description = "Enable multi-tenant mode"
  type        = bool
}

variable "min_capacity" {
  description = "Minimum ASG capacity"
  type        = number
}

variable "max_capacity" {
  description = "Maximum ASG capacity"
  type        = number
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
  description = "Private subnet IDs for ASG"
  type        = list(string)
}

variable "additional_nhp_udp_ingress_cidrs" {
  description = "Additional exact CIDRs allowed to send NHP UDP 62206 to server instances. Used by the peered relay DMZ subnets; empty by default."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for cidr in var.additional_nhp_udp_ingress_cidrs : can(cidrhost(cidr, 0))])
    error_message = "additional_nhp_udp_ingress_cidrs entries must be valid CIDRs."
  }

  validation {
    condition     = var.additional_nhp_udp_ingress_cidrs == sort(distinct(var.additional_nhp_udp_ingress_cidrs))
    error_message = "additional_nhp_udp_ingress_cidrs must be sorted and duplicate-free."
  }
}

variable "public_nhp_udp_ingress_cidrs" {
  description = <<-EOT
    Optional sources allowed to reach the assigned-cell public UDP NLB. null
    preserves the legacy NLB-without-security-group shape; a non-null list
    creates an NLB security group at NLB creation and makes the server target
    security group trust only that NLB security group.

    Two shapes are valid and nothing else:

      * a list of exact public IPv4 /32 sources, for a fenced cell; or
      * exactly ["0.0.0.0/0"], the deliberate open-cell value.

    A cell reached through the Hub must admit whatever the Hub admits, or an
    agent completes assignment and then stalls at registration one step later.
    Sandbox cells therefore use the open value alongside the open Hub (see
    qurl-go ADR 0001). The open value is one exact literal rather than a general
    "any CIDR" allowance, so a fat-fingered "10.0.0.0/8" still fails the plan.
  EOT
  type        = list(string)
  default     = null

  validation {
    condition = var.public_nhp_udp_ingress_cidrs == null || (
      (length(var.public_nhp_udp_ingress_cidrs) == 1 && var.public_nhp_udp_ingress_cidrs[0] == "0.0.0.0/0") || (
        length(var.public_nhp_udp_ingress_cidrs) > 0 &&
        alltrue([
          for cidr in var.public_nhp_udp_ingress_cidrs :
          can(cidrnetmask(cidr)) && try(tonumber(split("/", cidr)[1]) == 32, false)
        ])
      )
    )
    error_message = "public_nhp_udp_ingress_cidrs must be null, exactly [\"0.0.0.0/0\"], or a non-empty list of exact IPv4 /32 CIDRs."
  }

  validation {
    condition = (
      var.public_nhp_udp_ingress_cidrs == null ||
      var.public_nhp_udp_ingress_cidrs == sort(distinct(var.public_nhp_udp_ingress_cidrs))
    )
    error_message = "public_nhp_udp_ingress_cidrs must be sorted and duplicate-free."
  }
}

variable "server_repo_url" {
  description = "ECR repository URL for NHP server"
  type        = string
}

variable "server_repo_arn" {
  description = "ECR repository ARN for NHP server"
  type        = string
}

variable "etcd_endpoint" {
  description = "etcd endpoint"
  type        = string
  default     = null
}

variable "etcd_secret_arn" {
  description = "etcd secret ARN"
  type        = string
  default     = null
}

variable "etcd_tls_secret_arn" {
  description = "etcd TLS certificates secret ARN"
  type        = string
  default     = null
}

variable "namespace_id" {
  description = "Service Discovery namespace ID"
  type        = string
}

variable "namespace_name" {
  description = "Service Discovery namespace name"
  type        = string
}

variable "name_prefix" {
  description = "Name prefix for resources"
  type        = string
}

variable "tags" {
  description = "Tags for resources"
  type        = map(string)
  default     = {}
}

variable "ebs_kms_key_arn" {
  description = "KMS key ARN for EBS encryption"
  type        = string
  default     = null
}

variable "logs_kms_key_arn" {
  description = "KMS key ARN for CloudWatch Logs encryption"
  type        = string
  default     = null
}

variable "secrets_kms_key_arn" {
  description = "KMS key ARN for Secrets Manager encryption"
  type        = string
  default     = null
}

# ============================================================================
# NHP Server Configuration Options
# These options control the server's authentication and resource management
# ============================================================================

variable "log_level" {
  description = "NHP server log level: 0=silent, 1=error, 2=info, 3=audit, 4=debug, 5=trace"
  type        = number
  default     = 2

  validation {
    condition     = var.log_level >= 0 && var.log_level <= 5
    error_message = "log_level must be between 0 (silent) and 5 (trace)."
  }
}

variable "dev_mode" {
  description = "Enable development mode for the NHP server"
  type        = bool
  default     = false
}

variable "overload_cookie_time_window_seconds" {
  description = "Rolling verification window for stateless NHP overload cookies. The server accepts the current and previous window, so cross-instance clocks must remain synchronized within this budget."
  type        = number
  default     = 60

  validation {
    condition     = var.overload_cookie_time_window_seconds > 0
    error_message = "overload_cookie_time_window_seconds must be positive."
  }
}

variable "enable_knock_ac_fanout" {
  description = "Cell-wide knock AC fan-out (qurl-service#948). When true an origin knock waits for all its local ACs AND fans the knock out to all assigned peer servers, so every AC the qurl.site NLB can route to opens the L3 pinhole before the knock acks — closing the firewall-coverage race. Default false = legacy first-success, local-only behavior. Rendered as Config.EnableKnockACFanout in config.toml. Rolled out sandbox-first; flip per environment via the root-module gate."
  type        = bool
  default     = false
}

variable "resource_mode" {
  description = "Resource management mode: 'local' (config file) or 'api' (external auth service)"
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
# NHP Server plugins (passcode, oidc, etc.) are baked into the Docker image.
# This ensures Go version compatibility between server and plugins.
# See docker/Dockerfile.server for plugin build configuration.
# ============================================================================

variable "server_plugins" {
  description = <<-EOT
    List of NHP Server plugin names that are baked into the Docker image.
    These are used for etcd seeding (AuthServiceId configuration).
    The actual plugin binaries are built into the Docker image at build time.
    Example: ["passcode", "oidc"]
  EOT
  type        = list(string)
  default     = []
}

variable "auth_service_id" {
  description = "Auth Service Provider ID for resource.toml (maps aspId to plugin paths)"
  type        = string
  default     = ""
}

# ============================================================================
# Phase 4: Pluggable Storage Backend
# These settings control which storage backend is used for AC assignments,
# licenses, and resources. DynamoDB is the default for cloud deployments.
# etcd is available as a feature flag for on-prem deployments.
# See docs/design/PLUGGABLE_STORAGE_BACKEND.md for full architecture.
# ============================================================================

variable "storage_backend" {
  description = <<-EOT
    Storage backend for AC assignments, licenses, and resources.
    - "dynamodb" (default): Use AWS DynamoDB for cloud deployments
    - "etcd": Use etcd for on-prem deployments (feature flag)
    When set to "dynamodb", attach_storage_policies must be true.
    When set to "etcd", etcd_endpoint and etcd_tls_secret_arn should be configured.
  EOT
  type        = string
  default     = "dynamodb"
  validation {
    condition     = contains(["dynamodb", "etcd"], var.storage_backend)
    error_message = "storage_backend must be either 'dynamodb' or 'etcd'"
  }
}

variable "dynamodb_region" {
  description = "AWS region for DynamoDB tables (defaults to current region)"
  type        = string
  default     = null
}

variable "dynamodb_licenses_table" {
  description = "DynamoDB table name for licenses"
  type        = string
  default     = null
}

variable "dynamodb_ac_assignments_table" {
  description = "DynamoDB table name for AC assignments"
  type        = string
  default     = null
}

variable "dynamodb_resources_table" {
  description = "DynamoDB table name for resources"
  type        = string
  default     = null
}

variable "dynamodb_agent_keys_table" {
  description = "DynamoDB table name for sidecar agent registrations (qurl-agent-keys, queried by nhp-server's pubkey-index GSI on knock receipt — PR-1b)."
  type        = string
  default     = null
}

# Control-mode identity plane for the agent-keys read path.
#
# Identity is global, not cell-scoped (see the root variables.tf for the full
# rationale): when the identity plane runs in Control mode, agent registration
# (the Connector Authority) writes agent pubkey rows to the CONTROL
# qurl-agent-keys table and the caller repoints var.dynamodb_agent_keys_table
# at that table. The cell dynamodb module's read policy
# (var.dynamodb_read_policy_arn) covers only cell-local table ARNs, so the
# server role needs its own grant for the Control table — and, because the
# Control tables are SSE-KMS encrypted with the Control identity key (NOT this
# cell's key), kms:Decrypt on that key. All three variables travel together
# with the repointed table name; empty disables the grant entirely (cell
# compatibility mode).
variable "control_identity_agent_keys_table_arn" {
  description = "ARN of the Control qurl-agent-keys table the server resolves agent knocks against in Control identity mode. Empty keeps the cell-local grant surface only."
  type        = string
  default     = ""
}

variable "control_identity_kms_key_arn" {
  description = "KMS key encrypting the Control identity tables. Required when control_identity_agent_keys_table_arn is set — DynamoDB reads of the SSE-KMS Control table fail with AccessDeniedException without decrypt on THIS key (the cell's own key does not cover it)."
  type        = string
  default     = ""
}

variable "control_identity_home_region" {
  description = "Home region of the Control identity tables. Required when control_identity_agent_keys_table_arn is set; must equal the server's effective DynamoDB region because storage.toml renders a single [DynamoDB] Region for every table."
  type        = string
  default     = ""
}

variable "dynamodb_ack_tokens_table" {
  description = "DynamoDB table name for short-lived ACK token metadata used by /nhp/internal/token/validate."
  type        = string
  default     = null
}

variable "attach_storage_policies" {
  description = "Whether to attach storage backend policies (DynamoDB + keypair). Must be true when storage_backend is 'dynamodb'. This boolean is required because Terraform cannot evaluate count based on module outputs at plan time."
  type        = bool
  default     = false
}

variable "dynamodb_read_policy_arn" {
  description = "IAM policy ARN for NHP server DynamoDB storage access (from dynamodb module). Required when attach_storage_policies is true and storage_backend is 'dynamodb'."
  type        = string
  default     = null
}

variable "dynamodb_read_policy_doc_hash" {
  description = "sha256 of the NHP server DynamoDB storage-access policy document. Used to re-fire the server IAM propagation wait when policy contents change."
  type        = string
  default     = null
}

variable "keypair_policy_arn" {
  description = "IAM policy ARN for SSM keypair access (from nhp-keypair module). Required when attach_storage_policies is true."
  type        = string
  default     = null
}

# =============================================================================
# Cloud Map Configuration for Server Health Discovery
# Used to filter stale AC assignments pointing to terminated servers.
# =============================================================================

variable "cloudmap_enabled" {
  description = "Enable Cloud Map health filtering for AC assignments"
  type        = bool
  default     = false
}

variable "cloudmap_namespace_name" {
  description = "Cloud Map namespace name (e.g., 'nhp.sandbox.internal')"
  type        = string
  default     = null
}

variable "cloudmap_service_name" {
  description = "Cloud Map service name within the namespace (e.g., 'server')"
  type        = string
  default     = null
}

# =============================================================================
# ASG Lifecycle Hook for Termination Cleanup
# =============================================================================

variable "enable_termination_cleanup" {
  description = "Enable ASG lifecycle hook for immediate DynamoDB cleanup on server termination. When enabled, a Lambda function cleans up AC assignments before the server terminates."
  type        = bool
  default     = false
}

variable "dynamodb_server_ac_index_table" {
  description = "DynamoDB table name for server-ac-index (inverted index). Required when enable_termination_cleanup is true."
  type        = string
  default     = null
}

variable "dynamodb_ac_assignments_arn" {
  description = "DynamoDB table ARN for AC assignments. Required when enable_termination_cleanup is true."
  type        = string
  default     = null
}

variable "dynamodb_server_ac_index_arn" {
  description = "DynamoDB table ARN for server-ac-index. Required when enable_termination_cleanup is true."
  type        = string
  default     = null
}

variable "alerts_sns_topic_arn" {
  description = "SNS topic ARN for CloudWatch alarms. Used for Lambda error alerts."
  type        = string
  default     = null
}

variable "enable_sns_alerts" {
  description = "Static boolean: set true when this module's SNS-routed alarms should be created and alerts_sns_topic_arn is wired. SNS-routed alarm counts gate on this value to avoid count-depends-on-computed."
  type        = bool
  default     = false
}

# =============================================================================
# QURL Plugin Configuration
# These settings configure the QURL token resolution plugin for qurl.link flow.
# All settings are passed as environment variables to the NHP Server container.
# =============================================================================

variable "qurl_config" {
  description = <<-EOT
    QURL plugin configuration. When enabled, the NHP Server will handle
    token resolution for the qurl.link → qurl.site authentication flow.
    All values are passed as environment variables to the Docker container.
  EOT
  type = object({
    enabled                 = bool
    api_url                 = string # QURL API base URL (e.g., https://api.qurl.internal)
    allowed_redirect_domain = string # Domain suffix for redirect validation (e.g., qurl.site)
    api_timeout             = number # API request timeout in seconds
    max_idle_conns          = number # Maximum idle HTTP connections
    max_idle_conns_per_host = number # Maximum idle connections per host
    idle_conn_timeout       = number # Idle connection timeout in seconds
  })
  default = null

  # Note: Use ternary instead of || because Terraform evaluates both sides
  # of || even when the first condition is true (no short-circuit evaluation)
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

# qURL v2 admission (NHP-server side of the NHP Server Contract). The qURL plugin
# on the NHP server independently verifies qv2 signed claims against this trust
# store before calling qurl-service's admission endpoints. Both default to the
# "off" shape so the plugin's LoadConfig stays satisfied (the trust store is only
# required when admission is enabled). The root module computes the trust store
# from the issuer KMS key's public half; enabling is coordinated with
# qurl-service's QURL_V2_ISSUANCE_ENABLED.
variable "qurl_v2_admission_enabled" {
  description = "Enable the NHP server's qURL v2 signed-claims admission path (QURL_V2_ADMISSION_ENABLED). Requires a non-empty qurl_v2_issuer_trust_store. Default false."
  type        = bool
  default     = false
}

variable "qurl_v2_issuer_trust_store" {
  description = "JSON {kid: base64(DER SPKI P-256 issuer public key)} for QURL_V2_ISSUER_TRUST_STORE. Computed by the root module from the issuer KMS key's public key. Default \"{}\" (no issuers) when admission is off."
  type        = string
  default     = "{}"
}

# Agent-registration email OTP (T1) — NHP-server QURL plugin side. Drives the
# AGENT_OTP_REGISTRATION_ENABLED env var. The user_data template renders it only
# inside the `qurl_enabled` block, so an env with the plugin off never emits it.
# Default false keeps a dark env's user_data byte-unchanged (no fleet roll until
# the coordinated PATH B enable, flipped in lockstep with qurl-service's
# QURL_AGENT_OTP_ENABLED).
variable "agent_otp_registration_enabled" {
  description = "Enable the NHP-server QURL plugin's agent-OTP registration path (AGENT_OTP_REGISTRATION_ENABLED). Rendered only when qurl_config.enabled is true. Default false → user_data byte-unchanged."
  type        = bool
  default     = false
}

variable "qurl_service_token_secret_arn" {
  description = "ARN of Secrets Manager secret containing the QURL service token for API authentication"
  type        = string
  default     = null
}

variable "nhp_internal_auth_secret_arn" {
  description = "Secrets Manager ARN for the NHP internal auth HMAC secret. Injected as NHP_INTERNAL_AUTH_SECRET on the server; shared with qurl-service."
  type        = string

  validation {
    # arn:aws[-partition]:secretsmanager:<region>:<account>:secret:<name> —
    # accepts commercial (aws), GovCloud (aws-us-gov), and China (aws-cn).
    condition     = can(regex("^arn:aws[a-z-]*:secretsmanager:[a-z0-9-]+:[0-9]+:secret:.+$", var.nhp_internal_auth_secret_arn))
    error_message = "nhp_internal_auth_secret_arn must be a valid Secrets Manager ARN."
  }
}

variable "enable_qurl_resolve_endpoint" {
  description = "Enable the QURL resolve endpoint (TLS listener on the qurl_resolve_listener_port output, 8443). When true, adds infrastructure for resolve.qurl.link to route to the NHP Server plugin endpoint. The listener is deliberately not on 443: that port carries the public UDP client edge, and an NLB allows only one listener per port."
  type        = bool
  default     = false
}

variable "qurl_resolve_via_cloudfront" {
  description = "Whether resolve.<domain> is fronted by CloudFront. Required true whenever enable_qurl_resolve_endpoint is true: the resolve TLS listener sits on a non-443 port, and only CloudFront can be pointed at a custom origin port. A browser aliased straight at the NLB would dial 443 and reach the UDP client edge instead."
  type        = bool
  default     = false
}

variable "relay_enabled" {
  description = "#2208 5c: whether an NHP-Relay is deployed (= var.deploy_relay). When true, the server renders relay.toml from relay_trusted_public_keys_b64 and sets DisableRelayValidation=true. This remains a static bool because it gates count/for_each resources; public trust material is a separate explicit input. Default false keeps the server behaviorally dark."
  type        = bool
  default     = false
}

# Keep canonical-key and ordering rules in lockstep with the root additional-key
# input and both environment wrappers; this is the final server trust-set gate.
variable "relay_trusted_public_keys_b64" {
  description = "Public-only X25519 relay identities trusted by the server. Root passes the current relay identity plus any temporary overlap key during rotation. The server instance role never reads the relay private-key secret. Must be non-empty exactly when relay_enabled=true."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for key in var.relay_trusted_public_keys_b64 :
      can(regex("^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$", key))
    ])
    error_message = "relay_trusted_public_keys_b64 entries must be canonical standard-base64 encodings of exactly 32 bytes."
  }

  validation {
    condition     = var.relay_trusted_public_keys_b64 == sort(distinct(var.relay_trusted_public_keys_b64))
    error_message = "relay_trusted_public_keys_b64 must be unique and canonically sorted."
  }
}

variable "qurl_resolve_certificate_arn" {
  description = "ACM certificate ARN for the QURL resolve endpoint (resolve.qurl.link). Required when enable_qurl_resolve_endpoint is true."
  type        = string
  default     = null
}

# =============================================================================
# NHP Server Env-Var Passthroughs
# Variables that flow into /opt/layerv/nhp-server/etc/env via user_data.sh.tpl
# and are consumed by the server binary at process start.
# =============================================================================

variable "cors_allowed_origins" {
  description = "Comma-separated list of allowed CORS origins for NHP HTTP server. When empty, falls back to wildcard '*' (dev mode only)."
  type        = string
  default     = ""
}

variable "cloudfront_cidrs_ssm_parameter" {
  description = "SSM parameter containing CloudFront origin-facing CIDRs for trusted proxy config"
  type        = string
  default     = null
}

variable "knock_headertype_verify_require" {
  description = <<-EOT
    Set NHP_KNOCK_HEADERTYPE_VERIFY=true on the server to enforce
    strict-mode rejection of the NHP_KNK→NHP_EXT type-flip attack
    (#1154 / #1257). Default false leaves the gate in permit mode:
    the server records MetricKnockHeaderTypeMismatch on each attack
    knock but does not reject; the local AC mitigation gap stays open.

    Flip strict only after MetricKnockHeaderTypeLegacy has drained to
    zero across the burn-in window. Legacy must be zero so that
    flipping strict does not lock out legitimate legacy agents AND so
    that the mismatch counter is trustworthy as a per-attack signal
    (under a majority-legacy fleet, an active attack against a legacy
    agent surfaces as Legacy, not Mismatch — see the
    "Additional alarm-semantics caveat" block in
    endpoints/server/knock_headertype_gate.go).
    MetricKnockHeaderTypeMismatch being non-zero is the attack signal
    itself, not a contraindication for flipping strict.

    Variable name uses `_require` to match the shared permit/strict
    gate convention (cf. NHP_INTERNAL_AUTH_REQUIRE); the env var
    keeps the upstream NHP_KNOCK_HEADERTYPE_VERIFY name.
  EOT
  type        = bool
  default     = false
}

variable "internal_auth_require" {
  description = <<-EOT
    Set NHP_INTERNAL_AUTH_REQUIRE=true on the server to enforce strict HMAC
    verification for /nhp/internal/knock and /nhp/internal/token/validate
    (#1122 / #1311). Default false leaves the gate in permit mode: unsigned or
    bad-signature internal requests are logged/metriced via
    InternalAuthFailPermit but are still allowed.

    Flip strict only after the environment/cell has completed permit-mode
    burn-in: InternalAuthFailPermit stays zero while InternalAuthSuccess
    confirms signed internal traffic, and all nhp-server instances plus
    signer fleets have rolled with NHP_INTERNAL_AUTH_SECRET.
  EOT
  type        = bool
  default     = false
}

variable "revocation_retry_enabled" {
  description = <<-EOT
    Set NHP_REVOCATION_RETRY_ENABLED for the server's qURL v2 NHP_REV
    proof-of-delivery engine (#2793): each targeted live AC slot must ACK
    (NHP_RVA) or the server retries until the age-out deadline and emits
    RevocationAgedOut.

    Default false matches the Go binary's absent-env OFF behavior and the
    sibling security-gate convention: module consumers must opt in explicitly
    after confirming the target AC fleet is NHP_RVA-capable. Sandbox/prod
    opt in via environment tfvars. Set this false as an emergency rollback or
    when intentionally deploying a mixed/pre-ACK fleet; doing so returns
    NHP_REV fanout to fire-and-forget semantics and should block relying on
    immediate qURL revocation for production authorization.
  EOT
  type        = bool
  default     = false
}

variable "revocation_retry_interval_seconds" {
  description = "NHP_REVOCATION_RETRY_INTERVAL_SECONDS: whole-second resend cadence for un-acked NHP_REV messages. Must stay >= 1 to avoid a busy retry loop."
  type        = number
  default     = 5

  validation {
    condition     = var.revocation_retry_interval_seconds >= 1 && floor(var.revocation_retry_interval_seconds) == var.revocation_retry_interval_seconds
    error_message = "revocation_retry_interval_seconds must be a whole number of seconds >= 1."
  }
}

variable "revocation_retry_age_out_seconds" {
  description = "NHP_REVOCATION_RETRY_AGE_OUT_SECONDS: whole-second deadline before an un-acked revoke is marked degraded via RevocationAgedOut. Keep above the retry interval and the 15s delivery-latency SLO."
  type        = number
  default     = 60

  validation {
    condition     = var.revocation_retry_age_out_seconds >= 1 && floor(var.revocation_retry_age_out_seconds) == var.revocation_retry_age_out_seconds
    error_message = "revocation_retry_age_out_seconds must be a positive whole number of seconds."
  }
}

# =============================================================================
# Knock-port DoS hardening (#1159)
# =============================================================================

variable "knock_global_rate_limit_pps" {
  description = <<-EOT
    Per-instance packets-per-second cap on UDP knock traffic, layered
    on top of the existing per-source-IP hashlimit (#1159). The per-IP
    limit handles a single noisy client; the global cap handles a
    distributed flood (e.g., 100k-source botnet under per-IP budget
    aggregating to >>ECDH throughput). Drops above this rate happen
    in the kernel before any cryptographic work — that's the point.

    Scope reminder: this is PER INSTANCE. An ASG of N instances has
    aggregate cap N × this value; the NLB hash-distributes flood
    traffic across them, so a 5000 pps cap × 4 instances = 20k pps
    aggregate. Size against per-instance ECDH ops/sec (measured on
    the deployed instance type), not against fleet headroom.

    Pick a value at 50–75% of measured ECDH ops/sec. 5000 pps is the
    conservative default from #1159 ("server's ECDH cost is ~200-400k
    ops/sec on 4 cores"); a follow-up issue (#1495) tracks adding a
    repeatable benchmark + a CloudWatch alarm at 90% so this default
    can be tuned from data instead of estimation.

    Set to 0 to disable the global cap — useful only for environments
    where iptables is provisioned externally (the per-IP rule still
    applies). Disabling here is a hardening regression; document the
    reason in the consuming env's tfvars.
  EOT
  type        = number
  default     = 5000

  validation {
    condition     = var.knock_global_rate_limit_pps >= 0
    error_message = "knock_global_rate_limit_pps must be non-negative (0 disables, positive is the cap)."
  }
}

variable "knock_global_rate_limit_burst" {
  description = <<-EOT
    Burst allowance for the global knock-rate cap (#1159). Default
    is 2× the sustained rate (10000 burst, 5000 pps). The per-IP rule
    intentionally runs the inverse ratio (50 burst, 100 pps = 0.5×):
    a single source spiking above 100 pps is almost always abuse, so
    its burst is tight. The aggregate, by contrast, sums many
    legitimate clients whose simultaneous handshake retries can
    spike well above the steady-state mean — a 2× burst absorbs
    those legitimate spikes without dropping.

    Pathological if 0 with knock_global_rate_limit_pps > 0 (every
    packet at the limit drops, no headroom for legitimate
    microbursts), so the validation below requires a positive burst
    when the cap is active.

    Incident-response breadcrumb: at the defaults, an attacker can
    push up to burst/pps = 2 seconds of above-rate traffic before
    drops engage. An operator running `iptables -L INPUT -n -v`
    during an active flood may see counters above the configured
    rate during that window — the cap is working, the burst is
    just absorbing the leading edge. After ~2s the steady-state
    drop count climbs and the rate stabilizes at the cap.
  EOT
  type        = number
  default     = 10000

  validation {
    condition     = var.knock_global_rate_limit_burst >= 0
    error_message = "knock_global_rate_limit_burst must be non-negative."
  }

  validation {
    condition     = var.knock_global_rate_limit_pps == 0 || var.knock_global_rate_limit_burst > 0
    error_message = "knock_global_rate_limit_burst must be > 0 when knock_global_rate_limit_pps > 0 (a 0-burst hashlimit drops every packet at the steady-state limit; pathological)."
  }
}

variable "udp_recv_buffer_bytes" {
  description = <<-EOT
    Target SO_RCVBUF for the NHP knock listen socket (#1159). The
    kernel default (~208 KiB on Ubuntu) fills quickly under flood,
    causing the kernel to drop legitimate packets first. 8 MiB gives
    a few hundred ms of headroom for the receive goroutine.

    user_data raises net.core.rmem_max to this value via a sysctl
    drop-in so SetReadBuffer takes effect — without that, the kernel
    silently clamps the syscall to ~208 KiB and the Go log emits a
    clamp warning at boot.

    Plumbed into the server as NHP_UDP_RECV_BUFFER_BYTES.
  EOT
  type        = number
  default     = 8388608

  validation {
    condition     = var.udp_recv_buffer_bytes > 0
    error_message = "udp_recv_buffer_bytes must be positive."
  }
}

# =============================================================================
# Blue/Green Deployment Configuration
# =============================================================================

variable "enable_blue_green" {
  description = "Enable blue/green deployment infrastructure. Creates a second ASG (green) and SSM parameters for traffic switching."
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

# =============================================================================
# HTTP server timeouts (http.toml). Grouped because the three values move
# together: `idle` must clear CloudFront's origin_keepalive_timeout (root
# module hard-fails plan/apply on violation via the
# `terraform_data.http_keepalive_contract` preconditions); `write` must
# stay below CF's origin_read_timeout so the server times out first.
# Required (no default) so the root locals are the single source of
# truth and the precondition can fence the relationship without drift.
# =============================================================================

variable "http_timeouts_ms" {
  description = "NHP server HTTP timeouts in milliseconds: idle (must exceed CF origin_keepalive_timeout + buffer), read (full request including body), write (handler exec + response write; must stay below CF origin_read_timeout). REQUIRED — no default — so the root module's locals are the single source of truth and the CF distribution's lifecycle.precondition can fence the relationship without drift."
  type = object({
    idle  = number
    read  = number
    write = number
  })

  validation {
    condition = alltrue([
      for v in [var.http_timeouts_ms.idle, var.http_timeouts_ms.read, var.http_timeouts_ms.write] :
      v >= 1000 && v <= 300000
    ])
    error_message = "All http_timeouts_ms values must be between 1000 (1s) and 300000 (5min). Note: this is the per-field range only — the cross-resource invariant (idle vs. CloudFront origin_keepalive_timeout, write vs. CloudFront origin_read_timeout) is enforced at the root module via `terraform_data.http_keepalive_contract`."
  }

  validation {
    condition     = var.http_timeouts_ms.idle > var.http_timeouts_ms.read && var.http_timeouts_ms.idle > var.http_timeouts_ms.write
    error_message = "http_timeouts_ms.idle must STRICTLY exceed both .read and .write. This is a config-shape sanity check: equal or inverted values (idle <= read or idle <= write) almost always indicate a copy-paste typo rather than a deliberate design choice — the strict comparison forces the operator to commit to two distinct values. (No runtime correctness depends on this — Go's IdleTimeout fires only between requests, never mid-read or mid-write — but a typo here would silently land a confusing config.)"
  }
}

# =============================================================================
# S3 bootstrap (plugin bucket — shared with AC, separate path prefix)
# =============================================================================
# The rendered user_data.sh.tpl is ~49KB raw / ~16KB gzipped, sitting at the
# EC2 user_data hard limit (16384 bytes post-gzip). Any new comment, env var,
# or systemd unit eats into a razor-thin headroom margin. Move the bulk of
# the bootstrap to S3, mirror the AC module pattern (which has used this
# since at least PR #239), and keep the launch template user_data as a
# small fetcher (~1.5KB raw, ~700B gzipped). PR #1809 introduced this for
# server; the matching launch-template size-guard precondition fences
# regrowth.

variable "plugin_bucket_name" {
  description = "Name of the S3 plugins bucket (also hosts server bootstrap scripts under scripts/server-init.sh). When non-null, user_data switches to the small S3 fetcher bootstrap. The null branch exists only as a structural fallback for bucket-not-yet-provisioned bootstrap on greenfield envs and will fail at apply for the same 16KB user_data size reason this S3 indirection exists to fix — it is NOT a viable runtime rollback. Existing envs always have a bucket and should never see the null branch."
  type        = string
  default     = null
}

variable "plugin_download_policy_arn" {
  description = "ARN of the IAM policy granting s3:GetObject + kms:Decrypt on the plugin bucket and its CMK. Sourced from modules/plugins.download_policy_arn (same policy AC uses). Required when plugin_bucket_name is set; without it the bootstrap fetch fails at apply with AccessDenied because the bucket is KMS-encrypted with a CMK the server role otherwise has no Decrypt grant on."
  type        = string
  default     = null
}
