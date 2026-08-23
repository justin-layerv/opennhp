# =============================================================================
# Sandbox cell1 — isolated NHP-server plus private qurl-service data plane.
# =============================================================================
#
# SCOPE DECISION:
#   A provisionable cell is a working cell-local data plane, not only a second
#   UDP socket. This root therefore owns the NHP UDP server fleet and a
#   dark-by-default private qurl-service ECS service with cell-local state. The
#   public assignment/catalog plane remains elsewhere and does not activate
#   cell1 merely because these healthy private tasks exist. This root provisions:
#
#     * networking  — cell1 VPC (10.104.0.0/16), public/private subnets, 1 NAT.
#     * kms         — cell1 CMKs (ebs/logs/secrets) for at-rest encryption.
#     * plugins     — cell1's OWN S3 plugin bucket. REQUIRED as its own bucket
#                     because modules/compute unconditionally writes
#                     scripts/server-init.sh into plugin_bucket_name; sharing
#                     cell0's bucket would overwrite cell0's bootstrap script.
#     * dynamodb    — cell1's cell-scoped assignment/licenses/resources/ack
#                     tables (cell_id="cell1").
#     * server keypair access — an INLINE IAM policy (NOT module.nhp-keypair):
#                     the registration key pool is account-global and owned by
#                     cell0, so cell1 references it read-only and never re-creates
#                     it. See the aws_iam_policy.server_keypair_access header.
#     * compute     — the NHP server: ASG (+ blue/green), public UDP:62206 NLB,
#                     UDP listener, and the /sandbox-cell1/nhp/server/* SSM
#                     parameters incl. udp-listener-arn.
#     * dns         — cell1.nhp.layerv.xyz A-alias -> cell1 NLB.
#     * qurl-service — optional, dark-by-default private ECS/ALB data plane.
#
# EXPLICITLY OMITTED:
#   * AC (deploy_ac) / relay / redis / billing / developer-portal
#     / status-page / bootstrap-alb / custom-domain-cert / qurl-link / e2e-echo
#     / cost-analytics / grafana / auth0 — these are not required for the
#     private cell qurl-service/NHP data plane.
#   * module.security (GuardDuty / AWS Config / Security Hub / WAF) — these are
#     ACCOUNT SINGLETONS. cell0 already owns them; a second copy would collide.
#     Not instantiating the giant root module is what keeps this guarantee.
#   * ECR repos — the container images are account-global and SHARED. cell1
#     references cell0's existing layerv/nhp-server repo (data source below)
#     instead of creating a duplicate.
#
# COLLISION GUARANTEE vs cell0:
#   * state key : nhp/sandbox-cell1/terraform.tfstate   (backend.tf)
#   * names     : name_prefix = layerv-nhp-sandbox-cell1 (distinct env string)
#   * SSM paths : /sandbox-cell1/nhp/server/*            (keyed on environment)
#   * VPC CIDR  : 10.104.0.0/16                (vs cell0 10.100/10.101,
#                                                Control 10.102, runner 10.103/28)
# =============================================================================

locals {
  # Mirrors the cell0 root's convention: layerv-nhp-<environment>. With
  # environment="sandbox-cell1" this yields layerv-nhp-sandbox-cell1, which is
  # what makes every compute/networking/kms/etc. resource name cell-distinct.
  name_prefix = "layerv-nhp-${var.environment}"

  common_tags = merge(var.tags, {
    Project     = "NHP"
    Application = "nhp"
    Environment = var.environment
    ManagedBy   = "terraform"
    Repository  = "layervai/nhp"
    Cell        = var.cell_id
  })

  # CF <-> server keep-alive contract values, copied from the cell0 root locals
  # (terraform/main.tf). modules/compute requires http_timeouts_ms with no
  # default so the caller is the single source of truth.
  http_timeouts_ms = {
    idle  = 36000
    read  = 30000
    write = 30000
  }

  # Control identity plane for the agent-keys read. Mirrors the cell0 root's
  # locals (terraform/main.tf): the table name/ARN are derived rather than
  # read across a state boundary — the prefix form is canonical and asserted
  # by the authority module, so drift there fails loudly instead of silently
  # mis-pointing this root. Name and ARN come from the same local so the
  # compute wiring cannot grant one table while reading another.
  control_identity_table_prefix          = var.control_identity_environment_id != "" ? "layerv-nhp-${var.control_identity_environment_id}-control" : ""
  control_identity_agent_keys_table_name = var.control_identity_environment_id != "" ? "${local.control_identity_table_prefix}-qurl-agent-keys" : ""
  control_identity_agent_keys_table_arn = var.control_identity_environment_id == "" ? "" : format(
    "arn:aws:dynamodb:%s:%s:table/%s",
    var.control_identity_home_region,
    var.aws_account_id,
    local.control_identity_agent_keys_table_name,
  )
}

data "aws_region" "current" {}

# Shared, account-global ECR repository for the NHP server image. Created and
# owned by the cell0 sandbox root (is_primary_account = true). cell1 REFERENCES
# it rather than creating a duplicate (repo names are not environment-scoped).
# ---------------------------------------------------------------------------
# qURL v2 issuer public key — READ ONLY.
#
# The issuer key is account-global and owned by the cell0 root, exactly like the
# ECR repositories and the registration key pool above. cell1 reads it by alias
# so both cells verify links against the SAME issuer identity; creating a second
# key here would mean two identities signing for one deployment, and a link
# minted by cell0 would not verify at cell1.
# ---------------------------------------------------------------------------
data "aws_kms_public_key" "qurl_v2_issuer" {
  key_id = var.qurl_v2_issuer_key_alias
}

data "aws_ecr_repository" "server" {
  name = "layerv/nhp-server"
}

# -----------------------------------------------------------------------------
# Cloud Map private DNS namespace (cell1's own, in cell1's VPC).
# modules/compute always creates aws_service_discovery_service.server against
# var.namespace_id, so a real namespace is mandatory even though server-side
# CloudMap health discovery (cloudmap_enabled) is off for this AC-less cell.
# -----------------------------------------------------------------------------
resource "aws_service_discovery_private_dns_namespace" "cell1" {
  name        = "${var.environment}.nhp.internal"
  description = "Private DNS namespace for NHP server discovery in cell1"
  vpc         = module.networking.vpc_id
  tags        = local.common_tags
}

# -----------------------------------------------------------------------------
# NHP internal-auth HMAC secret (shared by nhp-server and, when present,
# qurl-service). modules/compute requires a valid Secrets Manager ARN. Mirrors
# the cell0 root pattern: the value is seeded out-of-band so it never lands in
# Terraform state.
# -----------------------------------------------------------------------------
resource "aws_secretsmanager_secret" "nhp_internal_auth" {
  name                    = "${local.name_prefix}-nhp-internal-auth"
  description             = "HMAC secret for /nhp/internal/knock — nhp-server (cell1)"
  recovery_window_in_days = 0
  kms_key_id              = module.kms.secrets_key_arn

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-nhp-internal-auth"
    Component = "nhp-internal-auth"
  })
}

# 48 bytes > the 32-byte floor both sides enforce. Value written directly via
# the AWS CLI and never captured in state. --exclude-punctuation keeps the
# value safe through the env-file transports on both consumers.
resource "terraform_data" "nhp_internal_auth_seed" {
  triggers_replace = [aws_secretsmanager_secret.nhp_internal_auth.arn]

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -euo pipefail
      SECRET_VALUE=$(aws secretsmanager get-random-password \
        --region "${data.aws_region.current.region}" \
        --password-length 48 \
        --exclude-punctuation \
        --query RandomPassword --output text)
      if [ -z "$SECRET_VALUE" ]; then
        echo "ERROR: get-random-password returned empty" >&2
        exit 1
      fi
      aws secretsmanager put-secret-value \
        --region "${data.aws_region.current.region}" \
        --secret-id "${aws_secretsmanager_secret.nhp_internal_auth.id}" \
        --secret-string "$SECRET_VALUE" > /dev/null
    EOT
  }
}

# -----------------------------------------------------------------------------
# KMS — cell1 customer-managed keys.
# -----------------------------------------------------------------------------
module "kms" {
  source = "../../modules/kms"

  environment = var.environment
  name_prefix = local.name_prefix
  tags        = local.common_tags

  # qURL v2 ISSUANCE/ADMISSION remains off in this dark topology slice; cell1
  # mints no tickets and admits nothing.
  qurl_v2_issuer_key_enabled = false

  # Resource keys are NOT part of that gate and must be on. The qurl-service
  # image treats the resource public key as public REST resource identity and
  # refuses to boot without it:
  #
  #   fatal error: invalid configuration: QURL_V2_RESOURCE_KEYS_ENABLED=true is
  #   required because public REST resource identity is the resource public key
  #
  # so leaving this false made the cell1 task exit on every start. cell0 already
  # runs with it true (terraform/environments/sandbox/terraform.tfvars), so this
  # is parity, not a new capability -- and it stays independent of issuance,
  # which the flag above still holds dark.
  qurl_v2_resource_keys_enabled = true

  # No IAM propagation shim here, unlike terraform/main.tf. That shim waits on
  # the CI role's kms:EnableKeyRotation grant landing via module.ecr's apply
  # policy; this lean root is applied out-of-band with operator credentials that
  # already hold it, and it has no module.ecr to key the wait on.
  resource_key_envelope_create_after = null
}

# -----------------------------------------------------------------------------
# Networking — cell1 VPC, subnets, NACLs.
# -----------------------------------------------------------------------------
module "networking" {
  source = "../../modules/networking"

  environment      = var.environment
  vpc_cidr         = var.vpc_cidr
  name_prefix      = local.name_prefix
  logs_kms_key_arn = module.kms.logs_key_arn
  tags             = local.common_tags

  # NLB -> private-subnet instances; iptables/NHP enforces access.
  allow_private_ingress_443 = true

  # QURL service endpoints are created only with the dark deployment gate.
  deploy_vpc_endpoints                       = local.qurl_service_deployable
  enable_extensible_private_route_tables     = false
  extensible_private_route_table_ready_token = null
}

# -----------------------------------------------------------------------------
# Plugins — cell1's OWN S3 plugin bucket (hosts scripts/server-init.sh).
# -----------------------------------------------------------------------------
module "plugins" {
  source = "../../modules/plugins"

  environment = var.environment
  name_prefix = local.name_prefix
  tags        = local.common_tags

  # Plugin bucket is encrypted with the logs CMK (matches the cell0 root and
  # the download policy's kms:Decrypt grant threaded into compute below).
  kms_key_arn = module.kms.logs_key_arn

  # No Traefik-plugin uploaders for a server-only cell.
  plugin_repos            = []
  github_actions_role_arn = null
}

# -----------------------------------------------------------------------------
# DynamoDB — cell1's cell-scoped server assignment tables.
# -----------------------------------------------------------------------------
module "dynamodb" {
  source = "../../modules/dynamodb"

  environment = var.environment
  cell_id     = var.cell_id
  name_prefix = local.name_prefix
  tags        = local.common_tags

  kms_key_arn = module.kms.secrets_key_arn

  # Cell-local tables are independent from cell0 and from the Control Authority.
  deploy_qurl_tables = local.qurl_service_deployable
  enable_sns_alerts  = false
}

# -----------------------------------------------------------------------------
# NHP keypair — cell1's AC-registration keypair.
# -----------------------------------------------------------------------------
# Server keypair access policy — INLINE, not module.nhp-keypair.
#
# The nhp-keypair module CREATES the account-global registration key pool
# (`/nhp/pool/registration-key` via a keygen Lambda + `/nhp/pool/registration-
# public-key` as a Terraform-managed aws_ssm_parameter). Those are SHARED across
# every cell in the account and are already owned by cell0's Terraform, so a
# second instantiation here collides (`ParameterAlreadyExists` on the public-key
# param; the private-key Lambda is idempotent but the TF-managed param is not).
# cell1 is the SECOND cell — it must REFERENCE the pool key, never re-create it.
#
# cell1's server also never reads the pool key at boot (user_data.sh.tpl has no
# `/nhp/pool/registration-key` fetch), but attach_storage_policies=true still
# requires a keypair policy ARN, and the module's server policy is cell0-pathed
# (`/nhp/server/*`, not this cell's `/sandbox-cell1/nhp/server/*`). So publish a
# minimal, correctly-scoped inline policy instead: read cell0's shared pool key
# (harmless if unused at runtime) + manage THIS cell's own server key path +
# decrypt with this cell's secrets CMK. Nothing here creates a pool resource.
resource "aws_iam_policy" "server_keypair_access" {
  name        = "${local.name_prefix}-server-keypair-read"
  description = "cell1 server SSM keypair access (references the shared pool key; creates none)"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "SSMReadSharedRegistrationKey"
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = ["arn:aws:ssm:${data.aws_region.current.region}:${var.aws_account_id}:parameter/nhp/pool/registration-key"]
      },
      {
        Sid      = "SSMManageThisCellServerKey"
        Effect   = "Allow"
        Action   = ["ssm:GetParameter", "ssm:PutParameter"]
        Resource = ["arn:aws:ssm:${data.aws_region.current.region}:${var.aws_account_id}:parameter/${var.environment}/nhp/server/*"]
      },
      {
        Sid      = "KMSDecryptSecrets"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]
        Resource = [module.kms.secrets_key_arn]
      },
    ]
  })

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-server-keypair-read"
    Component = "nhp-keypair"
    Cell      = var.cell_id
  })
}

# -----------------------------------------------------------------------------
# Compute — the NHP server: ASG (+ blue/green), public UDP:62206 NLB, UDP
# listener, and the /sandbox-cell1/nhp/server/* SSM parameters (incl.
# udp-listener-arn, which requires enable_blue_green = true).
# -----------------------------------------------------------------------------
module "compute" {
  source = "../../modules/compute"

  # Keep resource names/state/SSM paths in the collision-free sandbox-cell1
  # namespace while placing this server in the same logical Authority
  # environment as cell0. Tickets bind {environment=sandbox, cell_id=cell1};
  # using sandbox-cell1 on the wire makes every strict Authority call fail.
  environment                     = var.environment
  protocol_environment            = var.protocol_environment
  cell_id                         = var.cell_id
  connector_authority_cell_config = local.connector_authority_cell_config # connector_authority_cell.tf; var still wins
  server_ami_id                   = var.server_ami_id                     # null -> reads /sandbox-cell1/nhp/server/ami-id
  domain_name                     = var.domain_name
  multi_tenant                    = true
  min_capacity                    = var.min_capacity
  max_capacity                    = var.max_capacity

  vpc_id                       = module.networking.vpc_id
  vpc_cidr                     = var.vpc_cidr
  public_subnet_ids            = module.networking.public_subnet_ids
  private_subnet_ids           = module.networking.private_subnet_ids
  public_nhp_udp_ingress_cidrs = var.public_nhp_udp_ingress_cidrs

  # Reference the shared, account-global server image repo.
  server_repo_url = data.aws_ecr_repository.server.repository_url
  server_repo_arn = data.aws_ecr_repository.server.arn

  # Cloud Map (namespace mandatory; server-side discovery off for AC-less cell).
  namespace_id            = aws_service_discovery_private_dns_namespace.cell1.id
  namespace_name          = aws_service_discovery_private_dns_namespace.cell1.name
  cloudmap_enabled        = false
  cloudmap_namespace_name = aws_service_discovery_private_dns_namespace.cell1.name
  cloudmap_service_name   = "server"

  name_prefix = local.name_prefix
  tags        = merge(local.common_tags, { Service = "nhp-server" })

  # KMS
  ebs_kms_key_arn     = module.kms.ebs_key_arn
  logs_kms_key_arn    = module.kms.logs_key_arn
  secrets_kms_key_arn = module.kms.secrets_key_arn

  # Server behavior (matches cell0 sandbox posture).
  log_level     = var.log_level
  dev_mode      = true
  resource_mode = "api"
  # cell0's ROOT coalesces auth_url to "" before passing to compute
  # (terraform/main.tf: `auth_url = var.auth_url != null ? var.auth_url : ""`);
  # its real value arrives via TF_VAR_auth_url at CI-apply time. This lean cell
  # has no auth backend wired yet, so pass "" explicitly to match cell0's
  # posture (renders `AuthUrl = ""` in the passcode plugin config.toml). The
  # compute module now null-guards that line (user_data.sh.tpl, alongside the
  # sibling SigningKey/AesKey), so a null would render safely too — "" is kept
  # for a byte-identical render and cell0 parity. Real auth is a Step-10 concern
  # (inject TF_VAR_auth_url + keys, or move to local mode, once the
  # udp-proof-runner's knock-auth model is fixed).
  auth_url = ""

  # Keep qURL handling dark with the service gate. When enabled, NHP reaches
  # only the cell1 private ALB alias and reads only the cell1 token secret.
  server_plugins = local.qurl_service_deployable ? ["passcode", "qurl"] : ["passcode"]
  qurl_config = local.qurl_service_deployable ? {
    enabled                 = true
    api_url                 = local.qurl_service_private_origin
    allowed_redirect_domain = var.qurl_site_domain
    api_timeout             = 10
    max_idle_conns          = 20
    max_idle_conns_per_host = 10
    idle_conn_timeout       = 30
  } : null
  qurl_service_token_secret_arn = local.qurl_service_deployable ? aws_secretsmanager_secret.qurl_service["internal-token"].arn : null

  # Native agent registration (NHP_OTP -> NHP_REG -> NHP_RAK) and independent
  # qURL v2 admission on the NHP-server side.
  #
  # cell0 has carried both since #3172; this root never passed them, so the
  # compute module took its `false` defaults and cell1's servers booted with
  # "NHP-native registration DISABLED" and no v2 trust store. The Connector
  # Authority assigns agents across cells, so any agent placed here failed
  # enrollment with errCode 52107 -- the fail-closed catch-all that never names
  # the cause -- and could not have been admitted afterwards either.
  #
  # Both are bound to qurl_service_deployable: they render only inside the
  # user_data template's `qurl_enabled` block, so enabling them while the QURL
  # plugin is dark would silently drop them and recreate the same failure.
  agent_otp_registration_enabled = local.qurl_service_deployable
  qurl_v2_admission_enabled      = local.qurl_service_deployable
  qurl_v2_issuer_trust_store = local.qurl_service_deployable ? jsonencode({
    (var.qurl_v2_issuer_kid) = data.aws_kms_public_key.qurl_v2_issuer.public_key
  }) : "{}"

  # HTTP timeouts (required; single source of truth in this root).
  http_timeouts_ms = local.http_timeouts_ms

  # Internal-auth secret.
  nhp_internal_auth_secret_arn = aws_secretsmanager_secret.nhp_internal_auth.arn

  # S3 plugin bucket (hosts the server bootstrap script) + its download policy.
  plugin_bucket_name         = module.plugins.bucket_name
  plugin_download_policy_arn = module.plugins.download_policy_arn

  # Storage backend — DynamoDB (cloud default).
  attach_storage_policies       = true
  dynamodb_read_policy_arn      = module.dynamodb.read_policy_arn
  dynamodb_read_policy_doc_hash = module.dynamodb.read_policy_doc_hash
  keypair_policy_arn            = aws_iam_policy.server_keypair_access.arn
  storage_backend               = "dynamodb"
  dynamodb_licenses_table       = module.dynamodb.licenses_table_name
  dynamodb_ac_assignments_table = module.dynamodb.ac_assignments_table_name
  dynamodb_resources_table      = module.dynamodb.resources_table_name
  # Agent keys follow the identity plane, not the cell. The Connector
  # Authority registers agent pubkeys into the CONTROL qurl-agent-keys table
  # (cell0 sandbox runs identity in Control mode), and the Hub places
  # registered agents on this cell too — the cell-local table never sees the
  # registrations, so reading it rejects every registered agent's knock as
  # event="agent_unknown_pubkey". The other storage tables here are genuinely
  # cell-local runtime state and stay on this cell's dynamodb module.
  dynamodb_agent_keys_table      = local.control_identity_agent_keys_table_name != "" ? local.control_identity_agent_keys_table_name : module.dynamodb.qurl_agent_keys_table_name
  dynamodb_ack_tokens_table      = module.dynamodb.ack_tokens_table_name
  dynamodb_session_control_table = module.dynamodb.session_control_table_name

  # IAM + KMS for the Control-mode agent-keys read path (empty in cell
  # compatibility mode, which emits no grant at all). The cell dynamodb
  # module's read policy cannot cover the Control table, and the Control
  # tables are encrypted with the Control identity key rather than this
  # cell's — the compute module carries the paired conditional grant.
  control_identity_agent_keys_table_arn = local.control_identity_agent_keys_table_arn
  control_identity_kms_key_arn          = var.control_identity_kms_key_arn
  control_identity_home_region          = var.control_identity_home_region

  # Blue/green REQUIRED so the udp-listener-arn SSM parameter is published.
  enable_blue_green      = true
  green_standby_min_size = var.green_standby_min_size

  # No account-wide SNS alarm fan-out in this separate cell root (skips
  # blue/green alarms and avoids duplicating cell0-owned monitoring).
  # alerts_sns_topic_arn stays null.
  enable_sns_alerts = false

  # No termination-cleanup Lambda, no relay, no qURL resolve endpoint.
  enable_termination_cleanup = false

  # Both plugin secrets must have a current value before any instance can
  # render its boot-time environment. Secret creation alone is insufficient:
  # the out-of-state seeders otherwise race the ASG launch template/instances.
  depends_on = [
    terraform_data.nhp_internal_auth_seed,
    terraform_data.qurl_service_secret_seed,
  ]
}

# -----------------------------------------------------------------------------
# DNS — cell1.nhp.layerv.xyz A-alias -> cell1 public NLB.
# The dns module cleanly supports a per-cell subdomain: passing the cell record
# name as domain_name with skip_main_record=false emits exactly one A-alias.
# -----------------------------------------------------------------------------
module "dns" {
  source = "../../modules/dns"

  environment    = var.environment
  domain_name    = var.cell_dns_name # cell1.nhp.layerv.xyz
  hosted_zone_id = var.hosted_zone_id
  nlb_dns_name   = module.compute.nlb_dns_name
  nlb_zone_id    = module.compute.nlb_zone_id
  name_prefix    = local.name_prefix
  tags           = local.common_tags

  skip_main_record = false
  create_wildcard  = false
}
