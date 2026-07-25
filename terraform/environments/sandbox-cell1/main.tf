# =============================================================================
# Sandbox cell1 — lean, standalone NHP-server cell (Step 6 of the two-cell UDP
# substrate for the qURL Connector).
# =============================================================================
#
# SCOPE DECISION (leanest that satisfies the two-cell UDP proof):
#   The proof is "agent registers on cell0 -> is reassigned to cell1 ->
#   refreshes on cell1". The only NEW infrastructure that requires is a second
#   public UDP:62206 knock endpoint (NLB) fronting a second NHP-server fleet,
#   discoverable by the control/deploy plane via SSM, in an isolated,
#   non-overlapping VPC. This root therefore provisions:
#
#     * networking  — cell1 VPC (10.102.0.0/16), public/private subnets, 1 NAT.
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
#
# EXPLICITLY OMITTED (justified — not needed for a UDP substrate proof):
#   * AC (deploy_ac) / qurl-service / relay / redis / billing / developer-portal
#     / status-page / bootstrap-alb / custom-domain-cert / qurl-link / e2e-echo
#     / cost-analytics / grafana / auth0 — these are optional data-plane and
#     control-plane features. The knock/refresh proof exercises the NHP UDP
#     substrate only; the L7 data plane rides cell0's existing deployment.
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
#   * VPC CIDR  : 10.102.0.0/16                          (vs cell0 10.100/10.101)
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
}

data "aws_region" "current" {}

# Shared, account-global ECR repository for the NHP server image. Created and
# owned by the cell0 sandbox root (is_primary_account = true). cell1 REFERENCES
# it rather than creating a duplicate (repo names are not environment-scoped).
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

  # qURL v2 keyed-identity is a data-plane feature; off for this lean cell.
  qurl_v2_issuer_key_enabled         = false
  qurl_v2_resource_keys_enabled      = false
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

  # No qurl-service VPC endpoints and no relay in this lean cell.
  deploy_vpc_endpoints                       = false
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

  # qurl-service is not deployed in this cell.
  deploy_qurl_tables = false
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

  environment   = var.environment
  cell_id       = var.cell_id
  server_ami_id = var.server_ami_id # null -> reads /sandbox-cell1/nhp/server/ami-id
  domain_name   = var.domain_name
  multi_tenant  = true
  min_capacity  = var.min_capacity
  max_capacity  = var.max_capacity

  vpc_id             = module.networking.vpc_id
  vpc_cidr           = var.vpc_cidr
  public_subnet_ids  = module.networking.public_subnet_ids
  private_subnet_ids = module.networking.private_subnet_ids

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

  # Minimal plugin set: the passcode knock plugin. The qURL plugin is omitted
  # (no qurl_config) because qurl-service is not deployed in this cell.
  server_plugins = ["passcode"]

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
  dynamodb_agent_keys_table     = module.dynamodb.qurl_agent_keys_table_name # null (qurl tables off)
  dynamodb_ack_tokens_table     = module.dynamodb.ack_tokens_table_name

  # Blue/green REQUIRED so the udp-listener-arn SSM parameter is published.
  enable_blue_green      = true
  green_standby_min_size = var.green_standby_min_size

  # No SNS alarm fan-out for this lean cell (skips blue/green alarms -> no
  # monitoring module / SNS topic needed). alerts_sns_topic_arn stays null.
  enable_sns_alerts = false

  # No termination-cleanup Lambda, no relay, no qURL resolve endpoint.
  enable_termination_cleanup = false

  depends_on = [terraform_data.nhp_internal_auth_seed]
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
