# Compute Module
# ASG, NLB, Launch Template, Cloud Map Service
#
# Cell Architecture:
# All resources in this module belong to a single cell (identified by var.cell_id).
# Each cell is an isolated failure domain with its own NLB, ASG, and server fleet.
#
# Secrets Manager Naming Convention:
# - Current: ${name_prefix}-server (e.g., nhp-sandbox-server)
# - Future cells: ${name_prefix}-${cell_id}-server (e.g., nhp-sandbox-cell1-server)
#
# The existing secret name is kept for backward compatibility with cell0.
# New cells should include cell_id in the secret name for clear isolation.
# IAM policies can then use ARN patterns: arn:aws:secretsmanager:*:*:secret:nhp-*-cell1-*

terraform {
  required_version = ">= 1.5"
}

# ==================== Data Sources ====================

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  # True when an SNS alert destination is actually wired. trimspace guards
  # against a whitespace-only ARN; try() handles the null default.
  sns_destination_present = try(trimspace(var.alerts_sns_topic_arn) != "", false)

  # Port for the qURL-resolve TLS listener on the public server NLB. It is NOT
  # 443: an NLB allows exactly one listener per port, and 443 is now the public
  # UDP client edge (aws_lb_listener.udp). Only CloudFront reaches this
  # listener, so a non-standard port is invisible to browsers — the root wires
  # the matching custom origin port from the qurl_resolve_port output.
  qurl_resolve_port = 8443
}

resource "terraform_data" "sns_alerts_contract" {
  lifecycle {
    precondition {
      condition     = !var.enable_sns_alerts || local.sns_destination_present
      error_message = "enable_sns_alerts=true requires a non-empty alerts_sns_topic_arn. Keep alarm resource counts gated on enable_sns_alerts, but wire the SNS ARN before enabling the gate."
    }
  }
}

resource "terraform_data" "revocation_retry_config_contract" {
  lifecycle {
    precondition {
      # Mirrors parseRevocationRetryConfig, which validates interval/age-out
      # relationships even when NHP_REVOCATION_RETRY_ENABLED=false.
      condition = (
        var.revocation_retry_age_out_seconds > var.revocation_retry_interval_seconds &&
        # Keep this 15s SLO mirror in scripts/check-revocation-slo-lockstep.sh
        # with RevocationDeliveryLatencyP99SLO and the CloudWatch alarm threshold.
        var.revocation_retry_age_out_seconds > 15
      )
      error_message = "revocation_retry_age_out_seconds must be greater than revocation_retry_interval_seconds and greater than the 15s RevocationDeliveryLatency p99 SLO."
    }
  }
}

check "sns_alerts_gate_matches_destination" {
  assert {
    condition     = var.enable_sns_alerts || !local.sns_destination_present
    error_message = "alerts_sns_topic_arn is set but enable_sns_alerts=false, so compute SNS alarms will not be created. Set enable_sns_alerts=true or clear alerts_sns_topic_arn."
  }
}

# AMI Selection (fail-fast, no fallback):
# 1. If var.server_ami_id is set directly, use it
# 2. Otherwise, read from SSM parameter /{environment}/nhp/server/ami-id
#
# The AMI must be pre-built with Docker installed. Without a custom AMI,
# Terraform will fail at plan time with a clear error.
#
# Build and publish AMI:
#   cd packer && packer build -var 'environment=sandbox' nhp-server-docker.pkr.hcl
#   aws ssm put-parameter --name "/sandbox/nhp/server/ami-id" \
#     --value "ami-xxx" --type String --overwrite
#
# Naming aligned with sibling /${env}/nhp/server/* parameters
# (image-tag, asg-name, active-color, ...). See blue_green.tf for the rest.
data "aws_ssm_parameter" "server_ami" {
  count = var.server_ami_id == null ? 1 : 0
  name  = "/${var.environment}/nhp/server/ami-id"
}

# ==================== Locals ====================

locals {
  is_prod = var.environment == "prod"

  # Source-fence toggle for the public UDP NLB. When set (non-null) the module
  # builds the fenced-shape resources (dedicated NLB SG plus scoped ingress and
  # egress); when null it keeps the legacy global-ingress shape. Named once so
  # the count/name guards below cannot drift in polarity — mirrors the sibling
  # connector-authority-foundation module's hub_edge toggle.
  public_udp_source_fenced = var.public_nhp_udp_ingress_cidrs != null
  public_udp_fence_count   = local.public_udp_source_fenced ? 1 : 0

  # Public server NLB name. The `nlb` -> `edge` suffix flip on a non-null
  # source-fence list is correctness-relevant (it forces physical replacement so
  # AWS can attach an SG to the new NLB); keep it defined once so the physical
  # `name` and its `Name` tag cannot drift.
  server_nlb_name = "${var.name_prefix}-${local.public_udp_source_fenced ? "edge" : "nlb"}"

  # Preserve cell0's established role/profile identity exactly. Future cells
  # receive an explicit cell-qualified identity so the Connector Authority can
  # grant each assigned-cell worker only its own qualified aliases.
  server_role_name = var.cell_id == "cell0" ? "${var.name_prefix}-server" : "${var.name_prefix}-${var.cell_id}-server"

  # Fail fast: either var.server_ami_id is set, or SSM parameter must exist.
  server_ami_id = var.server_ami_id != null ? var.server_ami_id : data.aws_ssm_parameter.server_ami[0].value

  # Pinned uid:gid for the non-root nhp-server container (#1090). Single source
  # of truth: rendered into BOTH `docker run --user` and the host useradd in
  # user_data.sh.tpl, which must agree or the container can't read its mounts.
  nhp_server_uid = 10001
  nhp_server_gid = 10001
}

# Lambda for generating Curve25519 keys (same approach as CDK)
resource "aws_iam_role" "keygen_lambda" {
  name = "${var.name_prefix}-keygen-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "keygen_lambda_basic" {
  role       = aws_iam_role.keygen_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "keygen_lambda_secrets" {
  name = "secrets-access"
  role = aws_iam_role.keygen_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue"
        ]
        Resource = [
          aws_secretsmanager_secret.server.arn,
          aws_secretsmanager_secret.cookie_secret.arn
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"]
        Resource = var.secrets_kms_key_arn != null ? [var.secrets_kms_key_arn] : []
      }
    ]
  })
}

# PR plans may invoke only this application-state-read-only function. A
# distinct execution role and handler-selected mode prevent an untrusted
# invocation payload from reaching Seed or PutSecretValue.
resource "aws_iam_role" "key_validator_lambda" {
  name = "${var.name_prefix}-key-validator-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = var.tags
}

resource "aws_cloudwatch_log_group" "key_validator" {
  name              = "/aws/lambda/${var.name_prefix}-key-validator"
  retention_in_days = local.is_prod ? 365 : 30
  kms_key_id        = var.logs_kms_key_arn
  tags              = var.tags

  lifecycle {
    precondition {
      condition     = try(trimspace(var.logs_kms_key_arn) != "", false)
      error_message = "key-validator requires logs_kms_key_arn so plan-time validation failures are never written to an unencrypted log group."
    }
  }
}

resource "aws_iam_role_policy" "key_validator_lambda_access" {
  name = "identity-read-and-logs"
  role = aws_iam_role.key_validator_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = [aws_secretsmanager_secret.server.arn]
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = ["${aws_cloudwatch_log_group.key_validator.arn}:*"]
      }
      ],
      var.secrets_kms_key_arn != null ? [
        {
          Effect   = "Allow"
          Action   = ["kms:Decrypt"]
          Resource = [var.secrets_kms_key_arn]
        }
    ] : [])
  })
}

# Lambda role/policy creation can precede IAM authorization propagation. This
# is a brand-new role-to-inline-policy attachment, so retain the repository's
# conservative 180-second first-use wait and key it to both documents; a first
# apply must not create the validator while its trust or GET-only policy is
# still stale. If either IAM resource is tainted without a document change,
# taint this wait too because its document-hash triggers remain unchanged.
resource "time_sleep" "key_validator_iam_propagation" {
  triggers = {
    assume_role_policy_hash = sha256(aws_iam_role.key_validator_lambda.assume_role_policy)
    access_policy_hash      = sha256(aws_iam_role_policy.key_validator_lambda_access.policy)
  }

  create_duration = "180s"
}

# Lambda function to generate Curve25519 keys
resource "aws_lambda_function" "keygen" {
  function_name = "${var.name_prefix}-keygen"
  role          = aws_iam_role.keygen_lambda.arn
  handler       = "index.seedHandler"
  runtime       = "nodejs22.x"
  timeout       = 30

  filename         = data.archive_file.keygen_lambda.output_path
  source_code_hash = data.archive_file.keygen_lambda.output_base64sha256

  tags = var.tags
}

# Same audited artifact, but a handler-selected Validate mode and a role with no
# mutation permissions. The PR plan role is scoped to this function's $LATEST
# qualifier and cannot invoke aws_lambda_function.keygen.
# Provision it ahead of the cell-assignment consumer so rollout can prove the
# validator is read-only before any plan depends on its result.
resource "aws_lambda_function" "key_validator" {
  function_name = "${var.name_prefix}-key-validator"
  role          = aws_iam_role.key_validator_lambda.arn
  handler       = "index.validateHandler"
  runtime       = "nodejs22.x"
  timeout       = 30

  # Intentionally use the account's bounded unreserved pool so concurrent PR
  # plans do not contend with a validator-specific reservation.

  filename         = data.archive_file.keygen_lambda.output_path
  source_code_hash = data.archive_file.keygen_lambda.output_base64sha256

  tags = var.tags

  depends_on = [
    time_sleep.key_validator_iam_propagation,
    aws_cloudwatch_log_group.key_validator,
  ]
}

# Adding a `count` here (or wrapping `module "compute"` in a toggle)
# requires removing the matching `lambda-compute-keygen` upload+download
# pair in promote-to-prod.yml in the same patch — see
# docs/runbooks/promote-to-prod-lambda-artifacts.md (loud-fail policy).
data "archive_file" "keygen_lambda" {
  type        = "zip"
  source_file = "${path.module}/lambda/keygen/index.js"
  output_path = "${path.module}/keygen_lambda.zip"
}

# Store server configuration in Secrets Manager
resource "aws_secretsmanager_secret" "server" {
  name                    = "${var.name_prefix}-server"
  description             = "NHP Server private key and configuration"
  recovery_window_in_days = local.is_prod ? 30 : 0
  kms_key_id              = var.secrets_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-server-secret"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# Custom resource to invoke Lambda for key generation. Seed deliberately fails
# closed if a future taint/replacement finds malformed key material or metadata
# drift (including hostname or environment mismatch): investigate and
# explicitly migrate the secret; never self-heal or rotate it from this
# stateful invocation.
resource "aws_lambda_invocation" "keygen" {
  function_name = aws_lambda_function.keygen.function_name
  # Seed may write a missing secret; never invoke it during update or destroy.
  lifecycle_scope = "CREATE_ONLY"

  input = jsonencode({
    RequestType = "Create"
    ResourceProperties = {
      SecretId    = aws_secretsmanager_secret.server.id
      Hostname    = var.domain_name
      Environment = var.environment
    }
  })

  depends_on = [aws_iam_role_policy.keygen_lambda_secrets]

  lifecycle {
    ignore_changes = [input]
  }
}

# Read back the publicKey the Lambda generated so we can thread it
# through terraform to other modules that need to know which key the
# running NHP server actually signs packets with (specifically
# qurl-service's agent-bootstrap response — see #server_public_key_b64
# in outputs.tf for the contract).
#
# tfstate exposure: this data source materializes secret_string
# (full JSON: privateKey + publicKey + hostname + environment) as a
# sensitive-marked attribute in state. tfstate access already implies
# Secrets Manager access in this org's threat model (S3+KMS+IAM
# scoped), and the same pattern is used by the auth0-backend / etcd-
# tls / cookie-secret data sources in this tree. The output above
# nonsensitive()-wraps only the publicKey so downstream consumers
# get a non-sensitive string for env-var injection; the privateKey
# stays in state, sensitive-marked.
#
# depends_on the lambda invocation so the secret_string is populated
# before the data source reads it. AWS provider caches the value
# within an apply, so refreshing this on every plan is a single
# Secrets Manager GET, not a per-resource cost.
#
# version_stage = "AWSCURRENT" is the AWS default and is set here
# explicitly because `seedHandler` in lambda/keygen/index.js writes via
# PutSecretValueCommand without a VersionStages arg — which also defaults to
# AWSCURRENT. A future rotation flow that stages a new
# key under AWSPENDING before promoting it would silently desync
# the terraform-exposed value from the running server until the
# stage promotion completed; pinning the stage here makes the
# rotation contract grep-discoverable and the desync window
# explicit at the boundary instead of buried in defaults.
data "aws_secretsmanager_secret_version" "server" {
  secret_id     = aws_secretsmanager_secret.server.id
  version_stage = "AWSCURRENT"
  depends_on    = [aws_lambda_invocation.keygen]
}

# Cookie session keys for HTTP session cookies (shared across all server instances)
# JSON structure:
#   {
#     "current":  {"auth_key": "...", "encrypt_key": "..."},
#     "previous": {"auth_key": "...", "encrypt_key": "..."}  // optional
#   }
#
# - current: Used for writing new cookies AND reading existing ones
# - previous: Read-only, enables graceful rotation during rolling deployments
#
# Rotation procedure:
#   1. Read the current secret value
#   2. Move "current" → "previous"
#   3. Generate new keys for "current"
#   4. Update the secret with both current and previous
#   5. Trigger ASG instance refresh — as instances roll:
#      - New instances write cookies with new keys
#      - New instances can still read cookies signed with old keys
#   6. After all instances are refreshed, remove "previous" (optional)
resource "aws_secretsmanager_secret" "cookie_secret" {
  name                    = "${var.name_prefix}-cookie-secret"
  description             = "NHP Server cookie session keys (HMAC auth + AES-256 encryption)"
  recovery_window_in_days = local.is_prod ? 30 : 0
  kms_key_id              = var.secrets_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-cookie-secret"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# Seed the secret with random keys generated server-side by AWS.
# Keys are generated via AWS CLI (secretsmanager:GetRandomPassword) and stored
# directly in Secrets Manager — they never appear in Terraform state.
# Only runs on first creation (triggered by secret ARN).
resource "terraform_data" "cookie_secret_seed" {
  triggers_replace = [aws_secretsmanager_secret.cookie_secret.arn]

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -euo pipefail
      AUTH_KEY=$(aws secretsmanager get-random-password --password-length 32 --exclude-punctuation --query RandomPassword --output text)
      ENCRYPT_KEY=$(aws secretsmanager get-random-password --password-length 32 --exclude-punctuation --query RandomPassword --output text)
      aws secretsmanager put-secret-value --secret-id "${aws_secretsmanager_secret.cookie_secret.id}" --secret-string "{\"current\":{\"auth_key\":\"$AUTH_KEY\",\"encrypt_key\":\"$ENCRYPT_KEY\"}}"
    EOT
  }
}

# Signing key for NHP overload cookies (KNK -> COK -> RKN). Kept separate
# from HTTP session-cookie keys so the UDP/browser-agent protocol does not
# share HMAC material with the web session layer. The value is read at boot and
# written into config.toml as CookieSigningKeyBase64.
resource "aws_secretsmanager_secret" "overload_cookie_secret" {
  name                    = "${var.name_prefix}-overload-cookie-secret"
  description             = "NHP overload-cookie signing key shared across server instances"
  recovery_window_in_days = local.is_prod ? 30 : 0
  kms_key_id              = var.secrets_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-overload-cookie-secret"
    Component = "compute"
    Cell      = var.cell_id
  })
}

resource "terraform_data" "overload_cookie_secret_seed" {
  triggers_replace = [aws_secretsmanager_secret.overload_cookie_secret.arn]

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
			set -euo pipefail
			COOKIE_KEY=$(openssl rand -base64 32)
			aws secretsmanager put-secret-value --secret-id "${aws_secretsmanager_secret.overload_cookie_secret.id}" --secret-string "$COOKIE_KEY"
		EOT
  }
}

# CloudWatch Log Group for servers
resource "aws_cloudwatch_log_group" "server" {
  name              = "/layerv/nhp/${var.environment}/${var.cell_id}/server"
  retention_in_days = local.is_prod ? 365 : 30
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-logs-server"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# CloudWatch Log Group for the server container's stdout/stderr. Routed
# by the docker --log-driver=awslogs on the systemd unit, so any panic
# or runtime error that Go writes directly to os.Stderr -- bypassing the
# structured file logger that feeds `aws_cloudwatch_log_group.server` --
# is captured here instead of being dropped to the host's docker json
# log file. This closes the observability gap that let the "panic: send
# on closed channel" crash loop (fixed in PR #1096) live undetected
# through every blue/green deploy. Retention is short on purpose: this
# group is an alert surface, not an archive; long-term diagnostics live
# in the structured `server` group alongside context.
resource "aws_cloudwatch_log_group" "server_stderr" {
  name              = "/layerv/nhp/${var.environment}/${var.cell_id}/server-stderr"
  retention_in_days = 7
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-logs-server-stderr"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# =============================================================================
# SSM Parameters for Deployment State
# These parameters enable CI/CD to update image tags without Terraform apply.
# Instances read the image tag from SSM at boot time.
# =============================================================================

# Current deployed image tag - updated by CI/CD after successful builds
resource "aws_ssm_parameter" "image_tag" {
  name        = "/${var.environment}/nhp/server/image-tag"
  description = "NHP Server Docker image tag - updated by CI/CD"
  type        = "String"
  value       = var.image_tag

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ssm-image-tag"
    Component = "compute"
    Cell      = var.cell_id
  })

  # Allow CI/CD to update the value without TF drift
  lifecycle {
    ignore_changes = [value]
  }
}

# ASG name - used by CI/CD scripts to trigger instance refresh
resource "aws_ssm_parameter" "asg_name" {
  name        = "/${var.environment}/nhp/server/asg-name"
  description = "NHP Server Auto Scaling Group name - used by CI/CD for instance refresh"
  type        = "String"
  value       = aws_autoscaling_group.server.name

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ssm-asg-name"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# Deployment tracking - commit SHA of the currently deployed version
resource "aws_ssm_parameter" "deployed_commit" {
  name        = "/${var.environment}/nhp/deploy/deployed-commit"
  description = "Git commit SHA of the currently deployed version"
  type        = "String"
  value       = "initial"

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ssm-deployed-commit"
    Component = "deploy"
    Cell      = var.cell_id
  })

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "deployed_at" {
  name        = "/${var.environment}/nhp/deploy/deployed-at"
  description = "ISO 8601 timestamp of last successful deployment"
  type        = "String"
  value       = "never"

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ssm-deployed-at"
    Component = "deploy"
    Cell      = var.cell_id
  })

  lifecycle {
    ignore_changes = [value]
  }
}

# Cloud Map Service for NHP servers
resource "aws_service_discovery_service" "server" {
  name        = "server"
  description = "NHP Server instances"

  dns_config {
    namespace_id = var.namespace_id

    dns_records {
      ttl  = 30
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  # No health_check_custom_config - instances register/deregister explicitly

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-cloudmap-server"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# IAM Role for NHP Server instances
resource "aws_iam_role" "server" {
  name = local.server_role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "server_ssm" {
  role       = aws_iam_role.server.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# DynamoDB storage access for per-AC assignment architecture (when storage_backend = "dynamodb").
# Variable names retain the older "read" wording to avoid a broad Terraform
# interface rename; the attached policy also carries bounded server writes.
# Uses boolean variable because Terraform cannot evaluate count based on module outputs at plan time
# See docs/design/PLUGGABLE_STORAGE_BACKEND.md
resource "terraform_data" "session_control_storage_contract" {
  lifecycle {
    precondition {
      condition = (
        var.storage_backend != "dynamodb" ||
        try(trimspace(var.dynamodb_session_control_table) != "", false)
      )
      error_message = "storage_backend=dynamodb requires a non-empty dynamodb_session_control_table; NHP session authority must fail before the server accepts AOL/knock traffic, never degrade to process-local close state."
    }
  }
}

resource "aws_iam_role_policy_attachment" "server_dynamodb" {
  count      = var.attach_storage_policies ? 1 : 0
  role       = aws_iam_role.server.name
  policy_arn = var.dynamodb_read_policy_arn
}

# Same-apply IAM policy edits can lag in AWS's authorization evaluator just
# long enough for freshly cycled instances to hit AccessDenied on their first
# DynamoDB calls. The 60s wait matches the observed upper edge of same-apply
# IAM evaluator lag in sandbox applies (last re-verified 2026-05-26 by the
# ACK token policy edit rollout). Re-verify with a sandbox apply that cycles
# fresh instances before shortening. Key this wait on the server DynamoDB
# policy content and the actual role-policy attachment, then make the launch
# template wait for it.
resource "time_sleep" "dynamodb_read_iam_propagation" {
  count = var.attach_storage_policies ? 1 : 0

  triggers = {
    policy_doc_hash = var.dynamodb_read_policy_doc_hash
    policy_arn      = var.dynamodb_read_policy_arn
    attachment_id   = aws_iam_role_policy_attachment.server_dynamodb[0].id
    # Content-keyed like policy_doc_hash above: re-fires the wait when the
    # Control-mode agent-keys grant appears, changes, or is removed, so the
    # identity-cutover apply's instance refresh cannot race the fresh inline
    # policy into AccessDenied on first-boot DynamoDB calls. The reference
    # also orders this wait after the policy write itself.
    control_identity_agent_keys_policy_hash = try(sha256(aws_iam_role_policy.server_control_identity_agent_keys[0].policy), "disabled")
  }

  create_duration = "60s"
}

# SSM keypair access for Noise K server-to-server forwarding
resource "aws_iam_role_policy_attachment" "server_keypair" {
  count      = var.attach_storage_policies ? 1 : 0
  role       = aws_iam_role.server.name
  policy_arn = var.keypair_policy_arn
}

# Control-mode agent-keys read grant (identity plane).
#
# When the identity plane runs in Control mode, agent registration (the
# Connector Authority) writes agent pubkey rows to the CONTROL qurl-agent-keys
# table and the caller repoints var.dynamodb_agent_keys_table at it. The cell
# dynamodb module's read policy (var.dynamodb_read_policy_arn) covers only
# cell-local table ARNs, so the resolve path needs its own grant here.
#
# Scope matches exactly what the server does with the table. The server's
# whole agent-keys surface is the read-only AgentKeysQuerier in
# endpoints/server/agent_peer_lookup.go: a Query against the pubkey-index GSI,
# then a strongly consistent GetItem on the base row. There are no server
# writes — last_seen/ttl keepalive bumps are qurl-service's (see the
# KEYS_ONLY note on the table in modules/dynamodb/main.tf) — so no PutItem
# and no kms:Encrypt/GenerateDataKey.
#
# The KMS statement is the classically-forgotten half: the Control tables are
# SSE-KMS encrypted with the Control identity key, NOT this cell's key, so the
# DynamoDB grant alone lets the server boot cleanly and then reject every
# registered-agent knock at resolveAgentPeerForKnock with
# AccessDeniedException. ViaService/CallerAccount mirror the cell read
# policy's KMS statement (modules/dynamodb/main.tf) — decrypt only through
# DynamoDB in the Control home region, only from this account.
resource "aws_iam_role_policy" "server_control_identity_agent_keys" {
  count = var.control_identity_agent_keys_table_arn != "" ? 1 : 0

  name = "server-control-identity-agent-keys"
  role = aws_iam_role.server.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ControlIdentityAgentKeysGetItem"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem"]
        Resource = var.control_identity_agent_keys_table_arn
      },
      {
        Sid      = "ControlIdentityAgentKeysIndexQuery"
        Effect   = "Allow"
        Action   = ["dynamodb:Query"]
        Resource = "${var.control_identity_agent_keys_table_arn}/index/*"
      },
      {
        Sid      = "ControlIdentityAgentKeysKMSDecrypt"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [var.control_identity_kms_key_arn]
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id
            "kms:ViaService"    = "dynamodb.${var.control_identity_home_region}.amazonaws.com"
          }
        }
      }
    ]
  })

  lifecycle {
    # A half-configured cutover is worse than either end state: the server
    # would hold a DynamoDB grant it cannot use (every read fails on the
    # missing KMS decrypt) or render a ViaService condition for region "".
    precondition {
      condition     = var.control_identity_kms_key_arn != "" && var.control_identity_home_region != ""
      error_message = "control_identity_agent_keys_table_arn requires control_identity_kms_key_arn and control_identity_home_region; without the KMS half the server boots cleanly and every registered-agent knock fails with AccessDeniedException."
    }
    # storage.toml renders ONE [DynamoDB] Region for every table, including
    # the repointed Control agent-keys table (user_data.sh.tpl). A Control
    # home region different from the server's effective DynamoDB region would
    # make every agent-keys read target a nonexistent same-name table in the
    # local region — the same dead-tunnel outage this grant exists to fix,
    # reintroduced cross-region and invisible until the first knock.
    precondition {
      condition     = var.control_identity_home_region == coalesce(var.dynamodb_region, data.aws_region.current.id)
      error_message = "control_identity_home_region must equal the server's effective DynamoDB region (var.dynamodb_region, defaulting to the current region): the server's DynamoDB client uses the single storage.toml Region for every table it reads, so a cross-region Control agent-keys table cannot be reached."
    }
  }
}

# Note: Plugins are now baked into the Docker image - no S3 IAM policy needed

resource "aws_iam_role_policy" "server" {
  name = "server-permissions"
  role = aws_iam_role.server.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = compact(concat(
          [aws_secretsmanager_secret.server.arn],
          [aws_secretsmanager_secret.cookie_secret.arn],
          [aws_secretsmanager_secret.overload_cookie_secret.arn],
          [var.etcd_secret_arn],
          [var.etcd_tls_secret_arn],
          [var.qurl_service_token_secret_arn],
          [var.nhp_internal_auth_secret_arn],
        ))
      },
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage"
        ]
        Resource = var.server_repo_arn
      },
      {
        Effect = "Allow"
        Action = [
          "servicediscovery:RegisterInstance",
          "servicediscovery:DeregisterInstance",
          "servicediscovery:UpdateInstanceCustomHealthStatus",
          "servicediscovery:GetInstance"
        ]
        Resource = aws_service_discovery_service.server.arn
      },
      {
        Effect = "Allow"
        Action = [
          "servicediscovery:DiscoverInstances",
          "servicediscovery:GetNamespace",
          "servicediscovery:GetService"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          "${aws_cloudwatch_log_group.server.arn}:*",
          "${aws_cloudwatch_log_group.server_stderr.arn}:*",
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = var.secrets_kms_key_arn != null ? [var.secrets_kms_key_arn] : []
      },
      # Allow instance to mark itself unhealthy for ASG replacement
      {
        Effect   = "Allow"
        Action   = ["autoscaling:SetInstanceHealth"]
        Resource = aws_autoscaling_group.server.arn
      },
      # SSM Parameter Store access for deployment state (image tags)
      {
        Effect = "Allow"
        Action = ["ssm:GetParameter", "ssm:GetParameters"]
        Resource = [
          "arn:aws:ssm:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:parameter/${var.environment}/nhp/server/*"
        ]
      },
      # Allow instance to read its own tags (for DeployColor detection in blue/green deployments)
      {
        Effect   = "Allow"
        Action   = ["ec2:DescribeTags"]
        Resource = "*"
      },
      {
        Sid      = "DenyDeploymentWindowNamespace"
        Effect   = "Deny"
        Action   = ["cloudwatch:PutMetricData"]
        Resource = "*"
        # Defense-in-depth: keep app instances out of the deploy-only
        # suppressor namespace even if a future allow broadens.
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "LayerV/NHP/Deploy"
          }
        }
      },
      # CloudWatch Agent + application metrics (mem, disk, NHP custom metrics)
      {
        Effect   = "Allow"
        Action   = ["cloudwatch:PutMetricData"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "LayerV/NHP"
          }
        }
      }
    ]
  })
}

resource "aws_iam_instance_profile" "server" {
  name = local.server_role_name
  role = aws_iam_role.server.name

  tags = var.tags
}

# Security Group for NHP servers
resource "aws_security_group" "server" {
  name_prefix = "${var.name_prefix}-server-"
  vpc_id      = var.vpc_id
  description = "Security group for NHP Server instances"

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-sg-server"
    Component = "compute"
    Cell      = var.cell_id
  })

  lifecycle {
    create_before_destroy = true
  }
}

# --- Server SG Rules (separate resources to avoid inline/standalone conflicts) ---

# Legacy public NHP Protocol (UDP 62206) ingress. Existing production cells keep
# this shape until their separately gated edge migration. New/proof cells set
# public_nhp_udp_ingress_cidrs, which removes this rule and makes the target
# trust only the NLB security group below.
resource "aws_vpc_security_group_ingress_rule" "server_nhp_udp" {
  count = local.public_udp_source_fenced ? 0 : 1

  security_group_id = aws_security_group.server.id
  description       = "NHP Protocol from assigned-cell public NLB"
  from_port         = 62206
  to_port           = 62206
  ip_protocol       = "udp"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "${var.name_prefix}-server-nhp-udp"
  }
}

# Fenced public NLB target ingress. AWS propagates the NLB security-group
# identity to targets even when preserve_client_ip is enabled, so the target
# never needs the proof runner's public CIDR or a global UDP rule.
resource "aws_vpc_security_group_ingress_rule" "server_nhp_udp_nlb" {
  count = local.public_udp_fence_count

  security_group_id            = aws_security_group.server.id
  description                  = "NHP Protocol from the assigned-cell public NLB security group"
  from_port                    = 62206
  to_port                      = 62206
  ip_protocol                  = "udp"
  referenced_security_group_id = aws_security_group.server_nlb[0].id

  tags = {
    Name = "${var.name_prefix}-server-nhp-udp-nlb"
  }
}

# In-VPC AC keepalive/refresh ingress. ACs send NHP_KPL and registration
# refreshes STRAIGHT to their assigned servers' private IPs, not through the
# public NLB -- see endpoints/ac/registration.go::refreshAssignedServerRegistrations
# and the keepalive note on DefaultNLBReregistrationInterval.
#
# Before the fence that path rode on server_nhp_udp, whose 0.0.0.0/0 source
# incidentally covered in-VPC callers (that rule's own comment calls out that it
# "still serves in-VPC AC traffic"). Fencing the public edge sets that rule's
# count to 0, which silently took the AC path down with it: every assigned-server
# keepalive times out, the all-unconnected detector re-registers through the NLB
# every ~30s, and because lastNLBRegistrationNano keeps resetting, the periodic
# NLB re-registration never reaches its interval and never fires. The fleet looks
# alive -- registration through the edge succeeds -- while no AC can actually
# reach the servers it was assigned.
#
# Scoped to the VPC CIDR, matching how server_http_traefik and server_http_plugins
# already admit AC traffic, and strictly tighter than the 0.0.0.0/0 rule it
# replaces here.
resource "aws_vpc_security_group_ingress_rule" "server_nhp_udp_vpc" {
  count = local.public_udp_fence_count

  security_group_id = aws_security_group.server.id
  description       = "NHP Protocol from in-VPC ACs to their assigned servers"
  from_port         = 62206
  to_port           = 62206
  ip_protocol       = "udp"
  cidr_ipv4         = var.vpc_cidr

  tags = {
    Name = "${var.name_prefix}-server-nhp-udp-vpc"
  }
}

# The public NLB health check is likewise accepted only through the NLB
# security-group identity. The existing VPC-scoped plugin rule remains for
# legitimate in-VPC callers and does not broaden public ingress.
resource "aws_vpc_security_group_ingress_rule" "server_nlb_health" {
  count = local.public_udp_fence_count

  security_group_id            = aws_security_group.server.id
  description                  = "Health checks from the assigned-cell public NLB security group"
  from_port                    = 8888
  to_port                      = 8888
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.server_nlb[0].id

  tags = {
    Name = "${var.name_prefix}-server-nlb-health"
  }
}

# Peered relay-DMZ ingress. The internal NLB preserves the relay instance's
# source IP, so the server SG must admit each exact relay subnet CIDR. Keep this
# separate from server_nhp_udp: the main-VPC rule still serves in-VPC AC traffic,
# while this set is independently reviewable and removable with the DMZ.
resource "aws_vpc_security_group_ingress_rule" "server_nhp_udp_additional" {
  for_each = toset(var.additional_nhp_udp_ingress_cidrs)

  security_group_id = aws_security_group.server.id
  description       = "NHP Protocol from peered relay DMZ subnet"
  from_port         = 62206
  to_port           = 62206
  ip_protocol       = "udp"
  cidr_ipv4         = each.value

  tags = {
    Name = "${var.name_prefix}-server-nhp-udp-${replace(each.value, "/", "-")}"
  }
}

# HTTP (TCP 62206) - from VPC (Traefik proxies here)
resource "aws_vpc_security_group_ingress_rule" "server_http_traefik" {
  security_group_id = aws_security_group.server.id
  description       = "HTTP from Traefik"
  from_port         = 62206
  to_port           = 62206
  ip_protocol       = "tcp"
  cidr_ipv4         = var.vpc_cidr

  tags = {
    Name = "${var.name_prefix}-server-http-traefik"
  }
}

# HTTP for plugin endpoints (AC Traefik and Demo Gateway route here)
resource "aws_vpc_security_group_ingress_rule" "server_http_plugins" {
  security_group_id = aws_security_group.server.id
  description       = "HTTP plugin endpoints from AC and Demo Gateway"
  from_port         = 8888
  to_port           = 8888
  ip_protocol       = "tcp"
  cidr_ipv4         = var.vpc_cidr

  tags = {
    Name = "${var.name_prefix}-server-http-plugins"
  }
}

# Fleet-close discovery advertises HTTP_PORT only from this exact admitted set
# (see endpoints/server/udpserver.go::fleetCloseHTTPPortIsVPCAdmitted). Keep the
# assertion adjacent to the source ingress rules so a future listener change
# cannot drift Cloud Map reachability from the server security group.
check "server_fleet_close_http_ports_are_vpc_admitted" {
  assert {
    condition = toset([
      aws_vpc_security_group_ingress_rule.server_http_traefik.from_port,
      aws_vpc_security_group_ingress_rule.server_http_plugins.from_port,
    ]) == toset([62206, 8888])
    error_message = "Fleet-close HTTP_PORT contract requires VPC TCP ingress on exactly 62206 and 8888."
  }
}

# QURL resolve endpoint: NLB TLS termination → Server HTTP on 8888.
# Must allow all IPs because NLB preserve_client_ip=true forwards packets
# with the original client IP (or CloudFront IP) as source. The endpoint
# is protected by TLS, short-lived token validation, and WAF (when
# CloudFront is enabled).
resource "aws_vpc_security_group_ingress_rule" "server_qurl_resolve" {
  count = var.enable_qurl_resolve_endpoint ? 1 : 0

  security_group_id = aws_security_group.server.id
  description       = "QURL resolve endpoint - browser/CloudFront access via NLB TLS"
  from_port         = 8888
  to_port           = 8888
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "${var.name_prefix}-server-qurl-resolve"
  }
}

# All outbound
resource "aws_vpc_security_group_egress_rule" "server_all" {
  security_group_id = aws_security_group.server.id
  description       = "All outbound"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "${var.name_prefix}-server-egress"
  }
}

# User Data script - using templatefile for proper interpolation
locals {
  protocol_environment = coalesce(var.protocol_environment, var.environment)
  user_data = templatefile("${path.module}/user_data.sh.tpl", {
    secret_arn                      = aws_secretsmanager_secret.server.arn
    region                          = data.aws_region.current.id
    account_id                      = data.aws_caller_identity.current.account_id
    cloudmap_service_id             = aws_service_discovery_service.server.id
    server_repo_url                 = var.server_repo_url
    environment                     = var.environment
    protocol_environment            = local.protocol_environment
    cell_id                         = var.cell_id
    connector_authority_cell_config = var.connector_authority_cell_config
    multi_tenant                    = var.multi_tenant
    # Non-root container service account (#1090) — same numerics in --user and useradd.
    nhp_server_uid      = local.nhp_server_uid
    nhp_server_gid      = local.nhp_server_gid
    etcd_endpoint       = var.etcd_endpoint
    etcd_tls_secret_arn = var.etcd_tls_secret_arn
    # Pass the stderr log group name directly from the TF resource so
    # it cannot drift from the Terraform-managed resource. Consumed by
    # the docker --log-opt awslogs-group flag in the systemd unit.
    server_stderr_log_group = aws_cloudwatch_log_group.server_stderr.name
    # Server configuration options
    log_level        = var.log_level
    dev_mode         = var.dev_mode
    resource_mode    = var.resource_mode
    auth_url         = var.auth_url
    auth_signing_key = var.auth_signing_key
    auth_aes_key     = var.auth_aes_key
    # Deployment configuration
    ssm_image_tag_parameter = aws_ssm_parameter.image_tag.name
    # Plugin configuration (plugins are baked into Docker image)
    server_plugins  = var.server_plugins
    auth_service_id = var.auth_service_id
    # Storage backend configuration (Phase 4)
    storage_backend                = var.storage_backend
    dynamodb_region                = coalesce(var.dynamodb_region, data.aws_region.current.id)
    dynamodb_licenses_table        = var.dynamodb_licenses_table
    dynamodb_ac_assignments_table  = var.dynamodb_ac_assignments_table
    dynamodb_resources_table       = var.dynamodb_resources_table
    dynamodb_agent_keys_table      = var.dynamodb_agent_keys_table
    dynamodb_ack_tokens_table      = var.dynamodb_ack_tokens_table
    dynamodb_session_control_table = var.dynamodb_session_control_table
    # Cloud Map configuration for server health discovery
    cloudmap_enabled        = var.cloudmap_enabled
    cloudmap_namespace_name = var.cloudmap_namespace_name
    cloudmap_service_name   = var.cloudmap_service_name
    # QURL plugin configuration
    qurl_enabled                  = var.qurl_config != null ? var.qurl_config.enabled : false
    qurl_api_url                  = var.qurl_config != null ? var.qurl_config.api_url : ""
    qurl_allowed_redirect_domain  = var.qurl_config != null ? var.qurl_config.allowed_redirect_domain : ""
    qurl_api_timeout              = var.qurl_config != null ? var.qurl_config.api_timeout : 10
    qurl_max_idle_conns           = var.qurl_config != null ? var.qurl_config.max_idle_conns : 10
    qurl_max_idle_conns_per_host  = var.qurl_config != null ? var.qurl_config.max_idle_conns_per_host : 5
    qurl_idle_conn_timeout        = var.qurl_config != null ? var.qurl_config.idle_conn_timeout : 30
    qurl_service_token_secret_arn = var.qurl_service_token_secret_arn != null ? var.qurl_service_token_secret_arn : ""
    # qURL v2 admission (NHP-server independent verifier). admission_enabled is a
    # bool gating whether the env block renders at all — an off env's user_data is
    # byte-unchanged, so this PR triggers no fleet roll until the coordinated enable.
    # The trust store JSON is base64-encoded for env-file transport (the JSON's quotes
    # would otherwise depend on systemd-vs-docker env-file quote handling); the qURL
    # plugin's LoadConfig base64-decodes it. Mirrors NHP_COOKIE_KEYS in this template.
    qurl_v2_admission_enabled  = var.qurl_v2_admission_enabled
    qurl_v2_issuer_trust_store = base64encode(var.qurl_v2_issuer_trust_store)
    # Agent-registration email OTP (T1). Bool gate; rendered inside the qurl_enabled
    # block below. Off env's user_data is byte-unchanged (no fleet roll until the
    # coordinated PATH B enable with qurl-service's QURL_AGENT_OTP_ENABLED).
    agent_otp_registration_enabled = var.agent_otp_registration_enabled
    # Blue/Green deployment configuration
    enable_blue_green = var.enable_blue_green
    # Cookie signing secret (shared across all instances)
    cookie_secret_arn                   = aws_secretsmanager_secret.cookie_secret.arn
    overload_cookie_secret_arn          = aws_secretsmanager_secret.overload_cookie_secret.arn
    overload_cookie_time_window_seconds = var.overload_cookie_time_window_seconds
    # Cell-wide knock AC fan-out toggle (qurl-service#948) -> Config.EnableKnockACFanout
    enable_knock_ac_fanout = var.enable_knock_ac_fanout
    # Shared HMAC secret for /nhp/internal/knock verification (matches qurl-service signer)
    nhp_internal_auth_secret_arn = var.nhp_internal_auth_secret_arn
    # CORS allowed origins for NHP HTTP server
    cors_allowed_origins = var.cors_allowed_origins
    # CloudFront trusted proxy CIDRs (for correct client IP via X-Forwarded-For)
    cloudfront_cidrs_ssm_parameter  = var.cloudfront_cidrs_ssm_parameter
    knock_headertype_verify_require = var.knock_headertype_verify_require
    internal_auth_require           = var.internal_auth_require
    # qURL v2 immediate-revocation proof engine (#2793): managed fleets arm it
    # explicitly while the Go binary remains default-off for unmanaged/pre-ACK ACs.
    revocation_retry_enabled          = var.revocation_retry_enabled
    revocation_retry_interval_seconds = var.revocation_retry_interval_seconds
    revocation_retry_age_out_seconds  = var.revocation_retry_age_out_seconds
    # Knock-port DoS hardening (#1159): global rate cap + receive-buffer tuning.
    knock_global_rate_limit_pps   = var.knock_global_rate_limit_pps
    knock_global_rate_limit_burst = var.knock_global_rate_limit_burst
    udp_recv_buffer_bytes         = var.udp_recv_buffer_bytes
    udp_edge_metrics_script       = chomp(file("${path.module}/udp_edge_metrics.py"))
    # HTTP server timeouts. Surfaced as a TF variable (not hard-coded in
    # the heredoc) so the root module's `aws_cloudfront_distribution.qurl_resolve`
    # lifecycle.precondition can hard-fail plan/apply if IdleTimeoutMs
    # drops below origin_keepalive_timeout + buffer. Bumping CF without
    # touching these would silently re-open the keep-alive race; the
    # precondition fences that.
    http_read_timeout_ms  = var.http_timeouts_ms.read
    http_write_timeout_ms = var.http_timeouts_ms.write
    http_idle_timeout_ms  = var.http_timeouts_ms.idle
    # #2208 5c: server trusts public relay identities supplied by the independent
    # relay-identity module. The server never reads the relay private-key secret.
    # relay_enabled remains the static topology gate for config/count resources;
    # the launch-template precondition below requires a non-empty trust set when lit.
    # The template's disabled branch deliberately preserves the former
    # comment-only output byte-for-byte so this sandbox-only migration does not
    # publish a production server launch-template change. Do not editorially
    # simplify that branch without accepting and planning a prod server roll.
    relay_enabled                 = var.relay_enabled
    relay_trusted_public_keys_b64 = var.relay_trusted_public_keys_b64
    # chomp removes the rendered template's terminal newline because the
    # user-data interpolation line contributes it. Without this, relay.toml
    # receives a cosmetic blank line immediately before its heredoc delimiter.
    relay_toml = var.relay_enabled ? chomp(templatefile("${path.module}/relay.toml.tpl", {
      relay_trusted_public_keys_b64 = var.relay_trusted_public_keys_b64
    })) : ""
  })

  # Launch template user_data — small fetcher when the plugin bucket exists,
  # legacy inline base64gzip path otherwise. Computed in a local so the
  # lifecycle.precondition on aws_launch_template.server can reference the
  # rendered bytes (TF preconditions can't reference `self`).
  server_launch_template_user_data = var.plugin_bucket_name != null ? base64encode(<<-BOOTSTRAP
#!/bin/bash
# -e: exit on error. -x: trace. pipefail: a write failure in the
# tee/logger pipe below shouldn't return 0 from the pipeline and let
# the rest of the script proceed logless.
set -exo pipefail
exec > >(tee /var/log/user-data.log | logger -t user-data) 2>&1
# Init script hash — md5 of local.user_data, NOT the S3 object's etag.
# The hash bumps the launch-template version whenever content changes.
# Referencing aws_s3_object.server_init_script[0].etag here triggers the
# AWS provider's "inconsistent values for sensitive attribute" bug on
# user_data updates: TF pre-computes one etag client-side, the apply-time
# S3 upload yields a different etag (sensitivity-handling or encoding
# divergence in the provider), and plan-expansion fails. md5(local.user_data)
# is computed entirely client-side, so it can't disagree with itself
# between plan and apply.
# Keep in sync with modules/ac/main.tf::aws_launch_template.ac.
# Init script hash: ${md5(local.user_data)}

# Fetch region from IMDSv2 BEFORE the trap and apt block. report_failure
# below uses --region "$REGION", and an early failure during apt/awscli
# install is the most common boot failure mode — fetching region after
# would leave the failure metric region-less and silently dropped.
#
# Defensive fetch: bash command-substitution failures don't trip set -e,
# and curl -s masks HTTP errors as empty bodies. Without retry, a single
# IMDS hiccup on a thundering-herd ASG scale-up bricks the instance with
# no signal. -f fails on HTTP non-2xx, explicit emptiness check catches
# the curl-returns-0-with-empty-body edge case.
fetch_imds_token_and_region() {
  local token region
  for _ in 1 2 3 4 5; do
    # Reset locals each iteration so a partial-success in one iteration
    # (token set, region failed) can't leak a stale token into the next
    # iteration's emptiness checks.
    token=""; region=""
    token=$(curl -fs -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60") || { sleep 2; continue; }
    [ -n "$token" ] || { sleep 2; continue; }
    region=$(curl -fs -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/placement/region) || { sleep 2; continue; }
    [ -n "$region" ] || { sleep 2; continue; }
    TOKEN=$token; REGION=$region; return 0
  done
  return 1
}
if ! fetch_imds_token_and_region; then
  echo "FATAL: IMDSv2 unreachable after 5 attempts; bricking instance loud rather than silent"
  # IMDS-failure path: REGION is unset, so report_failure (which uses
  # --region "$REGION") would silently drop the metric. Use the
  # TF-interpolated literal as a fallback so on-call gets paged on
  # this exact failure mode (the most likely one on a thundering-herd
  # ASG scale-up — see fetch_imds_token_and_region docstring).
  command -v aws &>/dev/null && aws cloudwatch put-metric-data \
    --namespace "LayerV/NHP" \
    --metric-name "BootstrapFailure" \
    --value 1 --unit Count \
    --dimensions "Component=server,Environment=${var.environment},FailureMode=imds-unreachable" \
    --region "${data.aws_region.current.id}" 2>/dev/null || true
  exit 1
fi

report_failure() {
  echo "BOOTSTRAP FAILED: $1"
  command -v aws &>/dev/null && aws cloudwatch put-metric-data \
    --namespace "LayerV/NHP" \
    --metric-name "BootstrapFailure" \
    --value 1 --unit Count \
    --dimensions "Component=server,Environment=${var.environment}" \
    --region "$REGION" 2>/dev/null || true
}
trap 'report_failure "unexpected error on line $LINENO"' ERR
retry_with_backoff() {
  local max_attempts=$1 delay=$2 max_delay=$3; shift 3
  local attempt=1
  while true; do
    if "$@"; then return 0; fi
    if [ "$attempt" -ge "$max_attempts" ]; then echo "ERROR: $* failed after $max_attempts attempts"; return 1; fi
    echo "$* failed (attempt $attempt/$max_attempts), retrying in $${delay}s..."
    sleep "$delay"; attempt=$((attempt + 1)); delay=$((delay * 2))
    if [ "$delay" -gt "$max_delay" ]; then delay=$max_delay; fi
  done
}
apt_get_with_retry() { retry_with_backoff 10 2 60 apt-get "$@"; }
# Custom NHP server AMI ships with awscli pre-installed (packer/nhp-server-docker.pkr.hcl).
# Defensive: install if missing in case the AMI builder regresses.
if ! command -v aws &>/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt_get_with_retry update -y
  apt_get_with_retry install -y unzip curl
  curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
  unzip -qo /tmp/awscliv2.zip -d /tmp && /tmp/aws/install --update
  rm -rf /tmp/awscliv2.zip /tmp/aws
fi
retry_with_backoff 3 5 30 aws s3 cp "s3://${var.plugin_bucket_name}/scripts/server-init.sh" /tmp/server-init.sh --region "$REGION"
chmod +x /tmp/server-init.sh
exec /tmp/server-init.sh
BOOTSTRAP
  ) : base64gzip(local.user_data) # legacy inline path — only kept as a structural fallback for bucket-not-yet-provisioned bootstrap; fails for the same size reason this PR exists to fix, so it's not a viable runtime rollback. To roll back, revert this PR.
}

# Plan-time fence required by terraform/CLAUDE.md for the first multi-line
# templatefile variable embedded in this bash template. The relay TOML is safe
# only because it occupies the body of a single-quoted heredoc; keep that exact
# placement and independently reject an unescaped interpolation in bash comments
# so a future documentation/refactor edit cannot reintroduce the #2044 class.
resource "terraform_data" "relay_toml_render_fence" {
  count = var.relay_enabled ? 1 : 0

  # Make template edits visible on this otherwise state-only guard as well as
  # on the launch template that consumes the rendered user data.
  input = filesha256("${path.module}/user_data.sh.tpl")

  lifecycle {
    precondition {
      condition = length(regexall(
        "(?m)cat > /opt/layerv/nhp-server/etc/relay\\.toml << 'RELAYEOF'\\n\\$\\{relay_toml\\}\\nRELAYEOF",
        file("${path.module}/user_data.sh.tpl"),
      )) == 1
      error_message = "user_data.sh.tpl must interpolate relay_toml exactly once as the body of the single-quoted RELAYEOF heredoc; review the multi-line templatefile safety rule in terraform/CLAUDE.md before changing this placement."
    }

    precondition {
      condition = length(regexall(
        "(?m)(^|[[:space:]])#(?:[^\\n]*[^$\\n])?\\$\\{relay_toml\\}",
        file("${path.module}/user_data.sh.tpl"),
      )) == 0
      error_message = "user_data.sh.tpl must not interpolate the multi-line relay_toml value inside a bash comment; escape a documentation-only token or keep the value inside its single-quoted heredoc."
    }
  }
}

resource "terraform_data" "udp_edge_metrics_render_fence" {
  input = filesha256("${path.module}/udp_edge_metrics.py")

  lifecycle {
    precondition {
      condition = length(regexall(
        "(?m)cat > /usr/local/bin/nhp-udp-edge-metrics << 'PYEOF'\\n\\$\\{udp_edge_metrics_script\\}\\nPYEOF",
        file("${path.module}/user_data.sh.tpl"),
      )) == 1
      error_message = "udp_edge_metrics_script must appear exactly once as the body of the single-quoted PYEOF heredoc."
    }
  }
}

# Server bootstrap script in S3 (mirrors AC module pattern). The rendered
# user_data sits at the EC2 16KB user_data limit (post-gzip), so we move
# the bulk to S3 and keep the launch template's user_data as a small
# fetcher. Introduced in PR #1809; the matching size-guard precondition
# on aws_launch_template.server fences regrowth.
resource "aws_s3_object" "server_init_script" {
  count = var.plugin_bucket_name != null ? 1 : 0

  bucket       = var.plugin_bucket_name
  key          = "scripts/server-init.sh"
  content      = local.user_data
  content_type = "text/x-shellscript"
}

# Attach the plugin-bucket download policy from modules/plugins to the
# server role. This grants s3:GetObject + KMS Decrypt on the bucket's
# CMK — needed because the plugin bucket is encrypted with
# module.kms.logs_key_arn, which is a different CMK from the server's
# secrets_kms_key_arn (modules/kms/outputs.tf:21,31). A scripts/*-only
# inline policy would land us with s3:GetObject but no KMS Decrypt, so
# `aws s3 cp` would AccessDenied at boot. Mirrors the AC module's
# pattern (modules/ac/main.tf::aws_iam_role_policy_attachment.ac_plugins).
resource "aws_iam_role_policy_attachment" "server_plugins" {
  count = var.plugin_download_policy_arn != null ? 1 : 0

  role       = aws_iam_role.server.name
  policy_arn = var.plugin_download_policy_arn
}

# Launch Template
resource "aws_launch_template" "server" {
  name_prefix   = "${var.name_prefix}-server-"
  image_id      = local.server_ami_id
  instance_type = local.is_prod ? "c6i.xlarge" : "t3.medium"

  iam_instance_profile {
    arn = aws_iam_instance_profile.server.arn
  }

  # NHP servers run in private subnets - NAT Gateway provides internet access
  # VPC endpoints provide access to ECR, Secrets Manager, CloudWatch Logs, SSM
  # NLB in public subnets routes traffic to servers in private subnets
  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.server.id]
  }

  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      volume_size           = 50
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = var.ebs_kms_key_arn
      delete_on_termination = true
    }
  }

  # Full init script lives in S3 because the rendered template exceeds
  # EC2's 16KB user_data limit (post-gzip). Bootstrap installs/uses AWS CLI,
  # downloads scripts/server-init.sh, and execs it. An md5 of the rendered
  # local.user_data is embedded so a content change forces a launch template
  # version bump (and thus an instance refresh on the next deploy). See the
  # in-heredoc comment for why md5(local.user_data) instead of the S3 object's
  # etag. Mirrors the AC module's battle-tested pattern
  # (modules/ac/main.tf::aws_launch_template.ac).
  # Computed via local.server_launch_template_user_data so the size guard
  # in lifecycle.precondition (below) can reference the rendered output.
  user_data = local.server_launch_template_user_data

  monitoring {
    enabled = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  tags = var.tags

  tag_specifications {
    resource_type = "instance"
    tags = merge(var.tags, {
      Name      = "${var.name_prefix}-server"
      Component = "compute"
      Cell      = var.cell_id
    })
  }

  lifecycle {
    create_before_destroy = true

    # Fail-loud guard against the size cliff this PR was created to escape.
    # EC2 caps user_data at 16,384 raw bytes (post-base64-decode); see
    # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html.
    # The whole point of the S3-hosted bootstrap is to keep the inline
    # user_data tiny — if a future PR adds enough to the bootstrap
    # heredoc to push past the limit, fail at plan time rather than at
    # apply time (where the only signal is a confusing "Modifying..."
    # error mid-apply).
    #
    # The user_data hash is md5(local.user_data) — fully plan-time computable
    # — so this precondition runs at plan, not apply.
    precondition {
      condition     = length(base64decode(local.server_launch_template_user_data)) <= 16384
      error_message = "Launch-template user_data exceeds EC2's 16384-byte cap (post-base64-decode). The S3 bootstrap pattern (modules/compute/main.tf::aws_s3_object.server_init_script) exists to keep the inline user_data tiny — move new logic into scripts/server-init.sh, not into the bootstrap heredoc."
    }

    # Both-or-neither: a future caller setting plugin_bucket_name without
    # plugin_download_policy_arn would render the BOOTSTRAP path, accept
    # the launch template, and brick instances at boot with AccessDenied
    # on the s3 cp (no KMS Decrypt grant). Plan-time fail is cheaper than
    # boot-time fail.
    precondition {
      condition     = (var.plugin_bucket_name == null) == (var.plugin_download_policy_arn == null)
      error_message = "plugin_bucket_name and plugin_download_policy_arn must be set together — the bucket needs the policy's KMS Decrypt grant or instances brick at boot."
    }

    precondition {
      condition = (
        (var.relay_enabled && length(var.relay_trusted_public_keys_b64) > 0) ||
        (!var.relay_enabled && length(var.relay_trusted_public_keys_b64) == 0)
      )
      error_message = "relay_enabled and relay_trusted_public_keys_b64 must be enabled together: a lit relay needs at least one public trust key, while a dark environment must not render relay.toml."
    }
  }

  # Explicit dependency on the policy attachment so the first ASG launch
  # in a greenfield apply can't race ahead of IAM eventual consistency.
  # The S3 init script is an explicit dependency for runtime ordering: an
  # instance launched against this LT does `aws s3 cp` of the script at
  # boot, so the object must exist by the time the ASG can launch. (The
  # user_data hash is md5(local.user_data), not the object's etag — there
  # is no longer an attribute reference for TF to infer this from.)
  depends_on = [
    aws_lambda_invocation.keygen,
    terraform_data.cookie_secret_seed,
    terraform_data.overload_cookie_secret_seed,
    aws_iam_role_policy_attachment.server_plugins,
    time_sleep.dynamodb_read_iam_propagation,
    aws_s3_object.server_init_script,
  ]
}

# Auto Scaling Group
# NHP servers are deployed in PRIVATE subnets with NLB routing:
# 1. NLB in public subnets handles internet-facing traffic
# 2. Servers in private subnets are protected from direct internet access
# 3. NAT Gateway provides outbound internet (apt updates)
# 4. VPC endpoints provide access to AWS services (ECR, SSM, CloudWatch)
resource "aws_autoscaling_group" "server" {
  name                = "${var.name_prefix}-server"
  vpc_zone_identifier = var.private_subnet_ids
  min_size            = var.min_capacity
  max_size            = var.max_capacity
  desired_capacity    = var.min_capacity

  launch_template {
    id      = aws_launch_template.server.id
    version = aws_launch_template.server.latest_version
  }

  # Use EC2 health checks (NOT ELB) for ASG lifecycle decisions. This is
  # load-bearing and prevents a bootstrap deadlock — see "Bootstrap deadlock
  # avoidance" below for the full chain.
  health_check_type = "EC2"
  # Docker is pre-baked into the AMI (see packer/nhp-server-docker.pkr.hcl),
  # so apt-get install Docker (~90s) and AWS CLI install (~30s) are no longer
  # in the critical path. Boot + user_data + container start now fit under
  # ~60s (~15s launch, ~15s user_data, ~15-30s ECR pull + container start).
  # 90s is ~1.5x the observed worst case to absorb slower ECR pulls when a
  # new image tag is rolled out for the first time.
  health_check_grace_period = 90
  #
  # Bootstrap deadlock avoidance:
  #
  # The HTTPS target group (aws_lb_target_group.https) uses /health/knock-ready
  # — that endpoint only returns 200 once the server has at least one connected
  # AC peer. That's intentional: HTTPS traffic on the QURL resolve listener
  # actually needs an AC peer to do anything useful, so we keep half-baked
  # servers out of the LB rotation.
  #
  # Naively, this would deadlock during bootstrap: the very first server has
  # no AC peers (no ACs have registered yet), so /health/knock-ready returns
  # non-200, the ELB marks it Unhealthy, and if the ASG were configured to
  # terminate on ELB failures, it would loop terminating fresh instances
  # forever — and ACs (which find servers via Cloud Map / DNS, not the LB)
  # would never get the chance to register against them.
  #
  # Two pieces break the deadlock:
  #   1. health_check_type = "EC2" above. The ASG only consults the EC2
  #      instance state (running/not-running) for lifecycle decisions and
  #      ignores the LB target group health entirely. Failing knock-ready
  #      affects LB routing, not instance termination.
  #   2. The HTTP forwarder fix in the server itself: when a knock arrives
  #      on a server that has no AC peers, the server forwards the knock to
  #      a peer server that does have AC peers, instead of failing. So
  #      bootstrap traffic still works even before the new server's own AC
  #      peers come up.
  #
  # The same /health/knock-ready path is used by the green HTTPS target group
  # (blue_green.tf::aws_lb_target_group.https_green); the same reasoning
  # applies. Keep this comment in sync if you ever change either.

  # Publish ASG group metrics to CloudWatch (AWS/AutoScaling namespace).
  # Without this, metrics like GroupInServiceInstances are not emitted.
  # Keep GroupDesiredCapacity + GroupInServiceInstances: green standby
  # capacity-deficit alarms use them as their publishable replacement for
  # AWS's non-existent GroupUnHealthyInstanceCount ASG group metric.
  enabled_metrics = [
    "GroupInServiceInstances",
    "GroupDesiredCapacity",
    "GroupMinSize",
    "GroupMaxSize",
    "GroupPendingInstances",
    "GroupTerminatingInstances",
    "GroupTotalInstances",
  ]

  tag {
    key                 = "Name"
    value               = "${var.name_prefix}-server"
    propagate_at_launch = true
  }

  tag {
    key                 = "Component"
    value               = "compute"
    propagate_at_launch = true
  }

  tag {
    key                 = "Cell"
    value               = var.cell_id
    propagate_at_launch = true
  }

  # Blue/Green deployment: Mark this as the blue ASG
  # user_data.sh.tpl reads this tag to determine which SSM image tag parameter to use
  tag {
    key                 = "DeployColor"
    value               = "blue"
    propagate_at_launch = true
  }

  dynamic "tag" {
    for_each = var.tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }

  lifecycle {
    create_before_destroy = true
    # CI/CD manages capacity on this ASG during blue/green switches.
    # When traffic is switched to green, this (blue) ASG is scaled down
    # to a warm standby by the `scale-down-previous` job in
    # blue-green-deploy.yml. Without `ignore_changes` here, the next
    # `terraform apply` — which runs on every main-push CI deploy — resets
    # desired_capacity/min_size back to `var.min_capacity`, undoing the
    # scale-down within seconds and silently leaving two full-size ASGs
    # (2x cost, drift between TF state and reality).
    #
    # Matches the `aws_autoscaling_group.server_green` lifecycle in
    # blue_green.tf; the asymmetry (blue not having it) was the bug —
    # every CI deploy that ran a TF apply also reverted the blue/green
    # state that CI had just established.
    #
    # Trade-off: operators cannot change capacity via `var.min_capacity`
    # on an existing ASG through TF. Use the ASG API / console or a
    # blue/green deploy to adjust scale. This is consistent with the
    # green ASG's existing behaviour and matches how CI already operates.
    # Process suspension is also an operational control. An attended migration
    # or incident response may suspend Launch/policy processes before Terraform
    # updates the ASG. Reconciliation must not silently resume them in the same
    # apply; the operator who froze the group owns the explicit, post-health
    # resume. This is particularly load-bearing for cross-VPC moves, where the
    # old fleet is drained before its subnets are destroyed.
    ignore_changes = [desired_capacity, min_size, max_size, suspended_processes]
  }
}

# Scaling Policies
resource "aws_autoscaling_policy" "cpu" {
  name                   = "${var.name_prefix}-cpu"
  autoscaling_group_name = aws_autoscaling_group.server.name
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 70.0
  }
}

# Network scaling policy removed: the 10MB threshold was too low —
# deploy-time Docker image pulls (~50-100MB) triggered scale-up from 3→4,
# breaking AZ balance (3 instances = 1 per AZ). The blue-green workflow
# copies DesiredCapacity to the standby ASG, so the spurious 4 propagated
# permanently. CPU target-tracking (70%) is sufficient for real load scaling.

# Network Load Balancer (PUBLIC native SDK knock surface). Constant count keeps
# the indexed state address introduced by #2628.
resource "aws_security_group" "server_nlb" {
  count = local.public_udp_fence_count

  name_prefix            = "${var.name_prefix}-nlb-"
  description            = "Source-fenced assigned-cell public UDP NLB"
  vpc_id                 = var.vpc_id
  revoke_rules_on_delete = true

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-sg-nlb"
    Component = "compute"
    Cell      = var.cell_id
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Client-facing ingress: the listener port (443), not the target port. The
# matching egress rule below stays on 62206 because the NLB translates.
resource "aws_vpc_security_group_ingress_rule" "server_nlb_udp" {
  for_each = toset(coalesce(var.public_nhp_udp_ingress_cidrs, []))

  security_group_id = aws_security_group.server_nlb[0].id
  description       = "NHP UDP proof source ${each.value}"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "udp"
  cidr_ipv4         = each.value

  tags = {
    Name = "${var.name_prefix}-nlb-udp-${replace(each.value, "/", "-")}"
  }
}

resource "aws_vpc_security_group_egress_rule" "server_nlb_udp" {
  count = local.public_udp_fence_count

  security_group_id            = aws_security_group.server_nlb[0].id
  description                  = "NHP UDP to assigned-cell server targets"
  from_port                    = 62206
  to_port                      = 62206
  ip_protocol                  = "udp"
  referenced_security_group_id = aws_security_group.server.id

  tags = {
    Name = "${var.name_prefix}-nlb-udp-target"
  }
}

resource "aws_vpc_security_group_egress_rule" "server_nlb_health" {
  count = local.public_udp_fence_count

  security_group_id            = aws_security_group.server_nlb[0].id
  description                  = "HTTP health checks to assigned-cell server targets"
  from_port                    = 8888
  to_port                      = 8888
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.server.id

  tags = {
    Name = "${var.name_prefix}-nlb-health-target"
  }
}

resource "aws_lb" "server" {
  count = 1
  # AWS cannot attach a security group to an NLB that was created without one.
  # The distinct fenced name is therefore correctness-relevant: changing
  # null -> a reviewed source list forces physical replacement and lets the old
  # edge coexist until Terraform moves the listener/DNS-facing outputs.
  name               = replace(local.server_nlb_name, "_", "-")
  internal           = false
  load_balancer_type = "network"
  subnets            = var.public_subnet_ids
  # Gated on the source-list variable directly, NOT on
  # local.public_udp_source_fenced. The relay DMZ contract admits exactly the
  # dedicated SG traversal plus this one reviewed staging-gate variable as
  # metadata (check-relay-dmz-plan.py: "assigned cell public NLB
  # security_groups must reference only its dedicated SG in authored config").
  # A local indirection adds an unreviewed `local.` traversal to the authored
  # expression and fails that contract, even though it resolves identically --
  # local.public_udp_source_fenced IS `var.public_nhp_udp_ingress_cidrs != null`.
  security_groups = var.public_nhp_udp_ingress_cidrs != null ? [aws_security_group.server_nlb[0].id] : null

  # Pin the PrivateLink posture of the source fence instead of inheriting it.
  # This governs whether the SG above is evaluated for traffic that reaches the
  # NLB through a VPC endpoint service. Read the threat model precisely, because
  # the naive reading is wrong in BOTH directions:
  #
  #   * AWS's documented default is to ENFORCE inbound rules on PrivateLink
  #     traffic; the setting exists to turn enforcement OFF. So an unset
  #     attribute is not an open bypass.
  #   * DescribeLoadBalancers OMITS the member entirely until it is set
  #     explicitly (it is `Required: No` with no documented response default),
  #     which is exactly what the live sandbox edges return today.
  #
  # So this is hardening, not an exploit fix: it converts an unpinned AWS
  # default into an asserted, Terraform-owned invariant, so that an out-of-band
  # flip to "off" becomes drift this repo can see. It also satisfies
  # .github/scripts/collect_udp_proof_deployment_evidence.py, which requires the
  # literal "on" of the live edge and cannot pass while the member is omitted.
  #
  # In-place ModifyLoadBalancerAttributes, NOT a replacement: the attribute is
  # Optional+Computed and not ForceNew, so this never re-runs the DNS repoint or
  # the canary/pin cycle that the fence transition above required.
  #
  # Gated on the SAME condition as security_groups, and that gate is
  # correctness-relevant, not cosmetic: the attribute only has meaning when the
  # NLB carries security groups to enforce. Production still runs the unfenced,
  # SG-less edge (terraform/environments/prod/variables.tf pins
  # public_nhp_udp_ingress_cidrs == null), so null leaves the attribute unset and
  # Computed there, preserving today's prod behaviour exactly rather than
  # risking a SetSecurityGroups call against a load balancer with no SGs. This
  # mirrors the authored-expression note above: the reviewed staging-gate
  # variable is referenced directly, never through a `local.` indirection.
  enforce_security_group_inbound_rules_on_private_link_traffic = var.public_nhp_udp_ingress_cidrs != null ? "on" : null

  enable_cross_zone_load_balancing = true
  enable_deletion_protection       = local.is_prod

  tags = merge(var.tags, {
    Name      = local.server_nlb_name
    Component = "compute"
    Cell      = var.cell_id
  })

  lifecycle {
    # AWS cannot attach a security group to an existing NLB, so the
    # source-fence transition (null -> a reviewed source list) has to stand up a
    # new physical edge and hand the listener over before the SG-less NLB is
    # retired. That ordering is only legal because the same transition also
    # flips the physical name via local.server_nlb_name (`-nlb` -> `-edge`), so
    # the old and new edges never contend for one ELBv2 name.
    #
    # The corollary is load-bearing: a replacement that does NOT change the name
    # would fail with DuplicateLoadBalancerName. Every cell now reaches the fence
    # through exactly that name-changing transition -- cell1's
    # `10.102.0.0/16` -> `10.104.0.0/16` relocation is already applied, so no
    # cell combines a VPC move with the fence. (The rollout runbook that used to
    # be cited here was deleted once every cell converged; recover it from git
    # history for this path if ever needed.) Any FUTURE VPC move
    # of an already-fenced cell fires replace_triggered_by below WITHOUT changing
    # the name, so it must carry an explicit name change in its reviewed saved
    # plan.
    create_before_destroy = true

    # ELBv2 cannot move an existing NLB to subnets in another VPC. Terraform's
    # AWS provider models `subnets` as an in-place update, so a VPC relocation
    # would otherwise reach apply and fail in SetSubnets. The server SG's vpc_id
    # changes exactly when the server VPC changes; key the trigger to that
    # attribute rather than the whole SG so an unrelated name/description
    # replacement cannot cascade into NLB downtime.
    replace_triggered_by = [aws_security_group.server.vpc_id]
  }
}

# UDP Target Group (PUBLIC knock surface). Constant count preserves state shape.
resource "aws_lb_target_group" "udp" {
  count       = 1
  name        = replace("${var.name_prefix}-udp", "_", "-")
  port        = 62206
  protocol    = "UDP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  # Direct SDK knocks must retain the original client address at nhp-server.
  # Keep this explicit even though AWS enables it for UDP instance targets so
  # the public edge contract is visible and plan-validated for both colors.
  preserve_client_ip = true

  # HTTP health check on port 8888 (NHP Server HTTP listener)
  # Uses /health/live endpoint for Kubernetes-style liveness probe
  # This checks that the server is running and can respond to requests
  health_check {
    enabled             = true
    protocol            = "HTTP"
    port                = "8888"
    path                = "/health/live"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 30
    matcher             = "200" # Expect HTTP 200 OK
  }

  deregistration_delay = 30

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-tg-udp"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# Attach ASG to the required public UDP target group.
resource "aws_autoscaling_attachment" "server" {
  count                  = 1
  autoscaling_group_name = aws_autoscaling_group.server.name
  lb_target_group_arn    = aws_lb_target_group.udp[0].arn
}

# UDP Listener (required PUBLIC knock surface).
#
# Clients dial UDP 443, not the server's own listen port. Restrictive corporate
# and hotel egress filters routinely drop high-numbered outbound UDP while
# leaving 443 open for QUIC/HTTP-3, so the public edge meets clients there. The
# NLB translates to the target group's port 62206, which is what the server
# process binds — do NOT propagate 443 to the target group, SG, or instance:
# that would require CAP_NET_BIND_SERVICE on the server for no benefit.
#
# An NLB permits only ONE listener per port, so this cannot coexist with the
# qURL-resolve TLS listener that used to sit on 443. That listener now serves
# aws_lb_listener.https on port 8443 (reached only by CloudFront, which sets a
# matching custom origin port). depends_on forces the TLS listener to vacate
# 443 BEFORE this one claims it; without it Terraform may order the two updates
# the other way and the apply fails with DuplicateListener.
resource "aws_lb_listener" "udp" {
  count             = 1
  load_balancer_arn = aws_lb.server[0].arn
  port              = 443
  protocol          = "UDP"

  depends_on = [aws_lb_listener.https]

  default_action {
    type = "forward"
    # A listener replacement must preserve the blue/green controller's
    # authoritative active color. ignore_changes protects ordinary traffic
    # switches, but Terraform still evaluates this create-time value when the
    # listener itself is replaced (for example, while adding an NLB security
    # group). Derive the target from the existing managed active-color record;
    # do not expose an operator-supplied replacement target.
    target_group_arn = var.enable_blue_green && aws_ssm_parameter.active_color[0].value == "green" ? aws_lb_target_group.udp_green[0].arn : aws_lb_target_group.udp[0].arn
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-listener-udp"
    Component = "compute"
    Cell      = var.cell_id
  })

  lifecycle {
    # The Switch Traffic step in blue-green-deploy.yml points
    # `default_action.target_group_arn` at the blue or green TG to
    # flip which ASG serves production knocks. Without this ignore,
    # every `terraform apply` resets the listener back to
    # `aws_lb_target_group.udp[0].arn` (the blue TG), silently undoing
    # the blue/green traffic switch within seconds of CI making it.
    # The sandbox state-drift incident on 2026-04-08 was caused
    # exactly by this: a green-active deploy landed, the next CI
    # push ran a TF apply, and the apply reset the listener back to
    # blue while SSM still said green → `Reconcile Listener and SSM
    # State` validation step failed on the next dispatched deploy.
    ignore_changes = [default_action]

    precondition {
      condition = (
        !var.enable_blue_green ||
        contains(["blue", "green"], aws_ssm_parameter.active_color[0].value)
      )
      error_message = "The managed active-color record must be exactly blue or green before creating the public UDP listener."
    }
  }
}

# =============================================================================
# Internal UDP NLB for the relay -> cell-server hop (#2208 #8 / #2628 steps 1-2;
# closes #2626)
# =============================================================================
# The relay forwards NHP_RLY to the cell server over UDP 62206. Pointing it at
# CloudMap (`server.<namespace>`) resolves ONCE at the relay's boot to a single
# IP, which goes stale when the server fleet churns (#2626 — relay stale-IP on
# churn). This internal NLB gives the relay a stable, load-balanced,
# churn-resilient target whose DNS name never changes.
#
# This internal target always coexists with the public server NLB and serves only
# relay-to-server NHP_RLY traffic. relay_enabled (= deploy_relay) count-gates it,
# so dark production creates no idle relay-only NLB.
#
# Mirrors the public UDP path's per-resource config (cross-zone, deletion
# protection per env, UDP 62206, instance target type, /health/live HTTP health
# check on 8888, deregistration_delay, tags) with these deliberate divergences:
#   - internal = true + private subnets (this is the in-VPC relay->server hop,
#     not an internet edge);
#   - UDP-only: NO resolver HTTPS listener/TG (the relay speaks only UDP knock);
#   - blue/green: per-color internal TGs plus listener flips, matching the
#     public UDP path. The relay keeps one stable cell/server identity, but the
#     target source behind that identity must be active-color-only. Routing
#     one-time qURL knocks to a warm-standby server can commit qURL admission and
#     then fail AC-open if that standby is not in the live AC assignment set.
#
# preserve_client_ip = true: the server sees the relay INSTANCE's private source
# IP and UDP 62207 source port. It returns the authenticated RelayReturnMsg
# directly to that instance and port, bypassing an NLB return hop. The relay
# validates the envelope and dispatches by random RequestID; its SG admits UDP
# 62207 only from the server SG
# (modules/relay/compute.tf::aws_vpc_security_group_ingress_rule.relay_udp_ack_return).
# The explicit peered relay-subnet rules preserve auditable topology evidence
# for this private path. The required public UDP 62206 base rule also remains in
# force for direct assigned-cell SDK traffic.
resource "aws_lb" "server_internal" {
  count              = var.relay_enabled ? 1 : 0
  name               = replace("${var.name_prefix}-srv-int", "_", "-")
  internal           = true
  load_balancer_type = "network"
  # Private subnets: the in-VPC relay->server hop lives with the ASG, not on the
  # public edge (see the divergences note in the block header above).
  subnets = var.private_subnet_ids

  # Cross-zone is correctness-relevant here, not just cost/parity: Go resolves
  # the relay.toml host ONCE at boot, so the relay may lock onto a single NLB
  # node IP (one AZ). With cross-zone disabled that node would only reach
  # same-AZ targets; enabling it lets the once-resolved relay reach the whole
  # fleet across AZs.
  enable_cross_zone_load_balancing = true
  enable_deletion_protection       = local.is_prod

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-srv-int-nlb"
    Component = "compute"
    Cell      = var.cell_id
  })

  lifecycle {
    # Same cross-VPC constraint as the public NLB above. This count is zero for
    # the lean sandbox cell1 root, but keeping the module's two server NLBs in
    # lockstep prevents a later relay-enabled VPC relocation from attempting an
    # impossible in-place SetSubnets call.
    replace_triggered_by = [aws_security_group.server.vpc_id]
  }
}

# Internal UDP Target Group for the BLUE server ASG (mirrors
# aws_lb_target_group.udp). The existing resource/name is retained as the blue
# target group to avoid replacing the live relay NLB TG during this migration.
resource "aws_lb_target_group" "udp_internal" {
  count       = var.relay_enabled ? 1 : 0
  name        = replace("${var.name_prefix}-srv-int-udp", "_", "-")
  port        = 62206
  protocol    = "UDP"
  vpc_id      = var.vpc_id
  target_type = "instance"
  # Explicit (not relying on the AWS UDP-instance-TG default) because the
  # relay->server return path depends on it — see the NLB block comment above.
  preserve_client_ip = true

  # HTTP health check on port 8888 — same /health/live liveness probe the public
  # UDP TG uses (NOT the HTTPS TG's /health/knock-ready: this is the knock data
  # path, which works before the local server has AC peers via HTTP forwarding).
  health_check {
    enabled             = true
    protocol            = "HTTP"
    port                = "8888"
    path                = "/health/live"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 30
    matcher             = "200" # Expect HTTP 200 OK
  }

  deregistration_delay = 30

  tags = merge(var.tags, {
    Name        = "${var.name_prefix}-tg-srv-int-udp-blue"
    Component   = "compute"
    Cell        = var.cell_id
    DeployColor = "blue"
  })
}

# Attach the BLUE server ASG to the BLUE internal TG (multi-TG attach on this ASG
# is already in use — aws_autoscaling_attachment.https alongside .server). The
# GREEN ASG attaches to its own internal TG in blue_green.tf.
resource "aws_autoscaling_attachment" "server_internal" {
  count                  = var.relay_enabled ? 1 : 0
  autoscaling_group_name = aws_autoscaling_group.server.name
  lb_target_group_arn    = aws_lb_target_group.udp_internal[0].arn
}

# Internal UDP Listener. Blue/green switch flips this listener between the blue
# and green internal TGs in the same operation that updates active-color. Keep
# Terraform from resetting a live green-active deployment back to blue.
resource "aws_lb_listener" "udp_internal" {
  count             = var.relay_enabled ? 1 : 0
  load_balancer_arn = aws_lb.server_internal[0].arn
  port              = 62206
  protocol          = "UDP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.udp_internal[0].arn
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-listener-srv-int-udp"
    Component = "compute"
    Cell      = var.cell_id
  })

  lifecycle {
    ignore_changes = [default_action]
  }
}

# Alarm: the BLUE internal cell-NLB target group has no healthy targets. Mirrors
# green_internal_tg_no_healthy_targets (blue_green.tf) for the relay->server hop.
# The internal NLB is the relay's ONLY path to the cell servers, so a fully
# unhealthy internal TG silently fails relayed knocks when that color is active,
# and is unsafe to flip to when that color is standby.
# treat_missing_data=breaching matches that sibling: a TG reporting no
# HealthyHostCount is itself the failure to page on.
# No cold-standby gate here: blue is the always-warm baseline ASG, while only
# the green standby ASG can intentionally scale to zero.
#
# Count gates on relay_enabled (the internal NLB only exists where the relay is
# deployed) + the STATIC enable_sns_alerts — NOT green_tg's computed
# alerts_sns_topic_arn != null. alerts_sns_topic_arn is module.monitoring's
# (computed) ARN, so gating count on it risks "Invalid count argument" on a
# greenfield relay_enabled=true apply before the ARN is in state; enable_sns_alerts
# is the static boolean that exists to avoid exactly that (variables.tf), and is
# what termination_cleanup_errors uses. alarm_actions still uses the ARN — valid
# because enable_sns_alerts=true means it's provided.
resource "aws_cloudwatch_metric_alarm" "internal_tg_no_healthy_targets" {
  count = var.relay_enabled && var.enable_sns_alerts ? 1 : 0

  alarm_name          = "${var.name_prefix}-srv-int-tg-no-healthy"
  alarm_description   = "Blue internal relay target group has no healthy targets - blue relay knocks would fail if blue is or becomes active"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HealthyHostCount"
  namespace           = "AWS/NetworkELB"
  period              = 60
  statistic           = "Minimum"
  threshold           = 1
  treat_missing_data  = "breaching"

  dimensions = {
    TargetGroup  = aws_lb_target_group.udp_internal[0].arn_suffix
    LoadBalancer = aws_lb.server_internal[0].arn_suffix
  }

  alarm_actions = [var.alerts_sns_topic_arn]
  ok_actions    = [var.alerts_sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-srv-int-tg-health-alarm"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# =============================================================================
# TLS/HTTPS Target Group and Listener (for QURL resolve endpoint)
# =============================================================================
# When enable_qurl_resolve_endpoint is true, these resources create an HTTPS
# endpoint on the NHP Server NLB for resolve.qurl.link traffic.
#
# This allows the QURL authentication flow to reach the NHP Server's plugin
# endpoint directly, bypassing the AC which has port 443 blocked until NHP knock.
#
# Traffic flow:
#   resolve.qurl.link → NLB:443 (TLS termination) → Server:8888 (HTTP plugin)

# TCP Target Group for HTTPS traffic (routes to HTTP plugin endpoint)
resource "aws_lb_target_group" "https" {
  count = var.enable_qurl_resolve_endpoint ? 1 : 0

  name        = replace("${var.name_prefix}-https", "_", "-")
  port        = 8888
  protocol    = "TCP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  # Health check on port 8888 — uses /health/knock-ready to verify the server
  # has connected AC peers before routing knock traffic to it (H1 hardening).
  # /health/live is still used by ASG/Docker to avoid terminating servers
  # that are healthy but waiting for AC connections.
  health_check {
    enabled             = true
    protocol            = "HTTP"
    port                = "8888"
    path                = "/health/knock-ready"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 10
    matcher             = "200"
  }

  deregistration_delay = 30

  # Force immediate TCP RST on in-flight flows when an instance is
  # deregistered (e.g. blue/green flip + old-ASG shrink). Default is
  # `false` for TCP/TLS TGs, which lets in-flight flows drain over
  # `deregistration_delay`. That default was the trigger for the
  # 2026-05-22 sandbox "qurl.link verifying-access page spins 60s,
  # then redirects to a closed-L3 firewall" incident: CloudFront's
  # pooled origin connections were stranded on a draining green
  # instance, the gin handler returned 302 in 75ms but the TCP
  # response never flushed before the instance was SIGTERM'd, and CF
  # sat on its `OriginReadTimeout=60s` instead of detecting the dead
  # peer and retrying immediately. Setting this `true` makes the
  # dereg send RST → CF detects → CF retries on a fresh blue
  # connection on its own retry cadence (sub-second to single-digit
  # seconds in practice, bounded by CF's connection-error retry
  # budget — much faster than the 60s OriginReadTimeout the
  # pre-2026-05-22-fix behaviour incurred). Empirical retry
  # latency to be confirmed by
  # the sandbox repro listed in the PR test plan; the regime is
  # "much better than 60s" either way. Matches the AWS-default
  # behaviour the UDP TG already gets for free (UDP is stateless
  # from NLB's POV).
  #
  # **POST-replay idempotency on this TG**: CF's connection-error
  # retry will replay an in-flight POST. The /plugins/qurl path lands
  # on qurl-service's atomic DDB conditional update
  # (qurl-service/internal/repository/dynamodb/qurl_repo.go ConsumeTokenByHash);
  # a replay returns 403 "Access Link Invalid" rather than double-
  # consuming. See the parallel duplicate-POST writeup on
  # ac/main.tf::aws_lb_target_group.ac_tcp for the customer-backend
  # half (qurl-router forwards retries transparently — different
  # idempotency surface).
  #
  # **Role of deregistration_delay above is now disjoint from
  # in-flight TCP behaviour.** With connection_termination=true, the
  # 30s deregistration_delay only governs LB-side target-state
  # cleanup (the period during which the TG continues to report the
  # deregistering target while it stops accepting NEW traffic) —
  # in-flight TCP flows are RST'd immediately, NOT drained for up to
  # 30s. A future operator tuning deploy timing should not read
  # `deregistration_delay = 30` as "in-flight flows have 30s to
  # complete"; they have ~0s and rely on the upstream retry instead.
  #
  # Why 30s is kept (not tightened): the value still controls how
  # long the deregistering target stays visible in the TG before
  # the LB forgets it. Tightening to <30s would make the LB stop
  # routing NEW connections sooner but also race against
  # health-check propagation (interval=10s, unhealthy_threshold=2
  # = 20s minimum before a non-shutdown target stops being routed
  # to). 30s preserves a small safety margin against that race
  # without trading observable deploy speed; revisit only if
  # health-check tuning changes.
  connection_termination = true

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-tg-https"
    Component = "compute"
    Cell      = var.cell_id
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Attach ASG to HTTPS Target Group
resource "aws_autoscaling_attachment" "https" {
  count = var.enable_qurl_resolve_endpoint ? 1 : 0

  autoscaling_group_name = aws_autoscaling_group.server.name
  lb_target_group_arn    = aws_lb_target_group.https[0].arn
}

# TLS Listener (terminates TLS, forwards to TCP target group).
#
# This listener used to sit on 443. It now sits on `local.qurl_resolve_port`
# (8443) because an NLB permits exactly one listener per port and 443 is the
# public UDP client edge — see aws_lb_listener.udp above.
#
# Moving it is safe because nothing dials this listener directly: the only
# caller is the CloudFront distribution in front of resolve.qurl.link, which
# reaches it via resolve-origin.<domain> with a matching custom origin port.
# The precondition below refuses the CloudFront-less shape, where a browser
# WOULD dial the NLB directly and find nothing on 443. TLS is unaffected — the
# ACM cert is bound to the hostname, not the port.
resource "aws_lb_listener" "https" {
  count = var.enable_qurl_resolve_endpoint ? 1 : 0

  # aws_lb.server retains its indexed state address and is always present.
  load_balancer_arn = aws_lb.server[0].arn
  port              = local.qurl_resolve_port
  protocol          = "TLS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.qurl_resolve_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.https[0].arn
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-listener-https"
    Component = "compute"
    Cell      = var.cell_id
  })

  lifecycle {
    precondition {
      condition     = var.qurl_resolve_via_cloudfront
      error_message = "enable_qurl_resolve_endpoint requires qurl_resolve_via_cloudfront: the resolve TLS listener moved off 443 (now the public UDP client edge) to ${local.qurl_resolve_port}, and only CloudFront can be pointed at a non-443 origin port. Serving resolve.<domain> straight off the NLB would need a browser to dial :${local.qurl_resolve_port}."
    }
    precondition {
      condition     = var.qurl_resolve_certificate_arn != null
      error_message = "qurl_resolve_certificate_arn is required when enable_qurl_resolve_endpoint is true."
    }
    # Same blue/green traffic-switch concern as the UDP listener above —
    # blue-green-switch.sh flips `default_action.target_group_arn` on
    # every traffic switch, and we do not want `terraform apply` to
    # revert it.
    ignore_changes = [default_action]
  }
}

# =============================================================================
# ASG Lifecycle Hook for Server Termination Cleanup
# =============================================================================
# When an NHP Server terminates, this lifecycle hook pauses termination and
# triggers a Lambda function that cleans up DynamoDB assignments pointing to
# the terminating server. This provides immediate cleanup instead of waiting
# for Console health monitor.
#
# Flow:
# 1. ASG initiates instance termination
# 2. Lifecycle hook pauses termination, sends event to EventBridge
# 3. EventBridge triggers Lambda function
# 4. Lambda queries server-ac-index, updates/deletes assignments
# 5. Lambda completes lifecycle action
# 6. Instance terminates
# =============================================================================

# Lifecycle Hook - pauses termination to allow cleanup
resource "aws_autoscaling_lifecycle_hook" "termination" {
  count = var.enable_termination_cleanup ? 1 : 0

  name                   = "${var.name_prefix}-termination-hook"
  autoscaling_group_name = aws_autoscaling_group.server.name
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_TERMINATING"
  default_result         = "CONTINUE" # Allow termination even if Lambda fails
  heartbeat_timeout      = 300        # 5 minutes max for cleanup

  # Note: We don't specify notification_target_arn here because we use
  # EventBridge to capture the lifecycle event instead of SNS
}

# EventBridge Rule - captures lifecycle hook events
resource "aws_cloudwatch_event_rule" "termination" {
  count = var.enable_termination_cleanup ? 1 : 0

  name        = "${var.name_prefix}-server-termination"
  description = "Captures NHP Server termination lifecycle events"

  event_pattern = jsonencode({
    source      = ["aws.autoscaling"]
    detail-type = ["EC2 Instance-terminate Lifecycle Action"]
    detail = {
      AutoScalingGroupName = [aws_autoscaling_group.server.name]
    }
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-termination-rule"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# EventBridge Target - triggers Lambda on lifecycle events
resource "aws_cloudwatch_event_target" "termination" {
  count = var.enable_termination_cleanup ? 1 : 0

  rule      = aws_cloudwatch_event_rule.termination[0].name
  target_id = "server-termination-cleanup"
  arn       = aws_lambda_function.termination_cleanup[0].arn
}

# Lambda Permission - allows EventBridge to invoke Lambda
resource "aws_lambda_permission" "termination" {
  count = var.enable_termination_cleanup ? 1 : 0

  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.termination_cleanup[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.termination[0].arn
}

# Lambda Function - performs DynamoDB cleanup
data "archive_file" "termination_cleanup" {
  count = var.enable_termination_cleanup ? 1 : 0

  type        = "zip"
  source_file = "${path.module}/lambda/server_termination_cleanup.py"
  output_path = "${path.module}/lambda/server_termination_cleanup.zip"
}

resource "aws_lambda_function" "termination_cleanup" {
  count = var.enable_termination_cleanup ? 1 : 0

  # Ensure log group is created first with KMS encryption and retention settings
  # Without this, Lambda auto-creates a log group without encryption
  depends_on = [aws_cloudwatch_log_group.termination_cleanup]

  filename         = data.archive_file.termination_cleanup[0].output_path
  function_name    = "${var.name_prefix}-server-termination-cleanup"
  role             = aws_iam_role.termination_cleanup[0].arn
  handler          = "server_termination_cleanup.handler"
  source_code_hash = data.archive_file.termination_cleanup[0].output_base64sha256
  runtime          = "python3.11"
  timeout          = 120 # 2 minutes; heartbeat_timeout is 300s
  memory_size      = 256

  environment {
    variables = {
      AC_ASSIGNMENTS_TABLE  = var.dynamodb_ac_assignments_table
      SERVER_AC_INDEX_TABLE = var.dynamodb_server_ac_index_table
    }
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-termination-cleanup"
    Component = "compute"
    Cell      = var.cell_id
  })

  lifecycle {
    precondition {
      condition     = var.dynamodb_server_ac_index_table != null
      error_message = "dynamodb_server_ac_index_table is required when enable_termination_cleanup is true."
    }
    precondition {
      condition     = var.dynamodb_ac_assignments_table != null
      error_message = "dynamodb_ac_assignments_table is required when enable_termination_cleanup is true."
    }
    precondition {
      condition     = var.dynamodb_ac_assignments_arn != null
      error_message = "dynamodb_ac_assignments_arn is required when enable_termination_cleanup is true."
    }
    precondition {
      condition     = var.dynamodb_server_ac_index_arn != null
      error_message = "dynamodb_server_ac_index_arn is required when enable_termination_cleanup is true."
    }
  }
}

# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "termination_cleanup" {
  count = var.enable_termination_cleanup ? 1 : 0

  name              = "/aws/lambda/${var.name_prefix}-server-termination-cleanup"
  retention_in_days = local.is_prod ? 90 : 14
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-termination-cleanup-logs"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# IAM Role for Lambda
resource "aws_iam_role" "termination_cleanup" {
  count = var.enable_termination_cleanup ? 1 : 0

  name = "${var.name_prefix}-termination-cleanup"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })

  tags = var.tags
}

# IAM Policy for Lambda - DynamoDB access (includes KMS for encrypted tables)
resource "aws_iam_role_policy" "termination_cleanup_dynamodb" {
  count = var.enable_termination_cleanup ? 1 : 0

  name = "dynamodb-access"
  role = aws_iam_role.termination_cleanup[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid    = "DynamoDBAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:BatchWriteItem"
        ]
        Resource = compact([
          var.dynamodb_ac_assignments_arn,
          var.dynamodb_server_ac_index_arn
        ])
      }
      ], var.secrets_kms_key_arn != null ? [{
        Sid    = "KMSAccess"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey"
        ]
        Resource = [var.secrets_kms_key_arn]
    }] : [])
  })
}

# IAM Policy for Lambda - ASG lifecycle completion
resource "aws_iam_role_policy" "termination_cleanup_asg" {
  count = var.enable_termination_cleanup ? 1 : 0

  name = "asg-lifecycle"
  role = aws_iam_role.termination_cleanup[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "CompleteLifecycleAction"
        Effect   = "Allow"
        Action   = ["autoscaling:CompleteLifecycleAction"]
        Resource = aws_autoscaling_group.server.arn
      }
    ]
  })
}

# IAM Policy for Lambda - CloudWatch Logs
resource "aws_iam_role_policy_attachment" "termination_cleanup_logs" {
  count = var.enable_termination_cleanup ? 1 : 0

  role       = aws_iam_role.termination_cleanup[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# CloudWatch Alarm for Lambda errors
# Alerts when termination cleanup Lambda fails, which could indicate stale assignments not being cleaned
resource "aws_cloudwatch_metric_alarm" "termination_cleanup_errors" {
  count = var.enable_termination_cleanup && var.enable_sns_alerts ? 1 : 0

  alarm_name          = "${var.name_prefix}-termination-cleanup-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300 # 5 minutes
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Termination cleanup Lambda errors - stale AC assignments may not be cleaned"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.termination_cleanup[0].function_name
  }

  alarm_actions = [var.alerts_sns_topic_arn]
  ok_actions    = [var.alerts_sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-termination-cleanup-errors"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# ============================================================================
# Bootstrap-deadlock invariant assertion
#
# The full deadlock-avoidance chain is documented at
# aws_autoscaling_group.server above (search "Bootstrap deadlock avoidance").
# Three conditions must all hold:
#   1. Both ASGs use health_check_type = "EC2" (NOT ELB).
#   2. The HTTPS target groups can use the strict /health/knock-ready path
#      because (1) means failing it doesn't trigger termination.
#   3. The server has an HTTP forwarder fallback that routes knocks to a
#      peer when the local AC peer count is zero.
#
# This check fires at plan time if anyone changes either ASG to ELB-based
# health checks. It is a non-blocking warning (Terraform `check` blocks
# emit ::warning::, not ::error::) — sufficient because anyone running
# `terraform plan` against this module will see the warning in CI output
# and on the PR. The first two conditions are easy to assert from
# Terraform; condition (3) is server-side Go code and is asserted in the
# server's own test suite.
# ============================================================================
check "asg_ec2_health_check_invariant" {
  assert {
    condition     = aws_autoscaling_group.server.health_check_type == "EC2"
    error_message = "BOOTSTRAP DEADLOCK RISK: aws_autoscaling_group.server.health_check_type must remain \"EC2\". Changing to ELB-based reintroduces the bootstrap deadlock documented at aws_autoscaling_group.server (search \"Bootstrap deadlock avoidance\"). If you genuinely need ELB health checks, update the documentation chain in main.tf and blue_green.tf, remove this check, AND verify the HTTP-forwarder fallback in the server still handles zero-AC-peers bootstrap correctly."
  }

  assert {
    # The conditional handles count=0 when blue/green is disabled — without
    # the guard the index lookup fails before the check runs.
    condition     = !var.enable_blue_green || (length(aws_autoscaling_group.server_green) > 0 && aws_autoscaling_group.server_green[0].health_check_type == "EC2")
    error_message = "BOOTSTRAP DEADLOCK RISK: aws_autoscaling_group.server_green.health_check_type must remain \"EC2\" when blue/green is enabled. Same reasoning as the blue ASG above; see aws_autoscaling_group.server in main.tf."
  }
}

# ============================================================================
# Blue/green HTTPS target group health-check drift detection
#
# The blue HTTPS target group (aws_lb_target_group.https in main.tf) and the
# green HTTPS target group (aws_lb_target_group.https_green in blue_green.tf)
# MUST have identical health check configurations. They serve the same
# traffic from the same kind of instance — any divergence means a blue/green
# swap will behave differently than blue/blue, which defeats the purpose of
# blue/green deployments and is exactly the class of bug that's invisible
# until you actually swap.
#
# Round-2 review of #252 caught a manual drift here (the green target group
# was using /health/live while blue used /health/knock-ready). Round-5 review
# asked for automated drift detection so the comment-only "keep these in
# sync" reminder doesn't decay into a lie.
#
# This check fires at plan time if any field of the two health check blocks
# diverges. Non-blocking warning (Terraform `check` blocks emit ::warning::,
# not ::error::) — sufficient because anyone running `terraform plan` will
# see the warning in CI output. To resolve the warning intentionally,
# update both blocks together AND keep the documentation cross-reference at
# blue_green.tf::https_green in sync.
# ============================================================================
check "https_target_group_blue_green_drift" {
  # Both asserts in this block use the same short-circuit shape:
  # `!var.enable_blue_green || length(https) == 0 || length(https_green) == 0`.
  # Strictly, `https` (blue) is counted on `enable_qurl_resolve_endpoint`
  # alone, while `https_green` is counted on
  # `enable_blue_green && enable_qurl_resolve_endpoint` — so the
  # `length(https) == 0` term covers the qurl-endpoint-off case and the
  # `!var.enable_blue_green` term covers the green-disabled case. The
  # `!var.enable_qurl_resolve_endpoint` clause is therefore redundant
  # with `length(https) == 0` and omitted.
  # Asymmetric with `ac/main.tf::ac_tcp_target_group_drift` because
  # ac_tcp (blue) is unconditional — that block has one `length == 0`
  # term to compute's two.
  assert {
    condition = (
      !var.enable_blue_green ||
      length(aws_lb_target_group.https) == 0 ||
      length(aws_lb_target_group.https_green) == 0 ||
      (
        aws_lb_target_group.https[0].health_check[0].path == aws_lb_target_group.https_green[0].health_check[0].path &&
        aws_lb_target_group.https[0].health_check[0].port == aws_lb_target_group.https_green[0].health_check[0].port &&
        aws_lb_target_group.https[0].health_check[0].protocol == aws_lb_target_group.https_green[0].health_check[0].protocol &&
        aws_lb_target_group.https[0].health_check[0].matcher == aws_lb_target_group.https_green[0].health_check[0].matcher &&
        aws_lb_target_group.https[0].health_check[0].interval == aws_lb_target_group.https_green[0].health_check[0].interval &&
        aws_lb_target_group.https[0].health_check[0].healthy_threshold == aws_lb_target_group.https_green[0].health_check[0].healthy_threshold &&
        aws_lb_target_group.https[0].health_check[0].unhealthy_threshold == aws_lb_target_group.https_green[0].health_check[0].unhealthy_threshold
      )
    )
    error_message = "BLUE/GREEN HEALTH CHECK DRIFT: aws_lb_target_group.https.health_check (main.tf) and aws_lb_target_group.https_green.health_check (blue_green.tf) have diverged. Both target groups serve the same traffic and MUST have identical health check configurations or a blue/green swap will silently change health-check semantics. Diff the two health_check blocks and align them. If the divergence is intentional (e.g. green is being upgraded), update this check together with the change so the next reader knows it was deliberate."
  }

  # connection_termination + deregistration_delay value-anchor. The
  # 2026-05-22 sandbox incident (see the comment block on
  # aws_lb_target_group.https) hinges on connection_termination=true
  # on BOTH colors. An equality-only assert would let a future PR
  # flip both to `false` together (silent regression on every flip);
  # the absolute value-anchor below structurally prevents that —
  # both colors must be `true` AND `deregistration_delay` must stay
  # at 30s. To tune either, edit BOTH resources AND this assert in
  # the same PR.
  assert {
    condition = (
      !var.enable_blue_green ||
      length(aws_lb_target_group.https) == 0 ||
      length(aws_lb_target_group.https_green) == 0 ||
      (
        # connection_termination is explicitly set on both referenced target
        # groups; if a future refactor drops it, tobool(null) makes this
        # non-blocking check warn instead of silently weakening this
        # deregistration contract. CI's contract test is the hard gate.
        tobool(aws_lb_target_group.https[0].connection_termination) &&
        tobool(aws_lb_target_group.https_green[0].connection_termination) &&
        tonumber(aws_lb_target_group.https[0].deregistration_delay) == 30 &&
        tonumber(aws_lb_target_group.https_green[0].deregistration_delay) == 30
      )
    )
    error_message = "BLUE/GREEN DEREG SEMANTICS VALUE-ANCHOR: aws_lb_target_group.https.{connection_termination,deregistration_delay} (main.tf) and aws_lb_target_group.https_green.{connection_termination,deregistration_delay} (blue_green.tf) must satisfy connection_termination=true AND deregistration_delay=30 on BOTH colors. The 2026-05-22 'CF stalled on stranded green-server flow for 60s' incident regresses if either color drops connection_termination=true (silent failure mode); deregistration_delay=30 here is calibrated against the COMPUTE-side health-check-propagation window (interval=10 × unhealthy_threshold=2 = 20s). The sibling AC value-anchor at ac/main.tf::ac_tcp_target_group_drift also pins =30 but for a DIFFERENT reason (intentional decoupling from AC's interval=30 × unhealthy_threshold=3 = 90s window); don't pattern-match both pins as a parallel calibration. Edit both colors AND this assert in the same PR; the comment block at main.tf::aws_lb_target_group.https carries the full incident history."
  }
}
