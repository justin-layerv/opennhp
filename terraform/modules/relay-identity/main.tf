# Stable relay identity control plane. Fleet modules consume the private-key
# secret; servers receive only the public-key output. Keeping this module outside
# either relay fleet lets legacy and DMZ fleets overlap without co-owning or
# rotating the Noise IK identity.

locals {
  is_prod = var.environment == "prod"
  tags = merge(var.tags, {
    Environment = var.environment
    # Preserve the pre-move resource tags exactly. Ownership changes in state;
    # remote tag drift is not part of this no-traffic prerequisite.
    Component = "relay"
  })
}

resource "aws_iam_role" "keygen_lambda" {
  name = "${var.name_prefix}-relay-keygen-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "keygen_lambda_basic" {
  role       = aws_iam_role.keygen_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# PR plans may invoke only this application-state-read-only function. Keeping
# it on a distinct execution role and handler prevents an untrusted PR payload
# from selecting the keygen Lambda's ensure/publish/stage mutation actions.
resource "aws_iam_role" "status_lambda" {
  name = "${var.name_prefix}-relay-status-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = local.tags
}

resource "aws_cloudwatch_log_group" "status" {
  name              = "/aws/lambda/${var.name_prefix}-relay-status"
  retention_in_days = 30
  tags              = local.tags
}

resource "aws_iam_role_policy" "status_lambda_access" {
  name = "identity-read-and-logs"
  role = aws_iam_role.status_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"]
        Resource = [aws_secretsmanager_secret.relay.arn]
      },
      {
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = [aws_ssm_parameter.relay_public_key.arn]
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = ["${aws_cloudwatch_log_group.status.arn}:*"]
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

resource "aws_iam_role_policy" "keygen_lambda_secrets" {
  name = "secrets-access"
  role = aws_iam_role.keygen_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue"]
        Resource = [aws_secretsmanager_secret.relay.arn]
      },
      {
        Effect   = "Allow"
        Action   = ["ssm:GetParameter", "ssm:PutParameter"]
        Resource = [aws_ssm_parameter.relay_public_key.arn]
      }
      ],
      var.secrets_kms_key_arn != null ? [
        {
          Effect   = "Allow"
          Action   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"]
          Resource = [var.secrets_kms_key_arn]
        }
    ] : [])
  })
}

# Historical Terraform address retained to avoid needless state churn. The
# single artifact intentionally backs both isolated handlers so validation and
# public-key derivation cannot drift between keygen and status functions.
data "archive_file" "keygen_lambda" {
  type        = "zip"
  output_path = "${path.module}/relay_keygen_lambda.zip"
  source_file = "${path.module}/lambda/relay_identity.js"
}

# Fresh environments create both Lambda trust policies, their keygen/status
# access policies, and the keygen basic-execution attachment in the same apply
# that creates and invokes the functions. AWS's authorization evaluator can lag
# those writes even after the IAM APIs return success. Key the established
# bounded wait on every load-bearing policy surface so a policy/trust edit
# re-arms it; existing environments pay no recurring delay while greenfield
# prod cannot intermittently fail its first identity bootstrap with
# AccessDenied.
resource "time_sleep" "keygen_iam_propagation" {
  triggers = {
    keygen_role_arn                   = aws_iam_role.keygen_lambda.arn
    keygen_assume_role_policy_hash    = sha256(aws_iam_role.keygen_lambda.assume_role_policy)
    keygen_secrets_policy_hash        = sha256(aws_iam_role_policy.keygen_lambda_secrets.policy)
    keygen_basic_policy_attachment_id = aws_iam_role_policy_attachment.keygen_lambda_basic.id
    status_role_arn                   = aws_iam_role.status_lambda.arn
    status_assume_role_policy_hash    = sha256(aws_iam_role.status_lambda.assume_role_policy)
    status_access_policy_hash         = sha256(aws_iam_role_policy.status_lambda_access.policy)
  }

  create_duration = var.iam_propagation_duration
}

resource "aws_lambda_function" "keygen" {
  function_name = "${var.name_prefix}-relay-keygen"
  role          = aws_iam_role.keygen_lambda.arn
  handler       = "relay_identity.handler"
  runtime       = "nodejs22.x"
  timeout       = 30

  # Serializes every identity invocation. In particular, two stage-pending
  # requests cannot race to create competing AWSPENDING versions; read-only
  # status and sync-current calls can also be throttled behind an in-flight
  # invocation. This singleton uses one reserved slot; the rollout preflight
  # verifies the account retains Lambda's required unreserved-concurrency floor
  # before this new reservation is applied.
  reserved_concurrent_executions = 1

  filename         = data.archive_file.keygen_lambda.output_path
  source_code_hash = data.archive_file.keygen_lambda.output_base64sha256

  tags = local.tags

  depends_on = [time_sleep.keygen_iam_propagation]
}

resource "aws_lambda_function" "status" {
  function_name = "${var.name_prefix}-relay-status"
  role          = aws_iam_role.status_lambda.arn
  handler       = "relay_identity.statusHandler"
  runtime       = "nodejs22.x"
  timeout       = 30

  # Intentionally use the account's bounded unreserved pool: concurrent PR
  # plans must not contend with the keygen singleton or a tiny status-specific
  # reservation. The handler is application-state-read-only and IAM-scoped.

  filename         = data.archive_file.keygen_lambda.output_path
  source_code_hash = data.archive_file.keygen_lambda.output_base64sha256

  tags = local.tags

  depends_on = [time_sleep.keygen_iam_propagation]
}

resource "aws_secretsmanager_secret" "relay" {
  name                    = "${var.name_prefix}-relay"
  description             = "NHP Relay fleet private key (one keypair per env; #2208)"
  recovery_window_in_days = local.is_prod ? 30 : 0
  kms_key_id              = var.secrets_kms_key_arn

  tags = merge(local.tags, { Name = "${var.name_prefix}-relay-secret" })
}

# Public-only copy of the current relay identity. Terraform and nhp-server read
# this value instead of materializing the private-key secret in state or granting
# the server role GetSecretValue. The Lambda seeds/synchronizes it; Terraform owns
# the stable name and ignores the rotation-managed value.
resource "aws_ssm_parameter" "relay_public_key" {
  name        = "/${var.environment}/nhp/relay/identity/current-public-key"
  description = "Current NHP relay X25519 public identity (private key remains in Secrets Manager)"
  type        = "String"
  value       = "pending-keygen"

  tags = merge(local.tags, { Name = "${var.name_prefix}-relay-public-key" })

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_lambda_invocation" "keygen" {
  function_name = aws_lambda_function.keygen.function_name

  input = jsonencode({
    Action = "ensure-current"
    ResourceProperties = {
      SecretId           = aws_secretsmanager_secret.relay.id
      Environment        = var.environment
      PublicKeyParameter = aws_ssm_parameter.relay_public_key.name
    }
  })

  depends_on = [aws_iam_role_policy.keygen_lambda_secrets]

  lifecycle {
    # Load-bearing migration fence: the moved historical object stored a
    # RequestType input that the new Action-only Lambda would reject. Never
    # remove this without retiring the moved invocation in #3145 first.
    ignore_changes = [input]
  }
}

# `keygen` exists only to preserve the historical invocation's Terraform state
# identity; ignore_changes prevents that moved object from re-running. This new
# invocation is the migration action that publishes the current public key into
# the public-only parameter after the identity/IAM move, without exposing the
# secret to Terraform. Both run on greenfield: ensure-current idempotently owns
# only AWSCURRENT creation, then this sole parameter writer runs after it.
# Neither invocation tracks Lambda code changes because function_name is stable;
# operators use the helper's `sync-current` subcommand (which invokes the
# Lambda's `publish-current` action) for an explicit validation/republish.
# `publish_public_key` intentionally has no ignore_changes: editing its input
# contract reruns the migration action, while a Lambda code-only edit does not.
resource "aws_lambda_invocation" "publish_public_key" {
  function_name = aws_lambda_function.keygen.function_name

  input = jsonencode({
    Action = "publish-current"
    ResourceProperties = {
      SecretId           = aws_secretsmanager_secret.relay.id
      Environment        = var.environment
      PublicKeyParameter = aws_ssm_parameter.relay_public_key.name
    }
  })

  depends_on = [
    aws_iam_role_policy.keygen_lambda_secrets,
    aws_lambda_invocation.keygen,
  ]

  # Some provider versions preserve a Lambda FunctionError payload in result
  # instead of failing the resource directly. Require our structured success
  # response and a canonical public key so migration failures surface here.
  # Consumers use this validated result rather than racing a second,
  # cross-principal Parameter Store read after the Lambda confirms publication.
  lifecycle {
    postcondition {
      condition = (
        try(jsondecode(self.result).action, "") == "publish-current" &&
        try(jsondecode(self.result).currentVersionId, "") != "" &&
        can(regex(
          "^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$",
          try(jsondecode(self.result).currentPublicKey, "")
        ))
      )
      error_message = "Relay public-key publication did not return a valid success result."
    }
  }
}

# Unlike the resource-form migration invocation above, this data source runs on
# refresh. It preserves rotation semantics by reading the live AWSCURRENT on
# every plan/apply, while the Lambda also proves that key matches the public-only
# SSM parameter. The ordinary status action remains mismatch-tolerant for
# rotation repair. This avoids both a historical resource-result snapshot and a
# cross-principal Parameter Store read in Terraform.
data "aws_lambda_invocation" "status" {
  function_name = aws_lambda_function.status.function_name
  # Pin the provider's default explicitly. Lambda authorizes qualified invokes
  # against the qualified ARN, so the PR-plan role grants this exact $LATEST
  # target rather than a wildcard across versions or aliases.
  qualifier = "$LATEST"

  input = jsonencode({
    Action = "confirmed-status"
    ResourceProperties = {
      SecretId           = aws_secretsmanager_secret.relay.id
      Environment        = var.environment
      PublicKeyParameter = aws_ssm_parameter.relay_public_key.name
    }
  })

  depends_on = [aws_lambda_invocation.publish_public_key]

  lifecycle {
    postcondition {
      condition = (
        try(jsondecode(self.result).action, "") == "confirmed-status" &&
        try(jsondecode(self.result).versions.AWSCURRENT.versionId, "") != "" &&
        can(regex(
          "^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$",
          try(jsondecode(self.result).versions.AWSCURRENT.publicKey, "")
        ))
      )
      error_message = "Relay identity status did not return a valid current public key."
    }
  }
}
