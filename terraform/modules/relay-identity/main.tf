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
        Action   = ["ssm:PutParameter"]
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

data "archive_file" "keygen_lambda" {
  type        = "zip"
  output_path = "${path.module}/relay_keygen_lambda.zip"
  source_file = "${path.module}/lambda/relay_identity.js"
}

# Fresh environments create the Lambda trust policy, managed basic-execution
# attachment, and inline Secrets Manager/SSM/KMS policy in the same apply that
# creates and invokes the function. AWS's authorization evaluator can lag those
# writes even after the IAM APIs return success. Key the established bounded
# wait on every load-bearing policy surface so a policy/trust edit re-arms it;
# existing environments pay no recurring delay while greenfield prod cannot
# intermittently fail its first identity bootstrap with AccessDenied.
resource "time_sleep" "keygen_iam_propagation" {
  triggers = {
    role_arn                   = aws_iam_role.keygen_lambda.arn
    assume_role_policy_hash    = sha256(aws_iam_role.keygen_lambda.assume_role_policy)
    secrets_policy_hash        = sha256(aws_iam_role_policy.keygen_lambda_secrets.policy)
    basic_policy_attachment_id = aws_iam_role_policy_attachment.keygen_lambda_basic.id
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
  # response so migration failures surface here, before the ordered SSM read.
  lifecycle {
    postcondition {
      condition = (
        try(jsondecode(self.result).action, "") == "publish-current" &&
        try(jsondecode(self.result).currentVersionId, "") != "" &&
        try(jsondecode(self.result).currentPublicKey, "") != ""
      )
      error_message = "Relay public-key publication did not return a valid success result."
    }
  }
}

data "aws_ssm_parameter" "relay_public_key" {
  name       = aws_ssm_parameter.relay_public_key.name
  depends_on = [aws_lambda_invocation.publish_public_key]

  lifecycle {
    postcondition {
      # Fail at the identity boundary instead of surfacing the bootstrap seed
      # later as a compute-module validation error. The explicit depends_on is
      # still load-bearing for greenfield ordering; this makes its outcome
      # independently fail closed if that edge is ever weakened or bypassed.
      condition = can(base64decode(self.value)) ? (
        length(base64decode(self.value)) == 32 &&
        base64encode(base64decode(self.value)) == self.value
      ) : false
      error_message = "Published relay identity must be a canonical Base64 encoding of exactly 32 public-key bytes; refusing a placeholder or malformed SSM value."
    }
  }
}
