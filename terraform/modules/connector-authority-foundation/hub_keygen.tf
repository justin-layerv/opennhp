# Connector Hub identity seeder (Step 5, slice 5b). A single-shot Lambda
# generates the Hub's long-lived X25519 private key and cookie keys, writes the
# private material into the pre-created Secrets Manager secret, and publishes
# ONLY the derived public identity to an exact SSM String parameter. No private
# or cookie key byte transits Terraform: the invocation returns only a
# {"seeded": true} marker because aws_lambda_invocation records the return value
# in state; the public identity is intentionally visible after refresh.
#
# DARK-FIRST: gated on local.hub_worker_count identically to the worker. Non-VPC
# (the seeder needs only the Secrets Manager and KMS control-plane APIs over the
# AWS network, not the isolated data-plane endpoints), nodejs22.x, zip-packaged.

locals {
  hub_keygen_function_name  = "${local.name_prefix}-hub-keygen"
  hub_keygen_log_group_name = "/aws/lambda/${local.hub_keygen_function_name}"
  # Constructed, plan-known own-log-group ARN (same pattern as
  # local.authority_runtime_log_group_arn): referencing the not-yet-created
  # aws_cloudwatch_log_group.hub_keygen[*].arn would leave the seeder's inline
  # policy unknown at plan and un-checkable. The group is created in this same
  # file and gated identically, so the literal is exact.
  hub_keygen_log_group_arn = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:${local.hub_keygen_log_group_name}"
  # SSM parameter ARNs are deterministic (unlike Secrets Manager's random ARN
  # suffix). Construct this from the same canonical path so the keygen IAM
  # policy is plan-known and the fail-closed migration checker can prove it
  # before the parameter exists.
  hub_public_key_parameter_arn = "arn:${data.aws_partition.current.partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter${local.hub_public_key_parameter_name}"
}

# Least-privilege seeder identity. Describe/Get are required only for
# idempotent repair after a partial first invocation: an existing AWSCURRENT is
# validated and reused, never overwritten. The role can mutate only that exact
# secret and the exact public-only parameter.
resource "aws_iam_role" "hub_keygen" {
  count = local.hub_worker_count

  name                 = "${local.name_prefix}-hub-keygen"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "LambdaAssume"
      Effect = "Allow"
      Principal = {
        Service = "lambda.${data.aws_partition.current.dns_suffix}"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-hub-keygen"
    Component = "connector-hub"
  })
}

resource "aws_iam_role_policy" "hub_keygen" {
  count = local.hub_worker_count

  name = "hub-keygen"
  role = aws_iam_role.hub_keygen[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SeedHubKeyMaterial"
        Effect = "Allow"
        Action = [
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
        ]
        Resource = aws_secretsmanager_secret.hub_key_material[0].arn
      },
      {
        Sid    = "PublishHubPublicIdentity"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:PutParameter",
        ]
        Resource = local.hub_public_key_parameter_arn
      },
      {
        Sid      = "WrapHubKeyMaterial"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = aws_kms_key.authority_data.arn
        Condition = {
          StringEquals = {
            "kms:ViaService"                  = "secretsmanager.${data.aws_region.current.region}.${data.aws_partition.current.dns_suffix}"
            "kms:EncryptionContext:SecretARN" = aws_secretsmanager_secret.hub_key_material[0].arn
          }
        }
      },
      {
        Sid    = "OwnLogStream"
        Effect = "Allow"
        Action = ["logs:CreateLogStream", "logs:PutLogEvents"]
        # Constructed ARN (not aws_cloudwatch_log_group.hub_keygen[*].arn) so the
        # whole policy is plan-known and checkable; the group is gated identically.
        Resource = "${local.hub_keygen_log_group_arn}:*"
      },
    ]
  })
}

# Default (AWS-managed) encryption, matching the other Lambda log groups in this
# module; the seeder logs no key material.
resource "aws_cloudwatch_log_group" "hub_keygen" {
  count = local.hub_worker_count

  name              = local.hub_keygen_log_group_name
  retention_in_days = local.hub_log_retention_days

  tags = merge(local.common_tags, {
    Name      = local.hub_keygen_log_group_name
    Component = "connector-hub"
  })
}

# The handler source is zipped in-place at plan time. source_code_hash pins the
# function to the exact bytes so an edit to keygen.js redeploys it.
data "archive_file" "hub_keygen" {
  count = local.hub_worker_count

  type        = "zip"
  source_file = "${path.module}/lambda/hub-keygen/keygen.js"
  output_path = "${path.module}/lambda/hub-keygen.zip"
}

resource "aws_lambda_function" "hub_keygen" {
  count = local.hub_worker_count

  function_name = local.hub_keygen_function_name
  description   = "Seeds or repairs the Connector Hub identity and publishes its public key at worker create (${var.environment})"
  role          = aws_iam_role.hub_keygen[0].arn
  runtime       = "nodejs22.x"
  handler       = "keygen.handler"
  timeout       = 30
  # Serializes Terraform/provider retries. The handler also reads and validates
  # AWSCURRENT before any write, so a partial first invocation repairs the
  # public parameter without rotating or overwriting the private identity.
  reserved_concurrent_executions = 1

  filename         = data.archive_file.hub_keygen[0].output_path
  source_code_hash = data.archive_file.hub_keygen[0].output_base64sha256

  environment {
    variables = {
      ENVIRONMENT          = var.environment
      PUBLIC_KEY_PARAMETER = aws_ssm_parameter.hub_public_key[0].name
      SECRET_ID            = aws_secretsmanager_secret.hub_key_material[0].arn
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.hub_keygen,
    aws_iam_role_policy.hub_keygen,
  ]

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-hub-keygen"
    Component = "connector-hub"
  })
}

# Public-only Hub trust root. Terraform owns the stable name and a deliberately
# invalid placeholder; the CREATE_ONLY seeder conditionally replaces only that
# placeholder, then reads back the exact canonical padded-base64 X25519 key.
# A pre-existing third value is a terminal conflict, never blindly overwritten.
resource "aws_ssm_parameter" "hub_public_key" {
  count = local.hub_worker_count

  name        = local.hub_public_key_parameter_name
  description = "Connector Hub X25519 public identity; private key remains in Secrets Manager"
  type        = "String"
  value       = "pending-keygen"

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-hub-public-key"
    Component = "connector-hub"
    Purpose   = "Connector Hub public identity"
  })

  lifecycle {
    ignore_changes = [value]
  }
}

# Original one-time seed. Keep this resource's configuration byte-for-byte
# compatible with the already-applied worker slice: adding a trigger would force
# a destructive replacement, which the dark-plan gate correctly rejects. Fresh
# environments still invoke it once; the publication migration below waits for
# this invocation so the function's singleton concurrency cannot self-throttle.
resource "aws_lambda_invocation" "hub_keygen" {
  count = local.hub_worker_count

  function_name   = aws_lambda_function.hub_keygen[0].function_name
  input           = jsonencode({})
  lifecycle_scope = "CREATE_ONLY"

  depends_on = [
    aws_secretsmanager_secret.hub_key_material,
    aws_iam_role_policy.hub_keygen,
  ]
}

# Additive one-time migration for workers whose original seed invocation is
# already in state. A distinct address makes the live transition a pure create,
# preserving the no-unreviewed-destruction gate. It intentionally has no
# triggers: a future repair must add a separately reviewed migration invocation
# rather than silently replacing and re-running this identity transaction.
resource "aws_lambda_invocation" "hub_identity_publication" {
  count = local.hub_worker_count

  function_name   = aws_lambda_function.hub_keygen[0].function_name
  input           = jsonencode({})
  lifecycle_scope = "CREATE_ONLY"

  depends_on = [
    aws_lambda_invocation.hub_keygen,
    aws_secretsmanager_secret.hub_key_material,
    aws_ssm_parameter.hub_public_key,
    aws_iam_role_policy.hub_keygen,
  ]

  lifecycle {
    postcondition {
      # `self.result` is unresolvable while this invocation is still pending
      # creation: the instance collection is empty, so evaluating it raises
      # "Invalid index" rather than returning null, and `try` around only the
      # jsondecode does not catch that. A `-refresh-only` plan evaluates this
      # check against exactly that empty collection, so the error made the
      # workflow's sole sanctioned drift-normalization operation impossible to
      # run until after the very apply it gates.
      #
      # CORRECTION (#3513 claimed otherwise and was wrong): `can()` does NOT
      # rescue this. Verified by reproducing a `-refresh-only` plan against the
      # live sandbox Control root with the guard in place — it still fails with
      # the same "Invalid index". `can()` traps errors raised while EVALUATING
      # an expression; this one is raised earlier, resolving the `self`
      # reference against an empty instance collection, so nothing in the
      # expression body can intercept it. The guard is therefore inert and the
      # exact-constant assertion below is the only live part of this check.
      #
      # `-refresh-only` is separately broken against this module regardless:
      # hub_worker.tf's locals dereference
      # `local.authority_selected_alias_targets.hub` while it is null, failing
      # with "Attempt to get attribute from null value" at lines 39, 68 and 69.
      # Fixing refresh-only means fixing both, and neither is on the path the
      # ordinary refresh-enabled plan takes.
      condition     = !can(self.result) || try(jsondecode(self.result), null) == { seeded = true }
      error_message = "Hub keygen must return only the exact constant seeded marker."
    }
  }
}
