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

  # NO postcondition on `self.result`, deliberately, and it must not be
  # reintroduced in that form.
  #
  # It asserted the invocation returned exactly {seeded = true}. But
  # `self.result` is unresolvable while this CREATE_ONLY invocation is still
  # pending: the instance collection is empty, so the reference raises "Invalid
  # index" during REFERENCE RESOLUTION -- earlier than expression evaluation,
  # which is why neither `try()` nor `can()` intercepts it. #3513 tried `can()`
  # and it was verified inert by reproducing a refresh-only plan against live
  # sandbox Control with the guard in place.
  #
  # That made `terraform plan -refresh-only` impossible against this module, and
  # the APPLY LANE REQUIRES IT: control-sandbox-update.yml re-proves the live
  # refresh drift observation with a refresh-only plan immediately before
  # applying (the "Re-prove exact live refresh observation before apply" step).
  # So this check blocked the very apply that would have created the instance it
  # wanted to inspect -- it could never once have run successfully.
  #
  # The seeded outcome is still proved, downstream and against REALITY rather
  # than a plan value:
  #   * the verify lane reads /sandbox/nhp/control/hub/identity/public-key;
  #   * the deployment-manifest producer rejects anything that is not a
  #     canonical 32-byte public key, failing closed on the `pending-keygen`
  #     sentinel (udp_proof_deployment_contract.py decode_public_key);
  #   * the keygen Lambda writes only while the parameter still holds that
  #     sentinel, so the identity transaction is single-shot and idempotent.
}
