# Connector Hub key-material seeder (Step 5, slice 5b). A single-shot Lambda that
# generates the Hub's long-lived private key and cookie keys and writes them into
# the pre-created Secrets Manager secret EXACTLY ONCE at worker create. It exists
# so no key byte ever transits Terraform: the material is generated inside the
# Lambda and put straight into the secret, and the invocation returns only a
# {"seeded": true} marker (aws_lambda_invocation records the return value in
# state, so returning any key byte would leak it into tfstate).
#
# DARK-FIRST: gated on local.hub_worker_count identically to the worker. Non-VPC
# (the seeder needs only the Secrets Manager and KMS control-plane APIs over the
# AWS network, not the isolated data-plane endpoints), python3.13, zip-packaged.

locals {
  hub_keygen_function_name  = "${local.name_prefix}-hub-keygen"
  hub_keygen_log_group_name = "/aws/lambda/${local.hub_keygen_function_name}"
  # Constructed, plan-known own-log-group ARN (same pattern as
  # local.authority_runtime_log_group_arn): referencing the not-yet-created
  # aws_cloudwatch_log_group.hub_keygen[*].arn would leave the seeder's inline
  # policy unknown at plan and un-checkable. The group is created in this same
  # file and gated identically, so the literal is exact.
  hub_keygen_log_group_arn = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:${local.hub_keygen_log_group_name}"
}

# Least-privilege seeder identity: PutSecretValue on ONLY the Hub key secret,
# the GenerateDataKey/Decrypt needed to write a CMK-encrypted secret, and its own
# log stream. It deliberately has NO GetSecretValue -- the seeder writes, it never
# reads the material back.
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
        Sid      = "SeedHubKeyMaterial"
        Effect   = "Allow"
        Action   = "secretsmanager:PutSecretValue"
        Resource = aws_secretsmanager_secret.hub_key_material[0].arn
      },
      {
        Sid      = "WrapHubKeyMaterial"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = aws_kms_key.authority_data.arn
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
# function to the exact bytes so an edit to keygen.py redeploys it.
data "archive_file" "hub_keygen" {
  count = local.hub_worker_count

  type        = "zip"
  source_file = "${path.module}/lambda/hub-keygen/keygen.py"
  output_path = "${path.module}/lambda/hub-keygen.zip"
}

resource "aws_lambda_function" "hub_keygen" {
  count = local.hub_worker_count

  function_name = local.hub_keygen_function_name
  description   = "Seeds the Connector Hub key material secret once at worker create (${var.environment})"
  role          = aws_iam_role.hub_keygen[0].arn
  runtime       = "python3.13"
  handler       = "keygen.handler"
  timeout       = 30

  filename         = data.archive_file.hub_keygen[0].output_path
  source_code_hash = data.archive_file.hub_keygen[0].output_base64sha256

  environment {
    variables = {
      SECRET_ID = aws_secretsmanager_secret.hub_key_material[0].arn
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

# One-time seed. lifecycle_scope=CREATE_ONLY invokes exactly at create and never
# on update/destroy, so a routine apply cannot rotate the live keys out from
# under running workers. The ECS service depends on this so tasks never start
# against an unseeded secret.
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
