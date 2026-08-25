# Sandbox-only custody for the fixed qURL customer-journey identities.
#
# These resources do not create or select a fleet. The existing sandbox
# server/AC blue-green workflow remains the only deployment authority, and the
# existing single relay path remains the relay transport. This state is used by
# non-mutating customer journeys after the live runtime has been read back.

locals {
  sandbox_fixed_canary_enabled   = var.environment == "sandbox"
  sandbox_fixed_canary_partition = "aws"
  sandbox_fixed_canary_identities = local.sandbox_fixed_canary_enabled ? {
    for label in ["direct-a", "direct-b", "relay-c", "relay-d"] :
    "shared/${label}" => {
      label = label
    }
  } : {}
  sandbox_fixed_canary_name = "${local.name_prefix}-fixed-canary"
}

resource "aws_dynamodb_table" "sandbox_fixed_canary" {
  count = local.sandbox_fixed_canary_enabled ? 1 : 0

  name         = local.sandbox_fixed_canary_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "lock_id"

  attribute {
    name = "lock_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = module.kms.secrets_key_arn
  }

  tags = merge(local.common_tags, {
    Name      = local.sandbox_fixed_canary_name
    Component = "customer-journey"
    Purpose   = "fixed-canary-custody"
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_secretsmanager_secret" "sandbox_fixed_canary" {
  for_each = local.sandbox_fixed_canary_identities

  name                    = "${local.sandbox_fixed_canary_name}-shared-${each.value.label}"
  description             = "Fixed shared sandbox ${each.value.label} qURL AgentState custody"
  kms_key_id              = module.kms.secrets_key_arn
  recovery_window_in_days = 30

  tags = merge(local.common_tags, {
    Name      = "${local.sandbox_fixed_canary_name}-shared-${each.value.label}"
    Component = "customer-journey"
    Purpose   = "fixed-canary-state"
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role" "sandbox_fixed_canary" {
  count = local.sandbox_fixed_canary_enabled ? 1 : 0

  name                 = local.sandbox_fixed_canary_name
  description          = "Protected sandbox qURL fixed-canary custody"
  max_session_duration = 7200
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = module.ecr.github_oidc_provider_arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:environment:sandbox"
        }
      }
    }]
  })

  tags = merge(local.common_tags, {
    Name      = local.sandbox_fixed_canary_name
    Component = "customer-journey"
    Purpose   = "fixed-canary-custody"
  })
}

resource "aws_iam_role_policy" "sandbox_fixed_canary" {
  count = local.sandbox_fixed_canary_enabled ? 1 : 0

  name = "fixed-canary-custody"
  role = aws_iam_role.sandbox_fixed_canary[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ExactCanaryStateCAS"
        Effect = "Allow"
        Action = [
          "dynamodb:DeleteItem",
          "dynamodb:GetItem",
          "dynamodb:PutItem",
        ]
        Resource = aws_dynamodb_table.sandbox_fixed_canary[0].arn
      },
      {
        Sid    = "ExactCanarySecretVersions"
        Effect = "Allow"
        Action = [
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
        ]
        Resource = values(aws_secretsmanager_secret.sandbox_fixed_canary)[*].arn
      },
      {
        Sid      = "ReadSandboxSmokeM2MCredential"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = "arn:${local.sandbox_fixed_canary_partition}:secretsmanager:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:secret:${local.name_prefix}-auth0-smoke-test-credentials-*"
      },
      {
        Sid    = "ReadExactSandboxRuntimeParameters"
        Effect = "Allow"
        Action = ["ssm:GetParameter", "ssm:GetParameters"]
        Resource = [
          "arn:${local.sandbox_fixed_canary_partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter/sandbox/nhp/server/active-color",
          "arn:${local.sandbox_fixed_canary_partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter/sandbox/nhp/server/asg-name",
          "arn:${local.sandbox_fixed_canary_partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter/sandbox/nhp/server/green-asg-name",
          "arn:${local.sandbox_fixed_canary_partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter/sandbox/nhp/server/image-tag",
          "arn:${local.sandbox_fixed_canary_partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter/sandbox/nhp/server/green-image-tag",
          "arn:${local.sandbox_fixed_canary_partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter/sandbox/nhp/ac/active-color",
          "arn:${local.sandbox_fixed_canary_partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter/sandbox/nhp/ac/asg-name",
          "arn:${local.sandbox_fixed_canary_partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter/sandbox/nhp/ac/green-asg-name",
          "arn:${local.sandbox_fixed_canary_partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter/sandbox/nhp/ac/image-tag",
          "arn:${local.sandbox_fixed_canary_partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter/sandbox/nhp/ac/green-image-tag",
          "arn:${local.sandbox_fixed_canary_partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter/sandbox/nhp/relay/asg-name",
          "arn:${local.sandbox_fixed_canary_partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter/sandbox/nhp/relay/image-tag",
          "arn:${local.sandbox_fixed_canary_partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter/sandbox/nhp/control/hub/identity/public-key",
          "arn:${local.sandbox_fixed_canary_partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter/sandbox/nhp/qurl/qv2-issuer-key",
          "arn:${local.sandbox_fixed_canary_partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter/sandbox/nhp/customer-journey/fixed-canary-v1",
          "arn:${local.sandbox_fixed_canary_partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter/layerv-nhp-sandbox/qurl-ecs-cluster",
          "arn:${local.sandbox_fixed_canary_partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter/layerv-nhp-sandbox/qurl-ecs-service",
        ]
      },
      {
        Sid    = "ReadExactSandboxRuntimeTables"
        Effect = "Allow"
        Action = [
          "dynamodb:DescribeTable",
          "dynamodb:GetItem",
        ]
        Resource = [
          "arn:${local.sandbox_fixed_canary_partition}:dynamodb:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:table/layerv-nhp-sandbox-control-connector-authority",
          "arn:${local.sandbox_fixed_canary_partition}:dynamodb:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:table/layerv-nhp-sandbox-control-qurl-agent-keys",
          "arn:${local.sandbox_fixed_canary_partition}:dynamodb:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:table/layerv-nhp-sandbox-cell0-nhp-session-control",
        ]
      },
      {
        Sid      = "ReadSandboxFixedCanaryMemberships"
        Effect   = "Allow"
        Action   = ["dynamodb:Query"]
        Resource = "arn:${local.sandbox_fixed_canary_partition}:dynamodb:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:table/layerv-nhp-sandbox-cell0-nhp-session-control"
        Condition = {
          "ForAllValues:StringLike" = {
            "dynamodb:LeadingKeys" = ["AGENT#*"]
          }
        }
      },
      {
        Sid    = "ReadExactSandboxRuntimeFleets"
        Effect = "Allow"
        Action = [
          "autoscaling:DescribeAutoScalingGroups",
          "ec2:DescribeInstances",
          "ec2:DescribeLaunchTemplateVersions",
          "ecs:DescribeServices",
          "ecs:DescribeTaskDefinition",
          "ecs:DescribeTasks",
          "ecs:ListTasks",
        ]
        Resource = "*"
      },
      {
        Sid    = "ReadExactSandboxRuntimeImages"
        Effect = "Allow"
        Action = ["ecr:DescribeImages", "ecr:BatchGetImage"]
        Resource = [
          "arn:${local.sandbox_fixed_canary_partition}:ecr:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:repository/layerv/nhp-server",
          "arn:${local.sandbox_fixed_canary_partition}:ecr:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:repository/layerv/nhp-ac",
          "arn:${local.sandbox_fixed_canary_partition}:ecr:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:repository/layerv/nhp-relay",
          "arn:${local.sandbox_fixed_canary_partition}:ecr:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:repository/layerv/nhp-qurl",
        ]
      },
      {
        Sid      = "ReadExactQURLServiceOCIProvenance"
        Effect   = "Allow"
        Action   = ["ecr:GetDownloadUrlForLayer"]
        Resource = "arn:${local.sandbox_fixed_canary_partition}:ecr:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:repository/layerv/nhp-qurl"
      },
      {
        Sid      = "CanarySecretKMS"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]
        Resource = module.kms.secrets_key_arn
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id
            "kms:ViaService"    = "secretsmanager.${data.aws_region.current.region}.amazonaws.com"
          }
        }
      },
      {
        Sid    = "ReceiveExactOTPMailbox"
        Effect = "Allow"
        Action = [
          "sqs:ChangeMessageVisibility",
          "sqs:DeleteMessage",
          "sqs:ReceiveMessage",
        ]
        Resource = aws_sqs_queue.agent_otp_ci_mailbox[0].arn
      },
      {
        Sid      = "ReadExactOTPObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.agent_otp_ci_mailbox[0].arn}/${local.agent_otp_ci_mailbox_prefix}*"
      },
    ]
  })
}

resource "aws_ssm_parameter" "sandbox_fixed_canary" {
  count = local.sandbox_fixed_canary_enabled ? 1 : 0

  name        = "/sandbox/nhp/customer-journey/fixed-canary-v1"
  description = "Credential-free fixed-canary custody addresses for protected sandbox customer journeys"
  type        = "String"
  value = jsonencode({
    schema                = 1
    environment           = "sandbox"
    assignment_generation = 1
    authority_role_arn    = aws_iam_role.sandbox_fixed_canary[0].arn
    state_table           = aws_dynamodb_table.sandbox_fixed_canary[0].name
    auth0_secret_name     = "${local.name_prefix}-auth0-smoke-test-credentials"
    secret_map = {
      for key, secret in aws_secretsmanager_secret.sandbox_fixed_canary : key => secret.arn
    }
    otp_mailbox = {
      queue_url = aws_sqs_queue.agent_otp_ci_mailbox[0].url
      bucket    = aws_s3_bucket.agent_otp_ci_mailbox[0].id
      recipient = local.agent_otp_ci_mailbox_recipient
    }
  })

  tags = merge(local.common_tags, {
    Name      = "${local.sandbox_fixed_canary_name}-contract"
    Component = "customer-journey"
    Purpose   = "fixed-canary-custody"
  })
}

check "sandbox_fixed_canary_preconditions" {
  assert {
    condition = !local.sandbox_fixed_canary_enabled || (
      local.agent_otp_ci_mailbox_enabled &&
      length(aws_secretsmanager_secret.sandbox_fixed_canary) == 4
    )
    error_message = "The sandbox fixed-canary journey requires the OTP mailbox and exactly four encrypted state containers."
  }
}

output "sandbox_fixed_canary_role_arn" {
  description = "Protected sandbox fixed-canary role; null outside sandbox."
  value       = local.sandbox_fixed_canary_enabled ? aws_iam_role.sandbox_fixed_canary[0].arn : null
}

output "sandbox_fixed_canary_contract_parameter" {
  description = "Sandbox fixed-canary custody contract parameter; null outside sandbox."
  value       = local.sandbox_fixed_canary_enabled ? aws_ssm_parameter.sandbox_fixed_canary[0].name : null
}
