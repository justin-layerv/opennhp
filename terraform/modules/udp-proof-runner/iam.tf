resource "aws_iam_role_policy" "runner" {
  name = "udp-proof-runtime"
  role = aws_iam_role.runner.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadSerializedSandboxJITConfiguration"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DeleteSecret"]
        Resource = local.jit_secret_arn_pattern
        Condition = {
          StringEquals = {
            "secretsmanager:ResourceTag/Environment" = var.environment
            "secretsmanager:ResourceTag/Purpose"     = local.purpose
          }
        }
      },
      {
        Sid      = "DecryptOwnJITConfiguration"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = aws_kms_key.jit.arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = local.secrets_kms_via_service
          }
          ArnLike = {
            "kms:EncryptionContext:SecretARN" = local.jit_secret_arn_pattern
          }
        }
      },
      {
        Sid      = "DescribeProofKeys"
        Effect   = "Allow"
        Action   = "kms:DescribeKey"
        Resource = var.proof_kms_key_arns
      },
      {
        Sid      = "DecryptBoundConnectorState"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = var.proof_kms_key_arns
        Condition = {
          StringEquals = {
            "kms:EncryptionContext:purpose"  = "qurl-agent-x25519-private-key"
            "kms:EncryptionContext:provider" = ["aws-kms", "aws-nitro"]
          }
        }
      },
    ]
  })

  lifecycle {
    precondition {
      condition = alltrue([
        for arn in var.proof_kms_key_arns : startswith(arn, local.proof_kms_key_arn_prefix)
      ])
      error_message = "proof_kms_key_arns must belong to the current sandbox account, partition, and region."
    }
  }
}

resource "aws_iam_role" "controller" {
  name        = "${var.name_prefix}-udp-proof-controller"
  description = "Protected NHP GitHub environment controller for one ephemeral sandbox UDP proof runner"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "sts:AssumeRoleWithWebIdentity"
      Principal = {
        Federated = var.github_oidc_provider_arn
      }
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:${var.github_repository}:environment:${var.github_environment}"
        }
      }
    }]
  })

  max_session_duration = 3600
  tags                 = local.tags
}

resource "aws_iam_role_policy" "controller" {
  name = "udp-proof-control"
  role = aws_iam_role.controller.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "CreateOneTimeJITConfiguration"
        Effect   = "Allow"
        Action   = "secretsmanager:CreateSecret"
        Resource = local.jit_secret_arn_pattern
        Condition = {
          StringEquals = {
            "aws:RequestTag/Environment" = var.environment
            "aws:RequestTag/Purpose"     = local.purpose
            "secretsmanager:KmsKeyArn"   = aws_kms_key.jit.arn
          }
          "ForAllValues:StringEquals" = {
            "aws:TagKeys" = ["Environment", "Purpose", "GitHubRunId", "GitHubRunAttempt"]
          }
          Null = {
            "aws:RequestTag/GitHubRunId"      = "false"
            "aws:RequestTag/GitHubRunAttempt" = "false"
          }
        }
      },
      {
        # Secrets Manager performs an additional TagResource authorization
        # when CreateSecret includes tags. Keep it separate because the
        # CreateSecret-only KmsKeyArn condition is absent from TagResource.
        Sid      = "TagOneTimeJITConfiguration"
        Effect   = "Allow"
        Action   = "secretsmanager:TagResource"
        Resource = local.jit_secret_arn_pattern
        Condition = {
          StringEquals = {
            "aws:RequestTag/Environment" = var.environment
            "aws:RequestTag/Purpose"     = local.purpose
          }
          "ForAllValues:StringEquals" = {
            "aws:TagKeys" = ["Environment", "Purpose", "GitHubRunId", "GitHubRunAttempt"]
          }
          Null = {
            "aws:RequestTag/GitHubRunId"      = "false"
            "aws:RequestTag/GitHubRunAttempt" = "false"
          }
        }
      },
      {
        Sid      = "PrepareOneTimeJITEncryption"
        Effect   = "Allow"
        Action   = "kms:GenerateDataKey"
        Resource = aws_kms_key.jit.arn
        # Scope to Secrets-Manager-invoked calls only. Deliberately NOT
        # constrained by kms:EncryptionContext:SecretARN: during CreateSecret
        # the secret ARN is assigned *as part of* the create, so Secrets
        # Manager's GenerateDataKey encryption context does not yet carry
        # SecretARN (it only appears on Put/Get of an existing secret). An
        # ArnLike condition on that key is therefore unsatisfiable at create
        # time and denies the one-use secret's sole KMS operation. The
        # controller's secretsmanager:CreateSecret is already resource-scoped to
        # local.jit_secret_arn_pattern with required tags, and this is a
        # dedicated single-purpose CMK, so ViaService is the correct fence here.
        Condition = {
          StringEquals = {
            "kms:ViaService" = local.secrets_kms_via_service
          }
        }
      },
      {
        Sid      = "InvokeBoundedRunnerBroker"
        Effect   = "Allow"
        Action   = "lambda:InvokeFunction"
        Resource = aws_lambda_function.broker.arn
      },
    ]
  })
}

resource "aws_iam_role" "broker" {
  name        = "${var.name_prefix}-udp-proof-broker"
  description = "Launches and reaps only the exact Terraform-owned UDP proof runner"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = local.tags
}

resource "aws_iam_role_policy" "broker" {
  name = "udp-proof-broker"
  role = aws_iam_role.broker.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # AWS documents this pair of launch-template conditions as the control
        # that prevents callers from replacing resources embedded in the
        # reviewed template. The workflow cannot call RunInstances directly;
        # this is defense in depth around the fixed broker code.
        Sid      = "LaunchExactTemplate"
        Effect   = "Allow"
        Action   = "ec2:RunInstances"
        Resource = "*"
        Condition = {
          ArnEquals = {
            "ec2:LaunchTemplate" = aws_launch_template.runner.arn
          }
          Bool = {
            "ec2:IsLaunchTemplateResource" = "true"
          }
          StringEquals = {
            "ec2:Region" = data.aws_region.current.region
          }
        }
      },
      {
        Sid    = "TagOnlyNewRunnerResources"
        Effect = "Allow"
        Action = "ec2:CreateTags"
        Resource = [
          "${local.ec2_arn_prefix}instance/*",
          "${local.ec2_arn_prefix}volume/*",
        ]
        Condition = {
          StringEquals = {
            "ec2:CreateAction" = "RunInstances"
          }
        }
      },
      {
        Sid      = "TerminateOnlyProofRunners"
        Effect   = "Allow"
        Action   = "ec2:TerminateInstances"
        Resource = "${local.ec2_arn_prefix}instance/*"
        Condition = {
          StringEquals = {
            "ec2:ResourceTag/Component"   = local.component
            "ec2:ResourceTag/Environment" = var.environment
            "ec2:ResourceTag/Purpose"     = local.purpose
          }
        }
      },
      {
        # AssociateAddress does not support resource-level permissions. The
        # broker code supplies only the Terraform-owned allocation ID and sets
        # AllowReassociation=false, while the controller cannot call EC2.
        Sid      = "AttachDedicatedSourceAddress"
        Effect   = "Allow"
        Action   = "ec2:AssociateAddress"
        Resource = "*"
        Condition = {
          StringEquals = {
            "ec2:Region" = data.aws_region.current.region
          }
        }
      },
      {
        Sid    = "DiscoverProofRunnerState"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeAddresses",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "ec2:Region" = data.aws_region.current.region
          }
        }
      },
      {
        Sid      = "PassOnlyProofRunnerRole"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = aws_iam_role.runner.arn
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "ec2.amazonaws.com"
          }
        }
      },
      {
        Sid      = "InspectJITSecretMetadata"
        Effect   = "Allow"
        Action   = "secretsmanager:DescribeSecret"
        Resource = local.jit_secret_arn_pattern
      },
      {
        Sid      = "DeleteExpiredJITSecrets"
        Effect   = "Allow"
        Action   = "secretsmanager:DeleteSecret"
        Resource = local.jit_secret_arn_pattern
        Condition = {
          StringEquals = {
            "secretsmanager:ResourceTag/Environment" = var.environment
            "secretsmanager:ResourceTag/Purpose"     = local.purpose
          }
        }
      },
      {
        # ListSecrets returns metadata, not SecretString. The broker filters by
        # the exact module prefix and cannot GetSecretValue.
        Sid      = "FindOrphanedJITSecretMetadata"
        Effect   = "Allow"
        Action   = "secretsmanager:ListSecrets"
        Resource = "*"
      },
      {
        Sid      = "WriteOwnLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.broker.arn}:*"
      },
    ]
  })
}
