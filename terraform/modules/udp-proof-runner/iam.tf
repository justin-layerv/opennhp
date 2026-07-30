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
        Sid      = "ReadAndDeleteRunBoundProofCredential"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DeleteSecret"]
        Resource = local.proof_account_jit_arn_pattern
        Condition = {
          StringEquals = {
            "secretsmanager:ResourceTag/Environment" = var.environment
            "secretsmanager:ResourceTag/Purpose"     = local.proof_account_jit_purpose
          }
        }
      },
      {
        Sid      = "CreateBoundRecoveryRequest"
        Effect   = "Allow"
        Action   = "secretsmanager:CreateSecret"
        Resource = local.recovery_request_secret_arn_pattern
        Condition = {
          StringEquals = {
            "aws:RequestTag/Environment" = var.environment
            "aws:RequestTag/Purpose"     = "udp-proof-recovery-request"
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
        Sid      = "TagBoundRecoveryRequest"
        Effect   = "Allow"
        Action   = "secretsmanager:TagResource"
        Resource = local.recovery_request_secret_arn_pattern
        Condition = {
          StringEquals = {
            "aws:RequestTag/Environment" = var.environment
            "aws:RequestTag/Purpose"     = "udp-proof-recovery-request"
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
        Sid      = "ReadAndDeleteBoundRecoveryResponse"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DeleteSecret"]
        Resource = local.recovery_response_secret_arn_pattern
        Condition = {
          StringEquals = {
            "secretsmanager:ResourceTag/Environment" = var.environment
            "secretsmanager:ResourceTag/Purpose"     = "udp-proof-recovery-response"
          }
        }
      },
      {
        Sid      = "UseRecoveryMailboxEncryption"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.jit.arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = local.secrets_kms_via_service
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
        Sid      = "UseBoundQURLGoAgentState"
        Effect   = "Allow"
        Action   = ["kms:Encrypt", "kms:Decrypt"]
        Resource = var.proof_kms_key_arns
        Condition = {
          StringEquals = {
            "kms:EncryptionContext:qurl_purpose"          = "qurl-go/agent-state"
            "kms:EncryptionContext:qurl_envelope_version" = "1"
            "kms:EncryptionContext:qurl_provider_id"      = "aws-kms"
          }
          StringLike = {
            "kms:EncryptionContext:qurl_agent_id" = "qurl-go-sandbox-*"
          }
          "ForAllValues:StringEquals" = {
            "kms:EncryptionContextKeys" = [
              "qurl_purpose",
              "qurl_envelope_version",
              "qurl_provider_id",
              "qurl_agent_id",
            ]
          }
        }
      },
      {
        Sid      = "UseBoundConnectorAgentState"
        Effect   = "Allow"
        Action   = ["kms:Encrypt", "kms:Decrypt"]
        Resource = var.proof_kms_key_arns
        Condition = {
          StringEquals = {
            "kms:EncryptionContext:purpose"          = "qurl-go/agent-state-dek/qurl-go/agent-state"
            "kms:EncryptionContext:envelope_version" = "1"
            "kms:EncryptionContext:provider_id"      = "aws-kms"
          }
          StringLike = {
            "kms:EncryptionContext:agent_id" = "connector-sandbox-*"
          }
          "ForAllValues:StringEquals" = {
            "kms:EncryptionContextKeys" = [
              "purpose",
              "envelope_version",
              "provider_id",
              "agent_id",
            ]
          }
        }
      },
      {
        Sid    = "ConsumeExactProofOTPMailboxQueue"
        Effect = "Allow"
        Action = [
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:GetQueueUrl",
          "sqs:ReceiveMessage",
        ]
        Resource = aws_sqs_queue.proof_otp_mailbox.arn
      },
      {
        Sid    = "ConsumeExactProofOTPMailboxObjects"
        Effect = "Allow"
        Action = [
          "s3:DeleteObject",
          "s3:GetObject",
        ]
        Resource = "${aws_s3_bucket.proof_otp_mailbox.arn}/${local.proof_mailbox_object_prefix}*"
      },
      {
        Sid      = "WriteAssignmentProofCheckpoint"
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "${local.assignment_handshake_bucket_arn}/${local.assignment_handshake_prefix}*/checkpoint.json"
      },
      {
        Sid      = "ReadAssignmentProofReceipt"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "${local.assignment_handshake_bucket_arn}/${local.assignment_handshake_prefix}*/receipt.json"
      },
      {
        Sid      = "WriteTransportProofCheckpoint"
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "${local.assignment_handshake_bucket_arn}/${local.assignment_handshake_prefix}*/transport-checkpoint.json"
      },
      {
        Sid      = "ReadTransportProofReceipt"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "${local.assignment_handshake_bucket_arn}/${local.assignment_handshake_prefix}*/transport-receipt.json"
      },
      {
        Sid      = "DenyAssignmentProofReceiptWrites"
        Effect   = "Deny"
        Action   = "s3:PutObject"
        Resource = "${local.assignment_handshake_bucket_arn}/${local.assignment_handshake_prefix}*/receipt.json"
      },
      {
        Sid      = "DenyTransportProofReceiptWrites"
        Effect   = "Deny"
        Action   = "s3:PutObject"
        Resource = "${local.assignment_handshake_bucket_arn}/${local.assignment_handshake_prefix}*/transport-receipt.json"
      },
      {
        Sid      = "EncryptAssignmentProofHandshake"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.assignment_handshake.arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = local.assignment_handshake_s3_via_service
          }
          StringLike = {
            "kms:EncryptionContext:aws:s3:arn" = "${local.assignment_handshake_bucket_arn}/${local.assignment_handshake_prefix}*"
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
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.jit.arn
        # Scope to Secrets-Manager-invoked calls only. Deliberately NOT
        # constrained by kms:EncryptionContext:SecretARN: during CreateSecret
        # the secret ARN is assigned *as part of* the create, so Secrets
        # Manager's GenerateDataKey encryption context does not yet carry
        # SecretARN (it only appears on Put/Get of an existing secret). An
        # ArnLike condition on that key is therefore unsatisfiable at create
        # time and denies the one-use secret's KMS authorization. AWS requires
        # both GenerateDataKey and Decrypt permission when CreateSecret writes
        # through a customer-managed key. Decrypt remains service-bound here;
        # the controller has no Secrets Manager read permission.
        #
        # The controller's secretsmanager:CreateSecret is already resource-scoped
        # to local.jit_secret_arn_pattern with required tags, and this is a
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
      {
        Sid      = "ReadBoundProofAccountCredential"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = aws_secretsmanager_secret.proof_account_credential.arn
        Condition = {
          StringEquals = {
            "secretsmanager:ResourceTag/Environment" = var.environment
            "secretsmanager:ResourceTag/Purpose"     = "udp-proof-account-credential"
          }
        }
      },
      {
        Sid      = "ReadBoundProofAccountCredentialDigest"
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = local.proof_account_sha_parameter_arn
      },
      {
        Sid      = "ConvergeExactProofCustomer"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem"]
        Resource = local.proof_control_customers_table_arn
        Condition = {
          "ForAllValues:StringEquals" = {
            "dynamodb:LeadingKeys" = [local.proof_account_owner_id]
          }
        }
      },
      {
        Sid    = "ConvergeAndRemoveExactProofAccountKey"
        Effect = "Allow"
        Action = [
          "dynamodb:DeleteItem",
          "dynamodb:GetItem",
          "dynamodb:PutItem",
        ]
        Resource = local.proof_control_api_keys_table_arn
        Condition = {
          "ForAllValues:StringEquals" = {
            "dynamodb:LeadingKeys" = [local.proof_account_credential_hash]
          }
        }
      },
      {
        Sid      = "DeleteRunBoundProofCredential"
        Effect   = "Allow"
        Action   = ["secretsmanager:DeleteSecret"]
        Resource = local.proof_account_jit_arn_pattern
        Condition = {
          StringEquals = {
            "secretsmanager:ResourceTag/Environment" = var.environment
            "secretsmanager:ResourceTag/Purpose"     = local.proof_account_jit_purpose
          }
        }
      },
      {
        Sid      = "CreateRunBoundProofCredential"
        Effect   = "Allow"
        Action   = ["secretsmanager:CreateSecret"]
        Resource = local.proof_account_jit_arn_pattern
        Condition = {
          StringEquals = {
            "aws:RequestTag/Environment" = var.environment
            "aws:RequestTag/Purpose"     = local.proof_account_jit_purpose
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
        Sid      = "TagRunBoundProofCredential"
        Effect   = "Allow"
        Action   = ["secretsmanager:TagResource"]
        Resource = local.proof_account_jit_arn_pattern
        Condition = {
          StringEquals = {
            "aws:RequestTag/Environment" = var.environment
            "aws:RequestTag/Purpose"     = local.proof_account_jit_purpose
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
        Sid    = "ReadExactAuthorityProofConcurrency"
        Effect = "Allow"
        Action = [
          "lambda:GetFunctionConcurrency",
          "lambda:ListProvisionedConcurrencyConfigs",
        ]
        Resource = [
          for function_name in local.authority_proof_rollout_function_names :
          "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:function:${function_name}"
        ]
      },
      {
        Sid    = "ReadExactAuthorityProofAliases"
        Effect = "Allow"
        Action = "lambda:GetAlias"
        Resource = flatten([
          for function_name in local.authority_proof_rollout_function_names : [
            "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:function:${function_name}:blue",
            "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:function:${function_name}:green",
          ]
        ])
      },
      {
        Sid      = "ReadAuthorityProofMetrics"
        Effect   = "Allow"
        Action   = "cloudwatch:GetMetricStatistics"
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = data.aws_region.current.region
          }
        }
      },
      {
        Sid      = "ReadAssignmentProofCheckpoint"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "${local.assignment_handshake_bucket_arn}/${local.assignment_handshake_prefix}*/checkpoint.json"
      },
      {
        Sid      = "WriteAssignmentProofReceipt"
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "${local.assignment_handshake_bucket_arn}/${local.assignment_handshake_prefix}*/receipt.json"
      },
      {
        Sid      = "ReadTransportProofCheckpoint"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "${local.assignment_handshake_bucket_arn}/${local.assignment_handshake_prefix}*/transport-checkpoint.json"
      },
      {
        Sid      = "WriteTransportProofReceipt"
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "${local.assignment_handshake_bucket_arn}/${local.assignment_handshake_prefix}*/transport-receipt.json"
      },
      {
        Sid      = "DenyAssignmentProofCheckpointWrites"
        Effect   = "Deny"
        Action   = "s3:PutObject"
        Resource = "${local.assignment_handshake_bucket_arn}/${local.assignment_handshake_prefix}*/checkpoint.json"
      },
      {
        Sid      = "DenyTransportProofCheckpointWrites"
        Effect   = "Deny"
        Action   = "s3:PutObject"
        Resource = "${local.assignment_handshake_bucket_arn}/${local.assignment_handshake_prefix}*/transport-checkpoint.json"
      },
      {
        Sid    = "ReadExactLifecycleRouteLogs"
        Effect = "Allow"
        Action = "logs:FilterLogEvents"
        Resource = [
          "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/layerv/nhp/${var.environment}/cell0/qurl-api:*",
          "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/layerv/nhp/${var.environment}/cell1/qurl-api:*",
          "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/layerv/nhp/${var.environment}/relay:*",
        ]
      },
      {
        Sid      = "EncryptAssignmentProofHandshake"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.assignment_handshake.arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = local.assignment_handshake_s3_via_service
          }
          StringLike = {
            "kms:EncryptionContext:aws:s3:arn" = "${local.assignment_handshake_bucket_arn}/${local.assignment_handshake_prefix}*"
          }
        }
      },
      {
        Sid      = "ResolveAssignmentProofHandshakeKey"
        Effect   = "Allow"
        Action   = "kms:DescribeKey"
        Resource = aws_kms_key.assignment_handshake.arn
      },
      {
        Sid      = "ReadAndDeleteBoundRecoveryRequest"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DeleteSecret"]
        Resource = local.recovery_request_secret_arn_pattern
        Condition = {
          StringEquals = {
            "secretsmanager:ResourceTag/Environment" = var.environment
            "secretsmanager:ResourceTag/Purpose"     = "udp-proof-recovery-request"
          }
        }
      },
      {
        Sid      = "PrepareExactUnlimitedProofOwner"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
        Resource = local.proof_customers_table_arn
        Condition = {
          "ForAllValues:StringEquals" = {
            "dynamodb:LeadingKeys" = [local.proof_owner_id]
          }
        }
      },
      {
        Sid      = "CreateBoundRecoveryResponse"
        Effect   = "Allow"
        Action   = "secretsmanager:CreateSecret"
        Resource = local.recovery_response_secret_arn_pattern
        Condition = {
          StringEquals = {
            "aws:RequestTag/Environment" = var.environment
            "aws:RequestTag/Purpose"     = "udp-proof-recovery-response"
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
        Sid      = "TagBoundRecoveryResponse"
        Effect   = "Allow"
        Action   = "secretsmanager:TagResource"
        Resource = local.recovery_response_secret_arn_pattern
        Condition = {
          StringEquals = {
            "aws:RequestTag/Environment" = var.environment
            "aws:RequestTag/Purpose"     = "udp-proof-recovery-response"
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
    ]
  })
}

resource "aws_iam_policy" "controller_control_data_decrypt" {
  count = var.provisioned_cell_catalog_kms_key_arn == null ? 0 : 1

  name        = "${var.name_prefix}-udp-proof-controller-control-data-decrypt"
  description = "DynamoDB-only decrypt for the exact Control proof-account data key"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "DecryptOnlyProofAccountTables"
      Effect   = "Allow"
      Action   = "kms:Decrypt"
      Resource = var.provisioned_cell_catalog_kms_key_arn
      Condition = {
        StringEquals = {
          "kms:ViaService" = "dynamodb.${data.aws_region.current.region}.${data.aws_partition.current.dns_suffix}"
        }
      }
    }]
  })

  tags = local.tags

  lifecycle {
    precondition {
      condition = startswith(
        var.provisioned_cell_catalog_kms_key_arn,
        "arn:${data.aws_partition.current.partition}:kms:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:key/",
      )
      error_message = "The Control data CMK must be a current-account, current-region KMS key ARN."
    }
  }
}

resource "aws_iam_role_policy_attachment" "controller_control_data_decrypt" {
  count = var.provisioned_cell_catalog_kms_key_arn == null ? 0 : 1

  role       = aws_iam_role.controller.name
  policy_arn = aws_iam_policy.controller_control_data_decrypt[0].arn
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
        Sid    = "InspectProofSecretMetadata"
        Effect = "Allow"
        Action = "secretsmanager:DescribeSecret"
        Resource = [
          local.jit_secret_arn_pattern,
          local.recovery_request_secret_arn_pattern,
          local.recovery_response_secret_arn_pattern,
        ]
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
        Sid      = "DeleteExpiredProofAccountCredentials"
        Effect   = "Allow"
        Action   = "secretsmanager:DeleteSecret"
        Resource = local.proof_account_jit_arn_pattern
        Condition = {
          StringEquals = {
            "secretsmanager:ResourceTag/Environment" = var.environment
            "secretsmanager:ResourceTag/Purpose"     = local.proof_account_jit_purpose
          }
        }
      },
      {
        Sid      = "DeleteExpiredRecoveryRequests"
        Effect   = "Allow"
        Action   = "secretsmanager:DeleteSecret"
        Resource = local.recovery_request_secret_arn_pattern
        Condition = {
          StringEquals = {
            "secretsmanager:ResourceTag/Environment" = var.environment
            "secretsmanager:ResourceTag/Purpose"     = "udp-proof-recovery-request"
          }
        }
      },
      {
        Sid      = "DeleteExpiredRecoveryResponses"
        Effect   = "Allow"
        Action   = "secretsmanager:DeleteSecret"
        Resource = local.recovery_response_secret_arn_pattern
        Condition = {
          StringEquals = {
            "secretsmanager:ResourceTag/Environment" = var.environment
            "secretsmanager:ResourceTag/Purpose"     = "udp-proof-recovery-response"
          }
        }
      },
      {
        # ListSecrets returns metadata, not SecretString. The broker filters by
        # exact module prefixes and cannot GetSecretValue.
        Sid      = "FindOrphanedProofSecretMetadata"
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
