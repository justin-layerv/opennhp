# Candidate-only assignment authority for the coordinated production canary.
#
# The active/rollback fleet keeps aws_dynamodb_table.ac_assignments unchanged.
# Candidate servers receive only this table name, so an existing blue row for
# the same logical AC ID can never redirect a green AC to a blue server.

resource "aws_dynamodb_table" "matched_cohort_ac_assignments" {
  count = var.enable_matched_cohort_canary ? 1 : 0

  name         = "${var.name_prefix}-${var.cell_id}-ac-assignments-candidate"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "ac_id"

  attribute {
    name = "ac_id"
    type = "S"
  }

  attribute {
    name = "resource_fqdn"
    type = "S"
  }

  attribute {
    name = "customer_id"
    type = "S"
  }

  global_secondary_index {
    name            = "resource_fqdn-index"
    hash_key        = "resource_fqdn"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "customer_id-index"
    hash_key        = "customer_id"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = local.is_prod
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = merge(var.tags, {
    Name        = "${var.name_prefix}-${var.cell_id}-ac-assignments-candidate"
    Component   = "dynamodb"
    Cell        = var.cell_id
    DeployColor = "green"
    Purpose     = "matched-cohort-candidate-assignment"
  })
}

# One durable journal serializes every attended maintenance-gate and selector
# mutation. Its stable release identity is the digest of PR2's immutable
# source/image manifest, while every command CAS-acquires a fresh invocation
# token. Candidate instances receive no IAM authority on this table. The row
# intentionally has no TTL: a crashed command remains fail-closed until normal
# workflow concurrency stops its predecessor and a successor exact-resumes it.
resource "aws_dynamodb_table" "matched_cohort_operator_lock" {
  count = var.enable_matched_cohort_canary ? 1 : 0

  name         = "${var.name_prefix}-${var.cell_id}-matched-cohort-operator-lock"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "lock_id"

  attribute {
    name = "lock_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = local.is_prod
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-${var.cell_id}-matched-cohort-operator-lock"
    Component = "dynamodb"
    Cell      = var.cell_id
    Purpose   = "matched-cohort-operator-lock"
  })
}

# Candidate server storage authority. This intentionally does not reuse the
# active server policy: a candidate may strongly read the active assignment row
# for immutable identity and revoked_pubkeys, but only the isolated candidate
# table is writable. The remaining grants mirror the runtime tables required by
# the same server binary during the protected customer lifecycle.
resource "aws_iam_policy" "matched_cohort_server" {
  count = var.enable_matched_cohort_canary ? 1 : 0

  name        = "${var.name_prefix}-${var.cell_id}-matched-cohort-server"
  description = "Least-privilege DynamoDB authority for the matched-cohort candidate server"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid    = "CandidateReadSharedRuntime"
        Effect = "Allow"
        Action = [
          "dynamodb:BatchGetItem",
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:Scan",
        ]
        Resource = concat([
          aws_dynamodb_table.licenses.arn,
          "${aws_dynamodb_table.licenses.arn}/index/*",
          aws_dynamodb_table.resources.arn,
          "${aws_dynamodb_table.resources.arn}/index/*",
          ], var.deploy_qurl_tables ? [
          aws_dynamodb_table.qurl_domains[0].arn,
          "${aws_dynamodb_table.qurl_domains[0].arn}/index/*",
          aws_dynamodb_table.qurl_access_codes[0].arn,
          "${aws_dynamodb_table.qurl_access_codes[0].arn}/index/*",
        ] : [])
      },
      {
        Sid      = "CandidateReadActiveAssignmentAuthority"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem"]
        Resource = aws_dynamodb_table.ac_assignments.arn
      },
      {
        Sid    = "CandidateRouteRead"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:Scan",
        ]
        Resource = [
          aws_dynamodb_table.matched_cohort_ac_assignments[0].arn,
          "${aws_dynamodb_table.matched_cohort_ac_assignments[0].arn}/index/*",
        ]
      },
      {
        Sid      = "CandidateRouteTerminationFenceCheck"
        Effect   = "Allow"
        Action   = ["dynamodb:ConditionCheckItem"]
        Resource = aws_dynamodb_table.matched_cohort_ac_assignments[0].arn
      },
      {
        Sid      = "CandidateRouteWrite"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = aws_dynamodb_table.matched_cohort_ac_assignments[0].arn
        Condition = {
          "ForAllValues:StringNotLike" = {
            "dynamodb:LeadingKeys" = ["__server_termination__#*"]
          }
        }
      },
      {
        Sid    = "CandidateAckTokenReadWrite"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
        ]
        Resource = aws_dynamodb_table.ack_tokens.arn
      },
      {
        Sid    = "CandidateSessionControlAuthority"
        Effect = "Allow"
        Action = [
          "dynamodb:ConditionCheckItem",
          "dynamodb:DeleteItem",
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:Query",
          "dynamodb:UpdateItem",
        ]
        Resource = aws_dynamodb_table.session_control.arn
      },
      ], var.enable_native_session_operations ? [
      {
        Sid      = "DenyCandidateDirectNativeSessionOperationWrite"
        Effect   = "Deny"
        Action   = ["dynamodb:PutItem"]
        Resource = [aws_dynamodb_table.session_control.arn]
        Condition = {
          "ForAnyValue:StringLike" = {
            "dynamodb:LeadingKeys" = ["OP#*"]
          }
          "StringNotEqualsIfExists" = {
            "dynamodb:EnclosingOperation" = "TransactWriteItems"
          }
        }
      }
      ] : [], var.enable_native_session_operations ? [
      {
        Sid    = "DenyCandidateNativeSessionOperationUpdateDelete"
        Effect = "Deny"
        Action = [
          "dynamodb:ConditionCheckItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",
          "dynamodb:UpdateItem",
        ]
        Resource = [aws_dynamodb_table.session_control.arn]
        Condition = {
          "ForAnyValue:StringLike" = {
            "dynamodb:LeadingKeys" = ["OP#*"]
          }
        }
      }
      ] : [], var.enable_native_session_operations ? [
      {
        Sid      = "DenyCandidateDirectNativeSessionOperationRead"
        Effect   = "Deny"
        Action   = ["dynamodb:GetItem"]
        Resource = [aws_dynamodb_table.session_control.arn]
        Condition = {
          "ForAnyValue:StringLike" = {
            "dynamodb:LeadingKeys" = ["OP#*"]
          }
          "StringNotEqualsIfExists" = {
            "dynamodb:EnclosingOperation" = "TransactGetItems"
          }
        }
      }
      ] : [], [
      {
        Sid      = "CandidateSessionControlDueIndex"
        Effect   = "Allow"
        Action   = ["dynamodb:Query"]
        Resource = "${aws_dynamodb_table.session_control.arn}/index/due-index"
      },
      ], var.deploy_qurl_tables ? [
      {
        Sid      = "CandidateQurlAgentKeysGetItem"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem"]
        Resource = aws_dynamodb_table.qurl_agent_keys[0].arn
      },
      {
        Sid      = "CandidateQurlAgentKeysPubkeyIndexQuery"
        Effect   = "Allow"
        Action   = ["dynamodb:Query"]
        Resource = "${aws_dynamodb_table.qurl_agent_keys[0].arn}/index/pubkey-index"
      },
      ] : [], var.native_session_operations_use_local_agent_keys ? [
      {
        Sid      = "CandidateQurlAgentKeysTransactionCondition"
        Effect   = "Allow"
        Action   = ["dynamodb:ConditionCheckItem"]
        Resource = aws_dynamodb_table.qurl_agent_keys[0].arn
        Condition = {
          StringEquals = {
            "dynamodb:EnclosingOperation" = "TransactWriteItems"
          }
        }
      }
      ] : [], var.kms_key_arn != null ? [{
        Sid      = "CandidateDynamoDBKMS"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]
        Resource = [var.kms_key_arn]
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id
            "kms:ViaService"    = "dynamodb.${data.aws_region.current.id}.amazonaws.com"
          }
        }
    }] : [])
  })

  tags = merge(var.tags, {
    Component = "nhp-server"
    Cell      = var.cell_id
    Purpose   = "matched-cohort-candidate"
  })
}
