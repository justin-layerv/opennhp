mock_provider "aws" {
  mock_data "aws_region" {
    defaults = {
      id     = "us-east-2"
      region = "us-east-2"
    }
  }

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "111122223333"
    }
  }
}

variables {
  environment = "sandbox"
  name_prefix = "layerv-nhp-sandbox"
  cell_id     = "cell0"
}

run "session_control_authority_is_durable_and_narrow" {
  command = apply

  variables {
    deploy_qurl_tables = true
    kms_key_arn        = "arn:aws:kms:us-east-2:111122223333:key/11111111-2222-3333-4444-555555555555"
  }

  assert {
    condition = (
      aws_dynamodb_table.session_control.name == "layerv-nhp-sandbox-cell0-nhp-session-control" &&
      aws_dynamodb_table.session_control.billing_mode == "PAY_PER_REQUEST" &&
      aws_dynamodb_table.session_control.hash_key == "pk" &&
      aws_dynamodb_table.session_control.range_key == "sk" &&
      aws_dynamodb_table.session_control.ttl[0].attribute_name == "ttl" &&
      aws_dynamodb_table.session_control.ttl[0].enabled &&
      aws_dynamodb_table.session_control.server_side_encryption[0].enabled &&
      one([
        for index in aws_dynamodb_table.session_control.global_secondary_index : index
        if index.name == "due-index"
      ]).projection_type == "KEYS_ONLY" &&
      one([
        for index in aws_dynamodb_table.session_control.global_secondary_index : index
        if index.name == "due-index"
      ]).hash_key == "due_shard" &&
      one([
        for index in aws_dynamodb_table.session_control.global_secondary_index : index
        if index.name == "due-index"
      ]).range_key == "due_sort"
    )
    error_message = "Session-control storage must be an encrypted PAY_PER_REQUEST PK/SK table with TTL available only for completed rows and one KEYS_ONLY due-work index."
  }

  assert {
    condition = contains(
      output.all_table_names,
      aws_dynamodb_table.session_control.name,
    )
    error_message = "The session-control table must participate in the shared DynamoDB throttle/system-error monitoring set."
  }

  assert {
    condition = (
      one([
        for statement in jsondecode(aws_iam_policy.dynamodb_read.policy).Statement : statement
        if statement.Sid == "DynamoDBSessionControlAuthority"
        ]).Action == [
        "dynamodb:ConditionCheckItem",
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:Query",
        "dynamodb:UpdateItem",
      ] &&
      one([
        for statement in jsondecode(aws_iam_policy.dynamodb_read.policy).Statement : statement
        if statement.Sid == "DynamoDBSessionControlAuthority"
      ]).Resource == [aws_dynamodb_table.session_control.arn]
    )
    error_message = "The server authority statement must grant only constituent item operations on the exact base table ARN, without Scan, BatchGet, Delete, or fictitious Transact* IAM actions."
  }

  assert {
    condition = (
      one([
        for statement in jsondecode(aws_iam_policy.dynamodb_read.policy).Statement : statement
        if statement.Sid == "DynamoDBSessionControlDueIndex"
      ]).Action == ["dynamodb:Query"] &&
      one([
        for statement in jsondecode(aws_iam_policy.dynamodb_read.policy).Statement : statement
        if statement.Sid == "DynamoDBSessionControlDueIndex"
      ]).Resource == "${aws_dynamodb_table.session_control.arn}/index/due-index"
    )
    error_message = "The due-work GSI must receive Query only on its exact ARN; it is discovery, never a correctness-read surface."
  }

  assert {
    condition = alltrue([
      for forbidden in [
        aws_dynamodb_table.session_control.arn,
        "${aws_dynamodb_table.session_control.arn}/index/*",
        ] : !contains(
        one([
          for statement in jsondecode(aws_iam_policy.dynamodb_read.policy).Statement : statement
          if statement.Sid == "DynamoDBReadAccess"
        ]).Resource,
        forbidden,
      )
    ])
    error_message = "The broad Scan/BatchGet read statement must not include session-control authority or its indexes."
  }

  assert {
    condition = alltrue([
      for forbidden in [
        aws_dynamodb_table.session_control.arn,
        "${aws_dynamodb_table.session_control.arn}/index/*",
        ] : !contains(
        one([
          for statement in jsondecode(aws_iam_policy.dynamodb_write.policy).Statement : statement
          if statement.Sid == "DynamoDBWriteAccess"
        ]).Resource,
        forbidden,
      )
    ])
    error_message = "The broad Console write policy must not include session-control authority or its indexes."
  }

  assert {
    condition = !contains(
      one([
        for statement in jsondecode(aws_iam_policy.dynamodb_read.policy).Statement : statement
        if statement.Sid == "DynamoDBSessionControlAuthority"
      ]).Action,
      "dynamodb:DeleteItem",
    )
    error_message = "The general server authority statement must not delete durable rows; terminal-close delete authority is a separate partition-fenced statement."
  }

  assert {
    condition = (
      one([
        for statement in jsondecode(aws_iam_policy.dynamodb_read.policy).Statement : statement
        if statement.Sid == "DynamoDBSessionControlTerminalCloseDelete"
        ]) == {
        Sid      = "DynamoDBSessionControlTerminalCloseDelete"
        Effect   = "Allow"
        Action   = ["dynamodb:DeleteItem"]
        Resource = [aws_dynamodb_table.session_control.arn]
        Condition = {
          "ForAllValues:StringLike" = {
            "dynamodb:LeadingKeys" = [
              "ACTIVE#ba9c4949557b0a0b68c6354dbdec84ab68d0e9af183243ac4ac1b89cf0b0c153",
              "EVENT#*",
              "TARGETWORK#*",
            ]
          }
          "ForAnyValue:StringEquals" = {
            "dynamodb:EnclosingOperation" = ["TransactWriteItems"]
          }
          Null = {
            "dynamodb:LeadingKeys" = "false"
          }
        }
      }
    )
    error_message = "Sandbox cell0 exact close and ACKED-task cleanup must receive DeleteItem only inside TransactWriteItems for the exact ACTIVE partition and EVENT/TARGETWORK partitions on the exact session-control table."
  }

  assert {
    condition = [
      for statement in jsondecode(aws_iam_policy.dynamodb_read.policy).Statement : statement.Sid
      ] == [
      "DynamoDBReadAccess",
      "DynamoDBWriteACAssignments",
      "DynamoDBAckTokenReadWrite",
      "DynamoDBSessionControlAuthority",
      "DynamoDBSessionControlDueIndex",
      "DynamoDBSessionControlTerminalCloseDelete",
      "DynamoDBQurlAgentKeysGetItem",
      "DynamoDBQurlAgentKeysPubkeyIndexQuery",
      "KMSReadAndServerWrite",
    ]
    error_message = "The incident helper and Terraform must derive the same ordered managed-policy document so the next ordinary plan is a no-op."
  }
}

run "production_protects_session_control_from_delete" {
  command = apply

  variables {
    environment = "prod"
  }

  assert {
    condition = (
      aws_dynamodb_table.session_control.deletion_protection_enabled &&
      aws_dynamodb_table.session_control.point_in_time_recovery[0].enabled
    )
    error_message = "Production session-control authority requires deletion protection and point-in-time recovery."
  }

  assert {
    condition = length([
      for statement in jsondecode(aws_iam_policy.dynamodb_read.policy).Statement : statement
      if statement.Sid == "DynamoDBSessionControlTerminalCloseDelete"
    ]) == 0
    error_message = "The attended sandbox incident permission must never appear in the production server policy."
  }
}

run "other_cells_do_not_receive_incident_delete_authority" {
  command = apply

  variables {
    environment = "sandbox-cell1"
    name_prefix = "layerv-nhp-sandbox-cell1"
    cell_id     = "cell1"
  }

  assert {
    condition = length([
      for statement in jsondecode(aws_iam_policy.dynamodb_read.policy).Statement : statement
      if statement.Sid == "DynamoDBSessionControlTerminalCloseDelete"
    ]) == 0
    error_message = "The attended sandbox cell0 incident permission must not widen to another cell."
  }
}

run "sandbox_native_operation_authority_is_transaction_only" {
  command = apply

  variables {
    deploy_qurl_tables                             = true
    enable_native_session_operations               = true
    native_session_operations_use_local_agent_keys = true
  }

  assert {
    condition = one([
      for statement in jsondecode(aws_iam_policy.dynamodb_read.policy).Statement : statement
      if statement.Sid == "DenyDirectNativeSessionOperationWrite"
      ]) == {
      Sid      = "DenyDirectNativeSessionOperationWrite"
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
    error_message = "Direct, missing-enclosure, and wrong-transaction OP mutations must be explicitly denied even though the legacy base-table statement allows constituent item verbs."
  }

  assert {
    condition = one([
      for statement in jsondecode(aws_iam_policy.dynamodb_read.policy).Statement : statement
      if statement.Sid == "DenyNativeSessionOperationUpdateDelete"
      ]) == {
      Sid    = "DenyNativeSessionOperationUpdateDelete"
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
    error_message = "OP ConditionCheckItem, Query, UpdateItem, and DeleteItem must be denied for every enclosing operation; exact transitions use conditional PutItem and exact reads use TransactGetItems only."
  }

  assert {
    condition = one([
      for statement in jsondecode(aws_iam_policy.dynamodb_read.policy).Statement : statement
      if statement.Sid == "DenyDirectNativeSessionOperationRead"
      ]) == {
      Sid      = "DenyDirectNativeSessionOperationRead"
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
    error_message = "OP reads must be available only as TransactGetItems members; direct GetItem and wrong enclosing operations must be denied."
  }

  assert {
    condition = one([
      for statement in jsondecode(aws_iam_policy.dynamodb_read.policy).Statement : statement
      if statement.Sid == "DynamoDBQurlAgentKeysTransactionCondition"
      ]) == {
      Sid      = "DynamoDBQurlAgentKeysTransactionCondition"
      Effect   = "Allow"
      Action   = ["dynamodb:ConditionCheckItem"]
      Resource = aws_dynamodb_table.qurl_agent_keys[0].arn
      Condition = {
        StringEquals = {
          "dynamodb:EnclosingOperation" = "TransactWriteItems"
        }
      }
    }
    error_message = "The agent-key table must grant only ConditionCheckItem inside TransactWriteItems on its exact base ARN."
  }

  assert {
    condition = alltrue([
      for statement in jsondecode(aws_iam_policy.dynamodb_read.policy).Statement : (
        statement.Resource != aws_dynamodb_table.qurl_agent_keys[0].arn ||
        length(setintersection(toset(statement.Action), toset([
          "dynamodb:DeleteItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
        ]))) == 0
      )
    ])
    error_message = "NHP must never receive Put, Update, or Delete authority on qurl-agent-keys."
  }

  assert {
    condition = alltrue([
      for statement in jsondecode(aws_iam_policy.dynamodb_read.policy).Statement :
      !can(regex("/index/", tostring(statement.Resource))) || statement.Sid == "DynamoDBQurlAgentKeysPubkeyIndexQuery" || statement.Sid == "DynamoDBSessionControlDueIndex" || statement.Sid == "DynamoDBReadAccess"
    ])
    error_message = "Native operation transaction authority must not widen to any index ARN."
  }
}

run "control_identity_native_operations_do_not_grant_local_agent_keys" {
  command = apply

  variables {
    deploy_qurl_tables                             = true
    enable_native_session_operations               = true
    native_session_operations_use_local_agent_keys = false
  }

  assert {
    condition = (
      length([
        for statement in jsondecode(aws_iam_policy.dynamodb_read.policy).Statement : statement
        if statement.Sid == "DynamoDBQurlAgentKeysTransactionCondition"
      ]) == 0 &&
      length([
        for statement in jsondecode(aws_iam_policy.dynamodb_read.policy).Statement : statement
        if statement.Sid == "DenyDirectNativeSessionOperationWrite" || statement.Sid == "DenyDirectNativeSessionOperationRead" || statement.Sid == "DenyNativeSessionOperationUpdateDelete"
      ]) == 3
    )
    error_message = "Control identity must retain the session-table OP fence without granting ConditionCheckItem on the unused cell-local agent-key table."
  }
}
