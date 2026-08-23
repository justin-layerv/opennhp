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
    error_message = "Server authority must not delete durable rows; completion is an explicit state transition and TTL is post-convergence retention only."
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
}
