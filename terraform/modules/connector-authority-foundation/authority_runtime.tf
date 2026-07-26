# Connector Authority Lambda runtime (Step 4 of the two-cell UDP substrate).
# This file is INERT until BOTH the runtime contract is bound
# (Step 3 sets authority_runtime_contract non-null) AND the separate runtime
# gate is flipped (var.authority_runtime_functions_enabled). Until then every
# resource below is count/for_each empty and the foundation stays dark.
#
# SCOPE: the exact complete contract graph: 3 Hub functions plus 4 functions
# for every provisioned cell. A ready two-cell sandbox therefore deploys 11
# functions. Partial cell groups are rejected by authority_runtime_contract.tf.
#
# DARK-FIRST: functions, both closed blue/green aliases, operation-specific
# execution roles, steady provisioned/reserved concurrency, and spillover
# alarms are created here with NO caller identity policy, NO aws_lambda_permission
# (a same-account caller resource Allow would bypass the SourceVpce condition on
# the caller identity policy; the plan forbids it), and NO opening of the Lambda
# caller interface endpoint (the Hub role/runtime does not exist yet — Step 5).
# The lockstep opening in endpoints.tf opens ONLY the dependency endpoints these
# functions provably reach (DynamoDB, KMS, Secrets Manager, and SES), to exactly
# the constructed execution-role principals.

locals {
  # Second, independent gate. Requires a bound contract; the precondition below
  # fails closed if the gate is set while the contract is null.
  authority_runtime_functions_deploy = (
    local.authority_runtime_contract_enabled && var.authority_runtime_functions_enabled
  )

  # Deploy exactly the complete function graph admitted by the contract.
  authority_runtime_functions = local.authority_runtime_functions_deploy ? {
    for function_name, spec in local.authority_expected_functions :
    function_name => {
      operation = spec.operation
      cell_id   = spec.cell_id
      spec      = local.authority_contract_functions[function_name]
    }
    if contains(local.authority_actual_function_names, function_name)
  } : {}

  authority_runtime_selected_color = local.authority_runtime_functions_deploy ? var.authority_runtime_contract.selected_authority_color : null

  # Both closed deployment qualifiers are published up front. For this initial
  # dark bootstrap they intentionally target the same first published version;
  # only the selected color receives steady provisioned concurrency below.
  # This is not a working blue/green rollout or rollback controller. NHP #3456
  # must land before the first post-bootstrap Authority image roll.
  authority_runtime_alias_colors = ["blue", "green"]
  authority_runtime_aliases = merge([
    for function_name, fn in local.authority_runtime_functions : {
      for color in local.authority_runtime_alias_colors :
      "${function_name}:${color}" => {
        function_name = function_name
        color         = color
      }
    }
  ]...)

  # Execution-role identity is constructed (account + deterministic name) so the
  # endpoint policies that reference these principals are fully known at plan
  # time and independently checkable, and so no dependency cycle forms between
  # the function, its role, and the endpoint policy.
  authority_runtime_exec_role_name = {
    for function_name, fn in local.authority_runtime_functions :
    function_name => "${function_name}-exec"
  }
  authority_runtime_exec_role_arn = {
    for function_name, fn in local.authority_runtime_functions :
    function_name => "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/${function_name}-exec"
  }

  # Sorted, deduplicated principal list for the dependency endpoint policies.
  authority_runtime_exec_role_arns = sort(values(local.authority_runtime_exec_role_arn))

  # Constructed, plan-known own-log-group ARNs (same pattern as
  # local.flow_log_group_arn). Building this as a literal rather than referencing
  # the not-yet-created aws_cloudwatch_log_group.authority[*].arn keeps every
  # per-operation execution policy fully known at plan time, so its scoped
  # actions/resources are independently checkable by the first-apply checker.
  authority_runtime_log_group_arn = {
    for function_name, fn in local.authority_runtime_functions :
    function_name => "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${function_name}"
  }

  # IssueAssignment signs; IssueRegistrationOTP and ActivateRegistration load
  # the public key to authenticate qat1 locally. No operation uses kms:Verify.
  authority_runtime_sign_function = "${local.authority_function_prefix}-ia"
  authority_runtime_sign_role_arns = local.authority_runtime_functions_deploy ? [
    local.authority_runtime_exec_role_arn[local.authority_runtime_sign_function],
  ] : []

  # Operation → capability classification. Each list is the single source of
  # truth for the matching Lambda environment block (and, for the first three,
  # the IAM/endpoint principal grant via the *_role_arns locals below); keep
  # them here so a grant and its env var cannot drift apart, and so every
  # capability axis is stated once in one place.
  authority_public_key_operations = ["issue_assignment", "issue_registration_otp", "activate_registration"]
  authority_otp_operations        = ["issue_registration_otp", "activate_registration"]
  authority_ses_operations        = ["issue_registration_otp"]
  # Env-only axes (no principal grant): operations that consume the cell DNS
  # suffix (every op that mints or refreshes assignment endpoint data;
  # IssueRegistrationOTP intentionally excluded) and the admission-gated ops.
  authority_cell_dns_operations  = ["issue_assignment", "refresh_assignment", "issue_credential_recovery", "activate_registration", "complete_registration", "complete_credential_recovery"]
  authority_admission_operations = ["activate_registration", "complete_registration"]

  authority_runtime_public_key_role_arns = local.authority_runtime_functions_deploy ? sort([
    for function_name, fn in local.authority_runtime_functions :
    local.authority_runtime_exec_role_arn[function_name]
    if contains(local.authority_public_key_operations, fn.operation)
  ]) : []

  authority_runtime_otp_role_arns = local.authority_runtime_functions_deploy ? sort([
    for function_name, fn in local.authority_runtime_functions :
    local.authority_runtime_exec_role_arn[function_name]
    if contains(local.authority_otp_operations, fn.operation)
  ]) : []
  authority_runtime_ses_role_arns = local.authority_runtime_functions_deploy ? sort([
    for function_name, fn in local.authority_runtime_functions :
    local.authority_runtime_exec_role_arn[function_name]
    if contains(local.authority_ses_operations, fn.operation)
  ]) : []

  # Environment-owned public cell DNS suffix (LayerV-owned; leading dot). It
  # matches the live native-UDP cell endpoints (e.g. cell0.nhp.layerv.xyz) and
  # is required by every operation that mints or refreshes assignment endpoint
  # data. IssueRegistrationOTP verifies an existing assignment ticket but
  # intentionally does not consume the suffix. The runtime contract does not
  # carry it, so it is derived from the environment domain here.
  authority_cell_dns_suffix = local.is_prod ? ".nhp.layerv.ai" : ".nhp.layerv.xyz"

  authority_runtime_log_retention_days = local.is_prod ? 365 : 30

  # ----------------------------------------------------------------------------
  # Operation-specific least-privilege execution policy.
  #
  # RECONCILED against the live handler in layervai/qurl-service (origin/main
  # internal/connectorauthorityruntime + internal/connectorauthority +
  # internal/repository/dynamodb). DynamoDB SSE with the authority data CMK is
  # applied by the DynamoDB service under the table grant, so an execution role
  # needs NO KMS permission for table access; each op still needs
  # dynamodb:DescribeTable to READ and verify that SSE key at cold start. KMS on
  # the identity layer is the qat1 assignment-ticket key for IssueAssignment
  # ONLY (GetPublicKey to load the key, Sign to mint the ticket); RefreshAssignment
  # and IssueCredentialRecovery construct no KMS client at all. ENI lifecycle
  # keeps the AWS-required Resource="*" (plan-sanctioned); no other statement
  # uses that escape.
  # ----------------------------------------------------------------------------
  authority_runtime_common_exec_statements = local.authority_runtime_functions_deploy ? [
    {
      Sid    = "LambdaVpcEni"
      Effect = "Allow"
      Action = [
        "ec2:AssignPrivateIpAddresses",
        "ec2:CreateNetworkInterface",
        "ec2:DeleteNetworkInterface",
        "ec2:DescribeNetworkInterfaces",
        "ec2:UnassignPrivateIpAddresses",
      ]
      Resource = "*"
    },
  ] : []

  # The 4 canonical tables reached by the complete runtime. api_key_idempotency
  # is intentionally excluded: no Authority constructor reaches it. Ungated so
  # the dependency-endpoint policy locals in endpoints.tf can reference them
  # even while the runtime is dark; they are only ever selected when deploying.
  authority_runtime_table_arns = {
    api_keys            = aws_dynamodb_table.api_keys.arn
    agent_keys          = aws_dynamodb_table.agent_keys.arn
    customers           = aws_dynamodb_table.customers.arn
    connector_authority = aws_dynamodb_table.connector_authority.arn
  }

  # Read = strongly consistent GetItem/Query plus the transaction ConditionCheck
  # verb, plus DescribeTable: EVERY operation verifies its selected Control tables'
  # SSE-KMS key at cold start before it can reach READY
  # (connectorauthorityruntime/dynamodb_sse.go verifySelectedControlTableEncryption).
  # BatchGetItem/TransactGetItems are dropped: no operation composes them, and a
  # read inside a transaction is authorized by GetItem, not a Transact* action.
  authority_runtime_ddb_read_actions = [
    "dynamodb:ConditionCheckItem",
    "dynamodb:DescribeTable",
    "dynamodb:GetItem",
    "dynamodb:Query",
  ]
  # The single-item replay tombstone both Hub request ops (issue/refresh) compose
  # as a TransactWriteItems{Put} on connector_authority
  # (repository/dynamodb/hub_request_replay_repo.go). A Put inside a transaction
  # is authorized by dynamodb:PutItem, not a Transact* action.
  authority_runtime_ddb_replay_write_actions = ["dynamodb:PutItem"]
  # IssueCredentialRecovery additionally UPDATEs the device-credential head anchor
  # on the first grant (agent_credential_recovery_repo.go recoveryHeadTransactionItem),
  # so it needs UpdateItem beyond the replay/grant Puts. DeleteItem is unused by
  # every operation and dropped.
  authority_runtime_ddb_recovery_write_actions = ["dynamodb:PutItem", "dynamodb:UpdateItem"]

  # Table resources. Only agent_keys is read through a GSI (the pubkey index in
  # agent_keys_repo.go GetByPublicKey, used by refresh/recovery identity
  # resolution); api_keys and connector_authority are reached only by primary key
  # (GetItem / base-table Query), so they get no /index/* grant.
  authority_runtime_table_resources = {
    api_keys            = [local.authority_runtime_table_arns.api_keys]
    agent_keys          = [local.authority_runtime_table_arns.agent_keys, "${local.authority_runtime_table_arns.agent_keys}/index/*"]
    customers           = [local.authority_runtime_table_arns.customers]
    connector_authority = [local.authority_runtime_table_arns.connector_authority]
  }

  authority_runtime_ses_identity_arn   = "arn:${data.aws_partition.current.partition}:ses:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:identity/${local.otp_sender_domain}"
  authority_runtime_ses_config_set_arn = "arn:${data.aws_partition.current.partition}:ses:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:configuration-set/${var.ses_configuration_set_name}"
  authority_runtime_redis_cache_arn    = "arn:${data.aws_partition.current.partition}:elasticache:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:serverlesscache:${aws_elasticache_serverless_cache.otp.name}"

  authority_runtime_qat1_public_key_statement = {
    Sid      = "Qat1PublicKey"
    Effect   = "Allow"
    Action   = ["kms:GetPublicKey"]
    Resource = [aws_kms_key.qat1_signing.arn]
  }
  authority_runtime_otp_secret_statements = [
    {
      Sid      = "OTPSecretRead"
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [aws_secretsmanager_secret.otp_pepper.arn]
    },
    {
      Sid      = "OTPSecretDecrypt"
      Effect   = "Allow"
      Action   = ["kms:Decrypt"]
      Resource = [aws_kms_key.authority_data.arn]
      Condition = {
        StringEquals = {
          "kms:ViaService"                  = "secretsmanager.${data.aws_region.current.region}.${data.aws_partition.current.dns_suffix}"
          "kms:EncryptionContext:SecretARN" = aws_secretsmanager_secret.otp_pepper.arn
        }
      }
    },
  ]

  # Per-operation statement lists. Every operation gets the common ENI statement,
  # a scoped CloudWatch Logs write to its own log group, and its exact — handler-
  # verified — data dependencies. Every resource is a concrete ARN (no wildcard).
  authority_runtime_operation_statements = {
    # IssueAssignment: reads the credential (api_keys) + authority placement rows
    # (connector_authority); writes only its single-item replay tombstone (Put)
    # to connector_authority; signs the assignment ticket with qat1.
    issue_assignment = [
      {
        Sid      = "AuthorityReads"
        Effect   = "Allow"
        Action   = local.authority_runtime_ddb_read_actions
        Resource = concat(local.authority_runtime_table_resources.api_keys, local.authority_runtime_table_resources.connector_authority)
      },
      {
        Sid      = "AuthorityReplayWrite"
        Effect   = "Allow"
        Action   = local.authority_runtime_ddb_replay_write_actions
        Resource = local.authority_runtime_table_resources.connector_authority
      },
      {
        Sid      = "Qat1Sign"
        Effect   = "Allow"
        Action   = ["kms:GetPublicKey", "kms:Sign"]
        Resource = [aws_kms_key.qat1_signing.arn]
      },
    ]
    # RefreshAssignment: strong agent-identity (agent_keys, incl. its pubkey GSI)
    # and authority-placement reads; writes only its single-item replay tombstone
    # (Put) to connector_authority. It builds NO KMS client (read-only domain
    # service; ticket verification is local p256, not kms:Verify).
    refresh_assignment = [
      {
        Sid      = "AuthorityReads"
        Effect   = "Allow"
        Action   = local.authority_runtime_ddb_read_actions
        Resource = concat(local.authority_runtime_table_resources.agent_keys, local.authority_runtime_table_resources.connector_authority)
      },
      {
        Sid      = "AuthorityReplayWrite"
        Effect   = "Allow"
        Action   = local.authority_runtime_ddb_replay_write_actions
        Resource = local.authority_runtime_table_resources.connector_authority
      },
    ]
    # IssueCredentialRecovery: api-key/agent/authority reads; its recovery
    # transaction WRITES only connector_authority (replay + grant Puts, first-grant
    # head-anchor Update). api_keys/agent_keys are touched only via ConditionCheck,
    # authorized by dynamodb:ConditionCheckItem in the read set. It builds NO KMS client.
    issue_credential_recovery = [
      {
        Sid    = "AuthorityReads"
        Effect = "Allow"
        Action = local.authority_runtime_ddb_read_actions
        Resource = concat(
          local.authority_runtime_table_resources.api_keys,
          local.authority_runtime_table_resources.agent_keys,
          local.authority_runtime_table_resources.connector_authority,
        )
      },
      {
        Sid      = "AuthorityRecoveryWrite"
        Effect   = "Allow"
        Action   = local.authority_runtime_ddb_recovery_write_actions
        Resource = local.authority_runtime_table_resources.connector_authority
      },
    ]
    issue_registration_otp = concat(
      [
        {
          Sid      = "AuthorityReads"
          Effect   = "Allow"
          Action   = local.authority_runtime_ddb_read_actions
          Resource = concat(local.authority_runtime_table_resources.api_keys, local.authority_runtime_table_resources.customers)
        },
        local.authority_runtime_qat1_public_key_statement,
      ],
      local.authority_runtime_otp_secret_statements,
      [
        {
          Sid      = "OTPRedisConnect"
          Effect   = "Allow"
          Action   = ["elasticache:Connect"]
          Resource = [local.authority_runtime_redis_cache_arn, aws_elasticache_user.otp_issuer.arn]
        },
        {
          Sid      = "OTPSendEmail"
          Effect   = "Allow"
          Action   = ["ses:SendEmail"]
          Resource = [local.authority_runtime_ses_identity_arn, local.authority_runtime_ses_config_set_arn]
        },
      ],
    )
    activate_registration = concat(
      [
        {
          Sid      = "AuthorityReads"
          Effect   = "Allow"
          Action   = local.authority_runtime_ddb_read_actions
          Resource = concat(local.authority_runtime_table_resources.api_keys, local.authority_runtime_table_resources.agent_keys, local.authority_runtime_table_resources.connector_authority)
        },
        {
          Sid      = "RegistrationCredentialWrite"
          Effect   = "Allow"
          Action   = ["dynamodb:UpdateItem"]
          Resource = local.authority_runtime_table_resources.api_keys
        },
        {
          Sid      = "RegistrationIdentityWrite"
          Effect   = "Allow"
          Action   = ["dynamodb:PutItem", "dynamodb:UpdateItem"]
          Resource = [local.authority_runtime_table_arns.agent_keys]
        },
        {
          Sid      = "RegistrationAuthorityWrite"
          Effect   = "Allow"
          Action   = ["dynamodb:PutItem", "dynamodb:UpdateItem"]
          Resource = local.authority_runtime_table_resources.connector_authority
        },
        local.authority_runtime_qat1_public_key_statement,
      ],
      local.authority_runtime_otp_secret_statements,
      [{
        Sid      = "OTPRedisConnect"
        Effect   = "Allow"
        Action   = ["elasticache:Connect"]
        Resource = [local.authority_runtime_redis_cache_arn, aws_elasticache_user.otp_activator.arn]
      }],
    )
    complete_registration = [
      {
        Sid      = "AuthorityReads"
        Effect   = "Allow"
        Action   = local.authority_runtime_ddb_read_actions
        Resource = concat(local.authority_runtime_table_resources.api_keys, local.authority_runtime_table_resources.agent_keys, local.authority_runtime_table_resources.connector_authority)
      },
      {
        Sid      = "RegistrationCredentialWrite"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem", "dynamodb:UpdateItem"]
        Resource = local.authority_runtime_table_resources.api_keys
      },
      {
        Sid      = "RegistrationAuthorityWrite"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = local.authority_runtime_table_resources.connector_authority
      },
    ]
    complete_credential_recovery = [
      {
        Sid      = "AuthorityReads"
        Effect   = "Allow"
        Action   = local.authority_runtime_ddb_read_actions
        Resource = concat(local.authority_runtime_table_resources.api_keys, local.authority_runtime_table_resources.agent_keys, local.authority_runtime_table_resources.connector_authority)
      },
      {
        Sid      = "RecoveryCredentialWrite"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem", "dynamodb:UpdateItem"]
        Resource = local.authority_runtime_table_resources.api_keys
      },
      {
        Sid      = "RecoveryAuthorityWrite"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = local.authority_runtime_table_resources.connector_authority
      },
    ]
  }

  authority_runtime_environment = local.authority_runtime_functions_deploy ? {
    for function_name, fn in local.authority_runtime_functions :
    function_name => merge(
      {
        CONNECTOR_AUTHORITY_OPERATION        = local.authority_operation_conformance_name[fn.operation]
        CONNECTOR_AUTHORITY_ENVIRONMENT_ID   = var.environment
        CONNECTOR_AUTHORITY_ACCOUNT_ID       = data.aws_caller_identity.current.account_id
        CONNECTOR_AUTHORITY_HOME_REGION      = data.aws_region.current.region
        CONNECTOR_AUTHORITY_DATA_KMS_KEY_ARN = aws_kms_key.authority_data.arn
      },
      fn.cell_id == "" ? {} : {
        CONNECTOR_AUTHORITY_CELL_ID = fn.cell_id
      },
      contains(local.authority_cell_dns_operations, fn.operation) ? {
        CONNECTOR_AUTHORITY_CELL_DNS_SUFFIX = local.authority_cell_dns_suffix
      } : {},
      contains(local.authority_public_key_operations, fn.operation) ? {
        CONNECTOR_AUTHORITY_ASSIGNMENT_KEY_ALIAS_ARN = aws_kms_alias.qat1_signing.arn
        CONNECTOR_AUTHORITY_ASSIGNMENT_KEY_KID       = tostring(var.authority_runtime_contract.qat1_kid)
      } : {},
      contains(local.authority_otp_operations, fn.operation) ? {
        CONNECTOR_AUTHORITY_REDIS_ENDPOINT        = "${aws_elasticache_serverless_cache.otp.endpoint[0].address}:6379"
        CONNECTOR_AUTHORITY_REDIS_CACHE_NAME      = aws_elasticache_serverless_cache.otp.name
        CONNECTOR_AUTHORITY_REDIS_USER_ID         = fn.operation == "issue_registration_otp" ? aws_elasticache_user.otp_issuer.user_id : aws_elasticache_user.otp_activator.user_id
        CONNECTOR_AUTHORITY_OTP_PEPPER_SECRET_ARN = aws_secretsmanager_secret.otp_pepper.arn
      } : {},
      contains(local.authority_ses_operations, fn.operation) ? {
        CONNECTOR_AUTHORITY_OTP_EMAIL_FROM            = var.otp_email_from
        CONNECTOR_AUTHORITY_OTP_SES_CONFIGURATION_SET = var.ses_configuration_set_name
      } : {},
      contains(local.authority_admission_operations, fn.operation) ? {
        CONNECTOR_AUTHORITY_ADMISSION_REQUESTS_PER_SECOND = tostring(local.authority_contract_cell_workers[fn.cell_id].preinvoke_rate_limits[fn.operation].refill_per_second)
        CONNECTOR_AUTHORITY_ADMISSION_BURST               = tostring(local.authority_contract_cell_workers[fn.cell_id].preinvoke_rate_limits[fn.operation].burst)
        CONNECTOR_AUTHORITY_ADMISSION_MAX_IN_FLIGHT       = tostring(local.authority_contract_cell_workers[fn.cell_id].preinvoke_limits[fn.operation])
      } : {},
    )
  } : {}
}

# One dedicated security group for every Authority function ENI. Egress is
# limited to HTTPS toward the interface endpoints and the DynamoDB
# gateway prefix list; the endpoint policies are the finer, principal-scoped
# gate. No ingress: nothing dials the functions on the network path — callers
# reach them only through the Lambda service's private Invoke transport.
resource "aws_security_group" "authority_lambda" {
  count = local.authority_runtime_functions_deploy ? 1 : 0

  # Generation 2 deliberately replaces the legacy inline-rule-owned sandbox
  # group. Merely omitting those inline rules would leave its VPC-CIDR egress
  # unmanaged alongside the standalone rules below. The replacement starts
  # with no implicit rules, after which Terraform owns every allowed path as an
  # exact standalone rule.
  name_prefix = "${local.name_prefix}-ca-fn-v2-"
  description = "Connector Authority function ENIs; egress to Control dependency endpoints only"
  vpc_id      = aws_vpc.control.id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-ca-fn"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Egress is HTTPS only. The interface endpoints are reached through an exact
# SG-to-SG rule; their ingress is scoped back to this function SG and endpoint
# policies are the finer principal/resource gate. DynamoDB uses the gateway
# endpoint's managed prefix list.
resource "aws_vpc_security_group_egress_rule" "authority_interface_endpoints" {
  count = local.authority_runtime_functions_deploy ? 1 : 0

  security_group_id            = aws_security_group.authority_lambda[0].id
  referenced_security_group_id = aws_security_group.interface_endpoints.id
  description                  = "HTTPS to Control interface endpoints"
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "authority_dynamodb" {
  count = local.authority_runtime_functions_deploy ? 1 : 0

  security_group_id = aws_security_group.authority_lambda[0].id
  prefix_list_id    = aws_vpc_endpoint.dynamodb.prefix_list_id
  description       = "HTTPS to the DynamoDB gateway endpoint"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

# Only the OTP issuer/activator functions have IAM permission to connect. The
# shared function SG opens the network path solely to the Redis SG on TLS/6379;
# Redis IAM users remain the per-operation authorization boundary.
resource "aws_vpc_security_group_egress_rule" "authority_otp_redis" {
  count = local.authority_runtime_functions_deploy ? 1 : 0

  security_group_id            = aws_security_group.authority_lambda[0].id
  referenced_security_group_id = aws_security_group.otp_redis.id
  description                  = "TLS to Connector OTP Redis"
  from_port                    = 6379
  to_port                      = 6379
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "otp_redis_authority" {
  count = local.authority_runtime_functions_deploy ? 1 : 0

  security_group_id            = aws_security_group.otp_redis.id
  referenced_security_group_id = aws_security_group.authority_lambda[0].id
  description                  = "TLS from Connector Authority OTP functions"
  from_port                    = 6379
  to_port                      = 6379
  ip_protocol                  = "tcp"
}

resource "aws_cloudwatch_log_group" "authority" {
  for_each = local.authority_runtime_functions

  name              = "/aws/lambda/${each.key}"
  retention_in_days = local.authority_runtime_log_retention_days

  # Default AWS-managed log encryption is intentional for this substrate:
  # payloads are forbidden from logs, and reusing authority_data would require
  # broadening its byte-reviewed policy to the CloudWatch Logs service. If a
  # customer-managed log key becomes a requirement, use a dedicated logs key
  # and exact Lambda log-group encryption context instead of widening the
  # Authority data-key boundary.

  tags = merge(local.common_tags, {
    Name      = "/aws/lambda/${each.key}"
    Operation = each.value.operation
  })
}

resource "aws_iam_role" "authority_exec" {
  for_each = local.authority_runtime_functions

  name                 = local.authority_runtime_exec_role_name[each.key]
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
      # NO confused-deputy Condition. This is a Lambda EXECUTION role: the Lambda
      # Hyperplane assumes it to create the function's VPC ENI in a context that
      # does NOT carry the function's aws:SourceArn, so an ArnEquals SourceArn
      # (or SourceAccount) condition denies that assume and the function fails to
      # reach Active with InsufficientRolePermissions. The role is usable only by
      # the function wired to it (the function's role= attribute), never by
      # arbitrary assumption, so the bare lambda-principal trust is both the
      # correct least privilege AND the only trust that lets a VPC function init.
    }]
  })

  tags = merge(local.common_tags, {
    Name      = local.authority_runtime_exec_role_name[each.key]
    Operation = each.value.operation
  })
}

resource "aws_iam_role_policy" "authority_exec" {
  for_each = local.authority_runtime_functions

  name = "connector-authority-${each.value.operation}"
  role = aws_iam_role.authority_exec[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      local.authority_runtime_common_exec_statements,
      [
        {
          Sid    = "OwnLogStream"
          Effect = "Allow"
          Action = ["logs:CreateLogStream", "logs:PutLogEvents"]
          # Constructed ARN (not aws_cloudwatch_log_group.authority[*].arn) so the
          # whole policy is known at plan time and its scope is checkable; the log
          # group is created in the same slice and gated identically.
          Resource = ["${local.authority_runtime_log_group_arn[each.key]}:*"]
        },
      ],
      local.authority_runtime_operation_statements[each.value.operation],
    )
  })
}

resource "aws_lambda_function" "authority" {
  for_each = local.authority_runtime_functions

  function_name = each.key
  description   = "Connector Authority ${each.value.operation} (${var.environment})"
  role          = aws_iam_role.authority_exec[each.key].arn
  package_type  = "Image"
  image_uri     = local.authority_runtime_image_uri

  # FLAG (POST-STEP-3 VERIFY): must match the published qurl-connector-authority
  # image architecture (docker/Dockerfile.connector-authority-lambda in
  # layervai/qurl-service). A mismatch fails the function at create. Confirm
  # before apply.
  architectures = ["x86_64"]

  # The immutable startup graph may consume up to ~9s; keep the whole request
  # inside the source-derived structural ladder. FLAG: resolve the exact
  # timeout/memory empirically against the handler's staged latency proof.
  timeout     = 10
  memory_size = 512
  publish     = true

  # One function-wide ceiling across every version and alias, pinned to the
  # bound contract's steady reserved envelope.
  reserved_concurrent_executions = each.value.spec.steady_reserved_concurrency

  vpc_config {
    subnet_ids         = aws_subnet.isolated[*].id
    security_group_ids = [aws_security_group.authority_lambda[0].id]
  }

  # Immutable operation/config identity, matched EXACTLY to the handler's config
  # contract (layervai/qurl-service connectorauthorityruntime/config.go). The
  # payload never echoes or selects these. A missing/mismatched key fails the
  # function closed at init (the intended dark behavior, not a reachable RPC).
  # AWS_REGION, AWS_LAMBDA_FUNCTION_NAME, and AWS_LAMBDA_FUNCTION_VERSION are
  # supplied by the Lambda runtime and are also required by the handler; they
  # must NOT be set here. QAT1 alias/kid are read only by IssueAssignment but are
  # published uniformly (the handler ignores unread keys); the DATA CMK ARN is
  # the SSE key each op verifies at cold start via DescribeTable.
  environment {
    variables = local.authority_runtime_environment[each.key]
  }

  depends_on = [
    aws_cloudwatch_log_group.authority,
    aws_iam_role_policy.authority_exec,
  ]

  tags = merge(local.common_tags, {
    Name      = each.key
    Operation = each.value.operation
  })
}

resource "aws_lambda_alias" "authority" {
  for_each = local.authority_runtime_aliases

  name             = each.value.color
  description      = "Closed ${each.value.color} deployment qualifier"
  function_name    = aws_lambda_function.authority[each.value.function_name].function_name
  function_version = aws_lambda_function.authority[each.value.function_name].version
}

# Initial-bootstrap steady state: only the caller-selected color receives
# provisioned capacity. The contract's rollout active/standby allocation and
# rollback-retention fields are validation-only in this slice; NHP #3456 tracks
# consuming them in the governed version-roll/alias-switch/rollback lifecycle.
# The startup graph cannot fit inside the request path, so unprovisioned
# authority work is forbidden; the handler additionally rejects any non
# provisioned-concurrency initialization type.
resource "aws_lambda_provisioned_concurrency_config" "authority" {
  for_each = local.authority_runtime_functions

  function_name                     = aws_lambda_function.authority[each.key].function_name
  qualifier                         = aws_lambda_alias.authority["${each.key}:${local.authority_runtime_selected_color}"].name
  provisioned_concurrent_executions = each.value.spec.steady_provisioned_concurrency

  # Provisioned-concurrency initialization runs the startup graph, which reaches
  # KMS (interface endpoint) and DynamoDB (gateway endpoint) through the Control
  # endpoints. Force the lockstep opening (endpoint policies + the interface-SG
  # 443 ingress from the function SG) to land first so the allocation can reach
  # READY instead of failing init closed.
  depends_on = [
    aws_vpc_endpoint.dynamodb,
    aws_vpc_endpoint.interface,
    aws_security_group.interface_endpoints,
    aws_security_group.authority_lambda,
  ]
}

# The rollout-aborting invariant: provisioned-concurrency spillover must remain
# exactly zero. NHP #3455 tracks operator alarm_actions (SNS) wiring plus the
# Throttles/Errors/Duration and custom admission/initialization-type alarms;
# this slice lands the security-critical spillover guard without inventing an
# unowned notification destination in the new Control root.
resource "aws_cloudwatch_metric_alarm" "authority_spillover" {
  for_each = local.authority_runtime_functions

  alarm_name          = "${each.key}-provisioned-concurrency-spillover"
  alarm_description   = "Connector Authority ${each.value.operation} spilled to an on-demand environment; a nonzero value aborts the rollout."
  namespace           = "AWS/Lambda"
  metric_name         = "ProvisionedConcurrencySpilloverInvocations"
  statistic           = "Sum"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  period              = 60
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  # Aggregate across both aliases deliberately: any active or standby
  # spillover violates the function-wide zero-spillover invariant.
  dimensions = {
    FunctionName = each.key
  }

  tags = merge(local.common_tags, {
    Name      = "${each.key}-provisioned-concurrency-spillover"
    Operation = each.value.operation
  })
}
