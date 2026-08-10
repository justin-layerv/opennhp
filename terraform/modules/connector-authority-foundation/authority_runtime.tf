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

  authority_proof_policy_consumer_functions = {
    for function_name, fn in local.authority_runtime_functions :
    function_name => fn
    if contains(local.authority_proof_policy_consumer_operations, fn.operation)
  }

  # Release-critical attended-proof rollout only. The ordinary contract remains
  # fixed on its reviewed blue selector; these two explicit colors own the
  # bounded IA/RA/ICR + ca-pm rehearsal without generalising the complete
  # eleven-function rollout system. Both must be null or both closed colors.
  authority_proof_policy_rollout_active = (
    var.authority_proof_policy_selected_color != null &&
    var.authority_proof_policy_prepared_color != null
  )
  authority_proof_policy_effective_color = (
    local.authority_proof_policy_rollout_active
    ? var.authority_proof_policy_selected_color
    : (
      local.authority_runtime_contract_enabled
      ? var.authority_runtime_contract.selected_authority_color
      : "blue"
    )
  )
  authority_proof_policy_standby_color = (
    try(var.authority_runtime_contract.selected_authority_color == "blue", true)
    ? "green"
    : "blue"
  )
  authority_proof_policy_rollout_functions = merge(
    local.authority_proof_policy_consumer_functions,
    {
      for function_name, fn in local.authority_runtime_functions :
      function_name => fn
      if fn.operation == "mutate_proof_agent"
    },
  )
  authority_proof_policy_rollout_function_names = toset(
    keys(local.authority_proof_policy_rollout_functions)
  )
  # Consumer aliases are pinned as soon as their proof-aware versions are
  # staged. During a rollout, pin ca-pm as well: its selected alias must remain
  # on the live version while the prepared alias receives a distinct published
  # version and its own provisioned pool.
  authority_proof_policy_pinned_functions = merge(
    local.authority_proof_policy_consumer_functions,
    local.authority_proof_policy_rollout_active ? {
      for function_name, fn in local.authority_runtime_functions :
      function_name => fn
      if fn.operation == "mutate_proof_agent"
    } : {},
  )
  authority_proof_policy_rollout_alias_arns = local.authority_proof_policy_rollout_active ? {
    for function_name, fn in local.authority_proof_policy_rollout_functions :
    function_name => {
      for color in local.authority_runtime_alias_colors :
      color => "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:function:${function_name}:${color}"
    }
  } : {}

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
  authority_cell_dns_operations  = ["issue_assignment", "refresh_assignment", "issue_credential_recovery", "activate_registration", "complete_registration", "complete_credential_recovery", "mutate_proof_agent", "prepare_proof_credential_recovery"]
  authority_admission_operations = ["activate_registration", "complete_registration"]
  # Attended-proof axis. ca-pm owns the mutation capability. IA/RA/ICR receive
  # a staged proof-aware version while both live aliases remain unchanged; a
  # separate governed zero-spill rollout must activate that version.
  authority_proof_policy_consumer_operations = [
    "issue_assignment",
    "refresh_assignment",
    "issue_credential_recovery",
  ]
  authority_proof_operations = distinct(concat(
    keys(local.authority_contract_proof_operation_suffixes),
    var.authority_proof_policy_consumers_staged ? local.authority_proof_policy_consumer_operations : [],
  ))
  # The shared qurl-service proof-policy reader constructor validates the
  # directive TTL and minimum lease even for IA/RA/ICR, while ca-pcr has a
  # separate owner/prefix-only recovery identity contract.
  authority_proof_policy_operations = [
    for operation in local.authority_proof_operations : operation
    if operation != "prepare_proof_credential_recovery"
  ]

  # The uniquely tagged ephemeral agent namespace the control may address. It
  # matches the attended proof harness's generated identity
  # (qurl-go-sandbox-<run id>-<run attempt>), so an agent id outside this
  # namespace is refused by the handler even inside the proof tenant.
  authority_proof_agent_id_prefix = "qurl-go-sandbox-"
  # A proof directive is single-run scoped. It expires well inside the attended
  # job's own 75-minute ceiling so an abandoned run cannot leave an armed
  # mutation behind.
  authority_proof_directive_ttl_seconds = 5400
  # Floor on a shortened proof lease. Short enough to prove expiry inside the
  # attended run, long enough that the client cannot mistake it for a failure.
  authority_proof_minimum_lease_seconds = 30

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
  # internal/repository/dynamodb). DynamoDB invokes the authority data CMK with
  # the caller's execution-role credentials, so every operation needs
  # kms:Decrypt on that exact key through DynamoDB in addition to its exact
  # table-scoped DynamoDB grant. Each op also needs dynamodb:DescribeTable to
  # read and verify that SSE key at cold start. KMS on the identity layer is the
  # separate qat1 assignment-ticket key for IssueAssignment only (GetPublicKey
  # to load the key, Sign to mint the ticket). ENI lifecycle keeps the
  # AWS-required Resource="*" (plan-sanctioned); no other statement uses that
  # escape.
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

  # DynamoDB performs the CMK call on behalf of the Lambda execution role. Keep
  # this distinct from direct KMS use: the exact authority-data key is usable
  # only when the request comes through DynamoDB, while the operation's
  # table-scoped DynamoDB statements remain the finer data boundary. ca-pm
  # retains its separately named proof grant because its policy is independently
  # byte-checked as an attended mutation capability.
  authority_runtime_dynamodb_decrypt_statements = local.authority_runtime_functions_deploy ? [{
    Sid      = "AuthorityDynamoDBDecrypt"
    Effect   = "Allow"
    Action   = ["kms:Decrypt"]
    Resource = [aws_kms_key.authority_data.arn]
    Condition = {
      StringEquals = {
        "kms:ViaService" = "dynamodb.${data.aws_region.current.region}.${data.aws_partition.current.dns_suffix}"
      }
    }
  }] : []

  # The 5 canonical tables reached by the complete runtime. The attended proof
  # recovery constructor uses api_key_idempotency for replay-safe credential
  # minting. Ungated so
  # the dependency-endpoint policy locals in endpoints.tf can reference them
  # even while the runtime is dark; they are only ever selected when deploying.
  authority_runtime_table_arns = {
    api_keys            = aws_dynamodb_table.api_keys.arn
    agent_keys          = aws_dynamodb_table.agent_keys.arn
    customers           = aws_dynamodb_table.customers.arn
    api_key_idempotency = aws_dynamodb_table.api_key_idempotency.arn
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
  # The item-level subset. dynamodb:LeadingKeys is a key-context condition, so a
  # statement that also carries the table-level DescribeTable would never match
  # and the function could not verify SSE at cold start. The attended-proof
  # operation therefore splits DescribeTable into its own unconditioned
  # statement and fences only these.
  authority_runtime_ddb_read_actions_without_describe = [
    "dynamodb:ConditionCheckItem",
    "dynamodb:GetItem",
    "dynamodb:Query",
  ]
  # The single-item replay tombstone both Hub request ops (issue/refresh) compose
  # as a TransactWriteItems{Put} on connector_authority
  # (repository/dynamodb/hub_request_replay_repo.go). A Put inside a transaction
  # is authorized by dynamodb:PutItem, not a Transact* action.
  authority_runtime_ddb_replay_write_actions = ["dynamodb:PutItem"]
  # The assignment-ticket handle store's partition-key prefix. The issuer writes
  # these rows and the verifiers resolve them; stated once so the write grant and
  # the read grant cannot drift apart.
  #
  # It is deliberately NOT folded into the replay grant above. That grant means
  # "may write its own replay tombstone" and should keep meaning exactly that;
  # widening it would make a future reviewer read one prefix list and believe it
  # covers both purposes.
  authority_runtime_ticket_handle_leading_keys = ["ASSIGNMENT_TICKET#*"]
  # Its own action list, deliberately not an alias of the replay one. The whole
  # point of a separate Sid is that these are distinct purposes; sharing the
  # action local would let the replay grant gaining an action silently widen
  # the handle grant too, which is the coupling the split exists to prevent.
  authority_runtime_ddb_ticket_handle_write_actions = ["dynamodb:PutItem"]
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
    api_keys              = [local.authority_runtime_table_arns.api_keys]
    api_keys_with_indexes = [local.authority_runtime_table_arns.api_keys, "${local.authority_runtime_table_arns.api_keys}/index/*"]
    agent_keys            = [local.authority_runtime_table_arns.agent_keys, "${local.authority_runtime_table_arns.agent_keys}/index/*"]
    customers             = [local.authority_runtime_table_arns.customers]
    api_key_idempotency   = [local.authority_runtime_table_arns.api_key_idempotency]
    connector_authority   = [local.authority_runtime_table_arns.connector_authority]
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
  # The attended-proof family is merged in separately and is empty unless its
  # sandbox-only gate is on.
  authority_runtime_operation_statements = merge({
    # IssueAssignment: reads the credential (api_keys) + authority placement rows
    # (connector_authority); writes only its single-item replay tombstone (Put)
    # to connector_authority; signs the assignment ticket with qat1.
    issue_assignment = concat([
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
        Condition = {
          "ForAllValues:StringLike" = {
            "dynamodb:LeadingKeys" = ["HUB_REQUEST#IssueAssignment#*"]
          }
          Null = {
            "dynamodb:LeadingKeys" = "false"
          }
        }
      },
      {
        # The signed ticket no longer travels in the assignment reply; it is
        # stored here under an unguessable handle and the reply carries the
        # handle. Without this grant the issuer fails closed -- it refuses to
        # publish a handle whose write it cannot prove -- so enrollment stops
        # rather than degrading, which is how the gap was found in sandbox.
        Sid      = "AuthorityTicketHandleWrite"
        Effect   = "Allow"
        Action   = local.authority_runtime_ddb_ticket_handle_write_actions
        Resource = local.authority_runtime_table_resources.connector_authority
        Condition = {
          "ForAllValues:StringLike" = {
            "dynamodb:LeadingKeys" = local.authority_runtime_ticket_handle_leading_keys
          }
          Null = {
            "dynamodb:LeadingKeys" = "false"
          }
        }
      },
      {
        Sid      = "Qat1Sign"
        Effect   = "Allow"
        Action   = ["kms:GetPublicKey", "kms:Sign"]
        Resource = [aws_kms_key.qat1_signing.arn]
      },
      ], [
      for statement in local.authority_runtime_proof_policy_consumer_statements :
      statement if var.authority_proof_policy_consumers_staged
    ])
    # RefreshAssignment: strong agent-identity (agent_keys, incl. its pubkey GSI)
    # and authority-placement reads; writes only its single-item replay tombstone
    # (Put) to connector_authority. It builds no direct KMS client (ticket
    # verification is local p256); the DynamoDB-mediated decrypt grant above
    # still applies to its encrypted table reads.
    refresh_assignment = concat([
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
        Condition = {
          "ForAllValues:StringLike" = {
            "dynamodb:LeadingKeys" = ["HUB_REQUEST#RefreshAssignment#*"]
          }
          Null = {
            "dynamodb:LeadingKeys" = "false"
          }
        }
      },
      ], [
      for statement in local.authority_runtime_proof_policy_consumer_statements :
      statement if var.authority_proof_policy_consumers_staged
    ])
    # IssueCredentialRecovery: api-key/agent/authority reads; its recovery
    # transaction WRITES only connector_authority (replay + grant Puts, first-grant
    # head-anchor Update). api_keys/agent_keys are touched only via ConditionCheck,
    # authorized by dynamodb:ConditionCheckItem in the read set. It builds no
    # direct KMS client; the DynamoDB-mediated decrypt grant above still applies.
    issue_credential_recovery = concat([
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
        Condition = {
          "ForAllValues:StringLike" = {
            "dynamodb:LeadingKeys" = [
              "CREDENTIAL_RECOVERY_GRANT#*",
              "CREDENTIAL_RECOVERY_ISSUE#*",
              "HUB_REQUEST#IssueCredentialRecovery#*",
              "OWNER#*",
            ]
          }
          Null = {
            "dynamodb:LeadingKeys" = "false"
          }
        }
      },
      ], [
      for statement in local.authority_runtime_proof_policy_consumer_statements :
      statement if var.authority_proof_policy_consumers_staged
    ])
    issue_registration_otp = concat(
      [
        {
          Sid      = "AuthorityReads"
          Effect   = "Allow"
          Action   = local.authority_runtime_ddb_read_actions
          Resource = concat(local.authority_runtime_table_resources.api_keys, local.authority_runtime_table_resources.customers)
        },
        {
          # This operation had no access to connector_authority at all, because
          # before the handle it never needed any -- the client carried the
          # signed ticket. GetItem only, and only the handle prefix: it resolves
          # a ticket, it does not read placement, replay or recovery state.
          Sid      = "AuthorityTicketHandleRead"
          Effect   = "Allow"
          Action   = ["dynamodb:GetItem"]
          Resource = local.authority_runtime_table_resources.connector_authority
          Condition = {
            "ForAllValues:StringLike" = {
              "dynamodb:LeadingKeys" = local.authority_runtime_ticket_handle_leading_keys
            }
            Null = {
              "dynamodb:LeadingKeys" = "false"
            }
          }
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
  }, local.authority_runtime_proof_mutation_operation_statements, local.authority_runtime_proof_recovery_operation_statements)

  authority_runtime_proof_policy_consumer_statements = [
    {
      Sid      = "ProofPolicyRead"
      Effect   = "Allow"
      Action   = ["dynamodb:GetItem"]
      Resource = local.authority_runtime_table_resources.connector_authority
      Condition = {
        "ForAllValues:StringEquals" = {
          "dynamodb:LeadingKeys" = [local.authority_proof_directive_partition_key]
        }
        Null = {
          "dynamodb:LeadingKeys" = "false"
        }
      }
    },
    {
      Sid      = "DenyProofPolicyWrite"
      Effect   = "Deny"
      Action   = ["dynamodb:DeleteItem", "dynamodb:PutItem", "dynamodb:UpdateItem"]
      Resource = local.authority_runtime_table_resources.connector_authority
      Condition = {
        "ForAnyValue:StringEquals" = {
          "dynamodb:LeadingKeys" = [local.authority_proof_directive_partition_key]
        }
        Null = {
          "dynamodb:LeadingKeys" = "false"
        }
      }
    },
  ]

  # MutateProofAgent: the attended-proof mutation control. It is the ONLY
  # Authority operation that writes an AGENT# placement row after activation, so
  # its execution policy carries the tightest fence in the module. Placement and
  # directive actions are constrained by dynamodb:LeadingKeys to exactly two
  # partitions -- the dedicated proof tenant's owner partition and the PROOF
  # directive partition. Replay actions have a separate, operation-scoped
  # HUB_REQUEST#MutateProofAgent#* fence.
  #
  # That fence is what makes the control safe independently of the handler. Even
  # a wholly incorrect MutateProofAgent build cannot read or write any other
  # tenant's placement, credential, or counter rows, because IAM denies the
  # request before DynamoDB evaluates it. It reaches only connector_authority:
  # api_keys, agent_keys, and customers are absent, so it can neither revoke a
  # device credential nor read an owner's credentials. (Device-credential
  # revocation for the proof agent is performed out of band through the existing
  # authenticated Control API path, not by this operation.)
  #
  # DescribeTable is unconditioned because it is a table-level call that carries
  # no key context; every item-level action below is fenced.
  authority_runtime_proof_mutation_operation_statements = length(local.authority_contract_proof_operation_suffixes) == 0 ? {} : {
    mutate_proof_agent = [
      {
        Sid      = "ProofVerifyTableEncryption"
        Effect   = "Allow"
        Action   = ["dynamodb:DescribeTable"]
        Resource = local.authority_runtime_table_resources.connector_authority
      },
      {
        # The connector-authority table uses the Control data CMK. DynamoDB
        # decrypts rows on the caller's behalf, so the proof function needs this
        # grant before its first replay GetItem can reach an absent-item result.
        Sid      = "ProofDynamoDBDecrypt"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [aws_kms_key.authority_data.arn]
        Condition = {
          StringEquals = {
            "kms:ViaService" = "dynamodb.${data.aws_region.current.region}.${data.aws_partition.current.dns_suffix}"
          }
        }
      },
      {
        Sid      = "ProofFencedPlacementRead"
        Effect   = "Allow"
        Action   = local.authority_runtime_ddb_read_actions_without_describe
        Resource = local.authority_runtime_table_resources.connector_authority
        Condition = {
          "ForAllValues:StringEquals" = {
            "dynamodb:LeadingKeys" = local.authority_runtime_proof_leading_keys
          }
          Null = {
            "dynamodb:LeadingKeys" = "false"
          }
        }
      },
      {
        # Read-only resolution of the target cell's endpoint, revision, and
        # server key, exactly as the ordinary placement reader does. REGISTRY is
        # deliberately absent from the write fence below, so the control can
        # read the catalog but can never edit it: cell provisioning stays
        # Terraform-owned.
        Sid      = "ProofRegistryRead"
        Effect   = "Allow"
        Action   = local.authority_runtime_ddb_read_actions_without_describe
        Resource = local.authority_runtime_table_resources.connector_authority
        Condition = {
          "ForAllValues:StringEquals" = {
            "dynamodb:LeadingKeys" = local.authority_runtime_proof_registry_leading_keys
          }
          Null = {
            "dynamodb:LeadingKeys" = "false"
          }
        }
      },
      {
        Sid    = "ProofFencedPlacementWrite"
        Effect = "Allow"
        # DeleteItem is deliberately absent: a proof move relocates and advances
        # placement, it never removes a row. UpdateItem covers the generation
        # advance and the active/moving transition; PutItem covers the directive
        # and the relocated dependent items.
        Action   = ["dynamodb:PutItem", "dynamodb:UpdateItem"]
        Resource = local.authority_runtime_table_resources.connector_authority
        Condition = {
          "ForAllValues:StringEquals" = {
            "dynamodb:LeadingKeys" = local.authority_runtime_proof_leading_keys
          }
          Null = {
            "dynamodb:LeadingKeys" = "false"
          }
        }
      },
      {
        # MutateProofAgent uses the same durable, request-id-scoped replay
        # protocol as the Hub operations. Keep it separate from the placement
        # fence: StringLike applies only to this operation's replay namespace,
        # never to generic HUB_REQUEST rows.
        Sid      = "ProofReplayReadWrite"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"]
        Resource = local.authority_runtime_table_resources.connector_authority
        Condition = {
          "ForAllValues:StringLike" = {
            "dynamodb:LeadingKeys" = local.authority_runtime_proof_replay_leading_keys
          }
          Null = {
            "dynamodb:LeadingKeys" = "false"
          }
        }
      },
    ]
  }

  authority_runtime_proof_recovery_operation_statements = length(local.authority_contract_proof_operation_suffixes) == 0 ? {} : {
    prepare_proof_credential_recovery = [
      {
        Sid    = "ProofRecoveryVerifyTableEncryption"
        Effect = "Allow"
        Action = ["dynamodb:DescribeTable"]
        Resource = concat(
          local.authority_runtime_table_resources.api_keys,
          local.authority_runtime_table_resources.api_key_idempotency,
          local.authority_runtime_table_resources.customers,
          local.authority_runtime_table_resources.connector_authority,
        )
      },
      {
        Sid    = "ProofRecoveryCredentialReadWrite"
        Effect = "Allow"
        Action = [
          "dynamodb:ConditionCheckItem",
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:Query",
          "dynamodb:UpdateItem",
        ]
        Resource = local.authority_runtime_table_resources.api_keys_with_indexes
      },
      {
        Sid      = "ProofRecoveryReplayReadWrite"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem"]
        Resource = local.authority_runtime_table_resources.api_key_idempotency
      },
      {
        Sid      = "ProofRecoveryOwnerRead"
        Effect   = "Allow"
        Action   = ["dynamodb:ConditionCheckItem", "dynamodb:GetItem"]
        Resource = local.authority_runtime_table_resources.customers
        Condition = {
          "ForAllValues:StringEquals" = {
            "dynamodb:LeadingKeys" = [var.authority_proof_mutation_owner_id]
          }
        }
      },
      {
        Sid      = "ProofRecoveryAssignmentReadWrite"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"]
        Resource = local.authority_runtime_table_resources.connector_authority
        Condition = {
          "ForAllValues:StringEquals" = {
            "dynamodb:LeadingKeys" = [local.authority_proof_owner_partition_key]
          }
        }
      },
    ]
  }

  # The two partitions the attended-proof control may both read and write: the
  # dedicated proof tenant's placement partition and the directive partition.
  # compact() keeps the list well-formed while the owner id is null (gate off),
  # where the statements are never emitted anyway.
  authority_runtime_proof_leading_keys = compact([
    local.authority_proof_owner_partition_key,
    local.authority_proof_directive_partition_key,
  ])
  # Catalog resolution only. REGISTRY is absent from the write fence above, so
  # cell provisioning stays exclusively Terraform-owned.
  authority_runtime_proof_registry_leading_keys = ["REGISTRY"]
  # Request replay only. The operation name is part of the partition prefix, so
  # ca-pm cannot read or mutate another Authority operation's replay rows.
  authority_runtime_proof_replay_leading_keys = ["HUB_REQUEST#MutateProofAgent#*"]

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
      # The attended-proof control is told, in its immutable function
      # environment, exactly which tenant it may address and how short a proof
      # lease may be. Both are also enforced by IAM (LeadingKeys) and by the
      # handler; the environment is the handler's copy, not the only fence.
      contains(local.authority_proof_operations, fn.operation) ? {
        CONNECTOR_AUTHORITY_PROOF_OWNER_ID        = var.authority_proof_mutation_owner_id
        CONNECTOR_AUTHORITY_PROOF_AGENT_ID_PREFIX = local.authority_proof_agent_id_prefix
      } : {},
      contains(local.authority_proof_policy_operations, fn.operation) ? {
        CONNECTOR_AUTHORITY_PROOF_DIRECTIVE_TTL     = tostring(local.authority_proof_directive_ttl_seconds)
        CONNECTOR_AUTHORITY_PROOF_MIN_LEASE_SECONDS = tostring(local.authority_proof_minimum_lease_seconds)
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
      each.value.operation == "mutate_proof_agent" ? [] : local.authority_runtime_dynamodb_decrypt_statements,
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

# Control used to manage an inline `connector-authority-proof-invoke` policy on
# `layerv-nhp-<env>-udp-proof-controller` — a role owned by the separate
# udp-proof-runner root. That cross-root seam is why this resource is gone.
#
# The seam's `count` keyed off authority_proof_mutation_controls_enabled rather
# than off the role existing, so destroying the runner root (#3804) left the
# resource in Control's graph pointing at nothing. Live AWS reports the role as
# NoSuchEntity, so every plan re-rendered the policy and every apply would call
# PutRolePolicy against a deleted role. The grant is also dead weight in its own
# right: it granted lambda:InvokeFunction to a principal that no longer exists,
# and the runner workflow that could assume it was removed with its App
# credentials revoked (#3806).
#
# Deleting the resource alone is not enough. The already-deleted policy is still
# in state, so a plain removal leaves a drift `delete` that
# scripts/check-connector-authority-foundation.sh folds into destructive actions
# and refuses. The `removed` block below drops it from state with a state-only
# `forget` — Terraform calls no AWS delete API, because AWS deleted it already.
#
# Retire this block once the forget has applied; it is a one-shot state
# migration, not a permanent declaration.
removed {
  from = aws_iam_role_policy.authority_proof_controller_invoke

  lifecycle {
    destroy = false
  }
}

resource "aws_lambda_function" "authority" {
  for_each = local.authority_runtime_functions

  function_name = each.key
  # ca-pm has no runtime-config delta when IA/RA/ICR become proof-aware. Bind
  # its immutable description to the prepared color so publish=true creates a
  # distinct version for the inactive alias and AWS can provision both colors
  # concurrently. Selector-only changes keep the prepared color unchanged and
  # therefore do not publish another version.
  description = (
    local.authority_proof_policy_rollout_active &&
    each.value.operation == "mutate_proof_agent"
    ? "Connector Authority ${each.value.operation} (${var.environment}; proof-policy-prepared=${var.authority_proof_policy_prepared_color})"
    : "Connector Authority ${each.value.operation} (${var.environment})"
  )
  role         = aws_iam_role.authority_exec[each.key].arn
  package_type = "Image"
  image_uri    = local.authority_runtime_image_uri

  # FLAG (POST-STEP-3 VERIFY): must match the published qurl-connector-authority
  # image architecture (docker/Dockerfile.connector-authority-lambda in
  # layervai/qurl-service). A mismatch fails the function at create. Confirm
  # before apply.
  architectures = ["x86_64"]

  # The immutable startup graph may consume up to ~9s; keep the whole request
  # inside the source-derived structural ladder. FLAG: resolve the exact
  # timeout/memory empirically against the handler's staged latency proof.
  # The duration alarm threshold is derived from this same local, so tightening
  # the budget tightens the alarm in the same edit (authority_alarms.tf).
  timeout     = local.authority_runtime_timeout_seconds
  memory_size = 512
  publish     = true

  # The attended proof's four-function retained window raises the function-wide
  # ceiling before the standby pool is requested. Every other function remains
  # on its steady envelope.
  reserved_concurrent_executions = (
    local.authority_proof_policy_rollout_active &&
    contains(local.authority_proof_policy_rollout_function_names, each.key)
    ? each.value.spec.rollout_reserved_concurrency
    : each.value.spec.steady_reserved_concurrency
  )

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

# Live alias versions for the blue/green hold. Empty while the gate is dark, so
# a first apply never asks AWS for an alias it has not created yet.
data "aws_lambda_alias" "authority_live" {
  for_each = (
    var.authority_blue_green_alias_hold_enabled &&
    local.authority_runtime_functions_deploy
  ) ? local.authority_runtime_aliases : {}

  function_name = each.value.function_name
  name          = each.value.color
}

data "aws_lambda_alias" "authority_proof_policy_live" {
  for_each = var.authority_proof_mutation_controls_enabled ? {
    for key, alias in local.authority_runtime_aliases :
    key => alias
    if contains(keys(local.authority_proof_policy_pinned_functions), alias.function_name)
  } : {}

  function_name = each.value.function_name
  name          = each.value.color
}

resource "aws_lambda_alias" "authority" {
  for_each = local.authority_runtime_aliases

  name          = each.value.color
  description   = "Closed ${each.value.color} deployment qualifier"
  function_name = aws_lambda_function.authority[each.value.function_name].function_name
  # Blue/green hold takes precedence when enabled: the selected colour keeps the
  # version live traffic is already on, and only standby advances. The proof
  # branch below is the older, narrower form of the same idea, scoped to the
  # IA/RA/ICR + ca-pm rollout; it is retired with the proof surface, after which
  # this expression has a single owner.
  function_version = (
    var.authority_blue_green_alias_hold_enabled &&
    local.authority_runtime_functions_deploy &&
    !var.authority_proof_mutation_controls_enabled
    ? (
      each.value.color == local.authority_runtime_selected_color
      ? data.aws_lambda_alias.authority_live[each.key].function_version
      : aws_lambda_function.authority[each.value.function_name].version
    )
    : (
      var.authority_proof_mutation_controls_enabled &&
      contains(keys(local.authority_proof_policy_pinned_functions), each.value.function_name)
      ? (
        local.authority_proof_policy_rollout_active &&
        each.value.color == var.authority_proof_policy_prepared_color
        ? aws_lambda_function.authority[each.value.function_name].version
        : data.aws_lambda_alias.authority_proof_policy_live[each.key].function_version
      )
      : aws_lambda_function.authority[each.value.function_name].version
    )
  )
}

# Outside the attended rollout, only the caller-selected color receives
# provisioned capacity. During the proof rollout, the fixed blue resource and
# fixed green standby resource consume the contract's retained allocations.
# The startup graph cannot fit inside the request path, so unprovisioned
# authority work is forbidden; the handler additionally rejects any non
# provisioned-concurrency initialization type.
resource "aws_lambda_provisioned_concurrency_config" "authority" {
  for_each = local.authority_runtime_functions

  function_name = aws_lambda_function.authority[each.key].function_name
  qualifier     = aws_lambda_alias.authority["${each.key}:${local.authority_runtime_selected_color}"].name
  provisioned_concurrent_executions = (
    local.authority_proof_policy_rollout_active &&
    contains(local.authority_proof_policy_rollout_function_names, each.key)
    ? each.value.spec.rollout_active_provisioned_concurrency
    : each.value.spec.steady_provisioned_concurrency
  )

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

# The first attended proof intentionally keeps the reviewed blue basis pool at
# the existing resource address and adds only the fixed green standby pool for
# IA/RA/ICR + ca-pm. Both pools remain allocated through promotion, rollback,
# and re-promotion. Preparing blue later replaces only its inactive pool and
# waits for READY before a rollback selector plan is admissible.
resource "aws_lambda_provisioned_concurrency_config" "authority_proof_standby" {
  for_each = local.authority_proof_policy_rollout_active ? local.authority_proof_policy_rollout_functions : {}

  function_name                     = aws_lambda_function.authority[each.key].function_name
  qualifier                         = aws_lambda_alias.authority["${each.key}:${local.authority_proof_policy_standby_color}"].name
  provisioned_concurrent_executions = each.value.spec.rollout_standby_provisioned_concurrency

  depends_on = [
    aws_vpc_endpoint.dynamodb,
    aws_vpc_endpoint.interface,
    aws_security_group.interface_endpoints,
    aws_security_group.authority_lambda,
  ]

}

# The complete runtime alarm set — including the rollout-aborting
# provisioned-concurrency spillover guard (aws_cloudwatch_metric_alarm
# .authority_spillover) — lives in authority_alarms.tf so every alarm, its exact
# dimension set, and its operator routing are reviewed in one place.
