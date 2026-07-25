# Connector Authority Lambda runtime slice (Step 4 of the two-cell UDP
# substrate). This file is INERT until BOTH the runtime contract is bound
# (Step 3 sets authority_runtime_contract non-null) AND the separate runtime
# gate is flipped (var.authority_runtime_functions_enabled). Until then every
# resource below is count/for_each empty and the foundation stays dark.
#
# SCOPE (matches the merged measurement basis exactly): the 3 Hub-facing
# functions layerv-nhp-<env>-ca-{ia,ra,icr}. The measurement contract's
# functions map is exactly {ia,ra,icr} and provisioned_cells is {cell0} as a
# FROZEN caller catalog only; it declares no cell function. The first-apply
# checker's _require_authority_runtime_binding independently hard-requires that
# exact set. The 4-per-cell functions (iro/ar/cr/ccr-<cell>) therefore belong
# to a LATER contract revision, not this slice; see the PR body.
#
# DARK-FIRST: functions, both closed blue/green aliases, operation-specific
# execution roles, steady provisioned/reserved concurrency, and spillover
# alarms are created here with NO caller identity policy, NO aws_lambda_permission
# (a same-account caller resource Allow would bypass the SourceVpce condition on
# the caller identity policy; the plan forbids it), and NO opening of the Lambda
# caller interface endpoint (the Hub role/runtime does not exist yet — Step 5).
# The lockstep opening in endpoints.tf opens ONLY the dependency endpoints these
# hub functions provably reach (DynamoDB gateway + KMS interface), to exactly the
# constructed execution-role principals.

locals {
  # Second, independent gate. Requires a bound contract; the precondition below
  # fails closed if the gate is set while the contract is null.
  authority_runtime_functions_deploy = (
    local.authority_runtime_contract_enabled && var.authority_runtime_functions_enabled
  )

  # Hub functions to deploy = the Hub-group functions actually present in the
  # bound contract's functions map. In the measurement basis this is all three.
  authority_runtime_hub_functions = local.authority_runtime_functions_deploy ? {
    for function_name, spec in local.authority_expected_hub_functions :
    function_name => {
      operation = spec.operation
      spec      = local.authority_contract_functions[function_name]
    }
    if contains(local.authority_actual_function_names, function_name)
  } : {}

  authority_runtime_selected_color = local.authority_runtime_functions_deploy ? var.authority_runtime_contract.selected_authority_color : null

  # Both closed deployment qualifiers are published up front (plan: "First
  # create functions, versions, the closed blue/green aliases ..."). Only the
  # selected color receives steady provisioned concurrency below.
  authority_runtime_alias_colors = ["blue", "green"]
  authority_runtime_aliases = merge([
    for function_name, fn in local.authority_runtime_hub_functions : {
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
    for function_name, fn in local.authority_runtime_hub_functions :
    function_name => "${function_name}-exec"
  }
  authority_runtime_exec_role_arn = {
    for function_name, fn in local.authority_runtime_hub_functions :
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
    for function_name, fn in local.authority_runtime_hub_functions :
    function_name => "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${function_name}"
  }

  # Only IssueAssignment (ca-ia) constructs a KMS client: it loads the assignment
  # verification key (kms:GetPublicKey) and signs the ticket (kms:Sign) at cold
  # start. RefreshAssignment and IssueCredentialRecovery build NO KMS client
  # (verified against layervai/qurl-service connectorauthorityruntime/wiring.go:
  # their factories never call newKMSClient), so the qat1 key opens to ca-ia
  # alone and no operation uses kms:Verify (ticket verification is local p256).
  authority_runtime_sign_function = "${local.authority_function_prefix}-ia"
  authority_runtime_sign_role_arns = local.authority_runtime_functions_deploy ? [
    local.authority_runtime_exec_role_arn[local.authority_runtime_sign_function],
  ] : []

  # Environment-owned public cell DNS suffix (LayerV-owned; leading dot). It
  # matches the live native-UDP cell endpoints (e.g. cell0.nhp.layerv.xyz) and
  # is required by the handler for every hub op (domain.ValidateProvisionedCellDNSSuffix
  # in connectorauthorityruntime/config.go loadDNSSuffix). The runtime contract
  # does not carry it, so it is derived from the environment domain here.
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

  # The 3 canonical tables the Hub-facing operations reach. customers and
  # api_key_idempotency are intentionally excluded: they are read by the
  # (out-of-scope) cell OTP/mint paths, not by ia/ra/icr. Ungated so the
  # dependency-endpoint policy locals in endpoints.tf can reference them even
  # while the runtime is dark; they are only ever selected when deploying.
  authority_runtime_table_arns = {
    api_keys            = aws_dynamodb_table.api_keys.arn
    agent_keys          = aws_dynamodb_table.agent_keys.arn
    connector_authority = aws_dynamodb_table.connector_authority.arn
  }

  # Read = strongly consistent GetItem/Query plus the transaction ConditionCheck
  # verb, plus DescribeTable: EVERY hub op verifies its selected Control tables'
  # SSE-KMS key at cold start before it can reach READY
  # (connectorauthorityruntime/dynamodb_sse.go verifySelectedControlTableEncryption).
  # BatchGetItem/TransactGetItems are dropped: no hub op composes them, and a
  # read inside a transaction is authorized by GetItem, not a Transact* action.
  authority_runtime_ddb_read_actions = [
    "dynamodb:ConditionCheckItem",
    "dynamodb:DescribeTable",
    "dynamodb:GetItem",
    "dynamodb:Query",
  ]
  # The single-item replay tombstone both hub-request ops (issue/refresh) compose
  # as a TransactWriteItems{Put} on connector_authority
  # (repository/dynamodb/hub_request_replay_repo.go). A Put inside a transaction
  # is authorized by dynamodb:PutItem, not a Transact* action.
  authority_runtime_ddb_replay_write_actions = ["dynamodb:PutItem"]
  # IssueCredentialRecovery additionally UPDATEs the device-credential head anchor
  # on the first grant (agent_credential_recovery_repo.go recoveryHeadTransactionItem),
  # so it needs UpdateItem beyond the replay/grant Puts. DeleteItem is unused by
  # every hub op and dropped.
  authority_runtime_ddb_recovery_write_actions = ["dynamodb:PutItem", "dynamodb:UpdateItem"]

  # Table resources. Only agent_keys is read through a GSI (the pubkey index in
  # agent_keys_repo.go GetByPublicKey, used by refresh/recovery identity
  # resolution); api_keys and connector_authority are reached only by primary key
  # (GetItem / base-table Query), so they get no /index/* grant.
  authority_runtime_table_resources = {
    api_keys            = [local.authority_runtime_table_arns.api_keys]
    agent_keys          = [local.authority_runtime_table_arns.agent_keys, "${local.authority_runtime_table_arns.agent_keys}/index/*"]
    connector_authority = [local.authority_runtime_table_arns.connector_authority]
  }

  # Per-operation statement lists. Every operation gets the common ENI statement,
  # a scoped CloudWatch Logs write to its own log group, and its exact — handler-
  # verified — data dependencies. Every resource is a concrete ARN (no wildcard).
  authority_runtime_operation_statements = local.authority_runtime_functions_deploy ? {
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
  } : {}
}

# One dedicated security group for every Authority function ENI. Egress is
# limited to HTTPS toward the interface endpoints (KMS) and the DynamoDB
# gateway prefix list; the endpoint policies are the finer, principal-scoped
# gate. No ingress: nothing dials the functions on the network path — callers
# reach them only through the Lambda service's private Invoke transport.
resource "aws_security_group" "authority_lambda" {
  count = local.authority_runtime_functions_deploy ? 1 : 0

  name_prefix = "${local.name_prefix}-ca-fn-"
  description = "Connector Authority function ENIs; egress to Control dependency endpoints only"
  vpc_id      = aws_vpc.control.id

  ingress = []

  # Egress is HTTPS only. The interface endpoints are reached via the VPC CIDR
  # rather than an SG-to-SG reference: the tight direction (interface-endpoint
  # SG ingress) IS scoped to this function SG, and a reciprocal SG-to-SG egress
  # here would form an inline-rule dependency cycle between the two groups. The
  # isolated subnets expose no other :443 listener than these endpoints, and the
  # endpoint policies are the finer principal/resource gate. DynamoDB is the
  # gateway endpoint's managed prefix list.
  egress = [
    {
      description      = "HTTPS to Control interface endpoints (KMS) in-VPC"
      from_port        = 443
      to_port          = 443
      protocol         = "tcp"
      cidr_blocks      = [var.vpc_cidr]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      description      = "HTTPS to the DynamoDB gateway endpoint prefix list"
      from_port        = 443
      to_port          = 443
      protocol         = "tcp"
      prefix_list_ids  = [aws_vpc_endpoint.dynamodb.prefix_list_id]
      cidr_blocks      = []
      ipv6_cidr_blocks = []
      security_groups  = []
      self             = false
    },
  ]

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-ca-fn"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_cloudwatch_log_group" "authority" {
  for_each = local.authority_runtime_hub_functions

  name              = "/aws/lambda/${each.key}"
  retention_in_days = local.authority_runtime_log_retention_days

  # NOTE: default (AWS-managed) log encryption. CMK-encrypting these groups with
  # authority_data would require extending that key's byte-reviewed policy to
  # allow the CloudWatch Logs service for the Lambda log-group ARNs (today it is
  # scoped to the flow-log group only). Deferred to a follow-up so this slice
  # does not mutate the KMS key policy. Payloads are already forbidden from logs.

  tags = merge(local.common_tags, {
    Name      = "/aws/lambda/${each.key}"
    Operation = each.value.operation
  })
}

resource "aws_iam_role" "authority_exec" {
  for_each = local.authority_runtime_hub_functions

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
  for_each = local.authority_runtime_hub_functions

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
  for_each = local.authority_runtime_hub_functions

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
    variables = {
      CONNECTOR_AUTHORITY_OPERATION                = local.authority_operation_conformance_name[each.value.operation]
      CONNECTOR_AUTHORITY_ENVIRONMENT_ID           = var.environment
      CONNECTOR_AUTHORITY_ACCOUNT_ID               = data.aws_caller_identity.current.account_id
      CONNECTOR_AUTHORITY_HOME_REGION              = data.aws_region.current.region
      CONNECTOR_AUTHORITY_CELL_DNS_SUFFIX          = local.authority_cell_dns_suffix
      CONNECTOR_AUTHORITY_DATA_KMS_KEY_ARN         = aws_kms_key.authority_data.arn
      CONNECTOR_AUTHORITY_ASSIGNMENT_KEY_ALIAS_ARN = aws_kms_alias.qat1_signing.arn
      CONNECTOR_AUTHORITY_ASSIGNMENT_KEY_KID       = tostring(var.authority_runtime_contract.qat1_kid)
    }
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

# Steady state: only the caller-selected color retains provisioned capacity
# (plan). The standby color's provisioned pool is a later rollout transition.
# The startup graph cannot fit inside the request path, so unprovisioned
# authority work is forbidden; the handler additionally rejects any non
# provisioned-concurrency initialization type.
resource "aws_lambda_provisioned_concurrency_config" "authority" {
  for_each = local.authority_runtime_hub_functions

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
# exactly zero. FLAG: alarm_actions (SNS) wiring plus the Throttles/Errors/
# Duration and custom admission/initialization-type alarms are an immediate
# follow-up; this slice lands the security-critical spillover guard.
resource "aws_cloudwatch_metric_alarm" "authority_spillover" {
  for_each = local.authority_runtime_hub_functions

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

  dimensions = {
    FunctionName = each.key
  }

  tags = merge(local.common_tags, {
    Name      = "${each.key}-provisioned-concurrency-spillover"
    Operation = each.value.operation
  })
}
