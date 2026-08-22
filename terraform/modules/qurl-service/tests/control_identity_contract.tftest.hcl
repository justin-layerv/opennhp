# Control identity plane contract.
#
# Identity is not cell-scoped. A customer exists before any cell assignment, can
# hold resources in more than one cell, and must outlive the loss of any single
# cell; the Connector Authority is global and validates enrollment credentials
# for every cell, so it reads the Control namespace and never a cell. These runs
# pin the two end states and, crucially, that a half-configured cutover cannot
# plan -- the failure mode there is silent (either the service refuses to boot
# on the prefix check, or it runs against Control with no IAM grant).

mock_provider "aws" {
  mock_data "aws_region" {
    defaults = {
      id     = "us-east-2"
      region = "us-east-2"
    }
  }

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "767397897469"
    }
  }

  mock_data "aws_subnet" {
    defaults = {
      cidr_block = "10.102.10.0/24"
    }
  }

  mock_resource "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws:logs:us-east-2:767397897469:log-group:/layerv/mock"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::767397897469:role/mock"
    }
  }

  mock_resource "aws_iam_policy" {
    defaults = {
      arn = "arn:aws:iam::767397897469:policy/mock"
    }
  }

  mock_resource "aws_lb" {
    defaults = {
      arn        = "arn:aws:elasticloadbalancing:us-east-2:767397897469:loadbalancer/app/mock/1111111111111111"
      arn_suffix = "app/mock/1111111111111111"
      dns_name   = "internal-mock.us-east-2.elb.amazonaws.com"
      zone_id    = "Z0123456789"
    }
  }

  mock_resource "aws_lb_target_group" {
    defaults = {
      arn        = "arn:aws:elasticloadbalancing:us-east-2:767397897469:targetgroup/mock/1111111111111111"
      arn_suffix = "targetgroup/mock/1111111111111111"
    }
  }

  mock_resource "aws_security_group" {
    defaults = {
      id = "sg-0123456789abcdef0"
    }
  }
}

variables {
  environment                            = "sandbox"
  name_prefix                            = "layerv-nhp-sandbox"
  cell_id                                = "cell0"
  vpc_id                                 = "vpc-0123456789abcdef0"
  vpc_cidr                               = "10.100.0.0/16"
  private_subnet_ids                     = ["subnet-11111111", "subnet-22222222"]
  public_subnet_ids                      = ["subnet-33333333", "subnet-44444444"]
  ecr_repo_url                           = "767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/nhp-qurl"
  image_tag_ssm_param                    = "/layerv-nhp-sandbox/qurl-api-image-tag"
  dynamodb_table_arns                    = ["arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-cell0-qurl-resources"]
  qurl_resources_table_arn               = "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-cell0-qurl-resources"
  auth0_domain                           = "auth.layerv.ai"
  jwt_secret_arn                         = "arn:aws:secretsmanager:us-east-2:767397897469:secret:qurl-jwt-AbCdEf"
  internal_service_token_arn             = "arn:aws:secretsmanager:us-east-2:767397897469:secret:qurl-internal-AbCdEf"
  nhp_internal_auth_secret_arn           = "arn:aws:secretsmanager:us-east-2:767397897469:secret:nhp-internal-AbCdEf"
  feedback_slack_webhook_secret_arn      = "arn:aws:secretsmanager:us-east-2:767397897469:secret:qurl-feedback-AbCdEf"
  secrets_kms_key_arn                    = "arn:aws:kms:us-east-2:767397897469:key/11111111-1111-1111-1111-111111111111"
  logs_kms_key_arn                       = "arn:aws:kms:us-east-2:767397897469:key/22222222-2222-2222-2222-222222222222"
  cookie_domain                          = ".qurl.site.layerv.xyz"
  qurl_link_domain                       = "qurl.link.layerv.xyz"
  qurl_site_domain                       = "qurl.site.layerv.xyz"
  default_token_expire                   = 3600
  default_open_time                      = 300
  ip_rate_limit                          = 300
  ip_rate_burst                          = 100
  audit_retention_days                   = 90
  cors_allowed_origins                   = ""
  default_ac_id                          = "cell0"
  idempotency_cache_ttl_seconds          = 300
  idempotency_cache_max_size             = 1000
  idempotency_cleanup_interval_seconds   = 60
  health_check_timeout_seconds           = 10
  health_startup_timeout_seconds         = 30
  auth0_jwks_cache_ttl_seconds           = 3600
  auth0_jwks_fetch_timeout_seconds       = 10
  webhooks_worker_count                  = 4
  webhooks_max_webhooks_per_owner        = 10
  webhooks_delivery_timeout_seconds      = 30
  webhooks_max_retries                   = 5
  webhooks_event_channel_size            = 1000
  webhooks_retry_worker_interval_seconds = 30
  webhooks_drain_timeout_seconds         = 30
  webhooks_response_body_limit           = 8192
  webhooks_api_version                   = "2024-01-01"
  otel_service_name                      = "qurl-api"
  otel_service_version                   = "test"
  otel_environment                       = "sandbox"
  otel_exporter_endpoint                 = "http://localhost:4317"
  otel_exporter_protocol                 = "grpc"
  otel_exporter_insecure                 = true
  otel_trace_sample_rate                 = 0
  otel_metrics_interval                  = 60
  otel_metrics_enabled                   = false
  otel_tracing_enabled                   = false
  otel_log_correlation                   = false
  # Pin the image so the task definition is fully known at plan time; without
  # it the URI resolves from SSM and container_definitions stays unknown, which
  # makes every environment assertion below unevaluable.
  image_uri              = "767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/nhp-qurl@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  source_revision        = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  dynamodb_table_prefix  = "layerv-nhp-sandbox-cell0"
  connector_auth_enabled = true
}

# Cell compatibility mode is the default and must stay byte-identical to the
# historical behavior: no Control statement in the policy at all, and the
# service explicitly told to use its own cell namespace.
run "default_is_cell_identity_with_no_control_grant" {
  # apply against the mocked provider so the rendered policy and container
  # definitions are known; a plan leaves both computed and unassertable.
  command = apply

  assert {
    condition = alltrue([
      for statement in jsondecode(aws_iam_role_policy.task_dynamodb.policy).Statement :
      !contains([
        "ControlIdentityAccess",
        "ControlDeviceCredentialHeadRead",
        "ControlDeviceCredentialHeadRevoke",
      ], statement.Sid)
    ])
    error_message = "cell identity mode emitted a Control identity or device-credential IAM statement"
  }

  assert {
    condition = anytrue([
      for env in jsondecode(aws_ecs_task_definition.qurl.container_definitions)[0].environment :
      env.name == "DYNAMODB_IDENTITY_STORE_MODE" && env.value == "cell"
    ])
    error_message = "default identity store mode is not the cell namespace"
  }

  assert {
    condition = alltrue([
      for env in jsondecode(aws_ecs_task_definition.qurl.container_definitions)[0].environment :
      env.value == "" if contains(
        ["DYNAMODB_CONTROL_ENVIRONMENT_ID", "DYNAMODB_CONTROL_HOME_REGION", "DYNAMODB_CONTROL_TABLE_PREFIX"],
        env.name
      )
    ])
    error_message = "cell identity mode leaked a Control namespace value"
  }

  # The converse: cell mode must keep passing the caller-supplied cell table, so
  # fixing the Control case did not quietly repoint existing deployments.
  assert {
    condition = alltrue([
      for env in jsondecode(aws_ecs_task_definition.qurl.container_definitions)[0].environment :
      !strcontains(env.value, "-control-qurl-apikey-idempotency")
      if env.name == "APIKEY_IDEMPOTENCY_TABLE_NAME"
    ])
    error_message = "cell identity mode pointed the mint idempotency table at Control"
  }

  assert {
    condition = alltrue([
      for statement in jsondecode(aws_iam_role_policy.task_dynamodb.policy).Statement :
      statement.Sid != "KMSDecryptControlDynamoDB"
    ])
    error_message = "cell identity mode granted decrypt on the Control KMS key"
  }

  assert {
    condition = alltrue([
      for statement in jsondecode(aws_iam_role_policy.task_tunnel_session_fence[0].policy).Statement :
      statement.Action == [
        "dynamodb:ConditionCheckItem",
        "dynamodb:TransactWriteItems",
      ] &&
      statement.Resource == ["arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-cell0-qurl-resources"] &&
      !contains(statement.Resource, "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-cell0-qurl-resources/index/*") &&
      !can(statement.Condition)
      if statement.Sid == "TunnelSessionFenceAccess"
      ]) && length([
      for statement in jsondecode(aws_iam_role_policy.task_tunnel_session_fence[0].policy).Statement :
      statement if statement.Sid == "TunnelSessionFenceAccess"
    ]) == 1
    error_message = "tunnel-session transaction IAM must grant exactly ConditionCheckItem + TransactWriteItems on the qurl-resources table without indexes or conditions"
  }

  assert {
    condition = alltrue([
      for statement in jsondecode(aws_iam_role_policy.task_dynamodb.policy).Statement :
      !contains(statement.Action, "dynamodb:ConditionCheckItem") &&
      !contains(statement.Action, "dynamodb:TransactWriteItems")
    ])
    error_message = "cell-mode tunnel-session transaction actions leaked into a broader DynamoDB statement"
  }

  assert {
    condition = alltrue([
      for env in jsondecode(aws_ecs_task_definition.qurl.container_definitions)[0].environment :
      env.name != "QURL_CONNECTOR_ACTIVE_REGISTRATIONS_ENABLED"
    ])
    error_message = "retired QURL_CONNECTOR_ACTIVE_REGISTRATIONS_ENABLED is still rendered into the task definition"
  }
}

run "missing_resources_arn_does_not_broaden_primary_table_access" {
  command = apply

  variables {
    connector_auth_enabled   = false
    qurl_resources_table_arn = ""
  }

  assert {
    condition = length(aws_iam_role_policy.task_tunnel_session_fence) == 0 && alltrue([
      for statement in jsondecode(aws_iam_role_policy.task_dynamodb.policy).Statement :
      !contains(statement.Action, "dynamodb:ConditionCheckItem") &&
      !contains(statement.Action, "dynamodb:TransactWriteItems")
    ])
    error_message = "transaction actions were inferred from the broad DynamoDB table list instead of the exact qurl_resources_table_arn"
  }
}

run "connector_auth_requires_resources_arn" {
  command = plan

  variables {
    connector_auth_enabled   = true
    qurl_resources_table_arn = ""
  }

  expect_failures = [aws_iam_role_policy.task_tunnel_session_fence]
}

run "control_identity_grants_and_selects_the_control_namespace" {
  # apply against the mocked provider so the rendered policy and container
  # definitions are known; a plan leaves both computed and unassertable.
  command = apply

  variables {
    control_identity_environment_id = "sandbox"
    control_identity_home_region    = "us-east-2"
    control_identity_kms_key_arn    = "arn:aws:kms:us-east-2:767397897469:key/83680792-1ed7-4825-beb2-2e67f8056aee"
    # All four identity tables the root passes. The mint idempotency table is included
    # deliberately: naming it in the env var without granting IAM boots cleanly
    # and then fails with AccessDenied on the first mint.
    control_identity_table_arns = [
      "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-qurl-customers",
      "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-qurl-api-keys",
      "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-qurl-agent-keys",
      "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-qurl-apikey-idempotency",
    ]
    control_device_credential_authority_table_arn = "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-connector-authority"
  }

  assert {
    condition = anytrue([
      for env in jsondecode(aws_ecs_task_definition.qurl.container_definitions)[0].environment :
      env.name == "DYNAMODB_IDENTITY_STORE_MODE" && env.value == "control"
    ])
    error_message = "control identity mode did not select the Control namespace"
  }

  # The service recomputes this prefix from the environment id at startup and
  # refuses to boot if the two disagree, so an error here is a boot failure, not
  # a cosmetic drift. It must equal controlnamespace.DynamoDBTablePrefix.
  assert {
    condition = anytrue([
      for env in jsondecode(aws_ecs_task_definition.qurl.container_definitions)[0].environment :
      env.name == "DYNAMODB_CONTROL_TABLE_PREFIX" && env.value == "layerv-nhp-sandbox-control"
    ])
    error_message = "Control table prefix does not match the canonical namespace prefix"
  }

  assert {
    condition = length([
      for statement in jsondecode(aws_iam_role_policy.task_dynamodb.policy).Statement :
      statement if statement.Sid == "ControlIdentityAccess"
    ]) == 1
    error_message = "control identity mode did not emit exactly one Control identity IAM statement"
  }

  # The env var naming the Control idempotency table is only half the contract:
  # the task role must also be able to write it. Without this, the service boots
  # clean and the first mint fails with AccessDenied -- quieter than the fatal
  # boot check, and a worse rollback.
  assert {
    condition = anytrue([
      for statement in jsondecode(aws_iam_role_policy.task_dynamodb.policy).Statement :
      anytrue([
        for resource in statement.Resource :
        endswith(resource, "-control-qurl-apikey-idempotency")
      ]) if statement.Sid == "ControlIdentityAccess"
    ])
    error_message = "Control identity grant does not cover the mint idempotency table the env var names"
  }

  # Native Connector enrollment records a permanent device-credential head in
  # Connector Authority. Direct reads support ownership/state validation; the
  # head write is restricted to a transaction so the task cannot mutate it
  # independently of the API-key row.
  assert {
    condition = (
      length([
        for statement in jsondecode(aws_iam_role_policy.task_dynamodb.policy).Statement :
        statement if statement.Sid == "ControlDeviceCredentialHeadRead"
        ]) == 1 && alltrue([
        for statement in jsondecode(aws_iam_role_policy.task_dynamodb.policy).Statement :
        statement.Action == ["dynamodb:GetItem"] &&
        statement.Resource == ["arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-connector-authority"] &&
        statement.Condition["ForAllValues:StringLike"]["dynamodb:LeadingKeys"] == ["OWNER#*"] &&
        statement.Condition["Null"]["dynamodb:LeadingKeys"] == "false"
        if statement.Sid == "ControlDeviceCredentialHeadRead"
      ])
    )
    error_message = "device-credential head read is not scoped to GetItem on Connector Authority owner partitions"
  }

  assert {
    condition = (
      length([
        for statement in jsondecode(aws_iam_role_policy.task_dynamodb.policy).Statement :
        statement if statement.Sid == "ControlDeviceCredentialHeadRevoke"
        ]) == 1 && alltrue([
        for statement in jsondecode(aws_iam_role_policy.task_dynamodb.policy).Statement :
        statement.Action == ["dynamodb:PutItem"] &&
        statement.Resource == ["arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-connector-authority"] &&
        statement.Condition["ForAnyValue:StringEquals"]["dynamodb:EnclosingOperation"] == ["TransactWriteItems"] &&
        statement.Condition["ForAllValues:StringLike"]["dynamodb:LeadingKeys"] == ["OWNER#*"] &&
        statement.Condition["Null"]["dynamodb:LeadingKeys"] == "false"
        if statement.Sid == "ControlDeviceCredentialHeadRevoke"
      ])
    )
    error_message = "device-credential head revoke is not limited to transactional PutItem on Connector Authority owner partitions"
  }

  # Reading an SSE-KMS table needs decrypt on that table's key. Granting the
  # DynamoDB actions without it boots cleanly and then fails every API-key
  # lookup with AccessDeniedException -- a live 500, not a refusal to start.
  assert {
    condition = anytrue([
      for statement in jsondecode(aws_iam_role_policy.task_dynamodb.policy).Statement :
      contains(statement.Action, "kms:Decrypt")
      && contains(statement.Resource, "arn:aws:kms:us-east-2:767397897469:key/83680792-1ed7-4825-beb2-2e67f8056aee")
      if statement.Sid == "KMSDecryptControlDynamoDB"
    ])
    error_message = "Control identity mode does not grant decrypt on the Control tables' KMS key"
  }

  # ConditionCheckItem is authorized separately from TransactWriteItems. Minting
  # an API key condition-checks the owning customer row inside the transaction,
  # so without this action every POST /v1/api-keys returns 500 and no customer or
  # agent can enroll -- while every write action above looks correctly granted.
  assert {
    condition = alltrue([
      for statement in jsondecode(aws_iam_role_policy.task_dynamodb.policy).Statement :
      contains(statement.Action, "dynamodb:ConditionCheckItem")
      if statement.Sid == "ControlIdentityAccess"
    ])
    error_message = "Control identity grant omits dynamodb:ConditionCheckItem; transactional API-key mint will 500"
  }

  # Every identity read is a key or index lookup, which is what keeps validation
  # O(1) as cells are added. A Scan grant would hide an accidental table walk on
  # the enrollment hot path.
  assert {
    condition = alltrue([
      for statement in jsondecode(aws_iam_role_policy.task_dynamodb.policy).Statement :
      !contains(statement.Action, "dynamodb:Scan") if statement.Sid == "ControlIdentityAccess"
    ])
    error_message = "Control identity grant includes Scan; no identity path scans"
  }

  # The mint idempotency table must follow the identity namespace. qurl-service
  # asserts these agree and exits fatally otherwise -- a live rollout was rolled
  # back by exactly this mismatch, because the cell table name was still being
  # passed while identity had moved to Control. Deduplicating a mint against a
  # different namespace than it writes to would silently issue duplicate keys.
  assert {
    condition = anytrue([
      for env in jsondecode(aws_ecs_task_definition.qurl.container_definitions)[0].environment :
      env.name == "APIKEY_IDEMPOTENCY_TABLE_NAME"
      && env.value == "layerv-nhp-sandbox-control-qurl-apikey-idempotency"
    ])
    error_message = "mint idempotency table does not follow the Control identity namespace"
  }

  # Index ARNs are derived rather than listed, so a caller cannot pass a table
  # without its indexes and leave owner-index/key-id-index unreadable at runtime.
  assert {
    condition = alltrue([
      for statement in jsondecode(aws_iam_role_policy.task_dynamodb.policy).Statement :
      length(statement.Resource) == 8 if statement.Sid == "ControlIdentityAccess"
    ])
    error_message = "Control identity grant does not cover each table plus its indexes"
  }
}

# Half-configured cutovers must not plan. Both directions are covered: config
# without the grant, and the grant without the config.
run "control_identity_without_region_or_tables_is_rejected" {
  command = plan

  variables {
    control_identity_environment_id = "sandbox"
  }

  expect_failures = [aws_ecs_task_definition.qurl]
}

run "control_identity_without_device_authority_is_rejected" {
  command = plan

  variables {
    control_identity_environment_id = "sandbox"
    control_identity_home_region    = "us-east-2"
    control_identity_kms_key_arn    = "arn:aws:kms:us-east-2:767397897469:key/83680792-1ed7-4825-beb2-2e67f8056aee"
    control_identity_table_arns = [
      "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-qurl-api-keys",
    ]
  }

  expect_failures = [aws_ecs_task_definition.qurl]
}

run "control_identity_grant_without_mode_is_rejected" {
  command = plan

  variables {
    control_identity_table_arns = [
      "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-qurl-api-keys",
    ]
  }

  expect_failures = [aws_ecs_task_definition.qurl]
}

run "device_authority_grant_without_mode_is_rejected" {
  command = plan

  variables {
    control_device_credential_authority_table_arn = "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-connector-authority"
  }

  expect_failures = [aws_ecs_task_definition.qurl]
}

# The failure this run guards against is the one that reached production: the
# service boots, then every API-key lookup 500s on AccessDeniedException.
run "control_identity_without_the_kms_key_is_rejected" {
  command = plan

  variables {
    control_identity_environment_id = "sandbox"
    control_identity_home_region    = "us-east-2"
    control_identity_table_arns = [
      "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-qurl-api-keys",
    ]
  }

  expect_failures = [aws_ecs_task_definition.qurl]
}
