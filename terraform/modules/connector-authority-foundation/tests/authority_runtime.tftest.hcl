# Plan-only tests for the complete Connector Authority Lambda runtime. They
# prove the two-cell measurement graph deploys exactly 3 Hub + 4-per-cell
# functions, both closed aliases, steady concurrency, per-operation IAM, and
# the exact dependency endpoints; that the same contract with the gate off
# creates nothing; and that the gate fails closed against a null contract.

mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = { names = ["us-east-2a", "us-east-2b", "us-east-2c"] }
  }
  mock_data "aws_caller_identity" {
    defaults = { account_id = "767397897469" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws", dns_suffix = "amazonaws.com" }
  }
  mock_data "aws_region" {
    defaults = { region = "us-east-2" }
  }
  mock_data "aws_ssm_parameter" {
    defaults = { insecure_value = "sha256:1111111111111111111111111111111111111111111111111111111111111111" }
  }
  mock_data "aws_ecr_image" {
    defaults = {
      image_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
      image_uri    = "767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/qurl-connector-authority@sha256:1111111111111111111111111111111111111111111111111111111111111111"
    }
  }
}

override_resource {
  target          = aws_ecr_repository.authority
  override_during = plan
  values = {
    repository_url = "767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/qurl-connector-authority"
  }
}

override_resource {
  target          = aws_kms_key.qat1_signing
  override_during = plan
  values = {
    arn = "arn:aws:kms:us-east-2:767397897469:key/00000000-0000-0000-0000-000000000001"
  }
}

override_resource {
  target          = aws_kms_alias.qat1_signing
  override_during = plan
  values = {
    arn = "arn:aws:kms:us-east-2:767397897469:alias/layerv-nhp-sandbox-control-qat1"
  }
}

override_resource {
  target          = aws_kms_key.authority_data
  override_during = plan
  values = {
    arn = "arn:aws:kms:us-east-2:767397897469:key/00000000-0000-0000-0000-000000000002"
  }
}

override_resource {
  target          = aws_elasticache_serverless_cache.otp
  override_during = plan
  values = {
    name = "layerv-nhp-sandbox-control-otp"
    endpoint = [{
      address = "layerv-nhp-sandbox-control-otp.serverless.use2.cache.amazonaws.com"
      port    = 6379
    }]
  }
}

override_resource {
  target          = aws_elasticache_user.otp_issuer
  override_during = plan
  values = {
    arn     = "arn:aws:elasticache:us-east-2:767397897469:user:layerv-nhp-sandbox-control-otp-issuer"
    user_id = "layerv-nhp-sandbox-control-otp-issuer"
  }
}

override_resource {
  target          = aws_elasticache_user.otp_activator
  override_during = plan
  values = {
    arn     = "arn:aws:elasticache:us-east-2:767397897469:user:layerv-nhp-sandbox-control-otp-activator"
    user_id = "layerv-nhp-sandbox-control-otp-activator"
  }
}

override_resource {
  target          = aws_secretsmanager_secret.otp_pepper
  override_during = plan
  values = {
    arn = "arn:aws:secretsmanager:us-east-2:767397897469:secret:layerv-nhp-sandbox-control-otp-pepper-ABCDEF"
  }
}

override_resource {
  target          = aws_security_group.interface_endpoints
  override_during = plan
  values = {
    id = "sg-1face00000000000"
  }
}

override_resource {
  target          = aws_vpc_endpoint.dynamodb
  override_during = plan
  values = {
    prefix_list_id = "pl-0123456789abcdef0"
  }
}

# Known table ARNs so the DynamoDB gateway-endpoint policy resolves at plan.
override_resource {
  target          = aws_dynamodb_table.api_keys
  override_during = plan
  values          = { arn = "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-qurl-api-keys" }
}
override_resource {
  target          = aws_dynamodb_table.agent_keys
  override_during = plan
  values          = { arn = "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-qurl-agent-keys" }
}
override_resource {
  target          = aws_dynamodb_table.customers
  override_during = plan
  values          = { arn = "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-customers" }
}
override_resource {
  target          = aws_dynamodb_table.connector_authority
  override_during = plan
  values          = { arn = "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-connector-authority" }
}

override_data {
  target          = data.aws_ecr_image.authority_runtime[0]
  override_during = plan
  values = {
    image_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    image_uri    = "767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/qurl-connector-authority@sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }
}

variables {
  environment                                  = "sandbox"
  aws_account_id                               = "767397897469"
  vpc_cidr                                     = "10.102.0.0/16"
  otp_email_from                               = "noreply@notify.layerv.xyz"
  ses_configuration_set_name                   = "layerv-nhp-sandbox-agent-otp"
  authority_runtime_contract_evidence_verified = true

  # The exact complete two-cell measurement basis.
  authority_runtime_contract = {
    schema_version           = 1
    phase                    = "measurement"
    selected_authority_color = "blue"
    provisioned_cells = {
      cell0 = {
        caller_role_arn = "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-server"
      }
      cell1 = {
        caller_role_arn = "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-cell1-server"
      }
    }
    provisioned_cells_evidence = {
      repository     = "layervai/nhp"
      source_commit  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      path           = "docs/evidence/connector-authority/v1/sandbox-measurement-basis.json"
      sha256         = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
      schema_version = 1
    }
    qat1_kid = "sandbox-qat1-2026-07-v1"
    global = {
      environment                        = "sandbox"
      aws_partition                      = "aws"
      aws_account_id                     = "767397897469"
      aws_region                         = "us-east-2"
      authority_repository_url           = "767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/qurl-connector-authority"
      authority_digest_parameter_name    = "/sandbox/nhp/control/connector-authority/image-digest"
      authority_image_digest             = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
      qat1_raw_key_arn                   = "arn:aws:kms:us-east-2:767397897469:key/00000000-0000-0000-0000-000000000001"
      qat1_alias_arn                     = "arn:aws:kms:us-east-2:767397897469:alias/layerv-nhp-sandbox-control-qat1"
      otp_redis_cache_name               = "layerv-nhp-sandbox-control-otp"
      otp_redis_endpoint                 = "layerv-nhp-sandbox-control-otp.serverless.use2.cache.amazonaws.com:6379"
      regional_lambda_concurrency_quota  = 1000
      non_authority_reserved_concurrency = 0
      retained_unreserved_concurrency    = 100
      dependency_headroom = {
        dynamodb_max_in_flight = 20
        kms_max_in_flight      = 20
        redis_max_connections  = 20
        ses_max_in_flight      = 20
      }
      caller_capacity = {
        hub_workers = {
          max_replicas = 2
          preinvoke_limits = {
            issue_assignment          = 1
            refresh_assignment        = 1
            issue_credential_recovery = 1
          }
          preinvoke_rate_limits = {
            issue_assignment          = { burst = 1, refill_per_second = 1 }
            refresh_assignment        = { burst = 1, refill_per_second = 1 }
            issue_credential_recovery = { burst = 1, refill_per_second = 1 }
          }
        }
        cell_workers = {
          cell0 = {
            max_replicas = 2
            preinvoke_limits = {
              issue_registration_otp       = 1
              activate_registration        = 1
              complete_registration        = 1
              complete_credential_recovery = 1
            }
            preinvoke_rate_limits = {
              issue_registration_otp       = { burst = 1, refill_per_second = 1 }
              activate_registration        = { burst = 1, refill_per_second = 1 }
              complete_registration        = { burst = 1, refill_per_second = 1 }
              complete_credential_recovery = { burst = 1, refill_per_second = 1 }
            }
          }
          cell1 = {
            max_replicas = 2
            preinvoke_limits = {
              issue_registration_otp       = 1
              activate_registration        = 1
              complete_registration        = 1
              complete_credential_recovery = 1
            }
            preinvoke_rate_limits = {
              issue_registration_otp       = { burst = 1, refill_per_second = 1 }
              activate_registration        = { burst = 1, refill_per_second = 1 }
              complete_registration        = { burst = 1, refill_per_second = 1 }
              complete_credential_recovery = { burst = 1, refill_per_second = 1 }
            }
          }
        }
      }
      basis_evidence = {
        repository     = "layervai/nhp"
        source_commit  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        path           = "docs/evidence/connector-authority/v1/sandbox-measurement-basis.json"
        sha256         = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        schema_version = 1
      }
      result_evidence = null
    }
    functions = merge({
      "layerv-nhp-sandbox-ca-ia" = {
        steady_provisioned_concurrency          = 2
        steady_reserved_concurrency             = 2
        rollout_active_provisioned_concurrency  = 2
        rollout_standby_provisioned_concurrency = 2
        rollout_reserved_concurrency            = 4
        max_caller_in_flight                    = 2
        max_caller_requests_per_second          = 4
        rollback_retention_seconds              = 3600
        basis_evidence = {
          repository     = "layervai/nhp"
          source_commit  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          path           = "docs/evidence/connector-authority/v1/sandbox-measurement-basis.json"
          sha256         = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          schema_version = 1
        }
        result_evidence = null
      }
      "layerv-nhp-sandbox-ca-ra" = {
        steady_provisioned_concurrency          = 2
        steady_reserved_concurrency             = 2
        rollout_active_provisioned_concurrency  = 2
        rollout_standby_provisioned_concurrency = 2
        rollout_reserved_concurrency            = 4
        max_caller_in_flight                    = 2
        max_caller_requests_per_second          = 4
        rollback_retention_seconds              = 3600
        basis_evidence = {
          repository     = "layervai/nhp"
          source_commit  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          path           = "docs/evidence/connector-authority/v1/sandbox-measurement-basis.json"
          sha256         = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          schema_version = 1
        }
        result_evidence = null
      }
      "layerv-nhp-sandbox-ca-icr" = {
        steady_provisioned_concurrency          = 2
        steady_reserved_concurrency             = 2
        rollout_active_provisioned_concurrency  = 2
        rollout_standby_provisioned_concurrency = 2
        rollout_reserved_concurrency            = 4
        max_caller_in_flight                    = 2
        max_caller_requests_per_second          = 4
        rollback_retention_seconds              = 3600
        basis_evidence = {
          repository     = "layervai/nhp"
          source_commit  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          path           = "docs/evidence/connector-authority/v1/sandbox-measurement-basis.json"
          sha256         = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          schema_version = 1
        }
        result_evidence = null
      }
      }, {
      for function_name in toset([
        "layerv-nhp-sandbox-ca-iro-cell0",
        "layerv-nhp-sandbox-ca-ar-cell0",
        "layerv-nhp-sandbox-ca-cr-cell0",
        "layerv-nhp-sandbox-ca-ccr-cell0",
        "layerv-nhp-sandbox-ca-iro-cell1",
        "layerv-nhp-sandbox-ca-ar-cell1",
        "layerv-nhp-sandbox-ca-cr-cell1",
        "layerv-nhp-sandbox-ca-ccr-cell1",
        ]) : function_name => {
        steady_provisioned_concurrency          = 2
        steady_reserved_concurrency             = 2
        rollout_active_provisioned_concurrency  = 2
        rollout_standby_provisioned_concurrency = 2
        rollout_reserved_concurrency            = 4
        max_caller_in_flight                    = 2
        max_caller_requests_per_second          = 4
        rollback_retention_seconds              = 3600
        basis_evidence = {
          repository     = "layervai/nhp"
          source_commit  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          path           = "docs/evidence/connector-authority/v1/sandbox-measurement-basis.json"
          sha256         = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          schema_version = 1
        }
        result_evidence = null
      }
    })
  }
}

run "gate_off_bound_contract_creates_no_function_and_opens_nothing" {
  command = plan

  variables {
    authority_runtime_functions_enabled = false
  }

  assert {
    condition = (
      length(aws_lambda_function.authority) == 0 &&
      length(aws_lambda_alias.authority) == 0 &&
      length(aws_iam_role.authority_exec) == 0 &&
      length(aws_lambda_provisioned_concurrency_config.authority) == 0 &&
      length(aws_security_group.authority_lambda) == 0 &&
      length(aws_vpc_security_group_egress_rule.authority_interface_endpoints) == 0 &&
      length(aws_vpc_security_group_egress_rule.authority_dynamodb) == 0 &&
      length(aws_vpc_security_group_egress_rule.authority_otp_redis) == 0 &&
      length(aws_vpc_security_group_ingress_rule.otp_redis_authority) == 0
    )
    error_message = "Binding the contract with the runtime gate off must create no runtime resource (Step 3 stays foundation_contract-only)."
  }

  assert {
    condition = (
      jsondecode(aws_vpc_endpoint.dynamodb.policy).Statement[0].Effect == "Deny" &&
      jsondecode(aws_vpc_endpoint.interface["kms"].policy).Statement[0].Effect == "Deny" &&
      length(aws_security_group.interface_endpoints.ingress) == 0
    )
    error_message = "With the gate off every endpoint must stay deny-all and both SGs no-ingress."
  }
}

run "gate_on_deploys_complete_two_cell_graph_and_exact_dependencies" {
  command = plan

  variables {
    authority_runtime_functions_enabled = true
  }

  assert {
    condition = (
      length(aws_lambda_function.authority) == 11 &&
      length(aws_lambda_alias.authority) == 22 &&
      length(aws_iam_role.authority_exec) == 11 &&
      length(aws_iam_role_policy.authority_exec) == 11 &&
      length(aws_lambda_provisioned_concurrency_config.authority) == 11 &&
      length(aws_cloudwatch_log_group.authority) == 11 &&
      length(aws_cloudwatch_metric_alarm.authority_spillover) == 11 &&
      length(aws_security_group.authority_lambda) == 1 &&
      length(aws_vpc_security_group_egress_rule.authority_interface_endpoints) == 1 &&
      length(aws_vpc_security_group_egress_rule.authority_dynamodb) == 1 &&
      length(aws_vpc_security_group_egress_rule.authority_otp_redis) == 1 &&
      length(aws_vpc_security_group_ingress_rule.otp_redis_authority) == 1
    )
    error_message = "The runtime must plan exactly 11 functions, 22 closed aliases, 11 exec roles/policies, 11 provisioned-concurrency configs, 11 log groups, 11 spillover alarms, and 1 function SG."
  }

  assert {
    condition = (
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-ia"].reserved_concurrent_executions == 2 &&
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-ra"].reserved_concurrent_executions == 2 &&
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-icr"].reserved_concurrent_executions == 2 &&
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-iro-cell0"].reserved_concurrent_executions == 2 &&
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-ccr-cell1"].reserved_concurrent_executions == 2 &&
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-ia"].package_type == "Image" &&
      alltrue([
        for pc in values(aws_lambda_provisioned_concurrency_config.authority) :
        pc.provisioned_concurrent_executions == 2 && pc.qualifier == "blue"
      ])
    )
    error_message = "Every function must pin reserved=2, be Image-packaged, and provision exactly 2 on the selected blue alias."
  }

  assert {
    condition = (
      jsondecode(aws_vpc_endpoint.dynamodb.policy).Statement[0].Effect == "Allow" &&
      jsondecode(aws_vpc_endpoint.interface["kms"].policy).Statement[0].Effect == "Allow" &&
      jsondecode(aws_vpc_endpoint.interface["secretsmanager"].policy).Statement[0].Effect == "Allow" &&
      jsondecode(aws_vpc_endpoint.interface["email"].policy).Statement[0].Effect == "Allow"
    )
    error_message = "The complete runtime must open its scoped DynamoDB, KMS, Secrets Manager, and SES dependency endpoints."
  }

  assert {
    condition = (
      jsondecode(aws_vpc_endpoint.interface["lambda"].policy).Statement[0].Effect == "Deny" &&
      jsondecode(aws_vpc_endpoint.interface["logs"].policy).Statement[0].Effect == "Deny" &&
      jsondecode(aws_vpc_endpoint.interface["monitoring"].policy).Statement[0].Effect == "Deny"
    )
    error_message = "The Hub caller endpoint and non-runtime dependencies must stay deny-all until their independent worker gate opens."
  }

  assert {
    condition = (
      length(aws_security_group.interface_endpoints.ingress) == 1 &&
      one(aws_security_group.interface_endpoints.ingress).from_port == 443 &&
      length(one(aws_security_group.interface_endpoints.ingress).security_groups) == 1 &&
      aws_vpc_security_group_egress_rule.authority_interface_endpoints[0].from_port == 443 &&
      aws_vpc_security_group_egress_rule.authority_interface_endpoints[0].to_port == 443 &&
      aws_vpc_security_group_egress_rule.authority_interface_endpoints[0].referenced_security_group_id == aws_security_group.interface_endpoints.id &&
      aws_vpc_security_group_egress_rule.authority_dynamodb[0].from_port == 443 &&
      aws_vpc_security_group_egress_rule.authority_dynamodb[0].to_port == 443 &&
      aws_vpc_security_group_egress_rule.authority_dynamodb[0].prefix_list_id == "pl-0123456789abcdef0" &&
      length(aws_vpc_security_group_egress_rule.authority_otp_redis) == 1 &&
      length(aws_vpc_security_group_ingress_rule.otp_redis_authority) == 1
    )
    error_message = "Authority egress must be exact standalone HTTPS/Redis rules, with exact interface-endpoint and Redis ingress."
  }

  # Per-operation execution-policy CONTENT is plan-known (the own-log-group ARN is
  # a constructed literal), so the handler-reconciled least-privilege scope is
  # asserted here as well as, exhaustively, in the Python first-apply checker.
  assert {
    condition = (
      # IssueAssignment: reads include DescribeTable (SSE verify at cold start);
      # replay Put on connector_authority ONLY; signs qat1 (GetPublicKey + Sign).
      contains({ for s in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-ia"].policy).Statement : s.Sid => s }["AuthorityReads"].Action, "dynamodb:DescribeTable") &&
      { for s in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-ia"].policy).Statement : s.Sid => s }["AuthorityReplayWrite"].Action == ["dynamodb:PutItem"] &&
      { for s in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-ia"].policy).Statement : s.Sid => s }["AuthorityReplayWrite"].Resource == ["arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-connector-authority"] &&
      toset({ for s in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-ia"].policy).Statement : s.Sid => s }["Qat1Sign"].Action) == toset(["kms:GetPublicKey", "kms:Sign"])
    )
    error_message = "IssueAssignment must read (incl. DescribeTable), Put-only the replay on connector_authority, and Sign qat1 (GetPublicKey+Sign)."
  }

  assert {
    condition = (
      # RefreshAssignment: replay Put only; agent_keys read reaches its pubkey GSI;
      # NO KMS statement (builds no KMS client).
      { for s in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-ra"].policy).Statement : s.Sid => s }["AuthorityReplayWrite"].Action == ["dynamodb:PutItem"] &&
      contains({ for s in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-ra"].policy).Statement : s.Sid => s }["AuthorityReads"].Resource, "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-qurl-agent-keys/index/*") &&
      !contains([for s in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-ra"].policy).Statement : s.Sid], "Qat1Sign")
    )
    error_message = "RefreshAssignment must Put-only the replay, read the agent_keys pubkey GSI, and carry no KMS statement."
  }

  assert {
    condition = (
      # IssueCredentialRecovery: writes connector_authority ONLY (Put + Update);
      # api_keys/agent_keys are read-set only (ConditionCheck); NO KMS statement.
      toset({ for s in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-icr"].policy).Statement : s.Sid => s }["AuthorityRecoveryWrite"].Action) == toset(["dynamodb:PutItem", "dynamodb:UpdateItem"]) &&
      { for s in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-icr"].policy).Statement : s.Sid => s }["AuthorityRecoveryWrite"].Resource == ["arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-connector-authority"] &&
      !contains([for s in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-icr"].policy).Statement : s.Sid], "Qat1Sign")
    )
    error_message = "IssueCredentialRecovery must write only connector_authority (Put+Update) and carry no KMS statement."
  }

  assert {
    condition = (
      # IRO can read only credential/customer state, load the public qat1 key,
      # consume the OTP secret, connect as the issuer, and send OTP email.
      toset({ for s in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-iro-cell0"].policy).Statement : s.Sid => s }["AuthorityReads"].Resource) == toset([
        "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-qurl-api-keys",
        "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-customers",
      ]) &&
      { for s in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-iro-cell0"].policy).Statement : s.Sid => s }["Qat1PublicKey"].Action == ["kms:GetPublicKey"] &&
      { for s in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-iro-cell0"].policy).Statement : s.Sid => s }["OTPRedisConnect"].Resource[1] == "arn:aws:elasticache:us-east-2:767397897469:user:layerv-nhp-sandbox-control-otp-issuer" &&
      { for s in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-iro-cell0"].policy).Statement : s.Sid => s }["OTPSendEmail"].Action == ["ses:SendEmail"]
    )
    error_message = "IssueRegistrationOTP must have only its exact read, qat1 public-key, OTP secret, Redis issuer, and SES capabilities."
  }

  assert {
    condition = (
      # AR is the only registration operation that consumes the OTP and may
      # create/update agent and authority state.
      toset({ for s in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-ar-cell1"].policy).Statement : s.Sid => s }["RegistrationIdentityWrite"].Action) == toset(["dynamodb:PutItem", "dynamodb:UpdateItem"]) &&
      { for s in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-ar-cell1"].policy).Statement : s.Sid => s }["OTPRedisConnect"].Resource[1] == "arn:aws:elasticache:us-east-2:767397897469:user:layerv-nhp-sandbox-control-otp-activator" &&
      contains([for s in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-ar-cell1"].policy).Statement : s.Sid], "OTPSecretRead") &&
      !contains([for s in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-cr-cell1"].policy).Statement : s.Sid], "OTPSecretRead") &&
      !contains([for s in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-ccr-cell1"].policy).Statement : s.Sid], "OTPSecretRead")
    )
    error_message = "ActivateRegistration alone must consume OTP state; completion paths must not inherit OTP secret or Redis access."
  }

  assert {
    condition = (
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-iro-cell0"].environment[0].variables.CONNECTOR_AUTHORITY_CELL_ID == "cell0" &&
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-iro-cell0"].environment[0].variables.CONNECTOR_AUTHORITY_OPERATION == "IssueRegistrationOTP" &&
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-iro-cell0"].environment[0].variables.CONNECTOR_AUTHORITY_REDIS_USER_ID == "layerv-nhp-sandbox-control-otp-issuer" &&
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-ar-cell1"].environment[0].variables.CONNECTOR_AUTHORITY_CELL_ID == "cell1" &&
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-ar-cell1"].environment[0].variables.CONNECTOR_AUTHORITY_ADMISSION_MAX_IN_FLIGHT == "1" &&
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-cr-cell1"].environment[0].variables.CONNECTOR_AUTHORITY_OPERATION == "CompleteRegistration" &&
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-ccr-cell1"].environment[0].variables.CONNECTOR_AUTHORITY_OPERATION == "CompleteCredentialRecovery"
    )
    error_message = "Every cell function must receive its exact operation, cell, Redis identity, and admission configuration."
  }

  assert {
    condition = (
      # The qat1 interface endpoint permits GetPublicKey only to IA/IRO/AR,
      # while Sign remains exclusive to IA. No operation receives kms:Verify.
      # VPC endpoint policies do not match a role-ARN Principal against an
      # assumed-role session, so scoping lives in Principal "*" + an exact
      # aws:PrincipalArn condition (the DynamoDB gateway is the same shape).
      jsondecode(aws_vpc_endpoint.interface["kms"].policy).Statement[0].Principal == "*" &&
      jsondecode(aws_vpc_endpoint.interface["kms"].policy).Statement[1].Principal == "*" &&
      jsondecode(aws_vpc_endpoint.dynamodb.policy).Statement[0].Principal == "*" &&
      length(jsondecode(aws_vpc_endpoint.interface["kms"].policy).Statement[0].Condition.StringEquals["aws:PrincipalArn"]) == 5 &&
      contains(jsondecode(aws_vpc_endpoint.interface["kms"].policy).Statement[0].Condition.StringEquals["aws:PrincipalArn"], "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-ca-ia-exec") &&
      contains(jsondecode(aws_vpc_endpoint.interface["kms"].policy).Statement[0].Condition.StringEquals["aws:PrincipalArn"], "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-ca-iro-cell1-exec") &&
      contains(jsondecode(aws_vpc_endpoint.interface["kms"].policy).Statement[0].Condition.StringEquals["aws:PrincipalArn"], "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-ca-ar-cell0-exec") &&
      jsondecode(aws_vpc_endpoint.interface["kms"].policy).Statement[0].Action == ["kms:GetPublicKey"] &&
      jsondecode(aws_vpc_endpoint.interface["kms"].policy).Statement[1].Condition.StringEquals["aws:PrincipalArn"] == ["arn:aws:iam::767397897469:role/layerv-nhp-sandbox-ca-ia-exec"] &&
      jsondecode(aws_vpc_endpoint.interface["kms"].policy).Statement[1].Action == ["kms:Sign"] &&
      contains(jsondecode(aws_vpc_endpoint.dynamodb.policy).Statement[0].Action, "dynamodb:DescribeTable") &&
      !contains(jsondecode(aws_vpc_endpoint.dynamodb.policy).Statement[0].Action, "dynamodb:DeleteItem") &&
      !contains(jsondecode(aws_vpc_endpoint.dynamodb.policy).Statement[0].Action, "dynamodb:TransactWriteItems")
    )
    error_message = "KMS endpoint must separate exact public-key and sign principals; DynamoDB must include DescribeTable without Delete/Transact*."
  }

  assert {
    condition = (
      # Gateway VPC-endpoint policies are TABLE-GRANULAR: the DynamoDB endpoint
      # Resource must be EXACTLY the four base tables. A /index/* sub-resource
      # is InvalidPolicyDocument at ModifyVpcEndpoint (the apply-time failure this
      # guards). The finer pubkey-GSI grant lives on the RefreshAssignment
      # identity policy (asserted above), never on this coarse network gate.
      toset(jsondecode(aws_vpc_endpoint.dynamodb.policy).Statement[0].Resource) == toset([
        "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-qurl-api-keys",
        "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-qurl-agent-keys",
        "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-customers",
        "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-connector-authority",
      ]) &&
      !contains(jsondecode(aws_vpc_endpoint.dynamodb.policy).Statement[0].Resource, "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-qurl-agent-keys/index/*")
    )
    error_message = "The DynamoDB gateway-endpoint policy must list only the four base-table ARNs (table-granular); a /index/* sub-resource is invalid at apply."
  }
}

run "gate_on_without_contract_fails_closed" {
  command = plan

  variables {
    authority_runtime_contract          = null
    authority_runtime_functions_enabled = true
  }

  expect_failures = [
    terraform_data.foundation_contract,
  ]
}
