# Plan-only tests for the Connector Authority Lambda runtime slice. They prove
# the measurement runtime deploys exactly the 3 hub functions, both closed
# aliases, steady concurrency, and the lockstep opening of ONLY the dependency
# endpoints, while the caller (lambda) endpoint and the OTP Redis SG stay dark;
# that the same contract with the gate off creates nothing; and that the gate
# fails closed against a null contract.

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
  target          = aws_elasticache_serverless_cache.otp
  override_during = plan
  values = {
    endpoint = [{
      address = "layerv-nhp-sandbox-control-otp.serverless.use2.cache.amazonaws.com"
      port    = 6379
    }]
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

  # The exact merged measurement basis: 3 hub functions, cell0 frozen catalog.
  authority_runtime_contract = {
    schema_version           = 1
    phase                    = "measurement"
    selected_authority_color = "blue"
    provisioned_cells = {
      cell0 = {
        caller_role_arn = "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-server"
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
    functions = {
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
    }
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
      length(aws_security_group.authority_lambda) == 0
    )
    error_message = "Binding the contract with the runtime gate off must create no runtime resource (Step 3 stays foundation_contract-only)."
  }

  assert {
    condition = (
      jsondecode(aws_vpc_endpoint.dynamodb.policy).Statement[0].Effect == "Deny" &&
      jsondecode(aws_vpc_endpoint.interface["kms"].policy).Statement[0].Effect == "Deny" &&
      length(aws_security_group.interface_endpoints.ingress) == 0 &&
      length(aws_security_group.otp_redis.ingress) == 0
    )
    error_message = "With the gate off every endpoint must stay deny-all and both SGs no-ingress."
  }
}

run "gate_on_deploys_three_hub_functions_and_opens_only_dependency_endpoints" {
  command = plan

  variables {
    authority_runtime_functions_enabled = true
  }

  assert {
    condition = (
      length(aws_lambda_function.authority) == 3 &&
      length(aws_lambda_alias.authority) == 6 &&
      length(aws_iam_role.authority_exec) == 3 &&
      length(aws_iam_role_policy.authority_exec) == 3 &&
      length(aws_lambda_provisioned_concurrency_config.authority) == 3 &&
      length(aws_cloudwatch_log_group.authority) == 3 &&
      length(aws_cloudwatch_metric_alarm.authority_spillover) == 3 &&
      length(aws_security_group.authority_lambda) == 1
    )
    error_message = "The measurement runtime must plan exactly the 3 hub functions, 6 closed aliases, 3 exec roles/policies, 3 provisioned-concurrency configs, 3 log groups, 3 spillover alarms, and 1 function SG."
  }

  assert {
    condition = (
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-ia"].reserved_concurrent_executions == 2 &&
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-ra"].reserved_concurrent_executions == 2 &&
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-icr"].reserved_concurrent_executions == 2 &&
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
      jsondecode(aws_vpc_endpoint.interface["kms"].policy).Statement[0].Effect == "Allow"
    )
    error_message = "The DynamoDB gateway and KMS interface endpoints must open (deny replaced by a scoped Allow) in the runtime slice."
  }

  assert {
    condition = (
      jsondecode(aws_vpc_endpoint.interface["lambda"].policy).Statement[0].Effect == "Deny" &&
      jsondecode(aws_vpc_endpoint.interface["email"].policy).Statement[0].Effect == "Deny" &&
      jsondecode(aws_vpc_endpoint.interface["logs"].policy).Statement[0].Effect == "Deny" &&
      jsondecode(aws_vpc_endpoint.interface["monitoring"].policy).Statement[0].Effect == "Deny" &&
      jsondecode(aws_vpc_endpoint.interface["secretsmanager"].policy).Statement[0].Effect == "Deny"
    )
    error_message = "The caller (lambda) endpoint and every non-dependency endpoint must stay deny-all; the caller path is dark until the Hub role exists."
  }

  assert {
    condition = (
      length(aws_security_group.interface_endpoints.ingress) == 1 &&
      one(aws_security_group.interface_endpoints.ingress).from_port == 443 &&
      length(one(aws_security_group.interface_endpoints.ingress).security_groups) == 1 &&
      length(aws_security_group.otp_redis.ingress) == 0
    )
    error_message = "The interface-endpoint SG must gain exactly one 443 SG-scoped ingress; the OTP Redis SG must stay closed (no hub op touches Redis)."
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
      # The qat1 interface endpoint opens to the IssueAssignment role ALONE, actions
      # GetPublicKey + Sign (no kms:Verify); the DynamoDB endpoint action union adds
      # DescribeTable and drops every Transact*/BatchGetItem/DeleteItem entry.
      # VPC endpoint policies do not match a role-ARN Principal against an
      # assumed-role session, so scoping lives in Principal "*" + an exact
      # aws:PrincipalArn condition (the DynamoDB gateway is the same shape).
      jsondecode(aws_vpc_endpoint.interface["kms"].policy).Statement[0].Principal == "*" &&
      jsondecode(aws_vpc_endpoint.dynamodb.policy).Statement[0].Principal == "*" &&
      length(jsondecode(aws_vpc_endpoint.interface["kms"].policy).Statement[0].Condition.StringEquals["aws:PrincipalArn"]) == 1 &&
      contains(jsondecode(aws_vpc_endpoint.interface["kms"].policy).Statement[0].Condition.StringEquals["aws:PrincipalArn"], "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-ca-ia-exec") &&
      toset(jsondecode(aws_vpc_endpoint.interface["kms"].policy).Statement[0].Action) == toset(["kms:GetPublicKey", "kms:Sign"]) &&
      contains(jsondecode(aws_vpc_endpoint.dynamodb.policy).Statement[0].Action, "dynamodb:DescribeTable") &&
      !contains(jsondecode(aws_vpc_endpoint.dynamodb.policy).Statement[0].Action, "dynamodb:DeleteItem") &&
      !contains(jsondecode(aws_vpc_endpoint.dynamodb.policy).Statement[0].Action, "dynamodb:TransactWriteItems")
    )
    error_message = "KMS endpoint must open to ca-ia alone (GetPublicKey+Sign, no Verify); the DynamoDB endpoint must add DescribeTable and drop Delete/Transact* actions."
  }

  assert {
    condition = (
      # Gateway VPC-endpoint policies are TABLE-GRANULAR: the DynamoDB endpoint
      # Resource must be EXACTLY the three base tables. A /index/* sub-resource
      # is InvalidPolicyDocument at ModifyVpcEndpoint (the apply-time failure this
      # guards). The finer pubkey-GSI grant lives on the RefreshAssignment
      # identity policy (asserted above), never on this coarse network gate.
      toset(jsondecode(aws_vpc_endpoint.dynamodb.policy).Statement[0].Resource) == toset([
        "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-qurl-api-keys",
        "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-qurl-agent-keys",
        "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-connector-authority",
      ]) &&
      !contains(jsondecode(aws_vpc_endpoint.dynamodb.policy).Statement[0].Resource, "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-qurl-agent-keys/index/*")
    )
    error_message = "The DynamoDB gateway-endpoint policy must list only the three base-table ARNs (table-granular); a /index/* sub-resource is InvalidPolicyDocument at apply."
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
