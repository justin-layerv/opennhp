# Plan-only tests for the complete Connector Authority Lambda runtime. They
# prove the two-cell measurement graph deploys exactly 3 Hub + 5-per-cell
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
  target          = aws_dynamodb_table.api_key_idempotency
  override_during = plan
  values          = { arn = "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-qurl-apikey-idempotency" }
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

  # The runtime gate fails closed without a reviewed operator alarm destination.
  operator_alarm_topic_arns = ["arn:aws:sns:us-east-2:767397897469:layerv-nhp-sandbox-cell0-alerts"]

  # The exact complete two-cell measurement basis.
  authority_runtime_contract = {
    schema_version           = 1
    phase                    = "measurement"
    selected_authority_color = "blue"
    provisioned_cells = {
      cell0 = {
        caller_role_arn                       = "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-server"
        cell_table_prefix                     = "layerv-nhp-sandbox-cell0"
        qurl_resources_table_arn              = "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-cell0-qurl-resources"
        qurl_resource_key_material_table_arn  = "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-cell0-qurl-resource-key-material"
        cell_data_kms_key_arn                 = "arn:aws:kms:us-east-2:767397897469:key/49224991-f4c7-4e02-bb23-0003e6326d02"
        resource_key_envelope_kms_key_arn     = "arn:aws:kms:us-east-2:767397897469:key/eb55226b-3443-4913-8266-ac68c66efe96"
        resource_key_software_custody_enabled = true
      }
      cell1 = {
        caller_role_arn                       = "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-cell1-server"
        cell_table_prefix                     = "layerv-nhp-sandbox-cell1-cell1"
        qurl_resources_table_arn              = "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-cell1-cell1-qurl-resources"
        qurl_resource_key_material_table_arn  = "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-cell1-cell1-qurl-resource-key-material"
        cell_data_kms_key_arn                 = "arn:aws:kms:us-east-2:767397897469:key/fc5121da-c353-4621-b24b-7ec5f79446bd"
        resource_key_envelope_kms_key_arn     = "arn:aws:kms:us-east-2:767397897469:key/1ff3c518-1653-4126-ab7e-039a7e6ab0ff"
        resource_key_software_custody_enabled = true
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
      authority_image_source             = "pinned_digest"
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
              resolve_connector_resource   = 1
            }
            preinvoke_rate_limits = {
              issue_registration_otp       = { burst = 1, refill_per_second = 1 }
              activate_registration        = { burst = 1, refill_per_second = 1 }
              complete_registration        = { burst = 1, refill_per_second = 1 }
              complete_credential_recovery = { burst = 1, refill_per_second = 1 }
              resolve_connector_resource   = { burst = 1, refill_per_second = 1 }
            }
          }
          cell1 = {
            max_replicas = 2
            preinvoke_limits = {
              issue_registration_otp       = 1
              activate_registration        = 1
              complete_registration        = 1
              complete_credential_recovery = 1
              resolve_connector_resource   = 1
            }
            preinvoke_rate_limits = {
              issue_registration_otp       = { burst = 1, refill_per_second = 1 }
              activate_registration        = { burst = 1, refill_per_second = 1 }
              complete_registration        = { burst = 1, refill_per_second = 1 }
              complete_credential_recovery = { burst = 1, refill_per_second = 1 }
              resolve_connector_resource   = { burst = 1, refill_per_second = 1 }
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
        steady_reserved_concurrency             = 4
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
        steady_reserved_concurrency             = 4
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
        steady_reserved_concurrency             = 4
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
        "layerv-nhp-sandbox-ca-creso-cell0",
        "layerv-nhp-sandbox-ca-iro-cell1",
        "layerv-nhp-sandbox-ca-ar-cell1",
        "layerv-nhp-sandbox-ca-cr-cell1",
        "layerv-nhp-sandbox-ca-ccr-cell1",
        "layerv-nhp-sandbox-ca-creso-cell1",
        ]) : function_name => {
        steady_provisioned_concurrency          = 2
        steady_reserved_concurrency             = 4
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
      length(aws_lambda_function.authority) == 13 &&
      length(aws_lambda_alias.authority) == 26 &&
      length(aws_iam_role.authority_exec) == 13 &&
      length(aws_iam_role_policy.authority_exec) == 13 &&
      length(aws_lambda_provisioned_concurrency_config.authority) == 13 &&
      length(aws_cloudwatch_log_group.authority) == 13 &&
      length(aws_cloudwatch_metric_alarm.authority_spillover) == 13 &&
      length(aws_security_group.authority_lambda) == 1 &&
      length(aws_vpc_security_group_egress_rule.authority_interface_endpoints) == 1 &&
      length(aws_vpc_security_group_egress_rule.authority_dynamodb) == 1 &&
      length(aws_vpc_security_group_egress_rule.authority_otp_redis) == 1 &&
      length(aws_vpc_security_group_ingress_rule.otp_redis_authority) == 1
    )
    error_message = "The runtime must plan exactly 13 functions, 26 closed aliases, 13 exec roles/policies, 13 provisioned-concurrency configs, 13 log groups, 13 spillover alarms, and 1 function SG."
  }

  assert {
    condition = (
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-creso-cell0"].environment[0].variables.CONNECTOR_AUTHORITY_OPERATION == "ResolveConnectorResource" &&
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-creso-cell0"].environment[0].variables.CONNECTOR_AUTHORITY_CELL_TABLE_PREFIX == "layerv-nhp-sandbox-cell0" &&
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-creso-cell0"].environment[0].variables.CONNECTOR_AUTHORITY_CELL_DATA_KMS_KEY_ARN == "arn:aws:kms:us-east-2:767397897469:key/49224991-f4c7-4e02-bb23-0003e6326d02" &&
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-creso-cell0"].environment[0].variables.CONNECTOR_AUTHORITY_RESOURCE_KEY_ENVELOPE_KMS_KEY_ARN == "arn:aws:kms:us-east-2:767397897469:key/eb55226b-3443-4913-8266-ac68c66efe96" &&
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-creso-cell0"].environment[0].variables.CONNECTOR_AUTHORITY_RESOURCE_KEY_SERVICE_ROLE_ARN == "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-ca-creso-cell0-exec" &&
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-creso-cell0"].environment[0].variables.CONNECTOR_AUTHORITY_RESOURCE_KEY_SOFTWARE_CUSTODY_ENABLED == "true" &&
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-creso-cell1"].environment[0].variables.CONNECTOR_AUTHORITY_CELL_TABLE_PREFIX == "layerv-nhp-sandbox-cell1-cell1" &&
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-creso-cell1"].environment[0].variables.CONNECTOR_AUTHORITY_CELL_DATA_KMS_KEY_ARN == "arn:aws:kms:us-east-2:767397897469:key/fc5121da-c353-4621-b24b-7ec5f79446bd" &&
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-creso-cell1"].environment[0].variables.CONNECTOR_AUTHORITY_RESOURCE_KEY_ENVELOPE_KMS_KEY_ARN == "arn:aws:kms:us-east-2:767397897469:key/1ff3c518-1653-4126-ab7e-039a7e6ab0ff"
    )
    error_message = "Each creso function must receive its exact Terraform-owned canonical or doubled-legacy table prefix, raw cell/envelope CMKs, own execution role, and custody mode."
  }

  assert {
    condition = alltrue([
      for cell_id in ["cell0", "cell1"] :
      (
        toset({
          for statement in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-creso-${cell_id}"].policy).Statement :
          statement.Sid => statement
        }["ConnectorResourceControlRead"].Action) == toset(["dynamodb:GetItem"]) &&
        toset({
          for statement in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-creso-${cell_id}"].policy).Statement :
          statement.Sid => statement
        }["ConnectorResourceCellResourceData"].Action) == toset(["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"]) &&
        toset({
          for statement in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-creso-${cell_id}"].policy).Statement :
          statement.Sid => statement
        }["ConnectorResourceCellKeyMaterial"].Action) == toset(["dynamodb:DeleteItem", "dynamodb:PutItem"]) &&
        contains([
          for statement in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-creso-${cell_id}"].policy).Statement : statement.Sid
        ], "ConnectorResourceGenerateEnvelopeDataKey") &&
        !contains([
          for statement in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-creso-${cell_id}"].policy).Statement : statement.Sid
        ], "ConnectorResourceCreateHardwareKey") &&
        !contains([
          for statement in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-creso-${cell_id}"].policy).Statement : statement.Sid
        ], "AuthorityDynamoDBDecrypt") &&
        {
          for statement in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-creso-${cell_id}"].policy).Statement :
          statement.Sid => statement
          }["ConnectorResourceControlDynamoDBDecrypt"] == {
          Sid      = "ConnectorResourceControlDynamoDBDecrypt"
          Effect   = "Allow"
          Action   = ["kms:Decrypt"]
          Resource = [aws_kms_key.authority_data.arn]
          Condition = {
            StringEquals = {
              "kms:ViaService"                                  = "dynamodb.us-east-2.amazonaws.com"
              "kms:EncryptionContext:aws:dynamodb:subscriberId" = "767397897469"
              "kms:EncryptionContext:aws:dynamodb:tableName" = [
                "layerv-nhp-sandbox-control-qurl-agent-keys",
                "layerv-nhp-sandbox-control-connector-authority",
                "layerv-nhp-sandbox-control-qurl-customers",
              ]
            }
          }
        } &&
        {
          for statement in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-creso-${cell_id}"].policy).Statement :
          statement.Sid => statement
          }["ConnectorResourceCellDynamoDBDecrypt"] == {
          Sid      = "ConnectorResourceCellDynamoDBDecrypt"
          Effect   = "Allow"
          Action   = ["kms:Decrypt"]
          Resource = [cell_id == "cell0" ? "arn:aws:kms:us-east-2:767397897469:key/49224991-f4c7-4e02-bb23-0003e6326d02" : "arn:aws:kms:us-east-2:767397897469:key/fc5121da-c353-4621-b24b-7ec5f79446bd"]
          Condition = {
            StringEquals = {
              "kms:ViaService"                                  = "dynamodb.us-east-2.amazonaws.com"
              "kms:EncryptionContext:aws:dynamodb:subscriberId" = "767397897469"
              "kms:EncryptionContext:aws:dynamodb:tableName" = cell_id == "cell0" ? [
                "layerv-nhp-sandbox-cell0-qurl-resources",
                "layerv-nhp-sandbox-cell0-qurl-resource-key-material",
                ] : [
                "layerv-nhp-sandbox-cell1-cell1-qurl-resources",
                "layerv-nhp-sandbox-cell1-cell1-qurl-resource-key-material",
              ]
            }
          }
        } &&
        length([
          for statement in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-creso-${cell_id}"].policy).Statement : statement
          if contains(try(tolist(statement.Action), [statement.Action]), "kms:Decrypt")
        ]) == 2 &&
        length(setintersection(
          toset(flatten([
            for statement in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-creso-${cell_id}"].policy).Statement :
            try(tolist(statement.Action), [statement.Action])
          ])),
          toset(["dynamodb:Query", "dynamodb:Scan", "kms:PutKeyPolicy", "kms:Sign", "kms:TagResource"]),
        )) == 0
      )
    ])
    error_message = "creso IAM must carry exactly two DynamoDB-mediated decrypt grants for the Control CMK and its own cell CMK, plus only the exact Control/cell read-write and software-envelope capabilities; cross-cell keys, direct decrypt, Query, Scan, Sign, key-policy mutation, and tag mutation stay absent."
  }

  assert {
    condition = (
      toset({
        for statement in jsondecode(aws_vpc_endpoint.dynamodb.policy).Statement :
        statement.Sid => statement
        }["ConnectorResourceCellData"].Resource) == toset([
        "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-cell0-qurl-resource-key-material",
        "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-cell0-qurl-resources",
        "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-cell1-cell1-qurl-resource-key-material",
        "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-cell1-cell1-qurl-resources",
      ]) &&
      toset({
        for statement in jsondecode(aws_vpc_endpoint.interface["kms"].policy).Statement :
        statement.Sid => statement
        }["ConnectorResourceGenerateEnvelopeDataKey"].Resource) == toset([
        "arn:aws:kms:us-east-2:767397897469:key/1ff3c518-1653-4126-ab7e-039a7e6ab0ff",
        "arn:aws:kms:us-east-2:767397897469:key/eb55226b-3443-4913-8266-ac68c66efe96",
      ]) &&
      !contains([
        for statement in jsondecode(aws_vpc_endpoint.interface["kms"].policy).Statement : statement.Sid
      ], "ConnectorResourceCreateHardwareKey")
    )
    error_message = "Dependency endpoint policies must admit the exact cell tables and raw envelope keys to creso without rendering empty hardware-custody statements."
  }

  assert {
    condition = (
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-ia"].reserved_concurrent_executions == 4 &&
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-ra"].reserved_concurrent_executions == 4 &&
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-icr"].reserved_concurrent_executions == 4 &&
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-iro-cell0"].reserved_concurrent_executions == 4 &&
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-ccr-cell1"].reserved_concurrent_executions == 4 &&
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
      jsondecode(local.dynamodb_endpoint_policy).Statement[0].Effect == "Allow" &&
      jsondecode(local.interface_endpoint_policies["kms"]).Statement[0].Effect == "Allow" &&
      jsondecode(local.interface_endpoint_policies["secretsmanager"]).Statement[0].Effect == "Allow" &&
      jsondecode(local.interface_endpoint_policies["email"]).Statement[0].Effect == "Allow"
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
    condition = alltrue([
      for function in values(aws_lambda_function.authority) :
      length({
        for key, value in function.environment[0].variables :
        key => value if startswith(key, "CONNECTOR_AUTHORITY_PROOF_")
      }) == 0
    ])
    error_message = "A contract without the sandbox proof gate must render no proof-policy environment key on any function."
  }

  assert {
    condition = (
      # The qat1 interface endpoint permits GetPublicKey only to IA/IRO/AR,
      # while Sign remains exclusive to IA. No operation receives kms:Verify.
      # VPC endpoint policies do not match a role-ARN Principal against an
      # assumed-role session, so scoping lives in Principal "*" + an exact
      # aws:PrincipalArn condition (the DynamoDB gateway is the same shape).
      jsondecode(local.interface_endpoint_policies["kms"]).Statement[0].Principal == "*" &&
      jsondecode(local.interface_endpoint_policies["kms"]).Statement[1].Principal == "*" &&
      jsondecode(local.dynamodb_endpoint_policy).Statement[0].Principal == "*" &&
      length(jsondecode(local.interface_endpoint_policies["kms"]).Statement[0].Condition.StringEquals["aws:PrincipalArn"]) == 5 &&
      contains(jsondecode(local.interface_endpoint_policies["kms"]).Statement[0].Condition.StringEquals["aws:PrincipalArn"], "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-ca-ia-exec") &&
      contains(jsondecode(local.interface_endpoint_policies["kms"]).Statement[0].Condition.StringEquals["aws:PrincipalArn"], "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-ca-iro-cell1-exec") &&
      contains(jsondecode(local.interface_endpoint_policies["kms"]).Statement[0].Condition.StringEquals["aws:PrincipalArn"], "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-ca-ar-cell0-exec") &&
      jsondecode(local.interface_endpoint_policies["kms"]).Statement[0].Action == ["kms:GetPublicKey"] &&
      jsondecode(local.interface_endpoint_policies["kms"]).Statement[1].Condition.StringEquals["aws:PrincipalArn"] == ["arn:aws:iam::767397897469:role/layerv-nhp-sandbox-ca-ia-exec"] &&
      jsondecode(local.interface_endpoint_policies["kms"]).Statement[1].Action == ["kms:Sign"] &&
      contains(jsondecode(local.dynamodb_endpoint_policy).Statement[0].Action, "dynamodb:DescribeTable") &&
      !contains(jsondecode(local.dynamodb_endpoint_policy).Statement[0].Action, "dynamodb:DeleteItem") &&
      !contains(jsondecode(local.dynamodb_endpoint_policy).Statement[0].Action, "dynamodb:TransactGetItems") &&
      !contains(jsondecode(local.dynamodb_endpoint_policy).Statement[0].Action, "dynamodb:TransactWriteItems")
    )
    error_message = "KMS endpoint must separate exact public-key and sign principals; DynamoDB must include DescribeTable without Delete/Transact*."
  }

  assert {
    condition = (
      # Gateway VPC-endpoint policies are TABLE-GRANULAR: the DynamoDB endpoint
      # Resource must be EXACTLY the five base tables. A /index/* sub-resource
      # is InvalidPolicyDocument at ModifyVpcEndpoint (the apply-time failure this
      # guards). The finer pubkey-GSI grant lives on the RefreshAssignment
      # identity policy (asserted above), never on this coarse network gate.
      toset(jsondecode(local.dynamodb_endpoint_policy).Statement[0].Resource) == toset([
        "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-qurl-api-keys",
        "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-qurl-agent-keys",
        "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-qurl-apikey-idempotency",
        "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-customers",
        "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-connector-authority",
      ]) &&
      !contains(jsondecode(local.dynamodb_endpoint_policy).Statement[0].Resource, "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-qurl-agent-keys/index/*")
    )
    error_message = "The DynamoDB gateway-endpoint policy must list only the five base-table ARNs (table-granular); a /index/* sub-resource is invalid at apply."
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

# ---------------------------------------------------------------------------
# Operator alerts and the full runtime alarm set (NHP #3455).
# ---------------------------------------------------------------------------
run "alarm_set_is_complete_and_every_alarm_is_actionable" {
  command = plan

  variables {
    authority_runtime_functions_enabled = true
  }

  assert {
    condition = (
      length(aws_cloudwatch_metric_alarm.authority_spillover) == 13 &&
      length(aws_cloudwatch_metric_alarm.authority_runtime) == 65 &&
      length(aws_cloudwatch_composite_alarm.authority_non_provisioned_initialization) == 13 &&
      length(aws_cloudwatch_metric_alarm.authority_terminal_outcome) == 26 &&
      length(aws_cloudwatch_metric_alarm.authority_admission_rejected) == 8 &&
      length(aws_cloudwatch_metric_alarm.authority_adapter_contract_violation) == 4 &&
      length(aws_cloudwatch_metric_alarm.authority_adapter_late_result) == 4 &&
      length(aws_cloudwatch_metric_alarm.authority_completion_identity_rejected) == 2
    )
    error_message = "The runtime alarm set must be exactly 13 spillover + 65 platform + 13 composite + 26 terminal-outcome + 8 admission + 4 contract-violation + 4 late-result + 2 completion-identity alarms."
  }

  # Omitting a function from any per-function alarm family is the failure this
  # catches: every one of the 13 functions must carry all five platform alarms,
  # the spillover alarm, the composite, and both terminal-outcome alarms.
  assert {
    condition = alltrue(flatten([
      for name in keys(aws_lambda_function.authority) : [
        contains(keys(aws_cloudwatch_metric_alarm.authority_spillover), name),
        contains(keys(aws_cloudwatch_composite_alarm.authority_non_provisioned_initialization), name),
        contains(keys(aws_cloudwatch_metric_alarm.authority_runtime), "${name}:errors"),
        contains(keys(aws_cloudwatch_metric_alarm.authority_runtime), "${name}:throttles"),
        contains(keys(aws_cloudwatch_metric_alarm.authority_runtime), "${name}:duration"),
        contains(keys(aws_cloudwatch_metric_alarm.authority_runtime), "${name}:concurrency_exhaustion"),
        contains(keys(aws_cloudwatch_metric_alarm.authority_runtime), "${name}:async_invocation"),
        contains(keys(aws_cloudwatch_metric_alarm.authority_terminal_outcome), "${name}:internal"),
        contains(keys(aws_cloudwatch_metric_alarm.authority_terminal_outcome), "${name}:unavailable"),
      ]
    ]))
    error_message = "Every Authority function must carry spillover, errors, throttles, duration, concurrency-exhaustion, async-invocation, non-provisioned-initialization, and both terminal-outcome alarms."
  }

  # An alarm with no action is silent on a real fault while showing a green OK.
  assert {
    condition = alltrue(flatten([
      [for a in values(aws_cloudwatch_metric_alarm.authority_spillover) : a.alarm_actions == toset(["arn:aws:sns:us-east-2:767397897469:layerv-nhp-sandbox-cell0-alerts"])],
      [for a in values(aws_cloudwatch_metric_alarm.authority_runtime) : a.alarm_actions == toset(["arn:aws:sns:us-east-2:767397897469:layerv-nhp-sandbox-cell0-alerts"])],
      [for a in values(aws_cloudwatch_composite_alarm.authority_non_provisioned_initialization) : a.alarm_actions == toset(["arn:aws:sns:us-east-2:767397897469:layerv-nhp-sandbox-cell0-alerts"])],
      [for a in values(aws_cloudwatch_metric_alarm.authority_terminal_outcome) : a.alarm_actions == toset(["arn:aws:sns:us-east-2:767397897469:layerv-nhp-sandbox-cell0-alerts"])],
      [for a in values(aws_cloudwatch_metric_alarm.authority_admission_rejected) : a.alarm_actions == toset(["arn:aws:sns:us-east-2:767397897469:layerv-nhp-sandbox-cell0-alerts"])],
      [for a in values(aws_cloudwatch_metric_alarm.authority_adapter_contract_violation) : a.alarm_actions == toset(["arn:aws:sns:us-east-2:767397897469:layerv-nhp-sandbox-cell0-alerts"])],
      [for a in values(aws_cloudwatch_metric_alarm.authority_adapter_late_result) : a.alarm_actions == toset(["arn:aws:sns:us-east-2:767397897469:layerv-nhp-sandbox-cell0-alerts"])],
      [for a in values(aws_cloudwatch_metric_alarm.authority_completion_identity_rejected) : a.alarm_actions == toset(["arn:aws:sns:us-east-2:767397897469:layerv-nhp-sandbox-cell0-alerts"])],
    ]))
    error_message = "Every Authority alarm must route to exactly the reviewed operator destination."
  }

  # AWS/Lambda platform alarms select the function-wide aggregate stream. AWS
  # publishes {FunctionName} for every metric used here (verified live); adding
  # or dropping a dimension selects a stream nothing writes to.
  assert {
    condition = alltrue(flatten([
      [for k, a in aws_cloudwatch_metric_alarm.authority_spillover : a.dimensions == tomap({ FunctionName = k })],
      [for k, a in aws_cloudwatch_metric_alarm.authority_runtime : a.dimensions == tomap({ FunctionName = split(":", k)[0] })],
    ]))
    error_message = "Every AWS/Lambda Authority alarm must key on exactly {FunctionName}, the published function-wide dim set."
  }

  assert {
    condition = (
      aws_cloudwatch_metric_alarm.authority_runtime["layerv-nhp-sandbox-ca-ia:errors"].metric_name == "Errors" &&
      aws_cloudwatch_metric_alarm.authority_runtime["layerv-nhp-sandbox-ca-ia:throttles"].metric_name == "Throttles" &&
      aws_cloudwatch_metric_alarm.authority_runtime["layerv-nhp-sandbox-ca-ia:duration"].metric_name == "Duration" &&
      aws_cloudwatch_metric_alarm.authority_runtime["layerv-nhp-sandbox-ca-ia:concurrency_exhaustion"].metric_name == "ConcurrentExecutions" &&
      aws_cloudwatch_metric_alarm.authority_runtime["layerv-nhp-sandbox-ca-ia:async_invocation"].metric_name == "AsyncEventsReceived" &&
      aws_cloudwatch_metric_alarm.authority_spillover["layerv-nhp-sandbox-ca-ia"].metric_name == "ProvisionedConcurrencySpilloverInvocations" &&
      alltrue([for a in values(aws_cloudwatch_metric_alarm.authority_runtime) : a.namespace == "AWS/Lambda"])
    )
    error_message = "The platform alarm set must use exactly the AWS-published Lambda metric names."
  }

  # Thresholds. Weakening any of these is the silent-regression this catches:
  # the zero-tolerance counters must stay at 0, the duration budget must stay
  # derived from the reviewed timeout, and concurrency exhaustion must stay tied
  # to the bound contract's reserved envelope rather than a hand-typed number.
  assert {
    condition = (
      alltrue([for a in values(aws_cloudwatch_metric_alarm.authority_spillover) : a.threshold == 0 && a.comparison_operator == "GreaterThanThreshold"]) &&
      alltrue([
        for k, a in aws_cloudwatch_metric_alarm.authority_runtime :
        a.threshold == 0 && a.comparison_operator == "GreaterThanThreshold"
        if contains(["errors", "throttles", "async_invocation"], split(":", k)[1])
      ]) &&
      aws_cloudwatch_metric_alarm.authority_runtime["layerv-nhp-sandbox-ca-ia:duration"].threshold == 8000 &&
      aws_cloudwatch_metric_alarm.authority_runtime["layerv-nhp-sandbox-ca-ia:duration"].threshold == aws_lambda_function.authority["layerv-nhp-sandbox-ca-ia"].timeout * 800 &&
      aws_cloudwatch_metric_alarm.authority_runtime["layerv-nhp-sandbox-ca-ia:duration"].extended_statistic == "p99" &&
      aws_cloudwatch_metric_alarm.authority_runtime["layerv-nhp-sandbox-ca-ia:concurrency_exhaustion"].comparison_operator == "GreaterThanOrEqualToThreshold" &&
      alltrue([
        for k, a in aws_cloudwatch_metric_alarm.authority_runtime :
        a.threshold == aws_lambda_function.authority[split(":", k)[0]].reserved_concurrent_executions
        if split(":", k)[1] == "concurrency_exhaustion"
      ])
    )
    error_message = "Zero-tolerance alarms must stay at threshold 0; duration must stay 80% of the reviewed timeout; concurrency exhaustion must stay pinned to the contract reserved envelope."
  }

  # Missing data must never breach: every metric here is a zero-baseline fault
  # counter and idle periods publish no datapoint at all.
  assert {
    condition = alltrue(flatten([
      [for a in values(aws_cloudwatch_metric_alarm.authority_spillover) : a.treat_missing_data == "notBreaching"],
      [for a in values(aws_cloudwatch_metric_alarm.authority_runtime) : a.treat_missing_data == "notBreaching"],
      [for a in values(aws_cloudwatch_metric_alarm.authority_terminal_outcome) : a.treat_missing_data == "notBreaching"],
      [for a in values(aws_cloudwatch_metric_alarm.authority_admission_rejected) : a.treat_missing_data == "notBreaching"],
      [for a in values(aws_cloudwatch_metric_alarm.authority_adapter_contract_violation) : a.treat_missing_data == "notBreaching"],
      [for a in values(aws_cloudwatch_metric_alarm.authority_adapter_late_result) : a.treat_missing_data == "notBreaching"],
      [for a in values(aws_cloudwatch_metric_alarm.authority_completion_identity_rejected) : a.treat_missing_data == "notBreaching"],
    ]))
    error_message = "Every Authority alarm must treat missing data as notBreaching; these are zero-baseline fault counters on a path that publishes nothing when idle."
  }

  # The non-provisioned-initialization event has NO emitted metric (the handler
  # rejects it at init, before telemetry exists), so it must be composed from
  # the two published AWS/Lambda signals rather than named into existence.
  assert {
    condition = (
      aws_cloudwatch_composite_alarm.authority_non_provisioned_initialization["layerv-nhp-sandbox-ca-ia"].alarm_rule ==
      "ALARM(\"layerv-nhp-sandbox-ca-ia-provisioned-concurrency-spillover\") AND ALARM(\"layerv-nhp-sandbox-ca-ia-errors\")" &&
      aws_cloudwatch_composite_alarm.authority_non_provisioned_initialization["layerv-nhp-sandbox-ca-ccr-cell1"].alarm_rule ==
      "ALARM(\"layerv-nhp-sandbox-ca-ccr-cell1-provisioned-concurrency-spillover\") AND ALARM(\"layerv-nhp-sandbox-ca-ccr-cell1-errors\")"
    )
    error_message = "The non-provisioned-initialization alarm must be the exact conjunction of the published spillover and Errors alarms."
  }

  # No Authority function may carry a dead-letter queue: the Authority is a
  # synchronous RequestResponse contract, and a DLQ would silently absorb a
  # security decision the caller never learns failed. This is the structural
  # half of the async/DLQ axis; the AsyncEventsReceived alarm is the runtime
  # half. DeadLetterErrors is deliberately NOT alarmed — nothing publishes it.
  assert {
    condition = alltrue([
      for fn in values(aws_lambda_function.authority) :
      fn.dead_letter_config == null || length(fn.dead_letter_config) == 0
    ])
    error_message = "No Connector Authority function may declare a dead_letter_config; the Authority is a synchronous RequestResponse contract."
  }
}

run "custom_metric_alarms_match_the_handler_publisher_dim_sets" {
  command = plan

  variables {
    authority_runtime_functions_enabled = true
  }

  # Hub operations are NOT cell operations, so the publisher emits no CellID and
  # the alarm must not list one. AuthorityOperation carries the PascalCase
  # conformance name the handler reports, never the snake_case terraform key.
  assert {
    condition = (
      aws_cloudwatch_metric_alarm.authority_terminal_outcome["layerv-nhp-sandbox-ca-ia:internal"].dimensions == tomap({
        EnvironmentID      = "sandbox"
        AuthorityOperation = "IssueAssignment"
        Outcome            = "internal"
      }) &&
      aws_cloudwatch_metric_alarm.authority_terminal_outcome["layerv-nhp-sandbox-ca-icr:unavailable"].dimensions == tomap({
        EnvironmentID      = "sandbox"
        AuthorityOperation = "IssueCredentialRecovery"
        Outcome            = "unavailable"
      }) &&
      aws_cloudwatch_metric_alarm.authority_terminal_outcome["layerv-nhp-sandbox-ca-ia:internal"].namespace == "LayerV/ConnectorAuthority" &&
      aws_cloudwatch_metric_alarm.authority_terminal_outcome["layerv-nhp-sandbox-ca-ia:internal"].metric_name == "qurl.connector_authority.invocation.total"
    )
    error_message = "Hub-operation custom alarms must key on exactly {EnvironmentID, AuthorityOperation, Outcome} with the PascalCase conformance operation name."
  }

  # Cell operations DO emit CellID, so its absence would select a stream that
  # never exists.
  assert {
    condition = (
      aws_cloudwatch_metric_alarm.authority_terminal_outcome["layerv-nhp-sandbox-ca-ar-cell0:internal"].dimensions == tomap({
        EnvironmentID      = "sandbox"
        AuthorityOperation = "ActivateRegistration"
        CellID             = "cell0"
        Outcome            = "internal"
      }) &&
      aws_cloudwatch_metric_alarm.authority_admission_rejected["layerv-nhp-sandbox-ca-cr-cell1:limited"].dimensions == tomap({
        EnvironmentID      = "sandbox"
        AuthorityOperation = "CompleteRegistration"
        CellID             = "cell1"
        Outcome            = "limited"
      }) &&
      aws_cloudwatch_metric_alarm.authority_admission_rejected["layerv-nhp-sandbox-ca-ar-cell1:unavailable"].metric_name == "qurl.connector_registration.adapter_admission.total"
    )
    error_message = "Cell-operation custom alarms must include the exact CellID the publisher emits."
  }

  # The two counters the publisher emits with NO dynamic dimensions: the
  # identity prefix alone is the complete emitted set.
  assert {
    condition = (
      aws_cloudwatch_metric_alarm.authority_adapter_contract_violation["layerv-nhp-sandbox-ca-ar-cell0"].dimensions == tomap({
        EnvironmentID      = "sandbox"
        AuthorityOperation = "ActivateRegistration"
        CellID             = "cell0"
      }) &&
      aws_cloudwatch_metric_alarm.authority_adapter_late_result["layerv-nhp-sandbox-ca-cr-cell0"].dimensions == tomap({
        EnvironmentID      = "sandbox"
        AuthorityOperation = "CompleteRegistration"
        CellID             = "cell0"
      })
    )
    error_message = "Adapter contract-violation and late-result alarms must key on the identity prefix alone; the publisher adds no dynamic dimension."
  }

  # completion_identity_rejected is emitted only from the CompleteRegistration
  # adapter path, and only the authority_fence cause is a security refusal.
  assert {
    condition = (
      length(aws_cloudwatch_metric_alarm.authority_completion_identity_rejected) == 2 &&
      contains(keys(aws_cloudwatch_metric_alarm.authority_completion_identity_rejected), "layerv-nhp-sandbox-ca-cr-cell0") &&
      contains(keys(aws_cloudwatch_metric_alarm.authority_completion_identity_rejected), "layerv-nhp-sandbox-ca-cr-cell1") &&
      aws_cloudwatch_metric_alarm.authority_completion_identity_rejected["layerv-nhp-sandbox-ca-cr-cell0"].dimensions == tomap({
        EnvironmentID      = "sandbox"
        AuthorityOperation = "CompleteRegistration"
        CellID             = "cell0"
        Cause              = "authority_fence"
      })
    )
    error_message = "The completion-identity alarm must exist only on the CompleteRegistration functions and key on the authority_fence cause."
  }

  # Registration-adapter alarms exist only on the admission-gated operations,
  # which are the only functions whose handlers emit those metrics.
  assert {
    condition = (
      toset(keys(aws_cloudwatch_metric_alarm.authority_adapter_contract_violation)) == toset([
        "layerv-nhp-sandbox-ca-ar-cell0",
        "layerv-nhp-sandbox-ca-ar-cell1",
        "layerv-nhp-sandbox-ca-cr-cell0",
        "layerv-nhp-sandbox-ca-cr-cell1",
      ]) &&
      toset(keys(aws_cloudwatch_metric_alarm.authority_adapter_contract_violation)) ==
      toset(keys(aws_cloudwatch_metric_alarm.authority_adapter_late_result))
    )
    error_message = "Registration-adapter alarms must cover exactly the four admission-gated cell functions."
  }

  # Every custom alarm's AuthorityOperation must be the same string the function
  # reports in CONNECTOR_AUTHORITY_OPERATION. This is the drift guard that makes
  # a snake_case/PascalCase mistake impossible to land.
  assert {
    condition = alltrue(flatten([
      [for k, a in aws_cloudwatch_metric_alarm.authority_terminal_outcome :
      a.dimensions["AuthorityOperation"] == aws_lambda_function.authority[split(":", k)[0]].environment[0].variables.CONNECTOR_AUTHORITY_OPERATION],
      [for k, a in aws_cloudwatch_metric_alarm.authority_admission_rejected :
      a.dimensions["AuthorityOperation"] == aws_lambda_function.authority[split(":", k)[0]].environment[0].variables.CONNECTOR_AUTHORITY_OPERATION],
      [for k, a in aws_cloudwatch_metric_alarm.authority_adapter_contract_violation :
      a.dimensions["AuthorityOperation"] == aws_lambda_function.authority[k].environment[0].variables.CONNECTOR_AUTHORITY_OPERATION],
      [for k, a in aws_cloudwatch_metric_alarm.authority_adapter_late_result :
      a.dimensions["AuthorityOperation"] == aws_lambda_function.authority[k].environment[0].variables.CONNECTOR_AUTHORITY_OPERATION],
      [for k, a in aws_cloudwatch_metric_alarm.authority_completion_identity_rejected :
      a.dimensions["AuthorityOperation"] == aws_lambda_function.authority[k].environment[0].variables.CONNECTOR_AUTHORITY_OPERATION],
    ]))
    error_message = "Every custom alarm's AuthorityOperation must equal the operation the function itself reports."
  }

  # Cell alarms must carry the same CellID the function reports, and hub alarms
  # must carry none.
  assert {
    condition = alltrue([
      for k, a in aws_cloudwatch_metric_alarm.authority_terminal_outcome :
      (
        can(aws_lambda_function.authority[split(":", k)[0]].environment[0].variables.CONNECTOR_AUTHORITY_CELL_ID)
        ? a.dimensions["CellID"] == aws_lambda_function.authority[split(":", k)[0]].environment[0].variables.CONNECTOR_AUTHORITY_CELL_ID
        : !contains(keys(a.dimensions), "CellID")
      )
    ])
    error_message = "A custom alarm must carry CellID if and only if its function is a cell operation, matching the value the function reports."
  }
}

run "runtime_without_operator_destination_fails_closed" {
  command = plan

  variables {
    authority_runtime_functions_enabled = true
    operator_alarm_topic_arns           = []
  }

  expect_failures = [
    terraform_data.foundation_contract,
  ]
}

run "wildcard_operator_destination_is_rejected" {
  command = plan

  variables {
    authority_runtime_functions_enabled = true
    operator_alarm_topic_arns           = ["arn:aws:sns:us-east-2:767397897469:*"]
  }

  expect_failures = [
    var.operator_alarm_topic_arns,
  ]
}

run "bare_wildcard_operator_destination_is_rejected" {
  command = plan

  variables {
    authority_runtime_functions_enabled = true
    operator_alarm_topic_arns           = ["*"]
  }

  expect_failures = [
    var.operator_alarm_topic_arns,
  ]
}

run "duplicate_operator_destination_is_rejected" {
  command = plan

  variables {
    authority_runtime_functions_enabled = true
    operator_alarm_topic_arns = [
      "arn:aws:sns:us-east-2:767397897469:layerv-nhp-sandbox-cell0-alerts",
      "arn:aws:sns:us-east-2:767397897469:layerv-nhp-sandbox-cell0-alerts",
    ]
  }

  expect_failures = [
    var.operator_alarm_topic_arns,
  ]
}

run "foreign_account_operator_destination_fails_closed" {
  command = plan

  variables {
    authority_runtime_functions_enabled = true
    operator_alarm_topic_arns           = ["arn:aws:sns:us-east-2:000000000000:layerv-nhp-sandbox-cell0-alerts"]
  }

  expect_failures = [
    terraform_data.foundation_contract,
  ]
}

run "foreign_region_operator_destination_fails_closed" {
  command = plan

  variables {
    authority_runtime_functions_enabled = true
    operator_alarm_topic_arns           = ["arn:aws:sns:us-west-2:767397897469:layerv-nhp-sandbox-cell0-alerts"]
  }

  expect_failures = [
    terraform_data.foundation_contract,
  ]
}

run "dark_runtime_plans_no_alarm_and_needs_no_destination" {
  command = plan

  variables {
    authority_runtime_functions_enabled = false
    operator_alarm_topic_arns           = []
  }

  assert {
    condition = (
      length(aws_cloudwatch_metric_alarm.authority_spillover) == 0 &&
      length(aws_cloudwatch_metric_alarm.authority_runtime) == 0 &&
      length(aws_cloudwatch_composite_alarm.authority_non_provisioned_initialization) == 0 &&
      length(aws_cloudwatch_metric_alarm.authority_terminal_outcome) == 0 &&
      length(aws_cloudwatch_metric_alarm.authority_admission_rejected) == 0 &&
      length(aws_cloudwatch_metric_alarm.authority_adapter_contract_violation) == 0 &&
      length(aws_cloudwatch_metric_alarm.authority_adapter_late_result) == 0 &&
      length(aws_cloudwatch_metric_alarm.authority_completion_identity_rejected) == 0
    )
    error_message = "A dark runtime must plan no alarm at all, so the operator destination is only required once functions exist."
  }
}

# The handle store is only reachable if IAM says so, and nothing in this suite
# checked that. The gap was real and shipped: the issuer's write grant is
# LeadingKeys-scoped to HUB_REQUEST#IssueAssignment#*, so ASSIGNMENT_TICKET#*
# was denied, and IssueRegistrationOTP had no access to that table at all. The
# code failed closed and enrollment stopped -- found by invoking the deployed
# function in sandbox, which is the only place effective IAM is observable.
#
# Keyed on operation rather than physical function name so every cell's copy is
# covered, and length-checked so an empty selection cannot pass alltrue.
run "authority_ticket_handle_grants_exist_and_are_scoped" {
  command = plan

  variables {
    authority_runtime_functions_enabled = true
  }

  assert {
    condition = alltrue([
      for key, fn in local.authority_runtime_functions :
      anytrue([
        for statement in jsondecode(aws_iam_role_policy.authority_exec[key].policy).Statement :
        statement.Sid == "AuthorityTicketHandleWrite" &&
        # Exact, not contains: a superset is precisely the silent widening the
        # separate Sid exists to prevent, and contains() waves it through.
        statement.Action == ["dynamodb:PutItem"] &&
        statement.Condition["ForAllValues:StringLike"]["dynamodb:LeadingKeys"] == ["ASSIGNMENT_TICKET#*"]
      ]) if fn.operation == "issue_assignment"
    ]) && length([for k, fn in local.authority_runtime_functions : k if fn.operation == "issue_assignment"]) == 1
    error_message = "IssueAssignment cannot write the handle rows it must store; the issuer will fail closed."
  }

  assert {
    condition = alltrue([
      for key, fn in local.authority_runtime_functions :
      anytrue([
        for statement in jsondecode(aws_iam_role_policy.authority_exec[key].policy).Statement :
        statement.Sid == "AuthorityTicketHandleRead" &&
        statement.Action == ["dynamodb:GetItem"] &&
        statement.Condition["ForAllValues:StringLike"]["dynamodb:LeadingKeys"] == ["ASSIGNMENT_TICKET#*"] &&
        # Pinned symmetrically with the write grant rather than relying on the
        # fact that a GetItem always carries a key.
        statement.Condition["Null"]["dynamodb:LeadingKeys"] == "false"
      ]) if fn.operation == "issue_registration_otp"
    ]) && length([for k, fn in local.authority_runtime_functions : k if fn.operation == "issue_registration_otp"]) > 0
    error_message = "An IssueRegistrationOTP function cannot resolve an assignment ticket handle."
  }

  # ActivateRegistration already reads this table for its durable outcome, so it
  # needs no new grant. Asserted so a future tightening of that read does not
  # silently remove handle resolution from the activation path.
  assert {
    condition = alltrue([
      for key, fn in local.authority_runtime_functions :
      anytrue([
        for statement in jsondecode(aws_iam_role_policy.authority_exec[key].policy).Statement :
        statement.Sid == "AuthorityReads" &&
        contains(statement.Action, "dynamodb:GetItem") &&
        anytrue([for arn in statement.Resource : strcontains(arn, "connector-authority")])
      ]) if fn.operation == "activate_registration"
    ]) && length([for k, fn in local.authority_runtime_functions : k if fn.operation == "activate_registration"]) > 0
    error_message = "ActivateRegistration lost its connector-authority read and can no longer resolve a handle."
  }

  # The replay grant must keep meaning exactly "its own replay tombstone". If a
  # future change widens it to cover handles instead of adding a grant, the two
  # purposes become indistinguishable in review.
  assert {
    condition = alltrue([
      for key, fn in local.authority_runtime_functions :
      anytrue([
        for statement in jsondecode(aws_iam_role_policy.authority_exec[key].policy).Statement :
        statement.Sid == "AuthorityReplayWrite" &&
        statement.Condition["ForAllValues:StringLike"]["dynamodb:LeadingKeys"] == ["HUB_REQUEST#IssueAssignment#*"]
      ]) if fn.operation == "issue_assignment"
    ]) && length([for k, fn in local.authority_runtime_functions : k if fn.operation == "issue_assignment"]) == 1
    error_message = "The replay write grant was widened instead of a separate handle grant being added."
  }
}

# The tenant home-cell pin is an opt-in: with the gate on, IssueAssignment (and
# only IssueAssignment) may read and record assigned_cell_id on the customers
# table; with the gate off (the default) no function carries either Sid or the
# env var, so the ordinary runtime provably cannot touch customer rows.
run "tenant_pin_grants_follow_the_gate" {
  command = plan

  variables {
    authority_runtime_functions_enabled = true
    authority_tenant_pinning_enabled    = true
  }

  assert {
    condition = alltrue([
      for key, fn in local.authority_runtime_functions :
      anytrue([
        for statement in jsondecode(aws_iam_role_policy.authority_exec[key].policy).Statement :
        statement.Sid == "TenantCellPinRead" &&
        # Exact, not contains: a wider action list is the silent widening the
        # dedicated Sid exists to prevent.
        statement.Action == ["dynamodb:GetItem"] &&
        length(statement.Resource) == 1 &&
        strcontains(statement.Resource[0], "customers") &&
        !strcontains(statement.Resource[0], "/index/") &&
        statement.Condition["ForAllValues:StringEquals"]["dynamodb:Attributes"] == ["auth0_subject", "assigned_cell_id"] &&
        statement.Condition["StringEqualsIfExists"]["dynamodb:Select"] == "SPECIFIC_ATTRIBUTES"
      ]) if fn.operation == "issue_assignment"
    ]) && length([for k, fn in local.authority_runtime_functions : k if fn.operation == "issue_assignment"]) == 1
    error_message = "With pinning enabled IssueAssignment cannot read the tenant home-cell pin."
  }

  assert {
    condition = alltrue([
      for key, fn in local.authority_runtime_functions :
      anytrue([
        for statement in jsondecode(aws_iam_role_policy.authority_exec[key].policy).Statement :
        statement.Sid == "TenantCellPinWrite" &&
        statement.Action == ["dynamodb:UpdateItem"] &&
        length(statement.Resource) == 1 &&
        strcontains(statement.Resource[0], "customers") &&
        !strcontains(statement.Resource[0], "/index/") &&
        # The attribute fence is the load-bearing boundary: an UpdateItem
        # always names its attributes, so this confines the writer to the pin.
        statement.Condition["ForAllValues:StringEquals"]["dynamodb:Attributes"] == ["auth0_subject", "assigned_cell_id"] &&
        statement.Condition["StringEqualsIfExists"]["dynamodb:ReturnValues"] == ["NONE", "UPDATED_OLD", "UPDATED_NEW"]
      ]) if fn.operation == "issue_assignment"
    ]) && length([for k, fn in local.authority_runtime_functions : k if fn.operation == "issue_assignment"]) == 1
    error_message = "With pinning enabled IssueAssignment cannot record the tenant home-cell pin."
  }

  assert {
    condition = alltrue([
      for key, fn in local.authority_runtime_functions :
      alltrue([
        for statement in jsondecode(aws_iam_role_policy.authority_exec[key].policy).Statement :
        !contains(["TenantCellPinRead", "TenantCellPinWrite"], statement.Sid)
      ]) if fn.operation != "issue_assignment"
    ])
    error_message = "A pin grant leaked onto an operation other than IssueAssignment."
  }

  assert {
    condition = alltrue([
      for key, fn in local.authority_runtime_functions :
      (lookup(local.authority_runtime_environment[key], "CONNECTOR_AUTHORITY_TENANT_PINNING_ENABLED", "") == "true") == (fn.operation == "issue_assignment")
    ])
    error_message = "The pin env var must be rendered on exactly the IssueAssignment function when the gate is on."
  }
}

run "tenant_pin_grants_absent_at_default" {
  command = plan

  variables {
    authority_runtime_functions_enabled = true
  }

  assert {
    condition = alltrue([
      for key, fn in local.authority_runtime_functions :
      alltrue([
        for statement in jsondecode(aws_iam_role_policy.authority_exec[key].policy).Statement :
        !contains(["TenantCellPinRead", "TenantCellPinWrite"], statement.Sid)
      ]) && !contains(keys(local.authority_runtime_environment[key]), "CONNECTOR_AUTHORITY_TENANT_PINNING_ENABLED")
    ])
    error_message = "Pinning is opt-in: at the default no function may carry the pin grant or env var."
  }
}

run "pointer_parameter_is_seeded_with_the_contract_colour" {
  command = plan

  variables {
    authority_runtime_functions_enabled = true
  }

  assert {
    condition = (
      length(aws_ssm_parameter.authority_active_color) == 1 &&
      aws_ssm_parameter.authority_active_color[0].name == "/sandbox/nhp/control/authority/active-color" &&
      aws_ssm_parameter.authority_active_color[0].type == "String" &&
      aws_ssm_parameter.authority_active_color[0].value == "blue" &&
      length(data.aws_ssm_parameter.authority_active_color) == 0
    )
    error_message = "The switch pointer must be created with the runtime, seeded with the contract's selected colour, and never read while the pointer gate is dark."
  }
}

run "ssm_pointer_steers_every_colour_bearing_rendering" {
  command = plan

  variables {
    authority_runtime_functions_enabled     = true
    authority_blue_green_alias_hold_enabled = true
    authority_selector_ssm_pointer_enabled  = true
  }

  # The live pointer disagrees with the committed contract (green vs blue):
  # the module must follow the POINTER everywhere a colour is rendered, and
  # must record the effective colour in the foundation contract so the flip
  # presents as the reviewed contract before/after.
  override_data {
    target          = data.aws_ssm_parameter.authority_active_color[0]
    override_during = plan
    values = {
      value = "green"
    }
  }

  assert {
    condition     = local.authority_runtime_selected_color == "green"
    error_message = "With the pointer gate on, the effective selector must be the SSM value."
  }

  assert {
    condition = (
      length(data.aws_lambda_alias.authority_live) == 22 &&
      alltrue([
        for key, alias in data.aws_lambda_alias.authority_live :
        !strcontains(key, "-creso-")
      ])
    )
    error_message = "The live-alias hold must read all 22 established aliases and bootstrap only the four new creso aliases."
  }

  assert {
    condition     = local.authority_proof_policy_standby_color == "blue"
    error_message = "The standby colour must be the pointer value's complement."
  }

  assert {
    condition = alltrue([
      for pc in values(aws_lambda_provisioned_concurrency_config.authority) :
      pc.qualifier == "green"
    ])
    error_message = "The PC qualifiers must follow the pointer."
  }

  # The recorded contract selector (terraform_data.foundation_contract.input)
  # is deliberately NOT asserted here: the test harness defers terraform_data
  # planned input to unknown, though real plan JSON carries it known -- the
  # b1 live plan and the checker'"'"'s flip-lane fixtures pin that recording.

  assert {
    condition = (
      alltrue([
        for operation, arn in local.authority_selected_alias_targets.hub :
        endswith(arn, ":green")
      ]) &&
      alltrue([
        for cell_id, operations in local.authority_selected_alias_targets.cells :
        alltrue([for operation, arn in operations : endswith(arn, ":green")])
      ])
    )
    error_message = "Every Hub/cell alias target must follow the pointer."
  }
}

run "corrupted_pointer_value_fails_the_plan_closed" {
  command = plan

  variables {
    authority_runtime_functions_enabled     = true
    authority_blue_green_alias_hold_enabled = true
    authority_selector_ssm_pointer_enabled  = true
  }

  override_data {
    target          = data.aws_ssm_parameter.authority_active_color[0]
    override_during = plan
    values = {
      value = "purple"
    }
  }

  expect_failures = [data.aws_ssm_parameter.authority_active_color]
}

run "pointer_gate_without_the_hold_fails_closed" {
  command = plan

  variables {
    authority_runtime_functions_enabled     = true
    authority_blue_green_alias_hold_enabled = false
    authority_selector_ssm_pointer_enabled  = true
  }

  # A valid pointer value, so the read postcondition passes and the guard
  # under test -- pointer requires the hold -- is the failure that fires.
  override_data {
    target          = data.aws_ssm_parameter.authority_active_color[0]
    override_during = plan
    values = {
      value = "blue"
    }
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "agreeing_pointer_is_the_steady_state" {
  command = plan

  variables {
    authority_runtime_functions_enabled     = true
    authority_blue_green_alias_hold_enabled = true
    authority_selector_ssm_pointer_enabled  = true
  }

  # The expected state right after the pointer gate flips: the SSM value
  # agrees with the committed contract, so the effective selector -- and
  # every rendering behind it -- is unchanged from the contract-driven world.
  override_data {
    target          = data.aws_ssm_parameter.authority_active_color[0]
    override_during = plan
    values = {
      value = "blue"
    }
  }

  assert {
    condition = (
      local.authority_runtime_selected_color == "blue" &&
      alltrue([
        for pc in values(aws_lambda_provisioned_concurrency_config.authority) :
        pc.qualifier == "blue"
      ]) &&
      alltrue([
        for operation, arn in local.authority_selected_alias_targets.hub :
        endswith(arn, ":blue")
      ])
    )
    error_message = "An agreeing pointer must reproduce the contract-driven rendering exactly."
  }
}
