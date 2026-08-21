# Fences for the attended-proof Authority mutation control (MutateProofAgent).
#
# This operation mutates live authorization state, so every test below asserts a
# fence rather than a feature. The two that matter most are
# prod_rejects_proof_mutation_controls (the control cannot exist in production)
# and proof_alias_is_absent_from_every_runtime_caller_target (no ordinary caller
# path can name it).

mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = {
      names = ["us-east-2a", "us-east-2b", "us-east-2c"]
    }
  }

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "767397897469"
    }
  }

  mock_data "aws_partition" {
    defaults = {
      partition  = "aws"
      dns_suffix = "amazonaws.com"
    }
  }

  mock_data "aws_region" {
    defaults = {
      region = "us-east-2"
    }
  }

  mock_data "aws_ssm_parameter" {
    defaults = {
      insecure_value = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
      value          = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    }
  }

  mock_data "aws_ecr_image" {
    defaults = {
      image_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
      image_uri    = "767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/qurl-connector-authority@sha256:1111111111111111111111111111111111111111111111111111111111111111"
    }
  }

  mock_data "aws_lambda_alias" {
    defaults = {
      function_version = "6"
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
  target          = aws_lambda_function.authority["layerv-nhp-sandbox-ca-ia"]
  override_during = plan
  values          = { version = "7" }
}

override_resource {
  target          = aws_lambda_function.authority["layerv-nhp-sandbox-ca-ra"]
  override_during = plan
  values          = { version = "7" }
}

override_resource {
  target          = aws_lambda_function.authority["layerv-nhp-sandbox-ca-icr"]
  override_during = plan
  values          = { version = "7" }
}

override_resource {
  target          = aws_lambda_function.authority["layerv-nhp-sandbox-ca-pm"]
  override_during = plan
  values          = { version = "7" }
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

# Table ARNs must be plan-known so the rendered execution-policy content, not
# just its shape, is assertable.
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

override_resource {
  target          = aws_kms_key.authority_data
  override_during = plan
  values          = { arn = "arn:aws:kms:us-east-2:767397897469:key/00000000-0000-0000-0000-000000000002" }
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

  authority_proof_mutation_controls_enabled = true
  authority_proof_mutation_owner_id         = "layerv-nhp-sandbox-udp-proof"
  authority_proof_mutation_controller_role_arns = [
    "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-udp-proof-controller",
  ]

  authority_runtime_contract = {
    schema_version           = 1
    phase                    = "measurement"
    selected_authority_color = "blue"
    # Measurement phase with the Hub group plus the proof function only: the
    # cell operation groups are still absent, which is exactly the state the
    # attended proof substrate binds before the cell graphs are budgeted.
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
    }
    provisioned_cells_evidence = {
      repository     = "layervai/nhp"
      source_commit  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      path           = "docs/evidence/connector-authority/v1/sandbox-provisioned-cells.json"
      sha256         = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
      schema_version = 1
    }
    qat1_kid = "sandbox-qat1-v1"
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
      non_authority_reserved_concurrency = 100
      retained_unreserved_concurrency    = 100
      dependency_headroom = {
        dynamodb_max_in_flight = 100
        kms_max_in_flight      = 100
        redis_max_connections  = 100
        ses_max_in_flight      = 100
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
            issue_assignment          = { burst = 3, refill_per_second = 2 }
            refresh_assignment        = { burst = 3, refill_per_second = 2 }
            issue_credential_recovery = { burst = 3, refill_per_second = 2 }
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
              issue_registration_otp       = { burst = 2, refill_per_second = 1 }
              activate_registration        = { burst = 2, refill_per_second = 1 }
              complete_registration        = { burst = 2, refill_per_second = 1 }
              complete_credential_recovery = { burst = 2, refill_per_second = 1 }
              resolve_connector_resource   = { burst = 2, refill_per_second = 1 }
            }
          }
        }
        proof_controller = {
          max_replicas = 1
          preinvoke_limits = {
            mutate_proof_agent                = 1
            prepare_proof_credential_recovery = 1
          }
          preinvoke_rate_limits = {
            mutate_proof_agent                = { burst = 1, refill_per_second = 1 }
            prepare_proof_credential_recovery = { burst = 1, refill_per_second = 1 }
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
        steady_reserved_concurrency             = 4
        rollout_active_provisioned_concurrency  = 2
        rollout_standby_provisioned_concurrency = 2
        rollout_reserved_concurrency            = 4
        max_caller_in_flight                    = 2
        max_caller_requests_per_second          = 10
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
        max_caller_requests_per_second          = 10
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
        max_caller_requests_per_second          = 10
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
      "layerv-nhp-sandbox-ca-pm" = {
        steady_provisioned_concurrency          = 1
        steady_reserved_concurrency             = 2
        rollout_active_provisioned_concurrency  = 1
        rollout_standby_provisioned_concurrency = 1
        rollout_reserved_concurrency            = 2
        max_caller_in_flight                    = 1
        max_caller_requests_per_second          = 2
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
      "layerv-nhp-sandbox-ca-pcr" = {
        steady_provisioned_concurrency          = 1
        steady_reserved_concurrency             = 2
        rollout_active_provisioned_concurrency  = 1
        rollout_standby_provisioned_concurrency = 1
        rollout_reserved_concurrency            = 2
        max_caller_in_flight                    = 1
        max_caller_requests_per_second          = 2
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

run "sandbox_accepts_the_separate_proof_operation_family" {
  command = plan

  assert {
    condition = output.authority_selected_alias_targets.proof == {
      mutate_proof_agent                = "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-pm:blue"
      prepare_proof_credential_recovery = "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-pcr:blue"
    }
    error_message = "The proof family must publish exactly its own same-color alias target."
  }

}

run "proof_alias_is_absent_from_every_runtime_caller_target" {
  command = plan

  # The Hub task policy is built from .hub and each cell server policy from
  # .cells. If the proof alias never appears in either, no ordinary UDP traffic
  # path can name it, independent of any IAM review.
  assert {
    condition = toset(keys(output.authority_selected_alias_targets.hub)) == toset([
      "issue_assignment",
      "refresh_assignment",
      "issue_credential_recovery",
    ])
    error_message = "The Hub caller target must remain exactly the three hub operations."
  }

  assert {
    condition = length([
      for target in values(output.authority_selected_alias_targets.hub) :
      target if strcontains(target, "-ca-pm:") || strcontains(target, "-ca-pcr:")
    ]) == 0
    error_message = "The Hub caller target must never contain the proof mutation alias."
  }

  assert {
    condition = length(flatten([
      for cell_targets in values(output.authority_selected_alias_targets.cells) : [
        for target in values(cell_targets) :
        target if strcontains(target, "-ca-pm:") || strcontains(target, "-ca-pcr:")
      ]
    ])) == 0
    error_message = "No cell caller target may ever contain the proof mutation alias."
  }
}

run "prod_rejects_proof_mutation_controls" {
  command = plan

  variables {
    environment    = "prod"
    aws_account_id = "235500187906"
    otp_email_from = "noreply@notify.layerv.ai"
    # Prod cannot bind this contract at all; the proof fence must reject the
    # gate before any contract identity check even matters.
    authority_runtime_contract = null
    authority_proof_mutation_controller_role_arns = [
      "arn:aws:iam::235500187906:role/layerv-nhp-prod-udp-proof-controller",
    ]
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_proof_controls_without_a_named_proof_tenant" {
  command = plan

  variables {
    authority_proof_mutation_owner_id = null
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_proof_controls_without_an_attended_controller" {
  command = plan

  variables {
    authority_proof_mutation_controller_role_arns = []
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_the_hub_task_role_as_a_proof_controller" {
  command = plan

  variables {
    authority_proof_mutation_controller_role_arns = [
      "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-control-hub-task",
    ]
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_a_cell_server_role_as_a_proof_controller" {
  command = plan

  variables {
    authority_proof_mutation_controller_role_arns = [
      "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-server",
    ]
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_a_foreign_account_proof_controller" {
  command = plan

  variables {
    authority_proof_mutation_controller_role_arns = [
      "arn:aws:iam::235500187906:role/layerv-nhp-sandbox-udp-proof-controller",
    ]
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_a_duplicated_proof_controller" {
  command = plan

  variables {
    authority_proof_mutation_controller_role_arns = [
      "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-udp-proof-controller",
      "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-udp-proof-controller",
    ]
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_a_proof_function_while_the_gate_is_off" {
  command = plan

  variables {
    authority_proof_mutation_controls_enabled     = false
    authority_proof_mutation_owner_id             = null
    authority_proof_mutation_controller_role_arns = []
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_proof_controller_capacity_above_one_attended_call" {
  command = plan

  variables {
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
      }
      provisioned_cells_evidence = {
        repository     = "layervai/nhp"
        source_commit  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        path           = "docs/evidence/connector-authority/v1/sandbox-provisioned-cells.json"
        sha256         = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        schema_version = 1
      }
      qat1_kid = "sandbox-qat1-v1"
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
        non_authority_reserved_concurrency = 100
        retained_unreserved_concurrency    = 100
        dependency_headroom = {
          dynamodb_max_in_flight = 100
          kms_max_in_flight      = 100
          redis_max_connections  = 100
          ses_max_in_flight      = 100
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
              issue_assignment          = { burst = 3, refill_per_second = 2 }
              refresh_assignment        = { burst = 3, refill_per_second = 2 }
              issue_credential_recovery = { burst = 3, refill_per_second = 2 }
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
                issue_registration_otp       = { burst = 2, refill_per_second = 1 }
                activate_registration        = { burst = 2, refill_per_second = 1 }
                complete_registration        = { burst = 2, refill_per_second = 1 }
                complete_credential_recovery = { burst = 2, refill_per_second = 1 }
                resolve_connector_resource   = { burst = 2, refill_per_second = 1 }
              }
            }
          }
          proof_controller = {
            max_replicas = 2
            preinvoke_limits = {
              mutate_proof_agent                = 1
              prepare_proof_credential_recovery = 1
            }
            preinvoke_rate_limits = {
              mutate_proof_agent                = { burst = 1, refill_per_second = 1 }
              prepare_proof_credential_recovery = { burst = 1, refill_per_second = 1 }
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
          steady_reserved_concurrency             = 4
          rollout_active_provisioned_concurrency  = 2
          rollout_standby_provisioned_concurrency = 2
          rollout_reserved_concurrency            = 4
          max_caller_in_flight                    = 2
          max_caller_requests_per_second          = 10
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
          max_caller_requests_per_second          = 10
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
          max_caller_requests_per_second          = 10
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
        "layerv-nhp-sandbox-ca-pm" = {
          steady_provisioned_concurrency          = 1
          steady_reserved_concurrency             = 2
          rollout_active_provisioned_concurrency  = 1
          rollout_standby_provisioned_concurrency = 1
          rollout_reserved_concurrency            = 2
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
        "layerv-nhp-sandbox-ca-pcr" = {
          steady_provisioned_concurrency          = 1
          steady_reserved_concurrency             = 2
          rollout_active_provisioned_concurrency  = 1
          rollout_standby_provisioned_concurrency = 1
          rollout_reserved_concurrency            = 2
          max_caller_in_flight                    = 1
          max_caller_requests_per_second          = 2
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

  expect_failures = [terraform_data.foundation_contract]
}

run "runtime_fences_the_proof_execution_role_to_the_proof_tenant_partition" {
  command = plan

  variables {
    authority_runtime_functions_enabled = true
  }

  # The controller invoke grant that used to be asserted here is gone. It managed
  # an inline policy on layerv-nhp-<env>-udp-proof-controller, a role owned by the
  # separate udp-proof-runner root; destroying that root (#3804) left the grant
  # pointing at a role AWS reports as NoSuchEntity. See the `removed` block in
  # authority_runtime.tf.

  # This PR is dark ca-pm capability only. The consumer functions remain byte-
  # for-byte on their governed selected-alias versions until the later attended
  # proof rollout; only the mutation handler receives proof policy.
  assert {
    condition = {
      for key, value in aws_lambda_function.authority["layerv-nhp-sandbox-ca-pm"].environment[0].variables :
      key => value if startswith(key, "CONNECTOR_AUTHORITY_PROOF_")
      } == {
      CONNECTOR_AUTHORITY_PROOF_OWNER_ID          = "layerv-nhp-sandbox-udp-proof"
      CONNECTOR_AUTHORITY_PROOF_AGENT_ID_PREFIX   = "qurl-go-sandbox-"
      CONNECTOR_AUTHORITY_PROOF_DIRECTIVE_TTL     = "5400"
      CONNECTOR_AUTHORITY_PROOF_MIN_LEASE_SECONDS = "30"
    }
    error_message = "Only ca-pm must receive the exact four proof-policy environment variables."
  }

  assert {
    condition = {
      for key, value in aws_lambda_function.authority["layerv-nhp-sandbox-ca-pcr"].environment[0].variables :
      key => value if startswith(key, "CONNECTOR_AUTHORITY_PROOF_")
      } == {
      CONNECTOR_AUTHORITY_PROOF_OWNER_ID        = "layerv-nhp-sandbox-udp-proof"
      CONNECTOR_AUTHORITY_PROOF_AGENT_ID_PREFIX = "qurl-go-sandbox-"
    }
    error_message = "ca-pcr must receive only the exact proof owner and agent prefix."
  }

  assert {
    condition = alltrue([
      for function_name in [
        "layerv-nhp-sandbox-ca-ia",
        "layerv-nhp-sandbox-ca-ra",
        "layerv-nhp-sandbox-ca-icr",
      ] :
      length({
        for key, value in aws_lambda_function.authority[function_name].environment[0].variables :
        key => value if startswith(key, "CONNECTOR_AUTHORITY_PROOF_")
      }) == 0
    ])
    error_message = "IA, RA, and ICR must remain free of proof policy in the dark capability slice."
  }

  assert {
    condition = alltrue([
      for function_name, function in aws_lambda_function.authority :
      length({
        for key, value in function.environment[0].variables :
        key => value if startswith(key, "CONNECTOR_AUTHORITY_PROOF_")
      }) == 0
      if !contains([
        "layerv-nhp-sandbox-ca-pm",
        "layerv-nhp-sandbox-ca-pcr",
      ], function_name)
    ])
    error_message = "Cell operations must never inherit the attended-proof policy environment."
  }

  # Placement item actions are constrained to the dedicated proof tenant
  # partition (OWNER# + sha256 of the proof owner id), the PROOF directive
  # partition, or the read-only REGISTRY partition. This makes a wrong handler
  # unable to touch another tenant.
  assert {
    condition = alltrue([
      for statement in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-pm"].policy).Statement :
      (
        contains(
          try(statement.Condition["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"], []),
          "OWNER#${sha256("layerv-nhp-sandbox-udp-proof")}",
          ) || contains(
          try(statement.Condition["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"], []),
          "REGISTRY",
        )
      ) && try(statement.Condition.Null["dynamodb:LeadingKeys"], "") == "false"
      if startswith(try(statement.Sid, ""), "ProofFenced") || try(statement.Sid, "") == "ProofRegistryRead"
    ])
    error_message = "Every fenced proof statement must pin dynamodb:LeadingKeys to the proof tenant or the registry partition."
  }

  # Replay access is separately operation-scoped. Exact equality is
  # intentional: it rejects a generic HUB_REQUEST#* or bare HUB_REQUEST grant.
  assert {
    condition = (
      toset({ for statement in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-pm"].policy).Statement : statement.Sid => statement }["ProofReplayReadWrite"].Action) == toset([
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
      ]) &&
      { for statement in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-pm"].policy).Statement : statement.Sid => statement }["ProofReplayReadWrite"].Resource == [
        "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-connector-authority",
      ] &&
      { for statement in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-pm"].policy).Statement : statement.Sid => statement }["ProofReplayReadWrite"].Condition["ForAllValues:StringLike"]["dynamodb:LeadingKeys"] == [
        "HUB_REQUEST#MutateProofAgent#*",
      ] &&
      { for statement in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-pm"].policy).Statement : statement.Sid => statement }["ProofReplayReadWrite"].Condition.Null["dynamodb:LeadingKeys"] == "false"
    )
    error_message = "MutateProofAgent replay must be exact Get/Put/Update on its own HUB_REQUEST#MutateProofAgent#* namespace."
  }

  # DynamoDB decrypts SSE-KMS rows on the caller's behalf. Keep the required
  # grant confined to the exact Control data CMK and the DynamoDB service path.
  assert {
    condition = (
      { for statement in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-pm"].policy).Statement : statement.Sid => statement }["ProofDynamoDBDecrypt"].Action == [
        "kms:Decrypt",
      ] &&
      { for statement in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-pm"].policy).Statement : statement.Sid => statement }["ProofDynamoDBDecrypt"].Resource == [
        "arn:aws:kms:us-east-2:767397897469:key/00000000-0000-0000-0000-000000000002",
      ] &&
      { for statement in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-pm"].policy).Statement : statement.Sid => statement }["ProofDynamoDBDecrypt"].Condition == {
        StringEquals = {
          "kms:ViaService" = "dynamodb.us-east-2.amazonaws.com"
        }
      }
    )
    error_message = "MutateProofAgent must decrypt only the exact Control data CMK and only through DynamoDB."
  }

  # The Hub functions must be able to read proof placement/lease state from the
  # connector-authority table, and the gateway endpoint must admit that read
  # plus ca-pm's exact replay writes for their exact execution principals.
  assert {
    condition = alltrue([
      for function_name in [
        "layerv-nhp-sandbox-ca-ia",
        "layerv-nhp-sandbox-ca-ra",
        "layerv-nhp-sandbox-ca-icr",
      ] :
      contains(
        { for statement in jsondecode(aws_iam_role_policy.authority_exec[function_name].policy).Statement : statement.Sid => statement }["AuthorityReads"].Action,
        "dynamodb:GetItem",
        ) && contains(
        { for statement in jsondecode(aws_iam_role_policy.authority_exec[function_name].policy).Statement : statement.Sid => statement }["AuthorityReads"].Resource,
        "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-connector-authority",
      )
    ])
    error_message = "IA, RA, and ICR must retain GetItem access to connector-authority for proof placement and lease policy."
  }

  assert {
    condition = (
      contains(jsondecode(aws_vpc_endpoint.dynamodb.policy).Statement[0].Action, "dynamodb:GetItem") &&
      contains(jsondecode(aws_vpc_endpoint.dynamodb.policy).Statement[0].Action, "dynamodb:PutItem") &&
      contains(jsondecode(aws_vpc_endpoint.dynamodb.policy).Statement[0].Action, "dynamodb:UpdateItem") &&
      contains(jsondecode(aws_vpc_endpoint.dynamodb.policy).Statement[0].Resource, "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-control-connector-authority") &&
      alltrue([
        for role_arn in [
          "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-ca-ia-exec",
          "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-ca-ra-exec",
          "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-ca-icr-exec",
          "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-ca-pm-exec",
        ] :
        contains(jsondecode(aws_vpc_endpoint.dynamodb.policy).Statement[0].Condition.StringEquals["aws:PrincipalArn"], role_arn)
      ])
    )
    error_message = "The DynamoDB endpoint must carry the exact proof read/replay actions, connector-authority table, and IA/RA/ICR/PM principals."
  }

  # The control reaches only the placement table. Absent api_keys and agent_keys
  # means it can neither read an owner's credentials nor revoke one: device
  # credential revocation stays on the authenticated Control API path.
  assert {
    condition = length([
      for statement in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-pm"].policy).Statement :
      statement
      if length([
        for resource in try(tolist(statement.Resource), []) :
        resource
        if strcontains(resource, "-control-api_keys") || strcontains(resource, "-control-agent_keys") || strcontains(resource, "-control-customers")
      ]) > 0
    ]) == 0
    error_message = "The proof mutation control must not reach api_keys, agent_keys, or customers."
  }

  # A proof move relocates and advances placement; it never deletes a row, and
  # it may never edit the Terraform-owned cell catalog.
  assert {
    condition = length([
      for statement in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-pm"].policy).Statement :
      statement
      if contains(try(tolist(statement.Action), []), "dynamodb:DeleteItem")
    ]) == 0
    error_message = "The proof mutation control must never hold dynamodb:DeleteItem."
  }

  assert {
    condition = length([
      for statement in jsondecode(aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-pm"].policy).Statement :
      statement
      if try(statement.Sid, "") == "ProofRegistryRead" && length(setintersection(
        toset(try(tolist(statement.Action), [])),
        toset(["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem"]),
      )) > 0
    ]) == 0
    error_message = "The registry partition must remain read-only to the proof mutation control."
  }
}

run "selected_consumers_read_but_cannot_write_proof_policy" {
  command = plan

  variables {
    authority_runtime_functions_enabled     = true
    authority_proof_policy_consumers_staged = true
  }

  assert {
    condition = alltrue([
      for function_name in [
        "layerv-nhp-sandbox-ca-ia",
        "layerv-nhp-sandbox-ca-ra",
        "layerv-nhp-sandbox-ca-icr",
        ] : {
        for key, value in aws_lambda_function.authority[function_name].environment[0].variables :
        key => value if startswith(key, "CONNECTOR_AUTHORITY_PROOF_")
        } == {
        CONNECTOR_AUTHORITY_PROOF_OWNER_ID          = "layerv-nhp-sandbox-udp-proof"
        CONNECTOR_AUTHORITY_PROOF_AGENT_ID_PREFIX   = "qurl-go-sandbox-"
        CONNECTOR_AUTHORITY_PROOF_DIRECTIVE_TTL     = "5400"
        CONNECTOR_AUTHORITY_PROOF_MIN_LEASE_SECONDS = "30"
      }
    ])
    error_message = "The selected IA/RA/ICR versions must receive exactly the proof-policy contract."
  }

  assert {
    condition = alltrue([
      for function_name in [
        "layerv-nhp-sandbox-ca-ia",
        "layerv-nhp-sandbox-ca-ra",
        "layerv-nhp-sandbox-ca-icr",
        ] : (
        { for statement in jsondecode(aws_iam_role_policy.authority_exec[function_name].policy).Statement : statement.Sid => statement }["ProofPolicyRead"].Action == ["dynamodb:GetItem"] &&
        { for statement in jsondecode(aws_iam_role_policy.authority_exec[function_name].policy).Statement : statement.Sid => statement }["ProofPolicyRead"].Condition["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"] == ["PROOF"] &&
        { for statement in jsondecode(aws_iam_role_policy.authority_exec[function_name].policy).Statement : statement.Sid => statement }["ProofPolicyRead"].Condition.Null["dynamodb:LeadingKeys"] == "false" &&
        toset({ for statement in jsondecode(aws_iam_role_policy.authority_exec[function_name].policy).Statement : statement.Sid => statement }["DenyProofPolicyWrite"].Action) == toset([
          "dynamodb:DeleteItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
        ]) &&
        { for statement in jsondecode(aws_iam_role_policy.authority_exec[function_name].policy).Statement : statement.Sid => statement }["DenyProofPolicyWrite"].Effect == "Deny" &&
        { for statement in jsondecode(aws_iam_role_policy.authority_exec[function_name].policy).Statement : statement.Sid => statement }["DenyProofPolicyWrite"].Condition["ForAnyValue:StringEquals"]["dynamodb:LeadingKeys"] == ["PROOF"] &&
        { for statement in jsondecode(aws_iam_role_policy.authority_exec[function_name].policy).Statement : statement.Sid => statement }["DenyProofPolicyWrite"].Condition.Null["dynamodb:LeadingKeys"] == "false"
      )
    ])
    error_message = "Proof-policy consumers must have exact GetItem and an explicit PROOF-partition write deny."
  }

  assert {
    condition = alltrue([
      for function_name in [
        "layerv-nhp-sandbox-ca-ia",
        "layerv-nhp-sandbox-ca-ra",
        "layerv-nhp-sandbox-ca-icr",
        ] : (
        aws_lambda_alias.authority["${function_name}:blue"].function_version == "6" &&
        aws_lambda_alias.authority["${function_name}:green"].function_version == "6"
      )
    ])
    error_message = "Staging must publish the proof-aware version without moving either live consumer alias."
  }

  assert {
    condition = alltrue([
      for function_name, function in aws_lambda_function.authority :
      length({
        for key, value in function.environment[0].variables :
        key => value if startswith(key, "CONNECTOR_AUTHORITY_PROOF_")
      }) == 0
      if !contains([
        "layerv-nhp-sandbox-ca-pm",
        "layerv-nhp-sandbox-ca-pcr",
        "layerv-nhp-sandbox-ca-ia",
        "layerv-nhp-sandbox-ca-ra",
        "layerv-nhp-sandbox-ca-icr",
      ], function_name)
    ])
    error_message = "No cell Authority function may inherit proof policy."
  }
}

run "proof_rollout_prepares_green_without_moving_blue_selector" {
  command = plan

  variables {
    authority_runtime_functions_enabled     = true
    authority_proof_policy_consumers_staged = true
    authority_proof_policy_selected_color   = "blue"
    authority_proof_policy_prepared_color   = "green"
    hub_edge_enabled                        = true
    hub_worker_enabled                      = true
    hub_public_udp_ingress_cidrs            = ["198.51.100.42/32"]
  }

  assert {
    condition = alltrue([
      for function_name in [
        "layerv-nhp-sandbox-ca-ia",
        "layerv-nhp-sandbox-ca-ra",
        "layerv-nhp-sandbox-ca-icr",
        "layerv-nhp-sandbox-ca-pm",
        ] : (
        aws_lambda_function.authority[function_name].reserved_concurrent_executions ==
        var.authority_runtime_contract.functions[function_name].rollout_reserved_concurrency &&
        aws_lambda_provisioned_concurrency_config.authority[function_name].qualifier == "blue" &&
        aws_lambda_provisioned_concurrency_config.authority[function_name].provisioned_concurrent_executions ==
        var.authority_runtime_contract.functions[function_name].rollout_active_provisioned_concurrency &&
        aws_lambda_provisioned_concurrency_config.authority_proof_standby[function_name].qualifier == "green" &&
        aws_lambda_provisioned_concurrency_config.authority_proof_standby[function_name].provisioned_concurrent_executions ==
        var.authority_runtime_contract.functions[function_name].rollout_standby_provisioned_concurrency
      )
    ])
    error_message = "The proof rollout must raise each exact function ceiling and retain equal blue/green provisioned pools."
  }

  assert {
    condition = alltrue([
      for function_name in [
        "layerv-nhp-sandbox-ca-ia",
        "layerv-nhp-sandbox-ca-ra",
        "layerv-nhp-sandbox-ca-icr",
        "layerv-nhp-sandbox-ca-pm",
        ] : (
        aws_lambda_alias.authority["${function_name}:blue"].function_version == "6" &&
        aws_lambda_alias.authority["${function_name}:green"].function_version == "7"
      )
    ])
    error_message = "Preparation may retarget only the inactive green rollout aliases."
  }

  assert {
    condition = (
      aws_lambda_function.authority["layerv-nhp-sandbox-ca-pm"].description ==
      "Connector Authority mutate_proof_agent (sandbox; proof-policy-prepared=green)"
    )
    error_message = "Preparation must publish a distinct ca-pm version for the prepared color."
  }

  assert {
    condition = (
      output.authority_selected_alias_targets.hub.issue_assignment ==
      "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-ia:blue" &&
      output.authority_selected_alias_targets.proof.mutate_proof_agent ==
      "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-pm:blue" &&
      length(local.hub_authority_alias_arns) == 6
    )
    error_message = "Preparation must keep blue selected while expanding only the bounded Hub caller set to both colors."
  }
}

run "proof_rollout_promotes_green_without_moving_recovery_selector" {
  command = plan

  variables {
    authority_runtime_functions_enabled     = true
    authority_proof_policy_consumers_staged = true
    authority_proof_policy_selected_color   = "green"
    authority_proof_policy_prepared_color   = "blue"
    hub_edge_enabled                        = true
    hub_worker_enabled                      = true
    hub_public_udp_ingress_cidrs            = ["198.51.100.42/32"]
  }

  assert {
    condition = (
      output.authority_selected_alias_targets.proof.mutate_proof_agent ==
      "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-pm:green" &&
      output.authority_selected_alias_targets.proof.prepare_proof_credential_recovery ==
      "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-pcr:blue"
    )
    error_message = "Promotion may move only the provisioned proof-mutation selector; recovery remains on the contract-selected provisioned alias."
  }

  assert {
    condition = toset(local.hub_authority_alias_arns) == toset([
      "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-ia:blue",
      "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-ia:green",
      "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-icr:blue",
      "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-icr:green",
      "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-ra:blue",
      "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-ra:green",
    ])
    error_message = "Promoting the Hub selector to green must keep exactly the six valid closed blue/green aliases; it must never append a second color qualifier."
  }
}

run "proof_selector_rejects_a_stale_pm_alias_after_consumers_are_ready" {
  command = plan

  variables {
    authority_runtime_functions_enabled     = true
    authority_proof_policy_consumers_staged = true
    authority_proof_policy_selected_color   = "green"
    authority_proof_policy_prepared_color   = "green"
    hub_edge_enabled                        = true
    hub_worker_enabled                      = true
    hub_public_udp_ingress_cidrs            = ["198.51.100.42/32"]
  }

  override_data {
    target          = data.aws_lambda_alias.authority_proof_policy_live["layerv-nhp-sandbox-ca-ia:green"]
    override_during = plan
    values          = { function_version = "7" }
  }

  override_data {
    target          = data.aws_lambda_alias.authority_proof_policy_live["layerv-nhp-sandbox-ca-ra:green"]
    override_during = plan
    values          = { function_version = "7" }
  }

  override_data {
    target          = data.aws_lambda_alias.authority_proof_policy_live["layerv-nhp-sandbox-ca-icr:green"]
    override_during = plan
    values          = { function_version = "7" }
  }

  # ca-pm intentionally remains on the provider default version 6 while its
  # staged function is version 7. The selector fence must include PM, not only
  # the three Hub consumers.
  expect_failures = [terraform_data.foundation_contract]
}
