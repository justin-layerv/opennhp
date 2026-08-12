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
    }
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
            max_replicas = 3
            preinvoke_limits = {
              issue_registration_otp       = 1
              activate_registration        = 1
              complete_registration        = 1
              complete_credential_recovery = 1
            }
            preinvoke_rate_limits = {
              issue_registration_otp       = { burst = 2, refill_per_second = 1 }
              activate_registration        = { burst = 2, refill_per_second = 1 }
              complete_registration        = { burst = 2, refill_per_second = 1 }
              complete_credential_recovery = { burst = 2, refill_per_second = 1 }
            }
          }
          cell1 = {
            max_replicas = 1
            preinvoke_limits = {
              issue_registration_otp       = 2
              activate_registration        = 2
              complete_registration        = 2
              complete_credential_recovery = 2
            }
            preinvoke_rate_limits = {
              issue_registration_otp       = { burst = 3, refill_per_second = 3 }
              activate_registration        = { burst = 3, refill_per_second = 3 }
              complete_registration        = { burst = 3, refill_per_second = 3 }
              complete_credential_recovery = { burst = 3, refill_per_second = 3 }
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
    }
  }
}

run "measurement_accepts_hub_group_and_future_cell_catalog" {
  command = plan

  assert {
    condition = (
      length(data.aws_ecr_image.authority_runtime) == 1 &&
      length(local.authority_expected_functions) == 3 + 4 * 2 &&
      local.authority_expected_caller_requests_per_second["layerv-nhp-sandbox-ca-ia"] == 10 &&
      local.authority_expected_caller_requests_per_second["layerv-nhp-sandbox-ca-iro-cell0"] == 9 &&
      local.authority_expected_caller_requests_per_second["layerv-nhp-sandbox-ca-iro-cell1"] == 6 &&
      output.authority_selected_alias_targets.hub == {
        issue_assignment          = "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-ia:blue"
        refresh_assignment        = "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-ra:blue"
        issue_credential_recovery = "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-icr:blue"
      } &&
      toset(keys(output.authority_selected_alias_targets.cells)) == toset(["cell0", "cell1"]) &&
      alltrue([
        for targets in values(output.authority_selected_alias_targets.cells) :
        length(targets) == 0
      ])
    )
    error_message = "Measurement must freeze exact 3 + 4N identities while exposing only complete operation groups present in the contract."
  }
}

# Regression fence: the deployed Authority image must be selected by the
# reviewed measurement basis alone.
#
# The publisher-owned SSM parameter is rewritten by qurl-service's
# build-and-deploy workflow on every push to its main. While that value fed the
# ECR lookup, an unrelated repository's release invalidated every nhp Control
# plan the moment it published -- the reviewed basis stopped matching the live
# parameter and the foundation precondition failed closed on all open Control
# PRs until someone hand-rolled the basis by hand.
#
# This run reads no SSM parameter at all: the module resolves its image from
# the contract digest, so there is no override_data for one here and none can
# be reintroduced without this assertion noticing. If a future change routes
# the deployed digest back through the parameter, the plan below stops
# resolving to the reviewed digest and this fails.
run "pinned_source_deploys_the_basis_digest" {
  command = plan

  variables {
    authority_runtime_contract = run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract
  }

  assert {
    condition = (
      local.authority_image_source == "pinned_digest" &&
      local.authority_image_tracks_publish == false &&
      local.authority_runtime_image_digest == local.authority_contract_global.authority_image_digest
    )
    error_message = "A pinned contract must deploy the digest named in the reviewed basis."
  }
}

# The counterpart mode, and the reason this split exists: an environment that is
# supposed to track main must be able to run a new build without a commit, a
# review and an attended apply. Before this, sandbox could not, so its deployed
# image drifted days behind and it stopped measuring the builds whose
# measurements the basis records.
run "publish_source_deploys_the_published_digest" {
  command = plan

  # Deliberately NOT the digest the pinned fixtures use. If the resolved digest
  # matched the basis value by coincidence this assertion would pass while
  # reading the wrong source, so the parameter carries a distinct one.
  override_data {
    target          = data.aws_ssm_parameter.authority_image_publish[0]
    override_during = plan
    values = {
      insecure_value = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
    }
  }

  override_data {
    target          = data.aws_ecr_image.authority_runtime[0]
    override_during = plan
    values = {
      image_digest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
      image_uri    = "767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/qurl-connector-authority@sha256:2222222222222222222222222222222222222222222222222222222222222222"
    }
  }

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        global = merge(
          {
            for key, value in run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global :
            key => value if key != "authority_image_digest"
          },
          { authority_image_source = "publish_parameter" },
        )
      },
    )
  }

  assert {
    condition = (
      local.authority_image_tracks_publish &&
      local.authority_image_basis_digest == null &&
      local.authority_runtime_image_digest == "sha256:2222222222222222222222222222222222222222222222222222222222222222"
    )
    error_message = "A publish-tracking contract must deploy the digest currently in the publish parameter."
  }

  # The ECR leg is deliberately not asserted here. data.aws_ecr_image depends on
  # the managed repository, so its read defers to apply and cannot be evaluated
  # in a plan-only run -- the same reason the pinned tests never assert on it.
  # The shape gate above is the part that must hold at plan, and
  # publish_source_rejects_an_unpublished_parameter proves it does.
}

# The trust trade publish tracking makes -- qurl-service CI decides what runs,
# without review here -- is acceptable for an environment whose job is to track
# main. It is not acceptable for prod, and CR asked for a constraint rather than
# a convention resting on prod simply not having a contract yet.
#
# Asserted on the named local, not via expect_failures: a prod-flavoured plan
# fails identity for a dozen unrelated reasons (prod resource names against a
# sandbox contract), so an expect_failures test here passes with the rule
# deleted and proves nothing. Verified: it did.
run "publish_source_is_permitted_outside_prod" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        global = merge(
          {
            for key, value in run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global :
            key => value if key != "authority_image_digest"
          },
          { authority_image_source = "publish_parameter" },
        )
      },
    )
  }

  assert {
    condition     = local.authority_image_tracks_publish && local.authority_image_source_permitted
    error_message = "A sandbox contract must be allowed to track the publish parameter."
  }
}

run "pinned_source_is_permitted_anywhere" {
  command = plan

  variables {
    authority_runtime_contract = run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract
  }

  assert {
    condition     = local.authority_image_source_permitted
    error_message = "A pinned contract must be permitted in every environment."
  }
}

# The seeded value on a fresh environment. Shape is checked on the RESOLVED
# digest precisely so that tracking a parameter cannot deploy a placeholder.
run "publish_source_rejects_an_unpublished_parameter" {
  command = plan

  override_data {
    target          = data.aws_ssm_parameter.authority_image_publish[0]
    override_during = plan
    values = {
      insecure_value = "UNPUBLISHED"
    }
  }

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        global = merge(
          {
            for key, value in run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global :
            key => value if key != "authority_image_digest"
          },
          { authority_image_source = "publish_parameter" },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

# Naming a digest while tracking published images leaves it ambiguous which one
# governs. The closed key set makes that unrepresentable rather than resolving
# it by precedence.
run "rejects_publish_source_that_also_names_a_digest" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        global = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global,
          { authority_image_source = "publish_parameter" },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_pinned_source_with_no_digest" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        global = {
          for key, value in run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global :
          key => value if key != "authority_image_digest"
        }
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

# An unrecognized source must not fall through to tracking whatever was
# published last; it falls to the pinned shape and is rejected there.
run "rejects_unknown_image_source" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        global = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global,
          { authority_image_source = "latest" },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "ready_requires_and_accepts_exact_two_cell_graph" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        phase = "ready"
        global = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global,
          {
            result_evidence = run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.basis_evidence
          },
        )
        functions = merge(
          {
            for function_name, function in run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.functions :
            function_name => merge(function, { result_evidence = function.basis_evidence })
          },
          {
            for function_name in [
              "layerv-nhp-sandbox-ca-iro-cell0",
              "layerv-nhp-sandbox-ca-ar-cell0",
              "layerv-nhp-sandbox-ca-cr-cell0",
              "layerv-nhp-sandbox-ca-ccr-cell0",
            ] :
            function_name => merge(
              run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.functions["layerv-nhp-sandbox-ca-ia"],
              {
                steady_provisioned_concurrency          = 3
                steady_reserved_concurrency             = 6
                rollout_active_provisioned_concurrency  = 3
                rollout_standby_provisioned_concurrency = 3
                rollout_reserved_concurrency            = 6
                max_caller_in_flight                    = 3
                max_caller_requests_per_second          = 9
                result_evidence                         = run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.basis_evidence
              },
            )
          },
          {
            for function_name in [
              "layerv-nhp-sandbox-ca-iro-cell1",
              "layerv-nhp-sandbox-ca-ar-cell1",
              "layerv-nhp-sandbox-ca-cr-cell1",
              "layerv-nhp-sandbox-ca-ccr-cell1",
            ] :
            function_name => merge(
              run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.functions["layerv-nhp-sandbox-ca-ia"],
              {
                rollout_reserved_concurrency   = 4
                max_caller_in_flight           = 2
                max_caller_requests_per_second = 6
                result_evidence                = run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.basis_evidence
              },
            )
          },
        )
      },
    )
  }

  assert {
    condition = (
      length(output.authority_runtime_contract.functions) == 3 + 4 * 2 &&
      output.authority_selected_alias_targets.cells == {
        cell0 = {
          issue_registration_otp       = "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-iro-cell0:blue"
          activate_registration        = "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-ar-cell0:blue"
          complete_registration        = "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-cr-cell0:blue"
          complete_credential_recovery = "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-ccr-cell0:blue"
        }
        cell1 = {
          issue_registration_otp       = "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-iro-cell1:blue"
          activate_registration        = "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-ar-cell1:blue"
          complete_registration        = "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-cr-cell1:blue"
          complete_credential_recovery = "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-ccr-cell1:blue"
        }
      }
    )
    error_message = "Ready must accept only the complete same-color 3 + 4N graph with result evidence."
  }
}

run "measurement_accepts_green_as_the_one_global_color" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      { selected_authority_color = "green" },
    )
  }

  assert {
    condition = alltrue([
      for target in values(output.authority_selected_alias_targets.hub) :
      endswith(target, ":green")
    ])
    error_message = "The closed selector must accept green and derive every Hub target from that one color."
  }
}

run "rejects_unknown_top_level_key" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      { unexpected = true },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_enabled_contract_without_external_evidence_gate" {
  command = plan

  variables {
    authority_runtime_contract_evidence_verified = false
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_unknown_nested_operation_key" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        global = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global,
          {
            caller_capacity = merge(
              run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.caller_capacity,
              {
                hub_workers = merge(
                  run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.caller_capacity.hub_workers,
                  {
                    preinvoke_limits = merge(
                      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.caller_capacity.hub_workers.preinvoke_limits,
                      { unknown_operation = 1 },
                    )
                  },
                )
              },
            )
          },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_unknown_nested_rate_limit_key" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        global = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global,
          {
            caller_capacity = merge(
              run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.caller_capacity,
              {
                hub_workers = merge(
                  run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.caller_capacity.hub_workers,
                  {
                    preinvoke_rate_limits = merge(
                      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.caller_capacity.hub_workers.preinvoke_rate_limits,
                      {
                        issue_assignment = merge(
                          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.caller_capacity.hub_workers.preinvoke_rate_limits.issue_assignment,
                          { unknown = 1 },
                        )
                      },
                    )
                  },
                )
              },
            )
          },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_missing_catalog_evidence_key" {
  command = plan

  variables {
    authority_runtime_contract = {
      for key, value in run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract :
      key => value
      if key != "provisioned_cells_evidence"
    }
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_null_provisioned_cell_catalog_evidence" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      { provisioned_cells_evidence = null },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_wrong_rate_limit_type" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        global = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global,
          {
            caller_capacity = merge(
              run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.caller_capacity,
              {
                hub_workers = merge(
                  run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.caller_capacity.hub_workers,
                  {
                    preinvoke_rate_limits = merge(
                      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.caller_capacity.hub_workers.preinvoke_rate_limits,
                      { issue_assignment = "not-an-object" },
                    )
                  },
                )
              },
            )
          },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_zero_rate_limit_burst" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        global = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global,
          {
            caller_capacity = merge(
              run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.caller_capacity,
              {
                hub_workers = merge(
                  run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.caller_capacity.hub_workers,
                  {
                    preinvoke_rate_limits = merge(
                      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.caller_capacity.hub_workers.preinvoke_rate_limits,
                      {
                        issue_assignment = {
                          burst             = 0
                          refill_per_second = 2
                        }
                      },
                    )
                  },
                )
              },
            )
          },
        )
        functions = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.functions,
          {
            "layerv-nhp-sandbox-ca-ia" = merge(
              run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.functions["layerv-nhp-sandbox-ca-ia"],
              { max_caller_requests_per_second = 4 },
            )
          },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_legacy_active_color" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      { selected_authority_color = "active" },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_live_environment_identity_drift" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        global = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global,
          { environment = "prod" },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_malformed_authority_image_digest" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        global = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global,
          { authority_image_digest = "sha256:not-a-digest" },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_cell_role_name_substitution" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        provisioned_cells = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.provisioned_cells,
          {
            cell0 = {
              caller_role_arn = "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-cell0-server"
            }
          },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_duplicate_cell_caller_role" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        provisioned_cells = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.provisioned_cells,
          {
            cell1 = {
              caller_role_arn = "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-server"
            }
          },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_catalog_without_legacy_cell_zero" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        provisioned_cells = {
          cell1 = run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.provisioned_cells.cell1
        }
        global = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global,
          {
            caller_capacity = merge(
              run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.caller_capacity,
              {
                cell_workers = {
                  cell1 = run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.caller_capacity.cell_workers.cell1
                }
              },
            )
          },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_partial_cell_operation_group" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        functions = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.functions,
          {
            "layerv-nhp-sandbox-ca-iro-cell0" = {
              steady_provisioned_concurrency          = 3
              steady_reserved_concurrency             = 6
              rollout_active_provisioned_concurrency  = 3
              rollout_standby_provisioned_concurrency = 3
              rollout_reserved_concurrency            = 6
              max_caller_in_flight                    = 3
              max_caller_requests_per_second          = 9
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
          },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_ready_without_exact_three_plus_four_n" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        phase = "ready"
        global = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global,
          {
            result_evidence = run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.basis_evidence
          },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_unknown_physical_operation" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        functions = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.functions,
          {
            "layerv-nhp-sandbox-ca-unknown" = run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.functions["layerv-nhp-sandbox-ca-ia"]
          },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_non_integer_capacity" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        functions = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.functions,
          {
            "layerv-nhp-sandbox-ca-ia" = merge(
              run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.functions["layerv-nhp-sandbox-ca-ia"],
              { steady_provisioned_concurrency = 2.5 },
            )
          },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_numeric_string_capacity" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        global = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global,
          {
            regional_lambda_concurrency_quota = "1000"
          },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_non_string_qat1_kid" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      { qat1_kid = 12345 },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_derived_caller_capacity_mismatch" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        functions = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.functions,
          {
            "layerv-nhp-sandbox-ca-ra" = merge(
              run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.functions["layerv-nhp-sandbox-ca-ra"],
              { max_caller_in_flight = 1 },
            )
          },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_derived_caller_request_rate_mismatch" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        functions = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.functions,
          {
            "layerv-nhp-sandbox-ca-ra" = merge(
              run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.functions["layerv-nhp-sandbox-ca-ra"],
              { max_caller_requests_per_second = 9 },
            )
          },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_non_integer_caller_refill_rate" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        global = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global,
          {
            caller_capacity = merge(
              run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.caller_capacity,
              {
                hub_workers = merge(
                  run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.caller_capacity.hub_workers,
                  {
                    preinvoke_rate_limits = merge(
                      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.caller_capacity.hub_workers.preinvoke_rate_limits,
                      {
                        issue_assignment = {
                          burst             = 3
                          refill_per_second = 1.5
                        }
                      },
                    )
                  },
                )
              },
            )
          },
        )
        functions = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.functions,
          {
            "layerv-nhp-sandbox-ca-ia" = merge(
              run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.functions["layerv-nhp-sandbox-ca-ia"],
              { max_caller_requests_per_second = 9 },
            )
          },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_request_rate_above_steady_allocation_ceiling" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        global = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global,
          {
            caller_capacity = merge(
              run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.caller_capacity,
              {
                hub_workers = merge(
                  run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.caller_capacity.hub_workers,
                  {
                    preinvoke_rate_limits = merge(
                      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.caller_capacity.hub_workers.preinvoke_rate_limits,
                      {
                        issue_assignment = {
                          burst             = 9
                          refill_per_second = 2
                        }
                      },
                    )
                  },
                )
              },
            )
          },
        )
        functions = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.functions,
          {
            "layerv-nhp-sandbox-ca-ia" = merge(
              run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.functions["layerv-nhp-sandbox-ca-ia"],
              {
                rollout_active_provisioned_concurrency  = 3
                rollout_standby_provisioned_concurrency = 3
                rollout_reserved_concurrency            = 6
                max_caller_requests_per_second          = 22
              },
            )
          },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_request_rate_above_rollout_standby_allocation_ceiling" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        global = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global,
          {
            caller_capacity = merge(
              run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.caller_capacity,
              {
                hub_workers = merge(
                  run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.caller_capacity.hub_workers,
                  {
                    preinvoke_rate_limits = merge(
                      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.caller_capacity.hub_workers.preinvoke_rate_limits,
                      {
                        issue_assignment = {
                          burst             = 9
                          refill_per_second = 2
                        }
                      },
                    )
                  },
                )
              },
            )
          },
        )
        functions = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.functions,
          {
            "layerv-nhp-sandbox-ca-ia" = merge(
              run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.functions["layerv-nhp-sandbox-ca-ia"],
              {
                steady_provisioned_concurrency          = 3
                steady_reserved_concurrency             = 6
                rollout_active_provisioned_concurrency  = 3
                rollout_standby_provisioned_concurrency = 2
                rollout_reserved_concurrency            = 5
                max_caller_requests_per_second          = 22
              },
            )
          },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_rollout_algebra_mismatch" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        functions = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.functions,
          {
            "layerv-nhp-sandbox-ca-icr" = merge(
              run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.functions["layerv-nhp-sandbox-ca-icr"],
              { rollout_reserved_concurrency = 3 },
            )
          },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_rollout_total_over_account_envelope" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        global = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global,
          {
            regional_lambda_concurrency_quota = 210
          },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_steady_total_over_account_envelope" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        global = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global,
          {
            regional_lambda_concurrency_quota = 213
          },
        )
        functions = {
          for function_name, function in run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.functions :
          function_name => merge(
            function,
            {
              steady_provisioned_concurrency = 5
              steady_reserved_concurrency    = 5
            },
          )
        }
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_out_of_bounds_rollback_retention" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        functions = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.functions,
          {
            "layerv-nhp-sandbox-ca-ia" = merge(
              run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.functions["layerv-nhp-sandbox-ca-ia"],
              { rollback_retention_seconds = 86401 },
            )
          },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_unreserved_concurrency_floor_below_one_hundred" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        global = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global,
          { retained_unreserved_concurrency = 99 },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_measurement_result_evidence" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        global = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global,
          {
            result_evidence = run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.basis_evidence
          },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_malformed_evidence_reference" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        global = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global,
          {
            basis_evidence = merge(
              run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.basis_evidence,
              { path = "../outside.json" },
            )
          },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}

run "rejects_untrusted_evidence_repository" {
  command = plan

  variables {
    authority_runtime_contract = merge(
      run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract,
      {
        global = merge(
          run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global,
          {
            basis_evidence = merge(
              run.measurement_accepts_hub_group_and_future_cell_catalog.authority_runtime_contract.global.basis_evidence,
              { repository = "example/untrusted" },
            )
          },
        )
      },
    )
  }

  expect_failures = [terraform_data.foundation_contract]
}
