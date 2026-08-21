# Plan-only tests for the Connector Hub Fargate worker slice (Step 5, slice 5b).
# They prove the dark-first gate creates ZERO worker resources while off (even
# with BOTH dependencies -- the 5a edge and the authority runtime -- already
# live), that flipping it on plans EXACTLY the worker inventory (ECS
# cluster/task/service, exec/task/keygen identities, seeded secret + keygen
# Lambda, worker SG, log group, and the ECR/S3 pull endpoints) AND opens the
# caller (lambda) interface endpoint to the Hub task role alone, and that the
# fail-closed precondition rejects the gate when the public edge is dark. The
# provider mock / bound-contract preamble mirrors hub_edge.tftest.hcl so the
# whole module plans.

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

# The Hub image URI is repo_url@digest; pin the repo URL so the task definition
# image resolves at plan.
override_resource {
  target          = aws_ecr_repository.hub
  override_during = plan
  values = {
    arn            = "arn:aws:ecr:us-east-2:767397897469:repository/layerv/nhp-hub"
    repository_url = "767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/nhp-hub"
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

# Known data-CMK ARN so the execution/keygen inline policies (kms:Decrypt /
# GenerateDataKey on this key) resolve at plan.
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

  # The runtime gate fails closed without a reviewed operator alarm destination.
  operator_alarm_topic_arns = ["arn:aws:sns:us-east-2:767397897469:layerv-nhp-sandbox-cell0-alerts"]

  # The exact merged measurement basis: 3 hub functions, cell0 frozen catalog.
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
    }
  }
}

run "hub_worker_dark_creates_nothing" {
  command = plan

  # Both dependencies live (the 5a public edge and the authority runtime), yet
  # the worker gate is off: the module must still create ZERO worker resources.
  variables {
    hub_edge_enabled                    = true
    hub_public_udp_ingress_cidrs        = ["3.141.109.76/32"]
    authority_runtime_functions_enabled = true
    hub_worker_enabled                  = false
  }

  assert {
    condition = (
      length(aws_secretsmanager_secret.hub_key_material) == 0 &&
      length(aws_iam_role.hub_keygen) == 0 &&
      length(aws_iam_role_policy.hub_keygen) == 0 &&
      length(aws_cloudwatch_log_group.hub_keygen) == 0 &&
      length(aws_lambda_function.hub_keygen) == 0 &&
      length(aws_lambda_invocation.hub_keygen) == 0 &&
      length(aws_ssm_parameter.hub_public_key) == 0 &&
      length(aws_iam_role.hub_execution) == 0 &&
      length(aws_iam_role_policy_attachment.hub_execution) == 0 &&
      length(aws_iam_role_policy.hub_execution) == 0 &&
      length(aws_iam_role.hub_task) == 0 &&
      length(aws_iam_role_policy.hub_task) == 0 &&
      length(aws_security_group.hub_worker) == 0 &&
      length(aws_cloudwatch_log_group.hub) == 0 &&
      length(aws_ecs_cluster.hub) == 0 &&
      length(aws_ecs_task_definition.hub) == 0 &&
      length(aws_ecs_service.hub) == 0 &&
      length(aws_vpc_endpoint.hub_ecr_api) == 0 &&
      length(aws_vpc_endpoint.hub_ecr_dkr) == 0 &&
      length(aws_vpc_endpoint.hub_s3) == 0
    )
    error_message = "With the Hub worker dark the module must create none of the 20 worker resources, even when the 5a edge and the authority runtime are both live."
  }

  assert {
    # The caller (lambda) endpoint stays deny-all and the interface-endpoint SG
    # keeps ONLY the runtime's single 443 ingress: the worker slice adds neither.
    condition = (
      jsondecode(aws_vpc_endpoint.interface["lambda"].policy).Statement[0].Effect == "Deny" &&
      length(aws_security_group.interface_endpoints.ingress) == 1
    )
    error_message = "With the Hub worker dark the lambda endpoint must stay deny-all and the interface SG must keep only the runtime's single ingress rule."
  }
}

run "hub_worker_on_plans_the_worker_and_opens_the_lambda_endpoint" {
  command = plan

  variables {
    hub_edge_enabled                    = true
    hub_public_udp_ingress_cidrs        = ["3.141.109.76/32"]
    authority_runtime_functions_enabled = true
    hub_worker_enabled                  = true
  }

  # The Hub digest pin resolves to an immutable sha256 so the task-definition
  # precondition passes (the mock only sets insecure_value; the worker reads
  # .value).
  override_data {
    target          = data.aws_ssm_parameter.hub_image_digest[0]
    override_during = plan
    values = {
      value = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
    }
  }

  # Pin the computed ARNs/ids the worker policies and the ECS load_balancer / SG
  # ingress reference, so those plan values are fully known (and, for the SG
  # ingress set, so the two known-distinct ingress rules don't collapse under
  # set-dedup ambiguity).
  override_resource {
    target          = aws_secretsmanager_secret.hub_key_material[0]
    override_during = plan
    values = {
      arn = "arn:aws:secretsmanager:us-east-2:767397897469:secret:layerv-nhp-sandbox-control-hub-key-material-AbCdEf"
    }
  }
  override_resource {
    target          = aws_ssm_parameter.hub_public_key[0]
    override_during = plan
    values = {
      arn = "arn:aws:ssm:us-east-2:767397897469:parameter/sandbox/nhp/control/hub/identity/public-key"
    }
  }
  override_resource {
    target          = aws_lb_target_group.hub[0]
    override_during = plan
    values = {
      arn = "arn:aws:elasticloadbalancing:us-east-2:767397897469:targetgroup/layerv-nhp-sandbox-control-hub/1234567890abcdef"
    }
  }
  override_resource {
    target          = aws_security_group.hub_nlb[0]
    override_during = plan
    values = {
      id = "sg-0ccccccccccccccc3"
    }
  }
  override_resource {
    target          = aws_security_group.authority_lambda[0]
    override_during = plan
    values = {
      id = "sg-0aaaaaaaaaaaaaaa1"
    }
  }
  override_resource {
    target          = aws_security_group.hub_worker[0]
    override_during = plan
    values = {
      id = "sg-0bbbbbbbbbbbbbbb2"
    }
  }

  assert {
    condition = (
      length(aws_secretsmanager_secret.hub_key_material) == 1 &&
      length(aws_iam_role.hub_keygen) == 1 &&
      length(aws_iam_role_policy.hub_keygen) == 1 &&
      length(aws_cloudwatch_log_group.hub_keygen) == 1 &&
      length(aws_lambda_function.hub_keygen) == 1 &&
      length(aws_lambda_invocation.hub_keygen) == 1 &&
      length(aws_ssm_parameter.hub_public_key) == 1 &&
      length(aws_iam_role.hub_execution) == 1 &&
      length(aws_iam_role_policy_attachment.hub_execution) == 1 &&
      length(aws_iam_role_policy.hub_execution) == 1 &&
      length(aws_iam_role.hub_task) == 1 &&
      length(aws_iam_role_policy.hub_task) == 1 &&
      length(aws_security_group.hub_worker) == 1 &&
      length(aws_cloudwatch_log_group.hub) == 1 &&
      length(aws_ecs_cluster.hub) == 1 &&
      length(aws_ecs_task_definition.hub) == 1 &&
      length(aws_ecs_service.hub) == 1 &&
      length(aws_vpc_endpoint.hub_ecr_api) == 1 &&
      length(aws_vpc_endpoint.hub_ecr_dkr) == 1 &&
      length(aws_vpc_endpoint.hub_s3) == 1 &&
      length(aws_vpc_security_group_egress_rule.hub_nlb_udp) == 1 &&
      length(aws_vpc_security_group_egress_rule.hub_nlb_health) == 1
    )
    error_message = "Enabling the Hub worker must plan the 20 worker resources plus the exact NLB UDP and health egress rules."
  }

  assert {
    condition = (
      alltrue([
        for rule in aws_security_group.hub_worker[0].ingress :
        length(rule.cidr_blocks) == 0 &&
        length(rule.ipv6_cidr_blocks) == 0 &&
        length(rule.prefix_list_ids) == 0 &&
        toset(rule.security_groups) == toset(["sg-0ccccccccccccccc3"]) &&
        rule.self == false
      ]) &&
      aws_vpc_security_group_egress_rule.hub_nlb_udp[0].ip_protocol == "udp" &&
      aws_vpc_security_group_egress_rule.hub_nlb_udp[0].from_port == 62206 &&
      aws_vpc_security_group_egress_rule.hub_nlb_udp[0].to_port == 62206 &&
      aws_vpc_security_group_egress_rule.hub_nlb_health[0].ip_protocol == "tcp" &&
      aws_vpc_security_group_egress_rule.hub_nlb_health[0].from_port == 62207 &&
      aws_vpc_security_group_egress_rule.hub_nlb_health[0].to_port == 62207
    )
    error_message = "Hub workers must trust only the NLB SG on UDP/62206 and TCP/62207, and the NLB must egress only those two target ports."
  }

  assert {
    # The ECS service fronts the 5a NLB target group on the worker container's
    # UDP port and runs the measurement-basis two-task fleet on Fargate. (The
    # worker SG's inline ingress/egress sets are provider-computed at plan and
    # not length-assertable here; their content is covered by the module review
    # and the first-apply checker.)
    condition = (
      aws_ecs_service.hub[0].desired_count == 2 &&
      aws_ecs_service.hub[0].wait_for_steady_state == true &&
      aws_ecs_service.hub[0].launch_type == "FARGATE" &&
      one(aws_ecs_service.hub[0].load_balancer).container_name == "hub" &&
      one(aws_ecs_service.hub[0].load_balancer).container_port == 62206
    )
    error_message = "The ECS service must run desired_count=2 on FARGATE and register the hub container's 62206 into the target group."
  }

  assert {
    # The caller (lambda) interface endpoint OPENS: deny replaced by a scoped
    # Allow admitting ONLY the Hub task role to InvokeFunction, and the
    # interface-endpoint SG gains the worker's 443 ingress (now 2 rules total).
    condition = (
      jsondecode(aws_vpc_endpoint.interface["lambda"].policy).Statement[0].Effect == "Allow" &&
      jsondecode(aws_vpc_endpoint.interface["lambda"].policy).Statement[0].Sid == "HubWorkersInvokeAuthority" &&
      jsondecode(aws_vpc_endpoint.interface["lambda"].policy).Statement[0].Principal == "*" &&
      jsondecode(aws_vpc_endpoint.interface["lambda"].policy).Statement[0].Action == "lambda:InvokeFunction" &&
      length(jsondecode(aws_vpc_endpoint.interface["lambda"].policy).Statement[0].Condition.StringEquals["aws:PrincipalArn"]) == 1 &&
      contains(jsondecode(aws_vpc_endpoint.interface["lambda"].policy).Statement[0].Condition.StringEquals["aws:PrincipalArn"], "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-control-hub-task") &&
      length(aws_security_group.interface_endpoints.ingress) == 2
    )
    error_message = "The lambda endpoint must open to the Hub task role alone (InvokeFunction, Principal * + aws:PrincipalArn condition) and the interface SG must gain the worker's 443 ingress."
  }

  assert {
    # The lambda endpoint Resource and the task role's AuthorityInvoke Resource
    # are BOTH exactly the six closed blue/green alias ARNs. ECS drains old Hub
    # tasks after starting replacements, so both task revisions must remain
    # authorized throughout a selector flip.
    condition = (
      toset(jsondecode(aws_vpc_endpoint.interface["lambda"].policy).Statement[0].Resource) == toset([
        "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-ia:blue",
        "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-ia:green",
        "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-icr:blue",
        "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-icr:green",
        "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-ra:blue",
        "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-ra:green",
      ]) &&
      toset({ for s in jsondecode(aws_iam_role_policy.hub_task[0].policy).Statement : s.Sid => s }["AuthorityInvoke"].Resource) == toset([
        "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-ia:blue",
        "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-ia:green",
        "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-icr:blue",
        "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-icr:green",
        "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-ra:blue",
        "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-ra:green",
      ]) &&
      { for s in jsondecode(aws_iam_role_policy.hub_task[0].policy).Statement : s.Sid => s }["PublishHubMetrics"].Condition.StringEquals["cloudwatch:namespace"] == "LayerV/NHP"
    )
    error_message = "The lambda endpoint and task role must authorize exactly both closed aliases for the three Hub operations during ECS rollout overlap; PublishHubMetrics must pin the LayerV/NHP namespace."
  }

  assert {
    # The ECR interface endpoints admit ONLY the execution role, scoped to the
    # Hub repository. The S3 gateway endpoint carries NO principal condition: ECR
    # layer blobs are fetched via presigned URLs signed by the ECR service (not
    # the execution role), so an aws:PrincipalArn condition would 403 the pull.
    # The exact bucket + opaque layer-digest object keys are the access control.
    condition = (
      jsondecode(aws_vpc_endpoint.hub_ecr_api[0].policy).Statement[0].Sid == "HubPullImage" &&
      contains(jsondecode(aws_vpc_endpoint.hub_ecr_api[0].policy).Statement[0].Condition.StringEquals["aws:PrincipalArn"], "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-control-hub-exec") &&
      jsondecode(aws_vpc_endpoint.hub_ecr_api[0].policy).Statement[0].Resource[0] == "arn:aws:ecr:us-east-2:767397897469:repository/layerv/nhp-hub" &&
      jsondecode(aws_vpc_endpoint.hub_ecr_dkr[0].policy).Statement[1].Action == "ecr:GetAuthorizationToken" &&
      jsondecode(aws_vpc_endpoint.hub_s3[0].policy).Statement[0].Resource[0] == "arn:aws:s3:::prod-us-east-2-starport-layer-bucket/*" &&
      jsondecode(aws_vpc_endpoint.hub_s3[0].policy).Statement[0].Principal == "*" &&
      jsondecode(aws_vpc_endpoint.hub_s3[0].policy).Statement[0].Action == "s3:GetObject" &&
      !contains(keys(jsondecode(aws_vpc_endpoint.hub_s3[0].policy).Statement[0]), "Condition")
    )
    error_message = "The ECR endpoints must scope image pull to the Hub repository for the execution role (auth token registry-wide); S3 must allow s3:GetObject on exactly the region's ECR layer bucket with Principal \"*\" and NO condition (ECR presigned-URL layer GETs are not signed by the execution role)."
  }

  assert {
    # Execution role reads only the Hub secret + decrypts only the data CMK.
    # Keygen's retry-safe identity transaction reads/writes only that exact
    # secret and the exact public-only parameter.
    condition = (
      { for s in jsondecode(aws_iam_role_policy.hub_execution[0].policy).Statement : s.Sid => s }["ReadHubKeyMaterial"].Action == "secretsmanager:GetSecretValue" &&
      { for s in jsondecode(aws_iam_role_policy.hub_execution[0].policy).Statement : s.Sid => s }["DecryptHubKeyMaterial"].Action == "kms:Decrypt" &&
      toset({ for s in jsondecode(aws_iam_role_policy.hub_keygen[0].policy).Statement : s.Sid => s }["SeedHubKeyMaterial"].Action) == toset([
        "secretsmanager:DescribeSecret",
        "secretsmanager:GetSecretValue",
        "secretsmanager:PutSecretValue",
      ]) &&
      toset({ for s in jsondecode(aws_iam_role_policy.hub_keygen[0].policy).Statement : s.Sid => s }["PublishHubPublicIdentity"].Action) == toset([
        "ssm:GetParameter",
        "ssm:PutParameter",
      ]) &&
      { for s in jsondecode(aws_iam_role_policy.hub_keygen[0].policy).Statement : s.Sid => s }["PublishHubPublicIdentity"].Resource == "arn:aws:ssm:us-east-2:767397897469:parameter/sandbox/nhp/control/hub/identity/public-key"
    )
    error_message = "The execution role and retry-safe keygen must read/write only the exact Hub secret and public parameter."
  }

  assert {
    condition = (
      { for s in jsondecode(aws_iam_role_policy.hub_keygen[0].policy).Statement : s.Sid => s }["WrapHubKeyMaterial"].Condition.StringEquals["kms:ViaService"] == "secretsmanager.us-east-2.amazonaws.com" &&
      { for s in jsondecode(aws_iam_role_policy.hub_keygen[0].policy).Statement : s.Sid => s }["WrapHubKeyMaterial"].Condition.StringEquals["kms:EncryptionContext:SecretARN"] == aws_secretsmanager_secret.hub_key_material[0].arn &&
      { for s in jsondecode(aws_iam_role_policy.hub_execution[0].policy).Statement : s.Sid => s }["DecryptHubKeyMaterial"].Condition.StringEquals["kms:ViaService"] == "secretsmanager.us-east-2.amazonaws.com" &&
      { for s in jsondecode(aws_iam_role_policy.hub_execution[0].policy).Statement : s.Sid => s }["DecryptHubKeyMaterial"].Condition.StringEquals["kms:EncryptionContext:SecretARN"] == aws_secretsmanager_secret.hub_key_material[0].arn
    )
    error_message = "Hub keygen and execution KMS use must be mediated by Secrets Manager for the exact Hub secret encryption context."
  }

  assert {
    condition = (
      aws_lambda_function.hub_keygen[0].runtime == "nodejs22.x" &&
      aws_lambda_function.hub_keygen[0].reserved_concurrent_executions == 1 &&
      aws_ssm_parameter.hub_public_key[0].name == "/sandbox/nhp/control/hub/identity/public-key" &&
      aws_ssm_parameter.hub_public_key[0].type == "String"
    )
    error_message = "Hub identity publication must use the exact public-only parameter and a singleton Node 22 keygen."
  }

  assert {
    condition = (
      aws_lambda_invocation.hub_keygen[0].lifecycle_scope == "CREATE_ONLY" &&
      aws_lambda_invocation.hub_keygen[0].input == "{}" &&
      aws_lambda_invocation.hub_identity_publication[0].lifecycle_scope == "CREATE_ONLY" &&
      aws_lambda_invocation.hub_identity_publication[0].input == "{}" &&
      length(coalesce(aws_lambda_invocation.hub_keygen[0].triggers, {})) == 0 &&
      length(coalesce(aws_lambda_invocation.hub_identity_publication[0].triggers, {})) == 0
    )
    error_message = "The live-compatible keygen and additive publication migration must remain empty, triggerless CREATE_ONLY invocations."
  }
}

run "hub_worker_requires_edge_and_runtime_fails_closed" {
  command = plan

  # The worker gate is on but the public edge is dark: the foundation contract
  # precondition must reject the plan. The digest pin is still resolved so the
  # ONLY failing checkable object is the foundation contract precondition.
  variables {
    hub_edge_enabled                    = false
    authority_runtime_functions_enabled = true
    hub_worker_enabled                  = true
  }

  override_data {
    target          = data.aws_ssm_parameter.hub_image_digest[0]
    override_during = plan
    values = {
      value = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
    }
  }

  expect_failures = [
    terraform_data.foundation_contract,
  ]
}
