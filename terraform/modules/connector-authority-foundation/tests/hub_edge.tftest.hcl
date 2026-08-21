# Plan-only tests for the Connector Hub public UDP edge slice (Step 5, slice
# 5a). They prove the dark-first gate creates ZERO public-edge resources while
# off, and that flipping it opens EXACTLY the caller-facing public UDP-443
# edge -- three public subnets, one internet gateway, one public route table
# carrying a single 0.0.0.0/0 default route, and one internet-facing network
# NLB + UDP listener + IP target group -- without weakening the isolated
# workload subnets. The provider mock / bound-contract preamble mirrors
# authority_runtime.tftest.hcl so the whole module plans; the Hub edge is
# independent of the authority runtime gate, which stays off here.

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

run "hub_edge_dark_creates_nothing" {
  command = plan

  variables {
    hub_edge_enabled = false
  }

  assert {
    condition = (
      length(aws_subnet.hub_public) == 0 &&
      length(aws_internet_gateway.hub_edge) == 0 &&
      length(aws_route_table.hub_public) == 0 &&
      length(aws_route.hub_public_default) == 0 &&
      length(aws_route_table_association.hub_public) == 0 &&
      length(aws_security_group.hub_nlb) == 0 &&
      length(aws_vpc_security_group_ingress_rule.hub_nlb_udp) == 0 &&
      length(aws_lb.hub) == 0 &&
      length(aws_lb_target_group.hub) == 0 &&
      length(aws_lb_listener.hub) == 0 &&
      length(aws_ssm_parameter.hub_udp_listener_arn) == 0
    )
    error_message = "With the Hub edge dark the module must create no public subnet, internet gateway, public route table/route/association, NLB, target group, listener, or listener-ARN parameter."
  }

  assert {
    condition     = length(aws_route_table.isolated) == 3
    error_message = "The three isolated workload route tables must be untouched while the Hub edge is dark."
  }
}

run "hub_edge_enabled_without_source_fence_fails_closed" {
  command = plan

  variables {
    hub_edge_enabled             = true
    hub_public_udp_ingress_cidrs = null
  }

  expect_failures = [terraform_data.foundation_contract]
}

# Sandbox runs an open edge (qurl-go ADR 0001). Exactly ["0.0.0.0/0"] is the one
# broad value the module accepts, so opening an edge stays a greppable act.
run "hub_edge_accepts_the_exact_open_value" {
  command = plan

  variables {
    hub_edge_enabled             = true
    hub_public_udp_ingress_cidrs = ["0.0.0.0/0"]
  }

  assert {
    condition = (
      length(aws_vpc_security_group_ingress_rule.hub_nlb_udp) == 1 &&
      aws_vpc_security_group_ingress_rule.hub_nlb_udp["0.0.0.0/0"].cidr_ipv4 == "0.0.0.0/0" &&
      aws_vpc_security_group_ingress_rule.hub_nlb_udp["0.0.0.0/0"].ip_protocol == "udp" &&
      aws_vpc_security_group_ingress_rule.hub_nlb_udp["0.0.0.0/0"].from_port == 443 &&
      aws_vpc_security_group_ingress_rule.hub_nlb_udp["0.0.0.0/0"].to_port == 443
    )
    error_message = "The exact open value must produce one UDP-443 ingress rule admitting 0.0.0.0/0."
  }
}

# A near-miss broad CIDR is still rejected: only the exact open literal passes,
# so a fat-fingered supernet cannot quietly widen an edge.
run "hub_edge_rejects_broad_cidrs_other_than_the_open_value" {
  command = plan

  variables {
    hub_edge_enabled             = true
    hub_public_udp_ingress_cidrs = ["10.0.0.0/8"]
  }

  expect_failures = [var.hub_public_udp_ingress_cidrs]
}

run "hub_edge_rejects_a_half_open_supernet" {
  command = plan

  variables {
    hub_edge_enabled             = true
    hub_public_udp_ingress_cidrs = ["0.0.0.0/1"]
  }

  expect_failures = [var.hub_public_udp_ingress_cidrs]
}

# Mixing the open value with anything else is rejected: an open edge is open,
# and a list that pretends otherwise would be misleading in review.
run "hub_edge_rejects_the_open_value_mixed_with_a_fence" {
  command = plan

  variables {
    hub_edge_enabled             = true
    hub_public_udp_ingress_cidrs = ["0.0.0.0/0", "3.141.109.76/32"]
  }

  expect_failures = [var.hub_public_udp_ingress_cidrs]
}

run "hub_edge_on_opens_only_the_public_udp_edge" {
  command = plan

  variables {
    hub_edge_enabled             = true
    hub_public_udp_ingress_cidrs = ["3.141.109.76/32"]
  }

  assert {
    condition = (
      length(aws_subnet.hub_public) == 3 &&
      length(aws_internet_gateway.hub_edge) == 1 &&
      length(aws_route_table.hub_public) == 1 &&
      length(aws_route.hub_public_default) == 1 &&
      aws_route.hub_public_default[0].destination_cidr_block == "0.0.0.0/0" &&
      length(aws_security_group.hub_nlb) == 1 &&
      length(aws_vpc_security_group_ingress_rule.hub_nlb_udp) == 1 &&
      aws_vpc_security_group_ingress_rule.hub_nlb_udp["3.141.109.76/32"].cidr_ipv4 == "3.141.109.76/32" &&
      aws_vpc_security_group_ingress_rule.hub_nlb_udp["3.141.109.76/32"].ip_protocol == "udp" &&
      aws_vpc_security_group_ingress_rule.hub_nlb_udp["3.141.109.76/32"].from_port == 443 &&
      aws_vpc_security_group_ingress_rule.hub_nlb_udp["3.141.109.76/32"].to_port == 443 &&
      length(aws_lb.hub) == 1 &&
      aws_lb.hub[0].internal == false &&
      aws_lb.hub[0].load_balancer_type == "network" &&
      length(aws_lb.hub[0].security_groups) == 1 &&
      aws_lb.hub[0].name == "layerv-nhp-sandbox-hub-edge" &&
      length(aws_lb_listener.hub) == 1 &&
      aws_lb_listener.hub[0].port == 443 &&
      aws_lb_listener.hub[0].protocol == "UDP" &&
      aws_lb_target_group.hub[0].target_type == "ip" &&
      aws_lb_target_group.hub[0].port == 62206
    )
    error_message = "Enabling the Hub edge must open exactly the proof-/32-fenced public UDP-443 edge (translating to UDP-62206 targets) with its NLB security group attached at creation."
  }

  assert {
    # The public edge never weakens the isolated workload subnets: their three
    # route tables remain, and the module declares no aws_route resource on
    # them -- the sole route resource is aws_route.hub_public_default, on the
    # public edge table (inline isolated-table routes are lexically forbidden).
    condition = (
      length(aws_route_table.isolated) == 3 &&
      length(aws_route.hub_public_default) == 1
    )
    error_message = "The three isolated workload route tables must remain and carry no route resource; the only module route is the public-edge default route."
  }
}
