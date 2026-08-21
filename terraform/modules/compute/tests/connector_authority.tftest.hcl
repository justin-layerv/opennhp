mock_provider "aws" {
  mock_data "aws_region" {
    defaults = { region = "us-east-2" }
  }
  mock_data "aws_caller_identity" {
    defaults = { account_id = "767397897469" }
  }
  mock_data "aws_secretsmanager_secret_version" {
    defaults = {
      secret_string = jsonencode({
        privateKey  = "fixture-private"
        publicKey   = "fixture-public"
        hostname    = "fixture"
        environment = "sandbox"
      })
    }
  }
}

mock_provider "archive" {}
mock_provider "time" {}

override_resource {
  target          = aws_iam_role.server
  override_during = plan
  values = {
    id  = "layerv-nhp-sandbox-server"
    arn = "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-server"
  }
}

override_resource {
  target          = aws_security_group.server
  override_during = plan
  values = {
    id = "sg-server000000000"
  }
}

override_resource {
  target          = aws_security_group.connector_authority_lambda_endpoint
  override_during = plan
  values = {
    id = "sg-vpce0000000000"
  }
}

override_resource {
  target          = aws_vpc_endpoint.connector_authority_lambda
  override_during = plan
  values = {
    id = "vpce-00000000000000001"
  }
}

variables {
  environment                  = "sandbox"
  cell_id                      = "cell0"
  server_ami_id                = "ami-00000000000000001"
  domain_name                  = "nhp.layerv.xyz"
  multi_tenant                 = true
  min_capacity                 = 1
  max_capacity                 = 2
  vpc_id                       = "vpc-00000000000000001"
  vpc_cidr                     = "10.100.0.0/16"
  public_subnet_ids            = ["subnet-public-a", "subnet-public-b"]
  private_subnet_ids           = ["subnet-private-a", "subnet-private-b"]
  server_repo_url              = "767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/nhp-server"
  server_repo_arn              = "arn:aws:ecr:us-east-2:767397897469:repository/layerv/nhp-server"
  namespace_id                 = "ns-fixture"
  namespace_name               = "sandbox.internal"
  name_prefix                  = "layerv-nhp-sandbox"
  logs_kms_key_arn             = "arn:aws:kms:us-east-2:767397897469:key/00000000-0000-0000-0000-000000000001"
  nhp_internal_auth_secret_arn = "arn:aws:secretsmanager:us-east-2:767397897469:secret:nhp-internal-auth-ABCDEF"
  http_timeouts_ms             = { idle = 36000, read = 10000, write = 29000 }
  plugin_bucket_name           = "layerv-sandbox-plugins"
  plugin_download_policy_arn   = "arn:aws:iam::767397897469:policy/layerv-sandbox-plugin-download"

  connector_authority_cell_config = {
    environment                            = "sandbox"
    aws_account_id                         = "767397897469"
    aws_region                             = "us-east-2"
    issue_registration_otp_alias_arn       = "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-iro-cell0:blue"
    activate_registration_alias_arn        = "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-ar-cell0:blue"
    complete_registration_alias_arn        = "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-cr-cell0:blue"
    complete_credential_recovery_alias_arn = "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-ccr-cell0:blue"
    resolve_connector_resource_alias_arn   = "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-creso-cell0:blue"
    authority_lambda_timeout               = "3s"
    handler_budget                         = "3200ms"
    packet_budget                          = "3900ms"
    response_reserve                       = "700ms"
    write_budget                           = "137ms"
  }
}

run "complete_cell_graph_uses_one_exact_private_endpoint" {
  command = plan

  assert {
    condition = (
      length(aws_vpc_endpoint.connector_authority_lambda) == 1 &&
      aws_vpc_endpoint.connector_authority_lambda[0].private_dns_enabled &&
      aws_vpc_endpoint.connector_authority_lambda[0].service_name == "com.amazonaws.us-east-2.lambda" &&
      toset(aws_vpc_endpoint.connector_authority_lambda[0].subnet_ids) == toset(var.private_subnet_ids) &&
      toset(aws_vpc_endpoint.connector_authority_lambda[0].security_group_ids) == toset([aws_security_group.connector_authority_lambda_endpoint[0].id]) &&
      length(aws_security_group.connector_authority_lambda_endpoint) == 1 &&
      length(aws_vpc_security_group_ingress_rule.connector_authority_lambda_endpoint) == 1 &&
      aws_vpc_security_group_ingress_rule.connector_authority_lambda_endpoint[0].security_group_id == aws_security_group.connector_authority_lambda_endpoint[0].id &&
      aws_vpc_security_group_ingress_rule.connector_authority_lambda_endpoint[0].referenced_security_group_id == aws_security_group.server.id &&
      aws_vpc_security_group_ingress_rule.connector_authority_lambda_endpoint[0].from_port == 443 &&
      aws_vpc_security_group_ingress_rule.connector_authority_lambda_endpoint[0].to_port == 443 &&
      aws_vpc_security_group_ingress_rule.connector_authority_lambda_endpoint[0].ip_protocol == "tcp"
    )
    error_message = "The assigned cell must use one private-DNS Lambda endpoint in the private subnets with one exact server-SG TLS ingress."
  }

  assert {
    condition = (
      toset(jsondecode(aws_vpc_endpoint.connector_authority_lambda[0].policy).Statement[0].Resource) == toset(local.connector_authority_cell_alias_arns) &&
      jsondecode(aws_vpc_endpoint.connector_authority_lambda[0].policy).Statement[0].Principal == "*" &&
      jsondecode(aws_vpc_endpoint.connector_authority_lambda[0].policy).Statement[0].Condition.StringEquals["aws:PrincipalArn"] == [aws_iam_role.server.arn] &&
      toset(jsondecode(aws_iam_role_policy.server_connector_authority[0].policy).Statement[0].Resource) == toset(local.connector_authority_cell_alias_arns) &&
      jsondecode(aws_iam_role_policy.server_connector_authority[0].policy).Statement[0].Condition.StringEquals["aws:SourceVpce"] == aws_vpc_endpoint.connector_authority_lambda[0].id
    )
    error_message = "Endpoint and role policies must agree on the exact five aliases, cell role, and VPC endpoint."
  }

  assert {
    condition = alltrue([
      for expected in [
        "NHP_CONNECTOR_REGISTRATION_AWS_REGION=$${connector_authority_cell_config.aws_region}",
        "NHP_CONNECTOR_REGISTRATION_AWS_ACCOUNT_ID=$${connector_authority_cell_config.aws_account_id}",
        "NHP_CONNECTOR_REGISTRATION_ISSUE_OTP_ALIAS_ARN=$${connector_authority_cell_config.issue_registration_otp_alias_arn}",
        "NHP_CONNECTOR_REGISTRATION_ACTIVATE_ALIAS_ARN=$${connector_authority_cell_config.activate_registration_alias_arn}",
        "NHP_CONNECTOR_REGISTRATION_COMPLETE_ALIAS_ARN=$${connector_authority_cell_config.complete_registration_alias_arn}",
        "NHP_CONNECTOR_REGISTRATION_AUTHORITY_LAMBDA_TIMEOUT=$${connector_authority_cell_config.authority_lambda_timeout}",
        "NHP_CONNECTOR_REGISTRATION_HANDLER_BUDGET=$${connector_authority_cell_config.handler_budget}",
        "NHP_CONNECTOR_REGISTRATION_PACKET_BUDGET=$${connector_authority_cell_config.packet_budget}",
        "NHP_CONNECTOR_REGISTRATION_RESPONSE_RESERVE=$${connector_authority_cell_config.response_reserve}",
        "NHP_CONNECTOR_REGISTRATION_WRITE_BUDGET=$${connector_authority_cell_config.write_budget}",
        "NHP_CONNECTOR_CREDENTIAL_RECOVERY_AWS_REGION=$${connector_authority_cell_config.aws_region}",
        "NHP_CONNECTOR_CREDENTIAL_RECOVERY_AWS_ACCOUNT_ID=$${connector_authority_cell_config.aws_account_id}",
        "NHP_CONNECTOR_CREDENTIAL_RECOVERY_ALIAS_ARN=$${connector_authority_cell_config.complete_credential_recovery_alias_arn}",
        "NHP_CONNECTOR_RESOURCE_AWS_REGION=$${connector_authority_cell_config.aws_region}",
        "NHP_CONNECTOR_RESOURCE_AWS_ACCOUNT_ID=$${connector_authority_cell_config.aws_account_id}",
        "NHP_CONNECTOR_RESOURCE_ALIAS_ARN=$${connector_authority_cell_config.resolve_connector_resource_alias_arn}",
      ] : strcontains(file("${path.module}/user_data.sh.tpl"), expected)
    ])
    error_message = "The NHP init template must render the complete Authority graph and receipt budgets."
  }

  assert {
    condition = (
      local.connector_authority_resource_enabled &&
      strcontains(
        file("${path.module}/user_data.sh.tpl"),
        "%%{ if connector_authority_cell_config.resolve_connector_resource_alias_arn != null ~}",
      )
    )
    error_message = "The complete graph must enable creso and the template must guard its environment on that exact alias."
  }
}

run "four_operation_rollout_predecessor_is_byte_compatible" {
  command = plan

  variables {
    connector_authority_cell_config = merge(
      var.connector_authority_cell_config,
      { resolve_connector_resource_alias_arn = null },
    )
  }

  assert {
    condition = (
      local.connector_authority_cell_alias_arns == sort([
        var.connector_authority_cell_config.issue_registration_otp_alias_arn,
        var.connector_authority_cell_config.activate_registration_alias_arn,
        var.connector_authority_cell_config.complete_registration_alias_arn,
        var.connector_authority_cell_config.complete_credential_recovery_alias_arn,
      ]) &&
      toset(jsondecode(aws_vpc_endpoint.connector_authority_lambda[0].policy).Statement[0].Resource) == toset(local.connector_authority_cell_alias_arns) &&
      toset(jsondecode(aws_iam_role_policy.server_connector_authority[0].policy).Statement[0].Resource) == toset(local.connector_authority_cell_alias_arns)
    )
    error_message = "The rollout predecessor must preserve exactly the four applied aliases and no creso invoke reachability."
  }

  assert {
    condition = (
      !local.connector_authority_resource_enabled &&
      strcontains(
        file("${path.module}/user_data.sh.tpl"),
        "%%{ if connector_authority_cell_config.resolve_connector_resource_alias_arn != null ~}",
      )
    )
    error_message = "The rollout predecessor must disable connector-resource and keep its environment behind the exact alias-presence guard."
  }
}

run "null_graph_stays_dark" {
  command = plan

  variables {
    connector_authority_cell_config = null
  }

  assert {
    condition = (
      length(aws_vpc_endpoint.connector_authority_lambda) == 0 &&
      length(aws_iam_role_policy.server_connector_authority) == 0 &&
      length(aws_security_group.connector_authority_lambda_endpoint) == 0
    )
    error_message = "A null graph must create no caller reachability and render no Authority variables."
  }
}

run "mixed_alias_color_fails_closed" {
  command = plan

  variables {
    connector_authority_cell_config = merge(
      var.connector_authority_cell_config,
      {
        complete_registration_alias_arn = "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-cr-cell0:green"
      },
    )
  }

  expect_failures = [terraform_data.connector_authority_cell_contract]
}

run "cross_environment_graph_fails_closed" {
  command = plan

  variables {
    connector_authority_cell_config = {
      environment                            = "prod"
      aws_account_id                         = "767397897469"
      aws_region                             = "us-east-2"
      issue_registration_otp_alias_arn       = "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-prod-ca-iro-cell0:blue"
      activate_registration_alias_arn        = "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-prod-ca-ar-cell0:blue"
      complete_registration_alias_arn        = "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-prod-ca-cr-cell0:blue"
      complete_credential_recovery_alias_arn = "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-prod-ca-ccr-cell0:blue"
      resolve_connector_resource_alias_arn   = "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-prod-ca-creso-cell0:blue"
      authority_lambda_timeout               = "3s"
      handler_budget                         = "3200ms"
      packet_budget                          = "3900ms"
      response_reserve                       = "700ms"
      write_budget                           = "137ms"
    }
  }

  expect_failures = [terraform_data.connector_authority_cell_contract]
}

run "sandbox_graph_in_prod_account_fails_closed" {
  command = plan

  override_data {
    target = data.aws_caller_identity.current
    values = { account_id = "235500187906" }
  }

  variables {
    connector_authority_cell_config = {
      environment                            = "sandbox"
      aws_account_id                         = "235500187906"
      aws_region                             = "us-east-2"
      issue_registration_otp_alias_arn       = "arn:aws:lambda:us-east-2:235500187906:function:layerv-nhp-sandbox-ca-iro-cell0:blue"
      activate_registration_alias_arn        = "arn:aws:lambda:us-east-2:235500187906:function:layerv-nhp-sandbox-ca-ar-cell0:blue"
      complete_registration_alias_arn        = "arn:aws:lambda:us-east-2:235500187906:function:layerv-nhp-sandbox-ca-cr-cell0:blue"
      complete_credential_recovery_alias_arn = "arn:aws:lambda:us-east-2:235500187906:function:layerv-nhp-sandbox-ca-ccr-cell0:blue"
      resolve_connector_resource_alias_arn   = "arn:aws:lambda:us-east-2:235500187906:function:layerv-nhp-sandbox-ca-creso-cell0:blue"
      authority_lambda_timeout               = "3s"
      handler_budget                         = "3200ms"
      packet_budget                          = "3900ms"
      response_reserve                       = "700ms"
      write_budget                           = "137ms"
    }
  }

  expect_failures = [terraform_data.connector_authority_cell_contract]
}

run "non_home_region_graph_fails_closed" {
  command = plan

  override_data {
    target = data.aws_region.current
    values = { region = "us-west-2" }
  }

  variables {
    connector_authority_cell_config = {
      environment                            = "sandbox"
      aws_account_id                         = "767397897469"
      aws_region                             = "us-west-2"
      issue_registration_otp_alias_arn       = "arn:aws:lambda:us-west-2:767397897469:function:layerv-nhp-sandbox-ca-iro-cell0:blue"
      activate_registration_alias_arn        = "arn:aws:lambda:us-west-2:767397897469:function:layerv-nhp-sandbox-ca-ar-cell0:blue"
      complete_registration_alias_arn        = "arn:aws:lambda:us-west-2:767397897469:function:layerv-nhp-sandbox-ca-cr-cell0:blue"
      complete_credential_recovery_alias_arn = "arn:aws:lambda:us-west-2:767397897469:function:layerv-nhp-sandbox-ca-ccr-cell0:blue"
      resolve_connector_resource_alias_arn   = "arn:aws:lambda:us-west-2:767397897469:function:layerv-nhp-sandbox-ca-creso-cell0:blue"
      authority_lambda_timeout               = "3s"
      handler_budget                         = "3200ms"
      packet_budget                          = "3900ms"
      response_reserve                       = "700ms"
      write_budget                           = "137ms"
    }
  }

  expect_failures = [terraform_data.connector_authority_cell_contract]
}

run "receipt_budget_drift_fails_closed" {
  command = plan

  variables {
    connector_authority_cell_config = merge(
      var.connector_authority_cell_config,
      { write_budget = "138ms" },
    )
  }

  expect_failures = [terraform_data.connector_authority_cell_contract]
}
