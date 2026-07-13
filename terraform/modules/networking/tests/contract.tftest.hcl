mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = {
      names = ["us-east-2a", "us-east-2b", "us-east-2c"]
    }
  }

  mock_data "aws_region" {
    defaults = {
      id     = "us-east-2"
      region = "us-east-2"
    }
  }

  mock_resource "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws:logs:us-east-2:767397897469:log-group:mock"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::767397897469:role/mock"
    }
  }
}

variables {
  environment          = "sandbox"
  vpc_cidr             = "10.100.0.0/16"
  name_prefix          = "layerv-nhp-sandbox"
  logs_kms_key_arn     = "arn:aws:kms:us-east-2:767397897469:key/example"
  deploy_vpc_endpoints = true
  tags                 = { Environment = "sandbox" }
}

run "legacy_private_routes_unchanged_when_disabled" {
  command = apply

  variables {
    enable_extensible_private_route_tables = false
  }

  assert {
    condition = (
      length(aws_route_table.private) == 1 &&
      length(aws_route_table.private_extensible) == 0 &&
      length(aws_route.private_extensible_default) == 0 &&
      length(terraform_data.private_extensible_association_ready) == 0 &&
      toset(output.private_route_table_ids) == toset(aws_route_table.private[*].id) &&
      alltrue([
        for association in aws_route_table_association.private :
        association.route_table_id == aws_route_table.private[0].id
      ])
    )
    error_message = "The disabled path must preserve the legacy sandbox private route table and associations exactly."
  }

  assert {
    condition = (
      toset(aws_vpc_endpoint.s3.route_table_ids) == toset(concat(
        [aws_route_table.public.id],
        aws_route_table.private[*].id,
        [aws_route_table.isolated.id],
      )) &&
      toset(aws_vpc_endpoint.dynamodb[0].route_table_ids) == toset(concat(
        [aws_route_table.public.id],
        aws_route_table.private[*].id,
        [aws_route_table.isolated.id],
      ))
    )
    error_message = "The disabled path must preserve the legacy gateway-endpoint route-table set."
  }
}

run "extensible_private_routes_require_iam_readiness" {
  command = plan

  variables {
    enable_extensible_private_route_tables     = true
    extensible_private_route_table_ready_token = null
  }

  expect_failures = [
    terraform_data.private_extensible_association_ready,
  ]
}

run "extensible_private_routes_own_all_nonlocal_routes" {
  command = apply

  variables {
    enable_extensible_private_route_tables     = true
    extensible_private_route_table_ready_token = "iam-propagated"
  }

  assert {
    condition = (
      length(aws_route_table.private) == 1 &&
      length(aws_route_table.private_extensible) == 1 &&
      length(aws_route_table.private_extensible[0].route) == 0 &&
      length(aws_route.private_extensible_default) == 1 &&
      length(terraform_data.private_extensible_association_ready) == 1 &&
      aws_route.private_extensible_default[0].route_table_id == aws_route_table.private_extensible[0].id &&
      aws_route.private_extensible_default[0].destination_cidr_block == "0.0.0.0/0" &&
      aws_route.private_extensible_default[0].nat_gateway_id == aws_nat_gateway.main[0].id
    )
    error_message = "The extensible table must have no inline routes and exactly one standalone NAT default."
  }

  assert {
    condition = (
      toset(output.private_route_table_ids) == toset(aws_route_table.private_extensible[*].id) &&
      alltrue([
        for association in aws_route_table_association.private :
        association.route_table_id == aws_route_table.private_extensible[0].id
      ])
    )
    error_message = "Private subnets and consumers must select only the active extensible table."
  }

  assert {
    condition = (
      toset(aws_vpc_endpoint.s3.route_table_ids) == toset(concat(
        [aws_route_table.public.id],
        aws_route_table.private[*].id,
        aws_route_table.private_extensible[*].id,
        [aws_route_table.isolated.id],
      )) &&
      toset(aws_vpc_endpoint.dynamodb[0].route_table_ids) == toset(concat(
        [aws_route_table.public.id],
        aws_route_table.private[*].id,
        aws_route_table.private_extensible[*].id,
        [aws_route_table.isolated.id],
      ))
    )
    error_message = "Gateway endpoints must remain attached to rollback tables and also attach to the active extensible table."
  }
}
