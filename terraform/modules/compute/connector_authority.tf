locals {
  connector_authority_cell_enabled = var.connector_authority_cell_config != null
  # The Authority runtime enforces this same closed deployment map at cold
  # start. Mirror it at the caller boundary so a cell can never acquire invoke
  # reachability to a correctly named graph in the wrong LayerV account.
  connector_authority_account_by_environment = {
    sandbox = "767397897469"
    prod    = "235500187906"
  }
  connector_authority_home_region = "us-east-2"
  # Blue/green color qualifier carried on every cell alias ARN (the 8th
  # ':'-segment); the fail-closed contract below asserts it is a real color and
  # that every enabled operation alias shares it.
  connector_authority_cell_alias_color = local.connector_authority_cell_enabled ? try(split(":", var.connector_authority_cell_config.issue_registration_otp_alias_arn)[7], "") : ""
  connector_authority_resource_enabled = local.connector_authority_cell_enabled && var.connector_authority_cell_config.resolve_connector_resource_alias_arn != null
  connector_authority_cell_alias_arns = local.connector_authority_cell_enabled ? sort(concat([
    var.connector_authority_cell_config.issue_registration_otp_alias_arn,
    var.connector_authority_cell_config.activate_registration_alias_arn,
    var.connector_authority_cell_config.complete_registration_alias_arn,
    var.connector_authority_cell_config.complete_credential_recovery_alias_arn,
    ], local.connector_authority_resource_enabled ? [
    var.connector_authority_cell_config.resolve_connector_resource_alias_arn,
  ] : [])) : []
  connector_authority_cell_expected_alias_arns = local.connector_authority_cell_enabled ? sort([
    for suffix in concat(["iro", "ar", "cr", "ccr"], local.connector_authority_resource_enabled ? ["creso"] : []) :
    "arn:aws:lambda:${var.connector_authority_cell_config.aws_region}:${var.connector_authority_cell_config.aws_account_id}:function:layerv-nhp-${var.connector_authority_cell_config.environment}-ca-${suffix}-${var.cell_id}:${local.connector_authority_cell_alias_color}"
  ]) : []
  # Keep the candidate principal plan-known. Referencing the ARN attribute of
  # the new IAM role would make the saved-plan endpoint policy unknown and
  # prevent the pre-apply checker from validating the sole admitted update.
  matched_cohort_candidate_server_role_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.name_prefix}-server-candidate"
}

# One fail-closed boundary owns the caller graph. The exact four-operation
# predecessor exists only so a root plan remains valid before Control's first
# creso apply; it renders the same user data and IAM as the already-running
# servers. Once Control publishes creso, the only admitted shape is the complete
# five-operation graph. Any other partial config, wrong cell/environment,
# unqualified target, or mixed alias color cannot create IAM or reachability.
resource "terraform_data" "connector_authority_cell_contract" {
  count = local.connector_authority_cell_enabled ? 1 : 0

  input = {
    cell_id     = var.cell_id
    environment = var.connector_authority_cell_config.environment
    aliases     = local.connector_authority_cell_alias_arns
  }

  lifecycle {
    precondition {
      condition = (
        contains(["sandbox", "prod"], var.connector_authority_cell_config.environment) &&
        # Compare against the PROTOCOL environment, not the infrastructure
        # namespace. var.environment is the namespace ("sandbox",
        # "sandbox-cell1", ...); the Connector Authority is Control-global and
        # keyed by the protocol environment ("sandbox"/"prod"). On cell1 those
        # differ by design -- protocol_environment's own description says a
        # secondary cell "sets sandbox while retaining a distinct infrastructure
        # namespace" -- so `== var.environment` fails every sandbox-cell1 apply
        # with "sandbox" != "sandbox-cell1" and blocks the whole deploy.
        var.connector_authority_cell_config.environment == local.protocol_environment &&
        lookup(
          local.connector_authority_account_by_environment,
          var.connector_authority_cell_config.environment,
          "",
        ) == var.connector_authority_cell_config.aws_account_id &&
        var.connector_authority_cell_config.aws_account_id == data.aws_caller_identity.current.account_id &&
        var.connector_authority_cell_config.aws_region == local.connector_authority_home_region &&
        var.connector_authority_cell_config.aws_region == data.aws_region.current.region &&
        contains(["blue", "green"], local.connector_authority_cell_alias_color) &&
        local.connector_authority_cell_alias_arns == local.connector_authority_cell_expected_alias_arns
      )
      error_message = "connector_authority_cell_config must be the exact same-color 4-operation rollout predecessor or complete 5-operation graph for this environment, account, region, and cell."
    }
    precondition {
      condition = (
        var.connector_authority_cell_config.authority_lambda_timeout == "3s" &&
        var.connector_authority_cell_config.handler_budget == "3200ms" &&
        var.connector_authority_cell_config.packet_budget == "3900ms" &&
        var.connector_authority_cell_config.response_reserve == "700ms" &&
        var.connector_authority_cell_config.write_budget == "137ms"
      )
      error_message = "connector_authority_cell_config receipt budgets must equal the reviewed sandbox measurement candidate; revise all five together with timing evidence."
    }
  }
}

resource "aws_security_group" "connector_authority_lambda_endpoint" {
  count = local.connector_authority_cell_enabled ? 1 : 0

  name_prefix = "${var.name_prefix}-ca-lambda-vpce-"
  description = "Private Lambda Invoke endpoint for this NHP cell server"
  vpc_id      = var.vpc_id

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ca-lambda-vpce"
    Component = "compute"
    Cell      = var.cell_id
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "connector_authority_lambda_endpoint" {
  count = local.connector_authority_cell_enabled ? 1 : 0

  security_group_id            = aws_security_group.connector_authority_lambda_endpoint[0].id
  referenced_security_group_id = aws_security_group.server.id
  # No apostrophe: AWS restricts rule descriptions to
  # a-zA-Z0-9 and ._-:/()#,@[]+=&;{}!$* plus spaces, and rejects the whole
  # AuthorizeSecurityGroupIngress call otherwise.
  description = "HTTPS from the NHP server in this cell"
  from_port   = 443
  to_port     = 443
  ip_protocol = "tcp"
}

resource "aws_vpc_endpoint" "connector_authority_lambda" {
  count = local.connector_authority_cell_enabled ? 1 : 0

  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${data.aws_region.current.region}.lambda"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.connector_authority_lambda_endpoint[0].id]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "CellServerInvokeConnectorAuthority"
      Effect    = "Allow"
      Principal = "*"
      Action    = "lambda:InvokeFunction"
      Resource  = local.connector_authority_cell_alias_arns
      Condition = {
        StringEquals = {
          "aws:PrincipalArn" = sort(compact([
            aws_iam_role.server.arn,
            var.enable_matched_cohort_canary ? local.matched_cohort_candidate_server_role_arn : "",
          ]))
        }
      }
    }]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-vpce-ca-lambda"
    Component = "compute"
    Cell      = var.cell_id
  })

  depends_on = [terraform_data.connector_authority_cell_contract]
}

resource "aws_iam_role_policy" "server_connector_authority" {
  count = local.connector_authority_cell_enabled ? 1 : 0

  name = "connector-authority-cell-invoke"
  role = aws_iam_role.server.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "InvokeAssignedCellAuthority"
      Effect   = "Allow"
      Action   = "lambda:InvokeFunction"
      Resource = local.connector_authority_cell_alias_arns
      Condition = {
        StringEquals = {
          "aws:SourceVpce" = aws_vpc_endpoint.connector_authority_lambda[0].id
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "server_candidate_connector_authority" {
  count = local.connector_authority_cell_enabled && var.enable_matched_cohort_canary ? 1 : 0

  name = "connector-authority-cell-invoke"
  role = aws_iam_role.server_candidate[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "InvokeAssignedCellAuthority"
      Effect   = "Allow"
      Action   = "lambda:InvokeFunction"
      Resource = local.connector_authority_cell_alias_arns
      Condition = {
        StringEquals = {
          "aws:SourceVpce" = aws_vpc_endpoint.connector_authority_lambda[0].id
        }
      }
    }]
  })
}
