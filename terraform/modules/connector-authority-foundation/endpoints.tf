locals {
  interface_endpoint_services = {
    email          = "email"
    kms            = "kms"
    lambda         = "lambda"
    logs           = "logs"
    monitoring     = "monitoring"
    secretsmanager = "secretsmanager"
  }

  # Fail-closed baseline. Every endpoint starts here and stays here until an
  # exact caller/execution principal and its exact resources exist. The runtime
  # slice below replaces this policy ONLY for the dependency endpoints the 3 hub
  # functions provably reach (DynamoDB gateway + KMS interface) and ONLY for the
  # constructed execution-role principals. Merely deploying an endpoint never
  # creates a usable RPC surface.
  deny_all_endpoint_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyUntilAuthorityRuntimeExists"
      Effect    = "Deny"
      Principal = "*"
      Action    = "*"
      Resource  = "*"
    }]
  })

  # DynamoDB gateway endpoint: allow exactly the 3 hub execution roles the union
  # of the exact per-op actions (reads incl. DescribeTable; the replay Put and the
  # recovery Update) on the three canonical BASE tables. Gateway VPC-endpoint
  # policies are TABLE-GRANULAR: DynamoDB rejects a /index/* sub-resource here
  # with InvalidPolicyDocument, and a Query against agent_keys' pubkey GSI is
  # authorized at this coarse network gate by the base-table ARN. So this lists
  # only the base-table ARNs (authority_runtime_table_arns), NOT the identity
  # resource sets. The per-operation identity policies in authority_runtime.tf
  # are the finer intersecting gate: they carry the /index/* grant IAM does
  # accept, and e.g. UpdateItem is reachable only by IssueCredentialRecovery.
  authority_dynamodb_endpoint_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AuthorityFunctionsData"
      Effect = "Allow"
      Principal = {
        AWS = local.authority_runtime_exec_role_arns
      }
      Action = concat(
        local.authority_runtime_ddb_read_actions,
        local.authority_runtime_ddb_recovery_write_actions,
      )
      Resource = [
        for name in ["api_keys", "agent_keys", "connector_authority"] :
        local.authority_runtime_table_arns[name]
      ]
    }]
  })

  # KMS interface endpoint: allow ONLY the IssueAssignment execution role the qat1
  # assignment-ticket key, actions GetPublicKey + Sign. RefreshAssignment and
  # IssueCredentialRecovery build no KMS client, and no op uses kms:Verify
  # (verification is local p256), so both are excluded from principal and action.
  authority_kms_endpoint_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AuthorityFunctionsQat1"
      Effect = "Allow"
      Principal = {
        AWS = local.authority_runtime_sign_role_arns
      }
      Action   = ["kms:GetPublicKey", "kms:Sign"]
      Resource = [aws_kms_key.qat1_signing.arn]
    }]
  })

  # Per-service interface-endpoint policy. Only KMS opens in this slice; every
  # other interface endpoint (email, lambda [caller-only, dark until the Hub
  # role exists], logs, monitoring, secretsmanager) stays deny-all.
  interface_endpoint_policies = {
    for service in keys(local.interface_endpoint_services) :
    service => (
      local.authority_runtime_functions_deploy && service == "kms"
      ? local.authority_kms_endpoint_policy
      : local.deny_all_endpoint_policy
    )
  }

  dynamodb_endpoint_policy = (
    local.authority_runtime_functions_deploy
    ? local.authority_dynamodb_endpoint_policy
    : local.deny_all_endpoint_policy
  )

  # Interface-endpoint SG ingress: dark (empty) until the runtime slice adds
  # exactly TLS/443 from the Connector Authority function SG. The OTP Redis SG
  # stays no-ingress in this slice: no Hub-facing operation touches Redis (that
  # is the out-of-scope cell issuer/activator path).
  interface_endpoint_ingress = local.authority_runtime_functions_deploy ? [
    {
      description      = "HTTPS from Connector Authority function ENIs"
      from_port        = 443
      to_port          = 443
      protocol         = "tcp"
      security_groups  = [aws_security_group.authority_lambda[0].id]
      cidr_blocks      = []
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      self             = false
    },
  ] : []
}

resource "aws_security_group" "interface_endpoints" {
  name_prefix = "${local.name_prefix}-vpce-"
  description = "Dark Connector Authority endpoints; runtime adds exact caller ingress"
  vpc_id      = aws_vpc.control.id

  # Inert until the runtime slice adds SG-to-SG 443 ingress from the function SG
  # alongside the scoped KMS endpoint policy.
  ingress = local.interface_endpoint_ingress
  egress  = []

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-vpce"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_endpoint" "interface" {
  for_each = local.interface_endpoint_services

  vpc_id              = aws_vpc.control.id
  service_name        = "com.amazonaws.${data.aws_region.current.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = aws_subnet.isolated[*].id
  security_group_ids  = [aws_security_group.interface_endpoints.id]
  policy              = local.interface_endpoint_policies[each.key]

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-vpce-${each.key}"
    Service = each.key
  })
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.control.id
  service_name      = "com.amazonaws.${data.aws_region.current.region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = aws_route_table.isolated[*].id
  policy            = local.dynamodb_endpoint_policy

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-vpce-dynamodb"
    Service = "dynamodb"
  })
}
