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
      # A VPC endpoint policy does NOT match an assumed-role session against an
      # IAM role-ARN (or account-root) Principal: a role-ARN Principal here
      # silently denies every hub function with "no VPC endpoint policy allows
      # the dynamodb:* action" even though the identity policy grants it. Scope
      # with Principal "*" + an aws:PrincipalArn condition instead. Verified in
      # sandbox: the role-ARN form denied DescribeTable at cold start ->
      # control_sse_invalid; this form passes. The condition keeps the network
      # grant to exactly the constructed execution roles (fail-closed intact).
      Principal = "*"
      Action = concat(
        local.authority_runtime_ddb_read_actions,
        local.authority_runtime_ddb_recovery_write_actions,
      )
      Resource = [
        for name in ["api_keys", "agent_keys", "connector_authority"] :
        local.authority_runtime_table_arns[name]
      ]
      Condition = {
        StringEquals = {
          "aws:PrincipalArn" = local.authority_runtime_exec_role_arns
        }
      }
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
      # Same VPC-endpoint principal-matching constraint as the DynamoDB gateway
      # above: scope with Principal "*" + aws:PrincipalArn, not a role-ARN
      # Principal, or IssueAssignment's cold-start kms:Sign is denied here.
      Principal = "*"
      Action    = ["kms:GetPublicKey", "kms:Sign"]
      Resource  = [aws_kms_key.qat1_signing.arn]
      Condition = {
        StringEquals = {
          "aws:PrincipalArn" = local.authority_runtime_sign_role_arns
        }
      }
    }]
  })

  # Lambda interface endpoint: the CALLER path, opened by slice 5b only. It admits
  # the Hub task role (and no one else) to InvokeFunction on exactly the three
  # sorted :color Authority alias ARNs. Same VPC-endpoint principal-matching
  # constraint as the KMS/DynamoDB gates above: scope with Principal "*" +
  # aws:PrincipalArn, never a role-ARN Principal, or the Hub task's assumed-role
  # session is silently denied here. Resolves to an empty Resource list while the
  # worker is dark (never selected in that case -- lambda stays deny-all).
  hub_lambda_endpoint_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "HubWorkersInvokeAuthority"
      Effect    = "Allow"
      Principal = "*"
      Action    = "lambda:InvokeFunction"
      Resource  = local.hub_authority_alias_arns
      Condition = {
        StringEquals = {
          "aws:PrincipalArn" = [local.hub_task_role_arn]
        }
      }
    }]
  })

  # ECR interface endpoints (ecr.api + ecr.dkr, share this policy): the Fargate
  # EXECUTION role (agent identity), and only it, may pull the Hub image and
  # fetch an auth token. GetAuthorizationToken is unavoidably Resource "*" (it is
  # a registry-wide action); the repository-scoped pull actions are pinned to the
  # single Hub repository ARN. Same Principal "*" + aws:PrincipalArn scoping.
  hub_ecr_endpoint_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "HubPullImage"
        Effect    = "Allow"
        Principal = "*"
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability",
        ]
        Resource = [aws_ecr_repository.hub.arn]
        Condition = {
          StringEquals = {
            "aws:PrincipalArn" = [local.hub_execution_role_arn]
          }
        }
      },
      {
        Sid       = "HubAuthToken"
        Effect    = "Allow"
        Principal = "*"
        Action    = "ecr:GetAuthorizationToken"
        Resource  = "*"
        Condition = {
          StringEquals = {
            "aws:PrincipalArn" = [local.hub_execution_role_arn]
          }
        }
      },
    ]
  })

  # S3 gateway endpoint: the execution role may GET only from the region's
  # managed ECR layer bucket (where image layer blobs actually live). No other S3
  # reach is granted. Same Principal "*" + aws:PrincipalArn scoping.
  hub_s3_endpoint_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "HubPullLayers"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = ["arn:${data.aws_partition.current.partition}:s3:::prod-${data.aws_region.current.region}-starport-layer-bucket/*"]
      Condition = {
        StringEquals = {
          "aws:PrincipalArn" = [local.hub_execution_role_arn]
        }
      }
    }]
  })

  # Per-service interface-endpoint policy. KMS opens with the authority runtime;
  # the caller (lambda) endpoint opens with the Hub worker (slice 5b). Every
  # other interface endpoint (email, logs, monitoring, secretsmanager) stays
  # deny-all. The ecr.api/ecr.dkr interface endpoints are separate resources
  # (hub_worker.tf) and carry hub_ecr_endpoint_policy directly.
  interface_endpoint_policies = {
    for service in keys(local.interface_endpoint_services) :
    service => (
      local.authority_runtime_functions_deploy && service == "kms" ? local.authority_kms_endpoint_policy
      : local.hub_worker_deploy && service == "lambda" ? local.hub_lambda_endpoint_policy
      : local.deny_all_endpoint_policy
    )
  }

  dynamodb_endpoint_policy = (
    local.authority_runtime_functions_deploy
    ? local.authority_dynamodb_endpoint_policy
    : local.deny_all_endpoint_policy
  )

  # Interface-endpoint SG ingress: ADDITIVE across the two independent callers.
  # The runtime slice adds TLS/443 from the Connector Authority function SG; the
  # Hub worker slice (5b) adds TLS/443 from the Hub worker SG (its egress reaches
  # the lambda/logs/secrets/kms/ecr interface endpoints on this SG). Each rule is
  # present only while its own gate is live, so the SG carries 0, 1, or 2 rules.
  # The OTP Redis SG stays no-ingress in both slices: no Hub-facing operation
  # touches Redis (that is the out-of-scope cell issuer/activator path).
  interface_endpoint_ingress = concat(
    local.authority_runtime_functions_deploy ? [
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
    ] : [],
    local.hub_worker_deploy ? [
      {
        description      = "HTTPS from Hub worker ENIs"
        from_port        = 443
        to_port          = 443
        protocol         = "tcp"
        security_groups  = [aws_security_group.hub_worker[0].id]
        cidr_blocks      = []
        ipv6_cidr_blocks = []
        prefix_list_ids  = []
        self             = false
      },
    ] : [],
  )
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
