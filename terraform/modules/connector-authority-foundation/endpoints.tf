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
  # slice below replaces this policy ONLY for dependencies the complete
  # Authority graph provably reaches and ONLY for the constructed execution-role
  # principals. Merely deploying an endpoint never creates a usable RPC surface.
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

  # DynamoDB gateway endpoint: allow exactly the complete runtime execution-role
  # set the union of the exact per-op actions (reads incl. DescribeTable; replay
  # and registration/recovery writes) on the five canonical BASE tables.
  # Gateway VPC-endpoint
  # policies are TABLE-GRANULAR: DynamoDB rejects a /index/* sub-resource here
  # with InvalidPolicyDocument, and a Query against agent_keys' pubkey GSI is
  # authorized at this coarse network gate by the base-table ARN. So this lists
  # only the base-table ARNs (authority_runtime_table_arns), NOT the identity
  # resource sets. The per-operation identity policies in authority_runtime.tf
  # are the finer intersecting gate: they carry the /index/* grant IAM does
  # accept, and each write is reachable only by the operations that compose it.
  authority_dynamodb_endpoint_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
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
          for name in ["api_keys", "agent_keys", "customers", "api_key_idempotency", "connector_authority"] :
          local.authority_runtime_table_arns[name]
        ]
        Condition = {
          StringEquals = {
            "aws:PrincipalArn" = local.authority_runtime_exec_role_arns
          }
        }
      },
      {
        # Coarse network admission for the two cell-owned tables. The creso
        # identity policies retain the finer per-table action split.
        Sid       = "ConnectorResourceCellData"
        Effect    = "Allow"
        Principal = "*"
        Action = [
          "dynamodb:DeleteItem",
          "dynamodb:DescribeTable",
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
        ]
        Resource = sort(flatten([
          for cell in values(local.authority_contract_cells) : [
            cell.qurl_resources_table_arn,
            cell.qurl_resource_key_material_table_arn,
          ]
        ]))
        Condition = {
          StringEquals = {
            "aws:PrincipalArn" = local.authority_runtime_connector_resource_role_arns
          }
        }
      },
    ]
  })

  # KMS interface endpoint: all three public-key consumers may GetPublicKey;
  # IssueAssignment alone may Sign. No operation uses kms:Verify.
  authority_kms_endpoint_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Sid       = "AuthorityFunctionsQat1PublicKey"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["kms:GetPublicKey"]
        Resource  = [aws_kms_key.qat1_signing.arn]
        Condition = {
          StringEquals = {
            "aws:PrincipalArn" = local.authority_runtime_public_key_role_arns
          }
        }
        },
        {
          Sid       = "IssueAssignmentQat1Sign"
          Effect    = "Allow"
          Principal = "*"
          Action    = ["kms:Sign"]
          Resource  = [aws_kms_key.qat1_signing.arn]
          Condition = {
            StringEquals = {
              "aws:PrincipalArn" = local.authority_runtime_sign_role_arns
            }
          }
        },
      ],
      [for statement in [{
        Sid       = "ConnectorResourceCreateHardwareKey"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["kms:CreateKey"]
        Resource  = "*"
        Condition = {
          StringEquals = {
            "aws:PrincipalArn"       = local.authority_runtime_connector_resource_hardware_role_arns
            "aws:RequestTag/app"     = "qurl-service"
            "aws:RequestTag/purpose" = "qurl-v2-resource-key"
          }
          "ForAllValues:StringEquals" = {
            "aws:TagKeys" = ["app", "owner_id", "purpose", "resource_id"]
          }
          Null = {
            "aws:RequestTag/app"         = "false"
            "aws:RequestTag/owner_id"    = "false"
            "aws:RequestTag/purpose"     = "false"
            "aws:RequestTag/resource_id" = "false"
          }
        }
        },
        {
          Sid       = "ConnectorResourceHardwareKeyLifecycle"
          Effect    = "Allow"
          Principal = "*"
          Action    = ["kms:GetPublicKey", "kms:ScheduleKeyDeletion"]
          Resource  = "*"
          Condition = {
            StringEquals = {
              "aws:PrincipalArn"        = local.authority_runtime_connector_resource_hardware_role_arns
              "kms:ResourceTag/purpose" = "qurl-v2-resource-key"
            }
          }
        },
      ] : statement if length(local.authority_runtime_connector_resource_hardware_role_arns) > 0],
      [for statement in [{
        Sid       = "ConnectorResourceGenerateEnvelopeDataKey"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["kms:GenerateDataKey"]
        Resource = sort([
          for cell in values(local.authority_contract_cells) :
          cell.resource_key_envelope_kms_key_arn
          if cell.resource_key_software_custody_enabled
        ])
        Condition = {
          StringEquals = {
            "aws:PrincipalArn"              = local.authority_runtime_connector_resource_software_role_arns
            "kms:EncryptionContext:purpose" = "qurl-v2-resource-software-key"
          }
        }
        },
      ] : statement if length(local.authority_runtime_connector_resource_software_role_arns) > 0],
    )
  })

  authority_secretsmanager_statements = [{
    Sid       = "AuthorityOTPSecret"
    Effect    = "Allow"
    Principal = "*"
    Action    = "secretsmanager:GetSecretValue"
    Resource  = [aws_secretsmanager_secret.otp_pepper.arn]
    Condition = {
      StringEquals = {
        "aws:PrincipalArn" = local.authority_runtime_otp_role_arns
      }
    }
  }]

  authority_email_endpoint_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AuthorityOTPSendEmail"
      Effect    = "Allow"
      Principal = "*"
      Action    = "ses:SendEmail"
      Resource  = [local.authority_runtime_ses_identity_arn, local.authority_runtime_ses_config_set_arn]
      Condition = {
        StringEquals = {
          "aws:PrincipalArn" = local.authority_runtime_ses_role_arns
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

  # S3 gateway endpoint: GET only from the region's managed ECR layer bucket
  # (where image layer blobs actually live). No other S3 reach is granted. Unlike
  # the other Hub endpoint policies this carries NO aws:PrincipalArn condition:
  # ECR layer blobs are fetched from S3 via presigned URLs generated and signed by
  # the ECR service (not the execution role), so a principal condition 403s the
  # pull ("CannotPullContainerError: httpReadSeeker: unexpected status"). The
  # exact starport bucket + opaque layer-digest object keys are the access
  # control; this is the AWS-standard ECR-over-endpoint pattern.
  hub_s3_endpoint_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "HubPullLayers"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = ["arn:${data.aws_partition.current.partition}:s3:::prod-${data.aws_region.current.region}-starport-layer-bucket/*"]
    }]
  })

  # Secrets Manager interface endpoint: the Fargate EXECUTION role (agent
  # identity), and only it, may read the Hub key-material secret so the ECS agent
  # can inject the three key env vars into the short-lived materialize-config init
  # container. Opened only with the Hub worker. `[*].arn` resolves to an empty
  # Resource list while the worker is dark (this policy is never selected then --
  # secretsmanager stays deny-all). Same Principal "*" + aws:PrincipalArn scoping
  # (a role-ARN Principal would silently deny the assumed-role session). The KMS
  # decrypt of the CMK-encrypted secret happens server-side inside Secrets Manager
  # (checked against the exec role's IAM kms:Decrypt), NOT via the caller's KMS
  # endpoint, so the KMS interface endpoint needs no Hub opening.
  hub_secretsmanager_statements = [{
    Sid       = "HubWorkerReadKeyMaterial"
    Effect    = "Allow"
    Principal = "*"
    Action    = "secretsmanager:GetSecretValue"
    Resource  = aws_secretsmanager_secret.hub_key_material[*].arn
    Condition = {
      StringEquals = {
        "aws:PrincipalArn" = [local.hub_execution_role_arn]
      }
    }
  }]
  authority_and_hub_secretsmanager_endpoint_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      local.authority_runtime_functions_deploy ? local.authority_secretsmanager_statements : [],
      local.hub_worker_deploy ? local.hub_secretsmanager_statements : [],
    )
  })

  # CloudWatch Logs interface endpoint: the Fargate EXECUTION role's awslogs
  # driver creates the log stream and puts events for the init + worker
  # containers, scoped to exactly the Hub worker log group. The log group itself
  # is pre-created by Terraform (awslogs-create-group is not set), so no
  # CreateLogGroup is needed. Opened only with the Hub worker.
  hub_logs_endpoint_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "HubWorkerContainerLogs"
      Effect    = "Allow"
      Principal = "*"
      Action    = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = [
        "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:${local.hub_log_group_name}:*"
      ]
      Condition = {
        StringEquals = {
          "aws:PrincipalArn" = [local.hub_execution_role_arn]
        }
      }
    }]
  })

  # CloudWatch (monitoring) interface endpoint: the Hub worker TASK role publishes
  # its LayerV/NHP operational metrics. PutMetricData is a namespace-scoped action
  # with no resource ARN (Resource must be "*"), so BOTH the caller (aws:PrincipalArn)
  # and the LayerV/NHP namespace are fenced here -- every Terraform PutMetricData
  # grant must be namespace-scoped (validate-workflows enforces this), matching the
  # task IAM policy. Opened only with the Hub worker.
  hub_monitoring_endpoint_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "HubWorkerPublishMetrics"
      Effect    = "Allow"
      Principal = "*"
      Action    = "cloudwatch:PutMetricData"
      Resource  = "*"
      Condition = {
        StringEquals = {
          "aws:PrincipalArn"     = [local.hub_task_role_arn]
          "cloudwatch:namespace" = "LayerV/NHP"
        }
      }
    }]
  })

  # Per-service interface-endpoint policy. KMS, Secrets Manager, and SES open
  # with the Authority runtime; Lambda, Logs, and Monitoring open with the Hub
  # worker (slice 5b). Secrets Manager composes both exact statements if both
  # slices are live. The ecr.api/ecr.dkr interface endpoints are separate
  # resources (hub_worker.tf) and carry hub_ecr_endpoint_policy directly.
  interface_endpoint_policies = {
    for service in keys(local.interface_endpoint_services) :
    service => (
      local.authority_runtime_functions_deploy && service == "kms" ? local.authority_kms_endpoint_policy
      : (local.authority_runtime_functions_deploy || local.hub_worker_deploy) && service == "secretsmanager" ? local.authority_and_hub_secretsmanager_endpoint_policy
      : local.authority_runtime_functions_deploy && service == "email" ? local.authority_email_endpoint_policy
      : local.hub_worker_deploy && service == "lambda" ? local.hub_lambda_endpoint_policy
      : local.hub_worker_deploy && service == "logs" ? local.hub_logs_endpoint_policy
      : local.hub_worker_deploy && service == "monitoring" ? local.hub_monitoring_endpoint_policy
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
  # Redis uses a separate exact 6379 SG-to-SG path in authority_runtime.tf.
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
