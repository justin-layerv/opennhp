locals {
  image_tag_parameter_arn = "arn:${data.aws_partition.current.partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter${var.relay_image_tag_parameter_name}"
  relay_log_group_arn     = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/layerv/nhp/${var.environment}/relay:*"

  deny_cross_account = {
    Sid       = "DenyCrossAccountPrincipals"
    Effect    = "Deny"
    Principal = "*"
    Action    = "*"
    Resource  = "*"
    Condition = {
      StringNotEquals = {
        "aws:PrincipalAccount" = data.aws_caller_identity.current.account_id
      }
    }
  }

  endpoint_policies = {
    "ecr-api" = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Sid       = "RelayAuthorizationToken"
          Effect    = "Allow"
          Principal = "*"
          Action    = "ecr:GetAuthorizationToken"
          Resource  = "*"
        },
        {
          Sid       = "RelayRepositoryRead"
          Effect    = "Allow"
          Principal = "*"
          Action = [
            "ecr:BatchCheckLayerAvailability",
            "ecr:BatchGetImage",
            "ecr:GetDownloadUrlForLayer",
          ]
          Resource = var.relay_repo_arn
        },
        local.deny_cross_account,
      ]
    })
    "ecr-dkr" = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Sid       = "RelayRepositoryRegistryRead"
          Effect    = "Allow"
          Principal = "*"
          Action = [
            "ecr:BatchCheckLayerAvailability",
            "ecr:BatchGetImage",
            "ecr:GetDownloadUrlForLayer",
          ]
          Resource = var.relay_repo_arn
        },
        local.deny_cross_account,
      ]
    })
    secretsmanager = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Sid       = "RelayIdentityRead"
          Effect    = "Allow"
          Principal = "*"
          Action    = "secretsmanager:GetSecretValue"
          Resource  = var.relay_secret_arn
        },
        local.deny_cross_account,
      ]
    })
    ssm = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Sid       = "RelayImageTagRead"
          Effect    = "Allow"
          Principal = "*"
          Action    = "ssm:GetParameter"
          Resource  = local.image_tag_parameter_arn
        },
        {
          Sid       = "RelayManagedInstanceCore"
          Effect    = "Allow"
          Principal = "*"
          Action = [
            "ssm:DescribeAssociation",
            "ssm:DescribeDocument",
            "ssm:GetDocument",
            "ssm:GetManifest",
            "ssm:ListAssociations",
            "ssm:ListInstanceAssociations",
            "ssm:PutComplianceItems",
            "ssm:PutConfigurePackageResult",
            "ssm:PutInventory",
            "ssm:UpdateAssociationStatus",
            "ssm:UpdateInstanceAssociationStatus",
            "ssm:UpdateInstanceInformation",
          ]
          Resource = "*"
        },
        local.deny_cross_account,
      ]
    })
    ssmmessages = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Sid       = "RelaySessionChannels"
          Effect    = "Allow"
          Principal = "*"
          Action = [
            "ssmmessages:CreateControlChannel",
            "ssmmessages:CreateDataChannel",
            "ssmmessages:OpenControlChannel",
            "ssmmessages:OpenDataChannel",
          ]
          Resource = "*"
        },
        local.deny_cross_account,
      ]
    })
    logs = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Sid       = "RelayLogWrite"
          Effect    = "Allow"
          Principal = "*"
          Action = [
            "logs:CreateLogStream",
            "logs:DescribeLogStreams",
            "logs:PutLogEvents",
          ]
          Resource = local.relay_log_group_arn
        },
        local.deny_cross_account,
      ]
    })
    monitoring = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Sid       = "RelayMetrics"
          Effect    = "Allow"
          Principal = "*"
          Action    = "cloudwatch:PutMetricData"
          Resource  = "*"
          Condition = {
            StringEquals = {
              "cloudwatch:namespace" = "LayerV/NHP"
            }
          }
        },
        local.deny_cross_account,
      ]
    })
    "guardduty-data" = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Sid       = "RelayRuntimeTelemetry"
          Effect    = "Allow"
          Principal = "*"
          # GuardDuty's data-plane endpoint uses an internal ingestion API.
          # AWS's managed endpoint policy allows all endpoint actions, then
          # explicitly denies principals outside this account. Preserve that
          # documented shape rather than guessing a narrower hidden action set.
          Action   = "*"
          Resource = "*"
        },
        local.deny_cross_account,
      ]
    })
  }

  interface_endpoint_services = {
    "ecr-api"        = "ecr.api"
    "ecr-dkr"        = "ecr.dkr"
    "guardduty-data" = "guardduty-data"
    logs             = "logs"
    monitoring       = "monitoring"
    secretsmanager   = "secretsmanager"
    ssm              = "ssm"
    ssmmessages      = "ssmmessages"
  }
}

resource "aws_vpc_endpoint" "interface" {
  for_each = local.interface_endpoint_services

  vpc_id              = aws_vpc.relay.id
  service_name        = "com.amazonaws.${data.aws_region.current.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.endpoint[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  policy              = local.endpoint_policies[each.key]

  tags = merge(local.tags, { Name = "${var.name_prefix}-relay-dmz-vpce-${each.key}" })
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.relay.id
  service_name      = "com.amazonaws.${data.aws_region.current.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = aws_route_table.relay[*].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "ApprovedRelayBootstrapObjects"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource = [
        "arn:${data.aws_partition.current.partition}:s3:::prod-${data.aws_region.current.region}-starport-layer-bucket/*",
        "arn:${data.aws_partition.current.partition}:s3:::amazon-ssm-${data.aws_region.current.region}/*",
        "arn:${data.aws_partition.current.partition}:s3:::aws-ssm-${data.aws_region.current.region}/*",
        "arn:${data.aws_partition.current.partition}:s3:::${data.aws_region.current.region}-birdwatcher-prod/*",
        "arn:${data.aws_partition.current.partition}:s3:::aws-ssm-document-attachments-${data.aws_region.current.region}/*",
      ]
    }]
  })

  tags = merge(local.tags, { Name = "${var.name_prefix}-relay-dmz-vpce-s3" })
}
