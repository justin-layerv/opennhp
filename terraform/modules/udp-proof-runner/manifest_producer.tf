locals {
  manifest_producer_role_name = "${var.name_prefix}-udp-proof-manifest-producer"
  manifest_producer_sub       = "repo:${var.github_repository}:environment:${var.manifest_github_environment}"

  manifest_ssm_parameters = [
    "sandbox/nhp/control/hub/identity/public-key",
    "sandbox/nhp/udp-proof/runtime-attestation-bucket-arn",
    "sandbox/nhp/udp-proof/runtime-attestation-collector-contract",
    "sandbox/nhp/server/asg-name",
    "sandbox-cell1/nhp/server/asg-name",
    "sandbox/nhp/reverse-tunnel-server/asg-name",
    "sandbox/nhp/qurl-service/runtime-contract",
    "sandbox-cell1/nhp/qurl-service/runtime-contract",
  ]
  manifest_ssm_parameter_arns = [
    for parameter in local.manifest_ssm_parameters :
    "arn:${data.aws_partition.current.partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter/${parameter}"
  ]
  manifest_ecr_repositories = [
    "layerv/nhp-hub",
    "layerv/nhp-qurl",
    "layerv/nhp-server",
    "layerv/qurl-connector-authority",
    "layerv/qurl-reverse-tunnel-server",
  ]
  manifest_ecr_repository_arns = [
    for repository in local.manifest_ecr_repositories :
    "arn:${data.aws_partition.current.partition}:ecr:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:repository/${repository}"
  ]
  manifest_authority_functions = [
    "layerv-nhp-sandbox-ca-ar-cell0",
    "layerv-nhp-sandbox-ca-ar-cell1",
    "layerv-nhp-sandbox-ca-ccr-cell0",
    "layerv-nhp-sandbox-ca-ccr-cell1",
    "layerv-nhp-sandbox-ca-cr-cell0",
    "layerv-nhp-sandbox-ca-cr-cell1",
    "layerv-nhp-sandbox-ca-ia",
    "layerv-nhp-sandbox-ca-icr",
    "layerv-nhp-sandbox-ca-iro-cell0",
    "layerv-nhp-sandbox-ca-iro-cell1",
    "layerv-nhp-sandbox-ca-ra",
  ]
  manifest_authority_function_arns = flatten([
    for function in local.manifest_authority_functions : [
      "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:function:${function}",
      "arn:${data.aws_partition.current.partition}:lambda:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:function:${function}:*",
    ]
  ])
  manifest_ecs_clusters = [
    "layerv-nhp-sandbox-control-hub",
    "layerv-nhp-sandbox-cell0-qurl-api",
    "layerv-nhp-sandbox-cell1-qurl-api",
  ]
  manifest_ecs_cluster_arns = [
    for cluster in local.manifest_ecs_clusters :
    "arn:${data.aws_partition.current.partition}:ecs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:cluster/${cluster}"
  ]
  manifest_ecs_service_arns = [
    for cluster in local.manifest_ecs_clusters :
    "arn:${data.aws_partition.current.partition}:ecs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:service/${cluster}/${cluster}"
  ]
  manifest_ecs_task_arns = [
    for cluster in local.manifest_ecs_clusters :
    "arn:${data.aws_partition.current.partition}:ecs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:task/${cluster}/*"
  ]
  manifest_instance_profile_arns = [
    "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:instance-profile/layerv-nhp-sandbox-server",
    "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:instance-profile/layerv-nhp-sandbox-cell1-server",
    "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:instance-profile/layerv-nhp-sandbox-frps",
  ]
}

resource "aws_iam_role" "manifest_producer" {
  name        = local.manifest_producer_role_name
  description = "Read-only trusted-main producer for exact sandbox UDP proof deployment evidence"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "sts:AssumeRoleWithWebIdentity"
      Principal = {
        Federated = var.github_oidc_provider_arn
      }
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = local.manifest_producer_sub
        }
      }
    }]
  })

  max_session_duration = 3600
  tags                 = local.tags
}

resource "aws_iam_role_policy" "manifest_producer_core" {
  name = "udp-proof-manifest-read"
  role = aws_iam_role.manifest_producer.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadExactPublicRuntimeParameters"
        Effect   = "Allow"
        Action   = "ssm:GetParameter"
        Resource = local.manifest_ssm_parameter_arns
      },
      {
        Sid      = "ReadExactRepairDocument"
        Effect   = "Allow"
        Action   = "ssm:GetDocument"
        Resource = "arn:${data.aws_partition.current.partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:document/${var.name_prefix}-runtime-attestation-repair"
      },
      {
        Sid      = "ReadProvisionedCellCatalog"
        Effect   = "Allow"
        Action   = "dynamodb:GetItem"
        Resource = "arn:${data.aws_partition.current.partition}:dynamodb:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:table/${var.name_prefix}-control-connector-authority"
      },
      {
        Sid    = "ReadExactRuntimeImages"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:BatchGetImage",
          "ecr:GetDownloadUrlForLayer",
        ]
        Resource = local.manifest_ecr_repository_arns
      },
      {
        Sid      = "ReadECRAuthorizationToken"
        Effect   = "Allow"
        Action   = "ecr:GetAuthorizationToken"
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = data.aws_region.current.region
          }
        }
      },
      {
        Sid      = "ReadExactAuthorityFunctions"
        Effect   = "Allow"
        Action   = ["lambda:GetAlias", "lambda:GetFunction", "lambda:ListProvisionedConcurrencyConfigs"]
        Resource = local.manifest_authority_function_arns
      },
      {
        Sid      = "ReadExactECSDeployments"
        Effect   = "Allow"
        Action   = "ecs:DescribeServices"
        Resource = local.manifest_ecs_service_arns
      },
      {
        Sid      = "DescribeExactECSTasks"
        Effect   = "Allow"
        Action   = "ecs:DescribeTasks"
        Resource = local.manifest_ecs_task_arns
        Condition = {
          ArnEquals = {
            "ecs:cluster" = local.manifest_ecs_cluster_arns
          }
        }
      },
      {
        Sid      = "ListExactECSTasks"
        Effect   = "Allow"
        Action   = "ecs:ListTasks"
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = data.aws_region.current.region
          }
          ArnEquals = {
            "ecs:cluster" = local.manifest_ecs_cluster_arns
          }
        }
      },
      {
        Sid      = "ReadExactECSTaskDefinitions"
        Effect   = "Allow"
        Action   = "ecs:DescribeTaskDefinition"
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = data.aws_region.current.region
          }
        }
      },
      {
        Sid      = "ReadExactInstanceProfiles"
        Effect   = "Allow"
        Action   = "iam:GetInstanceProfile"
        Resource = local.manifest_instance_profile_arns
      },
      {
        Sid      = "ReadExactPublicDNSZone"
        Effect   = "Allow"
        Action   = "route53:ListResourceRecordSets"
        Resource = "arn:${data.aws_partition.current.partition}:route53:::hostedzone/Z10394893FM38A1RXLL32"
      },
      {
        Sid    = "ReadRegionalFleetTopology"
        Effect = "Allow"
        Action = [
          "autoscaling:DescribeAutoScalingGroups",
          "autoscaling:DescribeInstanceRefreshes",
          "ec2:DescribeAddresses",
          "ec2:DescribeInstances",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeSecurityGroups",
          "elasticloadbalancing:DescribeListeners",
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetHealth",
          "ssm:DescribeAssociation",
          "ssm:DescribeAssociationExecutions",
          "ssm:DescribeAssociationExecutionTargets",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = data.aws_region.current.region
          }
        }
      },
      {
        Sid      = "ConfirmSandboxIdentity"
        Effect   = "Allow"
        Action   = "sts:GetCallerIdentity"
        Resource = "*"
      },
    ]
  })
}

# ReadProvisionedCellCatalog (core policy, above) grants dynamodb:GetItem, but
# the catalog table is SSE-KMS encrypted with the Connector Authority
# customer-managed key (aws_kms_key.authority_data in
# terraform/modules/connector-authority-foundation/kms.tf). DynamoDB calls
# kms:Decrypt under the CALLER's identity for an SSE-KMS read, so a GetItem
# without this grant fails AccessDeniedException from KMS — not from DynamoDB —
# and no amount of table-scoped dynamodb: permission fixes it.
#
# kms:ViaService keeps the decrypt reachable only through DynamoDB, so this
# grant cannot be turned against the other stores that same CMK protects
# (Redis, ECR, secrets, control log groups). DynamoDB's per-table encryption
# context is not an IAM-conditionable key the way S3's aws:s3:arn is, so the
# exact key ARN plus ViaService is the tightest bound AWS supports here; the
# table itself stays pinned by ReadProvisionedCellCatalog's exact resource ARN.
resource "aws_iam_role_policy" "manifest_producer_catalog_decrypt" {
  count = var.provisioned_cell_catalog_kms_key_arn == null ? 0 : 1

  name = "udp-proof-catalog-decrypt"
  role = aws_iam_role.manifest_producer.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DecryptOnlyProvisionedCellCatalog"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = var.provisioned_cell_catalog_kms_key_arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = "dynamodb.${data.aws_region.current.region}.${data.aws_partition.current.dns_suffix}"
          }
        }
      },
    ]
  })

  lifecycle {
    precondition {
      condition = startswith(
        var.provisioned_cell_catalog_kms_key_arn,
        "arn:${data.aws_partition.current.partition}:kms:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:key/",
      )
      error_message = "The provisioned-cell catalog CMK must be a current-account, current-region KMS key ARN."
    }
  }
}

resource "aws_iam_role_policy" "manifest_producer_attestations" {
  count = var.runtime_attestation_bucket_arn == null ? 0 : 1

  name = "udp-proof-runtime-attestation-read"
  role = aws_iam_role.manifest_producer.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadAttestationBucketControls"
        Effect = "Allow"
        Action = [
          "s3:GetBucketEncryption",
          "s3:GetBucketOwnershipControls",
          "s3:GetBucketPolicy",
          "s3:GetBucketPolicyStatus",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketVersioning",
        ]
        Resource = var.runtime_attestation_bucket_arn
      },
      {
        Sid      = "ListVersionedRuntimeAttestations"
        Effect   = "Allow"
        Action   = "s3:ListBucketVersions"
        Resource = var.runtime_attestation_bucket_arn
        Condition = {
          StringLike = {
            "s3:prefix" = "runtime/*"
          }
        }
      },
      {
        Sid      = "ReadImmutableRuntimeAttestationVersions"
        Effect   = "Allow"
        Action   = "s3:GetObjectVersion"
        Resource = "${var.runtime_attestation_bucket_arn}/runtime/*"
      },
      # The encryption context is the bare bucket ARN, not an object ARN: the
      # collector contract requires BucketKeyEnabled on this bucket, and S3
      # Bucket Keys use the bucket ARN as the KMS encryption context. An
      # object-scoped context here can never match, so every get-object would
      # fail AccessDenied on kms:Decrypt. The runtime/ prefix stays enforced by
      # ReadImmutableRuntimeAttestationVersions above; kms:ViaService keeps this
      # decrypt reachable only through S3.
      {
        Sid      = "DecryptOnlyAttestationObjects"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = var.runtime_attestation_kms_key_arn
        Condition = {
          StringEquals = {
            "kms:ViaService"                   = "s3.${data.aws_region.current.region}.${data.aws_partition.current.dns_suffix}"
            "kms:EncryptionContext:aws:s3:arn" = var.runtime_attestation_bucket_arn
          }
        }
      },
    ]
  })

  lifecycle {
    precondition {
      condition = (
        startswith(
          var.runtime_attestation_bucket_arn,
          "arn:${data.aws_partition.current.partition}:s3:::layerv-nhp-sandbox-",
        ) &&
        startswith(
          var.runtime_attestation_kms_key_arn,
          "arn:${data.aws_partition.current.partition}:kms:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:key/",
        )
      )
      error_message = "Runtime attestation storage must be an exact sandbox-owned bucket and current-account regional KMS key."
    }
  }
}
