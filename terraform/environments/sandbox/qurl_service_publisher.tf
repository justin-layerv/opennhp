# =============================================================================
# Cell0 qurl-service immutable runtime publisher foundation
# =============================================================================
#
# This is the cell0 half of the governed qurl-service main workflow. It creates
# one atomic public runtime contract plus one least-privilege OIDC role. The
# role may stage/promote images in the shared qurl-service ECR repository,
# update only cell0's contract, and roll only cell0's established ECS service.
# It cannot read application secrets, mutate qURL data, call Connector
# Authority, or touch cell1.
#
# The workflow must independently reject every repository/ref/workflow/SHA
# mismatch before requesting these credentials. AWS IAM can bind the GitHub
# repository and main ref, but not GitHub's workflow_ref claim.

locals {
  qurl_service_publisher_source_repository = "layervai/qurl-service"
  qurl_service_publisher_repository_name   = "layerv/nhp-qurl"
  qurl_service_publisher_repository_arn    = "arn:aws:ecr:${var.aws_region}:${var.aws_account_id}:repository/${local.qurl_service_publisher_repository_name}"
  qurl_service_runtime_contract_path       = "/${var.environment}/nhp/qurl-service/runtime-contract"
  qurl_service_live_env_lock_path          = "/layerv-nhp-sandbox/qurl-live-env-lock"
  qurl_service_live_env_lock_arn           = "arn:aws:ssm:${var.aws_region}:${var.aws_account_id}:parameter${local.qurl_service_live_env_lock_path}"

  qurl_service_publisher_name      = "${local.name_prefix}-${var.cell_id}-qurl-service-publisher"
  qurl_service_runtime_name        = "${local.name_prefix}-${var.cell_id}-qurl-api"
  qurl_service_runtime_cluster_arn = "arn:aws:ecs:${var.aws_region}:${var.aws_account_id}:cluster/${local.qurl_service_runtime_name}"
  qurl_service_runtime_service_arn = "arn:aws:ecs:${var.aws_region}:${var.aws_account_id}:service/${local.qurl_service_runtime_name}/${local.qurl_service_runtime_name}"
  qurl_service_runtime_task_arn    = "arn:aws:ecs:${var.aws_region}:${var.aws_account_id}:task/${local.qurl_service_runtime_name}/*"
  qurl_service_runtime_taskdef_arn = "arn:aws:ecs:${var.aws_region}:${var.aws_account_id}:task-definition/${local.qurl_service_runtime_name}:*"
  qurl_service_runtime_task_cpu    = 512
  qurl_service_runtime_task_memory = 1024
  qurl_service_runtime_role_arns = [
    "arn:aws:iam::${var.aws_account_id}:role/${local.qurl_service_runtime_name}-execution",
    "arn:aws:iam::${var.aws_account_id}:role/${local.qurl_service_runtime_name}-task",
  ]

  # Publisher-created revisions retain the established ownership tags. Every
  # value is fixed in IAM; SourceRevision is the sole dynamic request tag.
  qurl_service_publisher_task_definition_tags = merge(local.common_tags, {
    Cell             = var.cell_id
    Component        = "qurl-service"
    LayerVCell       = var.cell_id
    ManagedBy        = "qurl-service-publisher"
    Name             = local.qurl_service_runtime_name
    Service          = "qurl"
    SourceRepository = local.qurl_service_publisher_source_repository
  })
  qurl_service_publisher_task_definition_tag_keys = sort(concat(
    keys(local.qurl_service_publisher_task_definition_tags),
    ["SourceRevision"],
  ))
}

# One parameter makes exact-image/source promotion atomic. Separate writable
# fields could temporarily pair a new image with an old source revision.
resource "aws_ssm_parameter" "qurl_service_runtime_contract" {
  name        = local.qurl_service_runtime_contract_path
  description = "Atomic immutable runtime contract for the cell0 qurl-service"
  type        = "String"
  value = jsonencode({
    schema_version = 1
    status         = "UNPUBLISHED"
  })

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-${var.cell_id}-qurl-service-runtime-contract"
    Cell      = var.cell_id
    Component = "qurl-service"
    Purpose   = "Immutable cell runtime promotion"
  })

  lifecycle {
    # Terraform creates and names the record; the governed qurl-service
    # publisher owns its live value after the foundation is applied.
    ignore_changes = [value]
  }
}

resource "aws_iam_role" "qurl_service_publisher" {
  name                 = local.qurl_service_publisher_name
  description          = "Promote and deploy the cell0 qurl-service runtime"
  max_session_duration = 10800

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "QurlServiceMainRef"
      Effect = "Allow"
      Principal = {
        Federated = "arn:aws:iam::${var.aws_account_id}:oidc-provider/token.actions.githubusercontent.com"
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:${local.qurl_service_publisher_source_repository}:ref:refs/heads/main"
        }
      }
    }]
  })

  tags = merge(local.common_tags, {
    Name       = local.qurl_service_publisher_name
    Cell       = var.cell_id
    Component  = "qurl-service"
    Purpose    = "Cell0 immutable image promotion"
    SourceRepo = local.qurl_service_publisher_source_repository
  })

  lifecycle {
    precondition {
      condition = (
        var.environment == "sandbox"
        && var.cell_id == "cell0"
        && var.aws_region == "us-east-2"
        && var.aws_account_id == "767397897469"
      )
      error_message = "The cell0 qurl-service publisher is bound to sandbox/cell0 in account 767397897469, us-east-2; do not reuse this environment-root foundation for another cell or account."
    }
    precondition {
      condition     = var.deploy_qurl_service
      error_message = "The cell0 publisher role requires the established cell0 qurl-service ECS family and service."
    }
    precondition {
      condition = (
        local.qurl_service_runtime_task_cpu == (
          var.qurl_grafana_cloud_enabled ? max(var.qurl_container_cpu, 512) : var.qurl_container_cpu
        )
        && local.qurl_service_runtime_task_memory == ceil((
          var.qurl_grafana_cloud_enabled ? var.qurl_container_memory + 256 : var.qurl_container_memory
        ) / 1024) * 1024
      )
      error_message = "The publisher's IAM CPU/memory conditions must equal the qurl-service module's effective task shape, including the ADOT sidecar overhead."
    }
  }
}

resource "aws_iam_role_policy" "qurl_service_publisher" {
  name = "promote-and-deploy-cell0-qurl-service"
  role = aws_iam_role.qurl_service_publisher.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AuthorizeECR"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Sid    = "ReadPublishedImage"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:BatchGetImage",
          "ecr:DescribeImages",
          "ecr:GetDownloadUrlForLayer",
          "ecr:ListImages",
        ]
        Resource = local.qurl_service_publisher_repository_arn
      },
      {
        Sid    = "StageAndPromotePublishedImage"
        Effect = "Allow"
        Action = [
          "ecr:CompleteLayerUpload",
          "ecr:InitiateLayerUpload",
          "ecr:PutImage",
          "ecr:UploadLayerPart",
        ]
        Resource = local.qurl_service_publisher_repository_arn
      },
      {
        Sid      = "PublishAtomicRuntimeContract"
        Effect   = "Allow"
        Action   = ["ssm:GetParameter", "ssm:PutParameter"]
        Resource = aws_ssm_parameter.qurl_service_runtime_contract.arn
      },
      {
        Sid      = "CoordinateSharedSandboxMutation"
        Effect   = "Allow"
        Action   = ["ssm:DeleteParameter", "ssm:GetParameter", "ssm:PutParameter"]
        Resource = local.qurl_service_live_env_lock_arn
      },
      {
        Sid      = "EmitSandboxLockFailureMetric"
        Effect   = "Allow"
        Action   = ["cloudwatch:PutMetricData"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "LayerV/QURLServiceCI"
          }
        }
      },
      {
        Sid      = "ReadCell0Service"
        Effect   = "Allow"
        Action   = ["ecs:DescribeServices"]
        Resource = local.qurl_service_runtime_service_arn
      },
      {
        Sid      = "DeployOnlyCell0Service"
        Effect   = "Allow"
        Action   = ["ecs:UpdateService"]
        Resource = local.qurl_service_runtime_service_arn
        Condition = {
          ArnEquals = {
            "ecs:cluster" = local.qurl_service_runtime_cluster_arn
          }
          ArnLike = {
            "ecs:task-definition" = local.qurl_service_runtime_taskdef_arn
          }
        }
      },
      {
        Sid      = "ListOnlyCell0Tasks"
        Effect   = "Allow"
        Action   = ["ecs:ListTasks"]
        Resource = "*"
        Condition = {
          ArnEquals = {
            "ecs:cluster" = local.qurl_service_runtime_cluster_arn
          }
        }
      },
      {
        Sid      = "ReadCell0Tasks"
        Effect   = "Allow"
        Action   = ["ecs:DescribeTasks"]
        Resource = local.qurl_service_runtime_task_arn
      },
      {
        Sid      = "DescribeTaskDefinition"
        Effect   = "Allow"
        Action   = ["ecs:DescribeTaskDefinition"]
        Resource = "*"
      },
      {
        Sid      = "RegisterOnlyCell0TaskDefinition"
        Effect   = "Allow"
        Action   = ["ecs:RegisterTaskDefinition"]
        Resource = local.qurl_service_runtime_taskdef_arn
        Condition = {
          StringEquals = {
            for tag_key, tag_value in local.qurl_service_publisher_task_definition_tags :
            "aws:RequestTag/${tag_key}" => tag_value
          }
          Null = {
            "aws:RequestTag/SourceRevision" = "false"
            "ecs:compute-compatibility"     = "false"
          }
          Bool = {
            "ecs:privileged" = "false"
          }
          NumericEquals = {
            "ecs:task-cpu"    = local.qurl_service_runtime_task_cpu
            "ecs:task-memory" = local.qurl_service_runtime_task_memory
          }
          "ForAllValues:StringEquals" = {
            "aws:TagKeys"               = local.qurl_service_publisher_task_definition_tag_keys
            "ecs:compute-compatibility" = ["FARGATE"]
          }
        }
      },
      {
        Sid      = "TagRegisteredTaskDefinition"
        Effect   = "Allow"
        Action   = ["ecs:TagResource"]
        Resource = local.qurl_service_runtime_taskdef_arn
        Condition = {
          StringEquals = merge(
            {
              for tag_key, tag_value in local.qurl_service_publisher_task_definition_tags :
              "aws:RequestTag/${tag_key}" => tag_value
            },
            {
              "ecs:CreateAction" = "RegisterTaskDefinition"
            },
          )
          Null = {
            "aws:RequestTag/SourceRevision" = "false"
          }
          "ForAllValues:StringEquals" = {
            "aws:TagKeys" = local.qurl_service_publisher_task_definition_tag_keys
          }
        }
      },
      {
        Sid      = "PassOnlyCell0TaskRoles"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = local.qurl_service_runtime_role_arns
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "ecs-tasks.amazonaws.com"
          }
        }
      },
    ]
  })
}
