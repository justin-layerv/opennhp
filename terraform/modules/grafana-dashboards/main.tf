# Grafana Dashboards Module
# Provisions QURL service dashboards to Grafana Cloud
#
# NOTE: This module requires a grafana provider to be passed from the caller.
# Example:
#   module "grafana_dashboards" {
#     source = "./modules/grafana-dashboards"
#     providers = { grafana = grafana }
#     ...
#   }

terraform {
  required_version = ">= 1.5"

  required_providers {
    grafana = {
      source                = "grafana/grafana"
      version               = "~> 3.0"
      configuration_aliases = [grafana]
    }
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

# Create a folder for QURL dashboards
resource "grafana_folder" "qurl" {
  title = var.folder_name
}

# QURL Operations Dashboard
# Monitors HTTP RED metrics (Rate, Errors, Duration) and DynamoDB performance
resource "grafana_dashboard" "operations" {
  folder = grafana_folder.qurl.id
  config_json = templatefile("${path.module}/dashboards/qurl-operations.json", {
    datasource_uid = var.prometheus_datasource_uid
    tempo_uid      = var.tempo_datasource_uid
    environment    = var.environment
  })

  overwrite = true
}

# QURL Business Dashboard
# Monitors business metrics: QURLs created, tokens, quotas
resource "grafana_dashboard" "business" {
  folder = grafana_folder.qurl.id
  config_json = templatefile("${path.module}/dashboards/qurl-business.json", {
    datasource_uid = var.prometheus_datasource_uid
    environment    = var.environment
  })

  overwrite = true
}

# QURL Webhooks Dashboard
# Monitors webhook delivery metrics and health
resource "grafana_dashboard" "webhooks" {
  folder = grafana_folder.qurl.id
  config_json = templatefile("${path.module}/dashboards/qurl-webhooks.json", {
    datasource_uid = var.prometheus_datasource_uid
    environment    = var.environment
  })

  overwrite = true
}

# ==============================================================================
# CloudWatch Data Source & NHP Infrastructure Dashboard
# ==============================================================================

locals {
  create_cw_role = var.cloudwatch_datasource_enabled && var.cloudwatch_assume_role_arn == "" && var.grafana_cloud_aws_account_id != ""
  cw_role_arn    = local.create_cw_role ? aws_iam_role.grafana_cloudwatch[0].arn : var.cloudwatch_assume_role_arn
}

resource "grafana_data_source" "cloudwatch" {
  count = var.cloudwatch_datasource_enabled ? 1 : 0

  type = "cloudwatch"
  name = "CloudWatch"

  json_data_encoded = jsonencode({
    defaultRegion = var.aws_region
    authType      = "ec2_iam_role"
    assumeRoleArn = local.cw_role_arn
  })
}

resource "grafana_folder" "nhp" {
  count = var.cloudwatch_datasource_enabled ? 1 : 0
  title = var.nhp_folder_name
}

resource "grafana_dashboard" "nhp_infrastructure" {
  count = var.cloudwatch_datasource_enabled ? 1 : 0

  folder = grafana_folder.nhp[0].id
  config_json = templatefile("${path.module}/dashboards/nhp-infrastructure.json", {
    cloudwatch_uid = grafana_data_source.cloudwatch[0].uid
    environment    = var.environment
  })

  overwrite = true
}

# ==============================================================================
# IAM Role for Grafana Cloud CloudWatch Access
# ==============================================================================

resource "aws_iam_role" "grafana_cloudwatch" {
  count = local.create_cw_role ? 1 : 0

  name = "${var.name_prefix}-grafana-cloudwatch"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.grafana_cloud_aws_account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = var.grafana_cloud_external_id != "" ? {
          StringEquals = {
            "sts:ExternalId" = var.grafana_cloud_external_id
          }
        } : {}
      }
    ]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-grafana-cloudwatch"
    Component = "grafana-dashboards"
  })
}

resource "aws_iam_role_policy" "grafana_cloudwatch" {
  count = local.create_cw_role ? 1 : 0

  name = "${var.name_prefix}-grafana-cloudwatch-policy"
  role = aws_iam_role.grafana_cloudwatch[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchReadOnly"
        Effect = "Allow"
        Action = [
          "cloudwatch:GetMetricData",
          "cloudwatch:ListMetrics",
          "cloudwatch:DescribeAlarms",
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:DescribeAlarmsForMetric"
        ]
        Resource = "*"
      },
      {
        Sid    = "EC2Describe"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeRegions"
        ]
        Resource = "*"
      },
      {
        Sid    = "AutoScalingDescribe"
        Effect = "Allow"
        Action = [
          "autoscaling:DescribeAutoScalingGroups",
          "autoscaling:DescribeAutoScalingInstances"
        ]
        Resource = "*"
      },
      {
        Sid    = "TagsRead"
        Effect = "Allow"
        Action = [
          "tag:GetResources"
        ]
        Resource = "*"
      }
    ]
  })
}
