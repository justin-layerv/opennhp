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
#
# Dashboard Unification:
# A single set of dashboards serves all environments. Each dashboard uses
# template variables (environment, cw_datasource, cell_id) for switching.
# Only the "primary" environment (create_dashboards=true) creates folder and
# dashboard resources. Every environment creates its own CloudWatch datasource
# and IAM role so the unified dashboards can query any environment's metrics.

terraform {
  required_version = ">= 1.5"

  required_providers {
    grafana = {
      source                = "grafana/grafana"
      version               = "~> 4.0"
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
  count                        = var.create_dashboards ? 1 : 0
  uid                          = "qurl"
  title                        = var.folder_name
  prevent_destroy_if_not_empty = true
}

# QURL Operations Dashboard
# Monitors HTTP RED metrics (Rate, Errors, Duration) and DynamoDB performance
resource "grafana_dashboard" "operations" {
  count = var.create_dashboards ? 1 : 0

  folder = grafana_folder.qurl[0].uid
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
  count = var.create_dashboards ? 1 : 0

  folder = grafana_folder.qurl[0].uid
  config_json = templatefile("${path.module}/dashboards/qurl-business.json", {
    datasource_uid = var.prometheus_datasource_uid
    environment    = var.environment
  })

  overwrite = true
}

# QURL Webhooks Dashboard
# Monitors webhook delivery metrics and health
resource "grafana_dashboard" "webhooks" {
  count = var.create_dashboards ? 1 : 0

  folder = grafana_folder.qurl[0].uid
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

  lifecycle {
    precondition {
      condition     = var.cloudwatch_assume_role_arn != "" || var.grafana_cloud_aws_account_id != ""
      error_message = "When cloudwatch_datasource_enabled is true, either cloudwatch_assume_role_arn or grafana_cloud_aws_account_id must be set so Grafana Cloud can assume an IAM role for CloudWatch access."
    }
  }

  type = "cloudwatch"
  name = "CloudWatch (${var.environment})"

  # Dashboard query targets use Grafana 11.x+ CloudWatch plugin format:
  # statistic (singular string), queryMode, metricQueryType, metricEditorMode.
  # customMetricsNamespaces enables discovery of LayerV/NHP metrics in Grafana UI.
  json_data_encoded = jsonencode({
    defaultRegion           = var.aws_region
    authType                = "grafana_assume_role"
    assumeRoleArn           = local.cw_role_arn
    customMetricsNamespaces = "LayerV/NHP"
  })
}

resource "grafana_folder" "nhp" {
  count                        = var.create_dashboards && (var.cloudwatch_datasource_enabled || var.athena_datasource_enabled) ? 1 : 0
  uid                          = "nhp"
  title                        = var.nhp_folder_name
  prevent_destroy_if_not_empty = true
}

# NHP Infrastructure Dashboard
resource "grafana_dashboard" "nhp_infrastructure" {
  count = var.create_dashboards && var.cloudwatch_datasource_enabled ? 1 : 0

  folder = grafana_folder.nhp[0].uid
  config_json = templatefile("${path.module}/dashboards/nhp-infrastructure.json", {
    environment = var.environment
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
        Sid    = "CloudWatchLogsRead"
        Effect = "Allow"
        Action = [
          "logs:DescribeLogGroups",
          "logs:GetLogGroupFields",
          "logs:StartQuery",
          "logs:StopQuery",
          "logs:GetQueryResults",
          "logs:GetLogEvents"
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

# ==============================================================================
# Athena Data Source & AWS Cost Dashboard
# ==============================================================================
# Requires grafana-athena-datasource plugin installed in Grafana Cloud UI
# (Administration > Plugins > "Athena" > Install)

resource "grafana_data_source" "athena" {
  count = var.athena_datasource_enabled ? 1 : 0

  type = "grafana-athena-datasource"
  name = "Amazon Athena (${var.environment})"

  json_data_encoded = jsonencode({
    defaultRegion = var.athena_region
    authType      = "grafana_assume_role"
    assumeRoleArn = var.athena_assume_role_arn
    catalog       = "AwsDataCatalog"
    database      = var.athena_database
    workgroup     = var.athena_workgroup
  })
}

resource "grafana_dashboard" "aws_cost" {
  count = var.create_dashboards && var.athena_datasource_enabled ? 1 : 0

  folder = grafana_folder.nhp[0].uid
  config_json = templatefile("${path.module}/dashboards/aws-cost.json", {
    athena_uid  = grafana_data_source.athena[0].uid
    environment = var.environment
  })

  overwrite = true
}

# ==============================================================================
# NHP Logs Dashboard (CloudWatch Logs Insights)
# ==============================================================================

resource "grafana_dashboard" "nhp_logs" {
  count = var.create_dashboards && var.cloudwatch_datasource_enabled ? 1 : 0

  folder = grafana_folder.nhp[0].uid
  config_json = templatefile("${path.module}/dashboards/nhp-logs.json", {
    environment = var.environment
  })

  overwrite = true
}
