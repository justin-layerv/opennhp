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
  uid                          = "qurl"
  title                        = var.folder_name
  prevent_destroy_if_not_empty = true
}

# QURL Operations Dashboard
# Monitors HTTP RED metrics (Rate, Errors, Duration) and DynamoDB performance
resource "grafana_dashboard" "operations" {
  folder = grafana_folder.qurl.uid
  config_json = templatefile("${path.module}/dashboards/qurl-operations.json", {
    datasource_uid = var.prometheus_datasource_uid
    tempo_uid      = var.tempo_datasource_uid
    loki_uid       = var.loki_datasource_uid
    environment    = var.environment
  })

  overwrite = true
}

# QURL Business Dashboard
# Monitors business metrics: QURLs created, tokens, quotas
resource "grafana_dashboard" "business" {
  folder = grafana_folder.qurl.uid
  config_json = templatefile("${path.module}/dashboards/qurl-business.json", {
    datasource_uid = var.prometheus_datasource_uid
    environment    = var.environment
  })

  overwrite = true
}

# QURL Webhooks Dashboard
# Monitors webhook delivery metrics and health
resource "grafana_dashboard" "webhooks" {
  folder = grafana_folder.qurl.uid
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
  count                        = (var.cloudwatch_datasource_enabled || var.athena_datasource_enabled || var.loki_datasource_enabled) ? 1 : 0
  uid                          = "nhp"
  title                        = var.nhp_folder_name
  prevent_destroy_if_not_empty = true
}

# NHP Infrastructure Dashboard
# Uses templatefile() to inject exact CloudWatch dimension values from module
# outputs. This is required because Grafana's CloudWatch plugin only supports
# "*" (match all) or exact dimension values — partial wildcards like
# "nhp-sandbox-*" silently match nothing. Pass exact ARN suffixes and ASG
# names from compute/AC module outputs to ensure panels query the right resources.
resource "grafana_dashboard" "nhp_infrastructure" {
  count = var.cloudwatch_datasource_enabled ? 1 : 0

  folder = grafana_folder.nhp[0].uid
  config_json = templatefile("${path.module}/dashboards/nhp-infrastructure.json", {
    cloudwatch_uid        = grafana_data_source.cloudwatch[0].uid
    environment           = var.environment
    server_nlb_arn_suffix = var.server_nlb_arn_suffix
    ac_nlb_arn_suffix     = var.ac_nlb_arn_suffix
    server_asg_name       = var.server_asg_name
    ac_asg_name           = var.ac_asg_name
    name_prefix           = var.name_prefix
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
  name = "Amazon Athena"

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
  count = var.athena_datasource_enabled ? 1 : 0

  folder = grafana_folder.nhp[0].uid
  config_json = templatefile("${path.module}/dashboards/aws-cost.json", {
    athena_uid  = grafana_data_source.athena[0].uid
    environment = var.environment
  })

  overwrite = true
}

# ==============================================================================
# Input Validation
# ==============================================================================

check "loki_datasource_uid_required" {
  assert {
    condition     = !var.loki_datasource_enabled || length(var.loki_datasource_uid) > 0
    error_message = "loki_datasource_uid must be set when loki_datasource_enabled is true."
  }
}

check "cloudwatch_log_groups_should_be_set" {
  assert {
    condition = !var.cloudwatch_datasource_enabled || (
      length(var.server_log_group_name) > 0 &&
      length(var.ac_log_group_name) > 0
    )
    error_message = "server_log_group_name and ac_log_group_name should be set when cloudwatch_datasource_enabled is true, otherwise NHP Logs dashboard panels will show no data. Pass these from compute and AC module outputs."
  }
}

check "cloudwatch_dimensions_should_be_set" {
  assert {
    condition = !var.cloudwatch_datasource_enabled || (
      length(var.server_nlb_arn_suffix) > 0 &&
      length(var.server_asg_name) > 0
    )
    error_message = "server_nlb_arn_suffix and server_asg_name should be set when cloudwatch_datasource_enabled is true, otherwise NHP Infrastructure dashboard panels will show no data. Pass these from compute module outputs."
  }
}

# ==============================================================================
# NHP Logs Dashboard (CloudWatch Logs Insights)
# ==============================================================================

resource "grafana_dashboard" "nhp_logs" {
  count = var.cloudwatch_datasource_enabled ? 1 : 0

  folder = grafana_folder.nhp[0].uid
  config_json = templatefile("${path.module}/dashboards/nhp-logs.json", {
    cloudwatch_uid   = grafana_data_source.cloudwatch[0].uid
    environment      = var.environment
    server_log_group = var.server_log_group_name
    ac_log_group     = var.ac_log_group_name
  })

  overwrite = true
}
