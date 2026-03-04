# Cost Analytics Module
# AWS Data Exports (CUR 2.0) → S3 (Parquet) → Glue → Athena → Grafana
#
# All resources run in the management/payer account (us-east-1).
# Consolidated billing: payer account sees costs for ALL linked accounts.
#
# NOTE: The caller must pass a single aws provider pointing to mgmt us-east-1.
# No configuration_aliases needed — the module receives a default provider.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

# ==============================================================================
# S3 Bucket for Cost Data
# ==============================================================================

resource "aws_s3_bucket" "cost_data" {
  bucket = "${var.name_prefix}-cost-data"

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-cost-data"
    Component = "cost-analytics"
  })
}

resource "aws_s3_bucket_versioning" "cost_data" {
  bucket = aws_s3_bucket.cost_data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cost_data" {
  bucket = aws_s3_bucket.cost_data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256" # SSE-S3 required by Data Exports
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cost_data" {
  bucket                  = aws_s3_bucket.cost_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "cost_data" {
  bucket = aws_s3_bucket.cost_data.id

  rule {
    id     = "noncurrent-cleanup"
    status = "Enabled"

    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "STANDARD_IA"
    }

    noncurrent_version_expiration {
      noncurrent_days = 365
    }
  }

  rule {
    id     = "athena-results-cleanup"
    status = "Enabled"

    filter {
      prefix = "athena-results/"
    }

    expiration {
      days = 7
    }
  }
}

resource "aws_s3_bucket_policy" "cost_data" {
  bucket = aws_s3_bucket.cost_data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowBCMDataExports"
        Effect = "Allow"
        Principal = {
          Service = [
            "bcm-data-exports.amazonaws.com",
            "billingreports.amazonaws.com"
          ]
        }
        Action = [
          "s3:PutObject",
          "s3:GetBucketPolicy"
        ]
        Resource = [
          aws_s3_bucket.cost_data.arn,
          "${aws_s3_bucket.cost_data.arn}/*"
        ]
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# ==============================================================================
# BCM Data Export (CUR 2.0)
# ==============================================================================

resource "aws_bcmdataexports_export" "cost_usage" {
  export {
    name = "${var.name_prefix}-cost-usage"

    data_query {
      # CUR 2.0 nested map columns: product and resource_tags.
      # Dot notation extracts keys; AS aliases match Glue table column names.
      query_statement = <<-SQL
        SELECT
          identity_line_item_id, identity_time_interval,
          bill_payer_account_id, bill_billing_period_start_date,
          line_item_usage_account_id, line_item_product_code,
          line_item_usage_type, line_item_operation,
          line_item_line_item_type, line_item_unblended_cost,
          line_item_blended_cost, line_item_usage_amount,
          line_item_currency_code, product_instance_type,
          pricing_unit,
          product.product_name AS product_product_name,
          product.region AS product_region,
          resource_tags
        FROM COST_AND_USAGE_REPORT
      SQL

      table_configurations = {
        COST_AND_USAGE_REPORT = {
          TIME_GRANULARITY                      = "DAILY"
          INCLUDE_RESOURCES                     = "TRUE"
          INCLUDE_MANUAL_DISCOUNT_COMPATIBILITY = "FALSE"
          INCLUDE_SPLIT_COST_ALLOCATION_DATA    = "FALSE"
          BILLING_VIEW_ARN                      = "arn:${data.aws_partition.current.partition}:billing::${data.aws_caller_identity.current.account_id}:billingview/primary"
        }
      }
    }

    destination_configurations {
      s3_destination {
        s3_bucket = aws_s3_bucket.cost_data.bucket
        s3_prefix = "exports"
        s3_region = "us-east-1"

        s3_output_configurations {
          overwrite   = "OVERWRITE_REPORT"
          format      = "PARQUET"
          compression = "PARQUET"
          output_type = "CUSTOM"
        }
      }
    }

    refresh_cadence {
      frequency = "SYNCHRONOUS"
    }
  }

  depends_on = [aws_s3_bucket_policy.cost_data]
}

# ==============================================================================
# Glue Database + Table (Partition Projection)
# ==============================================================================
# Partition projection eliminates the need for Glue Crawlers:
# - Zero cost (crawlers charge per DPU-hour)
# - Zero latency (crawlers take minutes)
# - Athena auto-discovers partitions from the range parameter

resource "aws_glue_catalog_database" "cost" {
  name = "${replace(var.name_prefix, "-", "_")}_cost"
}

resource "aws_glue_catalog_table" "cost_usage" {
  name          = "cost_and_usage"
  database_name = aws_glue_catalog_database.cost.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    "classification"                          = "parquet"
    "projection.enabled"                      = "true"
    "projection.billing_period.type"          = "date"
    "projection.billing_period.format"        = "yyyy-MM"
    "projection.billing_period.range"         = "2025-01,2099-12"
    "projection.billing_period.interval"      = "1"
    "projection.billing_period.interval.unit" = "MONTHS"
    "storage.location.template"               = "s3://${aws_s3_bucket.cost_data.bucket}/exports/${var.name_prefix}-cost-usage/data/BILLING_PERIOD=$${billing_period}"
  }

  partition_keys {
    name = "billing_period"
    type = "string"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.cost_data.bucket}/exports/"
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
    }

    columns {
      name = "identity_line_item_id"
      type = "string"
    }
    columns {
      name = "identity_time_interval"
      type = "string"
    }
    columns {
      name = "bill_payer_account_id"
      type = "string"
    }
    columns {
      name = "bill_billing_period_start_date"
      type = "string"
    }
    columns {
      name = "line_item_usage_account_id"
      type = "string"
    }
    columns {
      name = "line_item_product_code"
      type = "string"
    }
    columns {
      name = "line_item_usage_type"
      type = "string"
    }
    columns {
      name = "line_item_operation"
      type = "string"
    }
    columns {
      name = "line_item_line_item_type"
      type = "string"
    }
    columns {
      name = "line_item_unblended_cost"
      type = "double"
    }
    columns {
      name = "line_item_blended_cost"
      type = "double"
    }
    columns {
      name = "line_item_usage_amount"
      type = "double"
    }
    columns {
      name = "line_item_currency_code"
      type = "string"
    }
    columns {
      name = "product_product_name"
      type = "string"
    }
    columns {
      name = "product_region"
      type = "string"
    }
    columns {
      name = "product_instance_type"
      type = "string"
    }
    columns {
      name = "pricing_unit"
      type = "string"
    }
    columns {
      name = "resource_tags"
      type = "map<string,string>"
    }
  }
}

# ==============================================================================
# Athena Workgroup
# ==============================================================================

resource "aws_athena_workgroup" "cost" {
  name = "${var.name_prefix}-cost-analytics"

  configuration {
    result_configuration {
      output_location = "s3://${aws_s3_bucket.cost_data.bucket}/athena-results/"
      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
    enforce_workgroup_configuration = true
    bytes_scanned_cutoff_per_query  = 1073741824 # 1 GB = $0.005 max/query
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-cost-analytics"
    Component = "cost-analytics"
  })
}

# ==============================================================================
# IAM Role for Grafana Cloud Athena Access
# ==============================================================================
# Same trust pattern as the CloudWatch role in grafana-dashboards/main.tf

resource "aws_iam_role" "grafana_athena" {
  name = "${var.name_prefix}-grafana-athena"

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
    Name      = "${var.name_prefix}-grafana-athena"
    Component = "cost-analytics"
  })
}

# ==============================================================================
# Cost Allocation Tag Activation
# ==============================================================================
# Tags must be activated in the management/payer account for them to appear
# in CUR data. Without activation, resource_tags in Athena will be empty
# and the Grafana "Spend by Service Tag" panel shows only "untagged".
#
# NOTE: After activation, tags only appear in NEW CUR data (not retroactive).
# It may take up to 24 hours for newly activated tags to appear.
#
# Service is now managed by the native Terraform CE resource to avoid masking
# unexpected failures from a local-exec fallback.
resource "aws_ce_cost_allocation_tag" "service" {
  tag_key = "Service"
  status  = "Active"
}

resource "aws_ce_cost_allocation_tag" "environment" {
  tag_key = "Environment"
  status  = "Active"
}

resource "aws_ce_cost_allocation_tag" "project" {
  tag_key = "Project"
  status  = "Active"
}

resource "aws_ce_cost_allocation_tag" "cell" {
  tag_key = "Cell"
  status  = "Active"
}

resource "aws_iam_role_policy" "grafana_athena" {
  name = "${var.name_prefix}-grafana-athena-policy"
  role = aws_iam_role.grafana_athena.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AthenaQuery"
        Effect = "Allow"
        Action = [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
          "athena:StopQueryExecution",
          "athena:GetWorkGroup"
        ]
        Resource = aws_athena_workgroup.cost.arn
      },
      {
        Sid    = "AthenaCatalogBrowse"
        Effect = "Allow"
        Action = [
          "athena:GetDataCatalog",
          "athena:ListDataCatalogs",
          "athena:ListDatabases",
          "athena:ListTableMetadata",
          "athena:GetTableMetadata"
        ]
        Resource = "arn:${data.aws_partition.current.partition}:athena:us-east-1:${data.aws_caller_identity.current.account_id}:datacatalog/AwsDataCatalog"
      },
      {
        Sid      = "AthenaListWorkGroups"
        Effect   = "Allow"
        Action   = ["athena:ListWorkGroups"]
        Resource = "*"
      },
      {
        Sid    = "GlueRead"
        Effect = "Allow"
        Action = [
          "glue:GetDatabase",
          "glue:GetTable",
          "glue:GetPartitions"
        ]
        Resource = [
          "arn:${data.aws_partition.current.partition}:glue:us-east-1:${data.aws_caller_identity.current.account_id}:catalog",
          aws_glue_catalog_database.cost.arn,
          "arn:${data.aws_partition.current.partition}:glue:us-east-1:${data.aws_caller_identity.current.account_id}:table/${aws_glue_catalog_database.cost.name}/*"
        ]
      },
      {
        Sid    = "S3ReadCostData"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = [
          aws_s3_bucket.cost_data.arn,
          "${aws_s3_bucket.cost_data.arn}/*"
        ]
      },
      {
        Sid    = "S3AthenaResults"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:AbortMultipartUpload"
        ]
        Resource = "${aws_s3_bucket.cost_data.arn}/athena-results/*"
      }
    ]
  })
}
