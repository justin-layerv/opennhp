# Developer Portal Module
#
# Deploys infrastructure for the developer experience features:
# - Playground proxy Lambda (proxies requests to QURL API with M2M auth)
# - Credential provisioner Lambda (Auth0 app creation, email verification)
# - API Gateway HTTP API with CORS
# - DynamoDB tables for credentials and rate limiting

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.0"
    }
  }
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  is_prod           = var.environment == "prod"
  component         = "developer-portal"
  has_custom_domain = var.custom_domain != null && var.acm_certificate_arn != null
  has_sns           = var.sns_topic_arn != null
}

# ==============================================================================
# DynamoDB Tables
# ==============================================================================

resource "aws_dynamodb_table" "credentials" {
  name         = "${var.name_prefix}-dev-credentials"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "email"

  attribute {
    name = "email"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = local.is_prod
  }

  dynamic "server_side_encryption" {
    for_each = var.dynamodb_kms_key_arn != null ? [1] : []
    content {
      enabled     = true
      kms_key_arn = var.dynamodb_kms_key_arn
    }
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-dev-credentials"
    Component = local.component
  })
}

resource "aws_dynamodb_table" "rate_limits" {
  name         = "${var.name_prefix}-dev-rate-limits"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "ip"

  attribute {
    name = "ip"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  # No PITR - ephemeral rate limit data
  point_in_time_recovery {
    enabled = false
  }

  dynamic "server_side_encryption" {
    for_each = var.dynamodb_kms_key_arn != null ? [1] : []
    content {
      enabled     = true
      kms_key_arn = var.dynamodb_kms_key_arn
    }
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-dev-rate-limits"
    Component = local.component
  })
}
