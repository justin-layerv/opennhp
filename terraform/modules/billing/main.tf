# Billing Module
#
# Deploys infrastructure for Stripe billing integration:
# - Checkout session Lambda (creates Stripe Checkout/Portal sessions)
# - Stripe webhook Lambda (processes Stripe webhook events)
# - Usage reporter Lambda (SQS consumer, reports metered usage to Stripe)
# - Reconciliation Lambda (daily, compares usage counts)
# - Payment grace Lambda (hourly, freezes past-due accounts)
# - Invoices Lambda (returns customer invoices from Stripe)
# - API Gateway HTTP API with JWT authorizer
# - SQS queue + DLQ for usage events
# - EventBridge scheduled rules

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
  is_prod   = var.environment == "prod"
  component = "billing"
  has_sns   = var.sns_topic_arn != null

  # Build Secrets Manager ARN patterns for IAM policies
  stripe_secret_arn         = "arn:aws:secretsmanager:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:secret:${var.stripe_secret_name}-*"
  stripe_webhook_secret_arn = "arn:aws:secretsmanager:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:secret:${var.stripe_webhook_secret_name}-*"

  has_audit_table = var.billing_audit_table_arn != ""
}
