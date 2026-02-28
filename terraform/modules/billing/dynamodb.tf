# Billing - DynamoDB Tables
#
# Tables owned by the billing module (not shared with other modules).

# ==============================================================================
# Webhook Deduplication Table
# ==============================================================================
# Stores processed Stripe webhook event IDs for idempotency.
# TTL automatically cleans up entries after 48 hours.

resource "aws_dynamodb_table" "webhook_dedup" {
  name         = "${var.name_prefix}-billing-webhook-dedup"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "event_id"

  attribute {
    name = "event_id"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = false # Dedup table is ephemeral, no need for PITR
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.dynamodb_kms_key_arn
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-billing-webhook-dedup"
    Component = local.component
  })
}
