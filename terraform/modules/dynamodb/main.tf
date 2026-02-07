# DynamoDB Module
# Per-AC Server Assignment Storage for NHP
#
# This module creates DynamoDB Global Tables for:
# - nhp_licenses: Customer license validation
# - nhp_ac_assignments: AC-to-server assignment mapping
# - nhp_resources: Resource definitions per customer
#
# Part of the pluggable storage backend architecture:
# - DynamoDB is the DEFAULT for cloud deployments
# - etcd remains as a FEATURE FLAG for on-prem deployments
# See docs/design/PLUGGABLE_STORAGE_BACKEND.md for full architecture.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.29"
    }
  }
}

# ==================== Data Sources ====================

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# ==================== Locals ====================

locals {
  is_prod = var.environment == "prod"
}

# ==================== nhp_licenses Table ====================
# Stores customer license information for validation
#
# PK: license_key_sha256 (String) - SHA256 hash of the plaintext license key (globally unique)
# Attributes: license_key_hash (bcrypt), customer_id (ULID), resource_id, tier, max_acs, expires_at, active
#
# GSIs:
#   - customer_id-index: Query all licenses for a customer
#   - expires_at-index: Query licenses expiring before a given date (for renewal reminders)
#
# Note: License keys are globally unique, so no customer_id is needed for lookup.
# Customer ID (ULID format) is stored for querying and audit purposes.
# LayerV system customer uses nil ULID: 00000000000000000000000000

resource "aws_dynamodb_table" "licenses" {
  name         = "${var.name_prefix}-${var.cell_id}-licenses"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "license_key_sha256"

  attribute {
    name = "license_key_sha256"
    type = "S"
  }

  attribute {
    name = "customer_id"
    type = "S"
  }

  attribute {
    name = "expires_at"
    type = "N"
  }

  attribute {
    name = "auth0_subject"
    type = "S"
  }

  # GSI: Find all licenses for a customer
  global_secondary_index {
    name            = "customer_id-index"
    projection_type = "ALL"

    key_schema {
      attribute_name = "customer_id"
      key_type       = "HASH"
    }
  }

  # GSI: Find licenses by expiration date (for renewal reminders, compliance reports)
  # Query pattern: Query by customer_id with expires_at range condition
  # Example: "Find all licenses for customer X expiring before date Y"
  # Note: This is a per-customer query, not a global expiration scan.
  # For global expiration queries, use a table scan with FilterExpression (rare operation).
  global_secondary_index {
    name            = "expires_at-index"
    projection_type = "KEYS_ONLY"

    key_schema {
      attribute_name = "customer_id"
      key_type       = "HASH"
    }
    key_schema {
      attribute_name = "expires_at"
      key_type       = "RANGE"
    }
  }

  # GSI: Find license by Auth0 subject (for QURL quota lookup)
  # Query pattern: Query by auth0_subject to map Auth0 user to license/quota
  # Example: "Find license for Auth0 user auth0|507f1f77bcf86cd799439011"
  # Used by QURL service to determine quota plan based on license tier.
  global_secondary_index {
    name            = "auth0_subject-index"
    projection_type = "ALL"

    key_schema {
      attribute_name = "auth0_subject"
      key_type       = "HASH"
    }
  }

  # Enable point-in-time recovery for production
  point_in_time_recovery {
    enabled = local.is_prod
  }

  # Server-side encryption with KMS
  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  # TTL for automatic expiration (optional, set expires_at attribute)
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-${var.cell_id}-licenses"
    Component = "dynamodb"
    Cell      = var.cell_id
    Purpose   = "License validation"
  })
}

# ==================== nhp_ac_assignments Table ====================
# Stores AC-to-server assignment mapping
#
# PK: ac_id (String)
# Attributes: resource_fqdn, customer_id, assigned_servers, version,
#             reassigned_at, created_at, last_seen
#
# GSIs: resource_fqdn-index, customer_id-index
# Note: For server_id lookups, see nhp_server_ac_index table below.

resource "aws_dynamodb_table" "ac_assignments" {
  name         = "${var.name_prefix}-${var.cell_id}-ac-assignments"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "ac_id"

  attribute {
    name = "ac_id"
    type = "S"
  }

  attribute {
    name = "resource_fqdn"
    type = "S"
  }

  attribute {
    name = "customer_id"
    type = "S"
  }

  # GSI: Find AC by resource FQDN
  global_secondary_index {
    name            = "resource_fqdn-index"
    projection_type = "ALL"

    key_schema {
      attribute_name = "resource_fqdn"
      key_type       = "HASH"
    }
  }

  # GSI: List ACs by customer
  global_secondary_index {
    name            = "customer_id-index"
    projection_type = "ALL"

    key_schema {
      attribute_name = "customer_id"
      key_type       = "HASH"
    }
  }

  # Enable point-in-time recovery for production
  point_in_time_recovery {
    enabled = local.is_prod
  }

  # Server-side encryption with KMS
  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  # TTL for automatic cleanup (optional)
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-${var.cell_id}-ac-assignments"
    Component = "dynamodb"
    Cell      = var.cell_id
    Purpose   = "AC server assignment"
  })
}

# ==================== nhp_server_ac_index Table ====================
# Inverted index: maps server_id -> ac_id for efficient lookups
#
# This table enables efficient queries like "find all ACs assigned to server X"
# which is needed for health monitoring and reassignment when a server fails.
#
# PK: server_id (String) - The NHP server instance ID
# SK: ac_id (String) - The AC ID assigned to this server
#
# Example query (find all ACs assigned to server i-abc123):
#   aws dynamodb query \
#     --table-name nhp-sandbox-server-ac-index \
#     --key-condition-expression "server_id = :sid" \
#     --expression-attribute-values '{":sid":{"S":"i-abc123"}}'
#
# Console writes to this table when:
# - AC is created (add server_id -> ac_id mappings for each assigned server)
# - AC is deleted (remove all server_id -> ac_id mappings)
# - AC is reassigned (remove old mappings, add new mappings)
#
# Consistency model: Best-effort with fallback. Console writes to both
# ac_assignments and server_ac_index separately (not transactionally).
# If index operations fail, health monitoring falls back to table scan.
#
# Note: No GSI needed for reverse lookup (AC -> servers) since that data
# lives directly in ac_assignments.assigned_servers attribute.

resource "aws_dynamodb_table" "server_ac_index" {
  name         = "${var.name_prefix}-${var.cell_id}-server-ac-index"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "server_id"
  range_key    = "ac_id"

  attribute {
    name = "server_id"
    type = "S"
  }

  attribute {
    name = "ac_id"
    type = "S"
  }

  # Enable point-in-time recovery for production
  point_in_time_recovery {
    enabled = local.is_prod
  }

  # Server-side encryption with KMS
  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  # TTL for automatic cleanup of orphaned entries
  # Console sets TTL to 30 days from creation/update; refreshed on AC reassignment.
  # If an AC is stable (not reassigned) for >30 days, entries expire. This is intentional:
  # - Health monitor falls back to table scan if index entries are missing
  # - Truly idle ACs are rare; server health changes trigger reassignment and TTL refresh
  # - On next reassignment, entries are recreated with fresh TTL
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-${var.cell_id}-server-ac-index"
    Component = "dynamodb"
    Cell      = var.cell_id
    Purpose   = "Server to AC inverted index"
  })
}

# ==================== nhp_resources Table ====================
# Stores resource definitions per customer
#
# PK: customer_id (String)
# SK: resource_id (String)
# Attributes: resource_fqdn, ac_id, dest_host, dest_port, open_time, auth_service_id

resource "aws_dynamodb_table" "resources" {
  name         = "${var.name_prefix}-${var.cell_id}-resources"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "customer_id"
  range_key    = "resource_id"

  attribute {
    name = "customer_id"
    type = "S"
  }

  attribute {
    name = "resource_id"
    type = "S"
  }

  attribute {
    name = "ac_id"
    type = "S"
  }

  # GSI: Find resources by AC
  global_secondary_index {
    name            = "ac_id-index"
    projection_type = "ALL"

    key_schema {
      attribute_name = "ac_id"
      key_type       = "HASH"
    }
  }

  # Enable point-in-time recovery for production
  point_in_time_recovery {
    enabled = local.is_prod
  }

  # Server-side encryption with KMS
  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-${var.cell_id}-resources"
    Component = "dynamodb"
    Cell      = var.cell_id
    Purpose   = "Resource definitions"
  })
}

# ==================== IAM Policy for Read Access ====================
# This policy is attached to NHP Server IAM roles

resource "aws_iam_policy" "dynamodb_read" {
  name        = "${var.name_prefix}-dynamodb-read"
  description = "Read access to NHP DynamoDB tables for servers"

  # Use concat to conditionally include KMS statement (empty resource arrays are invalid)
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid    = "DynamoDBReadAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:DescribeTable",
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:BatchGetItem"
        ]
        Resource = [
          aws_dynamodb_table.licenses.arn,
          "${aws_dynamodb_table.licenses.arn}/index/*",
          aws_dynamodb_table.ac_assignments.arn,
          "${aws_dynamodb_table.ac_assignments.arn}/index/*",
          aws_dynamodb_table.server_ac_index.arn,
          aws_dynamodb_table.resources.arn,
          "${aws_dynamodb_table.resources.arn}/index/*"
        ]
      }
      ], var.kms_key_arn != null ? [{
        Sid      = "KMSDecrypt"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [var.kms_key_arn]
    }] : [])
  })

  tags = var.tags
}

# ==================== IAM Policy for Write Access ====================
# This policy is attached to Console IAM roles (separate repo)

resource "aws_iam_policy" "dynamodb_write" {
  name        = "${var.name_prefix}-dynamodb-write"
  description = "Write access to NHP DynamoDB tables for Console"

  # Use concat to conditionally include KMS statement (empty resource arrays are invalid)
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid    = "DynamoDBWriteAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:BatchGetItem",
          "dynamodb:BatchWriteItem"
        ]
        Resource = [
          aws_dynamodb_table.licenses.arn,
          "${aws_dynamodb_table.licenses.arn}/index/*",
          aws_dynamodb_table.ac_assignments.arn,
          "${aws_dynamodb_table.ac_assignments.arn}/index/*",
          aws_dynamodb_table.server_ac_index.arn,
          aws_dynamodb_table.resources.arn,
          "${aws_dynamodb_table.resources.arn}/index/*"
        ]
      }
      ], var.kms_key_arn != null ? [{
        Sid    = "KMSEncryptDecrypt"
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = [var.kms_key_arn]
    }] : [])
  })

  tags = var.tags
}

# ==================== QURL Service Tables ====================
# These tables are created when deploy_qurl_tables=true
# They store QURL resources, access tokens, sessions, and audit logs

# qurl-resources: Stores QURL resource definitions
# PK: resource_id, SK: sk (single-table design with "RESOURCE" sort key)
# GSI: owner-index (query resources by owner)
resource "aws_dynamodb_table" "qurl_resources" {
  count = var.deploy_qurl_tables ? 1 : 0

  name                        = "${var.name_prefix}-${var.cell_id}-qurl-resources"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "resource_id"
  range_key                   = "sk"
  deletion_protection_enabled = local.is_prod

  attribute {
    name = "resource_id"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  attribute {
    name = "owner_id"
    type = "S"
  }

  attribute {
    name = "created_at"
    type = "S"
  }

  # GSI: Find resources by owner, sorted by creation time (newest first with ScanIndexForward=false)
  global_secondary_index {
    name            = "owner-index"
    projection_type = "ALL"

    key_schema {
      attribute_name = "owner_id"
      key_type       = "HASH"
    }
    key_schema {
      attribute_name = "created_at"
      key_type       = "RANGE"
    }
  }

  # Enable point-in-time recovery for production
  point_in_time_recovery {
    enabled = local.is_prod
  }

  # Server-side encryption with KMS
  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-${var.cell_id}-qurl-resources"
    Cell      = var.cell_id
    Component = "qurl-service"
    Purpose   = "QURL resource definitions"
  })
}

# qurl-access-tokens: Stores access tokens (hashed)
# PK: token_hash, SK: sk (single-table design with "TOKEN" sort key)
# GSI: resource-token-index (query tokens by resource)
resource "aws_dynamodb_table" "qurl_access_tokens" {
  count = var.deploy_qurl_tables ? 1 : 0

  name                        = "${var.name_prefix}-${var.cell_id}-qurl-access-tokens"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "token_hash"
  range_key                   = "sk"
  deletion_protection_enabled = local.is_prod

  attribute {
    name = "token_hash"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  attribute {
    name = "resource_id"
    type = "S"
  }

  # GSI: Find tokens by resource
  global_secondary_index {
    name            = "resource-token-index"
    projection_type = "ALL"

    key_schema {
      attribute_name = "resource_id"
      key_type       = "HASH"
    }
  }

  # Enable point-in-time recovery for production
  point_in_time_recovery {
    enabled = local.is_prod
  }

  # Server-side encryption with KMS
  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  # TTL for automatic token expiration
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-${var.cell_id}-qurl-access-tokens"
    Cell      = var.cell_id
    Component = "qurl-service"
    Purpose   = "QURL access tokens"
  })
}

# qurl-sessions: Stores active sessions per resource
# PK: resource_id, SK: session_id
# Uses composite key for efficient per-resource session queries
resource "aws_dynamodb_table" "qurl_sessions" {
  count = var.deploy_qurl_tables ? 1 : 0

  name                        = "${var.name_prefix}-${var.cell_id}-qurl-sessions"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "resource_id"
  range_key                   = "session_id"
  deletion_protection_enabled = local.is_prod

  attribute {
    name = "resource_id"
    type = "S"
  }

  attribute {
    name = "session_id"
    type = "S"
  }

  # Enable point-in-time recovery for production
  point_in_time_recovery {
    enabled = local.is_prod
  }

  # Server-side encryption with KMS
  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  # TTL for automatic session expiration
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-${var.cell_id}-qurl-sessions"
    Cell      = var.cell_id
    Component = "qurl-service"
    Purpose   = "QURL active sessions"
  })
}

# qurl-audit-log: Stores audit log entries
# PK: owner_id, SK: timestamp
# Enables efficient time-range queries per owner
resource "aws_dynamodb_table" "qurl_audit_log" {
  count = var.deploy_qurl_tables ? 1 : 0

  name                        = "${var.name_prefix}-${var.cell_id}-qurl-audit-log"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "owner_id"
  range_key                   = "timestamp"
  deletion_protection_enabled = local.is_prod

  attribute {
    name = "owner_id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  # Enable point-in-time recovery for production
  point_in_time_recovery {
    enabled = local.is_prod
  }

  # Server-side encryption with KMS
  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  # TTL for automatic audit log retention (90 days default)
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-${var.cell_id}-qurl-audit-log"
    Cell      = var.cell_id
    Component = "qurl-service"
    Purpose   = "QURL audit logs"
  })
}

# qurl-webhooks: Stores webhook configurations
# PK: webhook_id
# GSI: owner-index (query webhooks by owner)
resource "aws_dynamodb_table" "qurl_webhooks" {
  count = var.deploy_qurl_tables ? 1 : 0

  name                        = "${var.name_prefix}-${var.cell_id}-qurl-webhooks"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "webhook_id"
  deletion_protection_enabled = local.is_prod

  attribute {
    name = "webhook_id"
    type = "S"
  }

  attribute {
    name = "owner_id"
    type = "S"
  }

  # GSI: Find webhooks by owner
  global_secondary_index {
    name            = "owner-index"
    projection_type = "ALL"

    key_schema {
      attribute_name = "owner_id"
      key_type       = "HASH"
    }
  }

  # Enable point-in-time recovery for production
  point_in_time_recovery {
    enabled = local.is_prod
  }

  # Server-side encryption with KMS
  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-${var.cell_id}-qurl-webhooks"
    Cell      = var.cell_id
    Component = "qurl-service"
    Purpose   = "QURL webhook configurations"
  })
}

# qurl-webhook-deliveries: Stores webhook delivery attempts
# PK: delivery_id
# GSI: webhook-index (query deliveries by webhook for history)
# GSI: status-index (query failed deliveries for retry processing)
resource "aws_dynamodb_table" "qurl_webhook_deliveries" {
  count = var.deploy_qurl_tables ? 1 : 0

  name                        = "${var.name_prefix}-${var.cell_id}-qurl-webhook-deliveries"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "delivery_id"
  deletion_protection_enabled = local.is_prod

  attribute {
    name = "delivery_id"
    type = "S"
  }

  attribute {
    name = "webhook_id"
    type = "S"
  }

  attribute {
    name = "created_at"
    type = "S"
  }

  attribute {
    name = "status"
    type = "S"
  }

  attribute {
    name = "next_retry_at"
    type = "S"
  }

  # GSI: Find deliveries by webhook, sorted by creation time (for delivery history)
  global_secondary_index {
    name            = "webhook-index"
    projection_type = "ALL"

    key_schema {
      attribute_name = "webhook_id"
      key_type       = "HASH"
    }
    key_schema {
      attribute_name = "created_at"
      key_type       = "RANGE"
    }
  }

  # GSI: Find deliveries by status for retry processing
  # Query pattern: status = "failed" AND next_retry_at < now()
  global_secondary_index {
    name            = "status-index"
    projection_type = "ALL"

    key_schema {
      attribute_name = "status"
      key_type       = "HASH"
    }
    key_schema {
      attribute_name = "next_retry_at"
      key_type       = "RANGE"
    }
  }

  # Enable point-in-time recovery for production
  point_in_time_recovery {
    enabled = local.is_prod
  }

  # Server-side encryption with KMS
  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  # TTL for automatic cleanup of old deliveries (30 days)
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-${var.cell_id}-qurl-webhook-deliveries"
    Cell      = var.cell_id
    Component = "qurl-service"
    Purpose   = "QURL webhook delivery attempts"
  })
}
