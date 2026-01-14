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
# PK: customer_id (String)
# SK: resource_fqdn (String)
# Attributes: license_key_hash, tier, max_acs, expires_at, active

resource "aws_dynamodb_table" "licenses" {
  name         = "${var.name_prefix}-licenses"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "customer_id"
  range_key    = "resource_fqdn"

  attribute {
    name = "customer_id"
    type = "S"
  }

  attribute {
    name = "resource_fqdn"
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

  # TTL for automatic expiration (optional, set expires_at attribute)
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-licenses"
    Component = "dynamodb"
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
  name         = "${var.name_prefix}-ac-assignments"
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
    hash_key        = "resource_fqdn"
    projection_type = "ALL"
  }

  # GSI: List ACs by customer
  global_secondary_index {
    name            = "customer_id-index"
    hash_key        = "customer_id"
    projection_type = "ALL"
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
    Name      = "${var.name_prefix}-ac-assignments"
    Component = "dynamodb"
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
  name         = "${var.name_prefix}-server-ac-index"
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
    Name      = "${var.name_prefix}-server-ac-index"
    Component = "dynamodb"
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
  name         = "${var.name_prefix}-resources"
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
    hash_key        = "ac_id"
    projection_type = "ALL"
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
    Name      = "${var.name_prefix}-resources"
    Component = "dynamodb"
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
