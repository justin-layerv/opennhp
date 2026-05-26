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
#
# NOTE: GSIs use hash_key/range_key attributes instead of key_schema blocks.
# The key_schema syntax causes perpetual plan diffs in the AWS provider (PR #399).

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
    hash_key        = "customer_id"
    projection_type = "ALL"
  }

  # GSI: Find licenses by expiration date (for renewal reminders, compliance reports)
  # Query pattern: Query by customer_id with expires_at range condition
  # Example: "Find all licenses for customer X expiring before date Y"
  # Note: This is a per-customer query, not a global expiration scan.
  # For global expiration queries, use a table scan with FilterExpression (rare operation).
  global_secondary_index {
    name            = "expires_at-index"
    hash_key        = "customer_id"
    range_key       = "expires_at"
    projection_type = "KEYS_ONLY"
  }

  # GSI: Find license by Auth0 subject
  # Query pattern: Query by auth0_subject to map Auth0 user to license
  # Example: "Find license for Auth0 user auth0|507f1f77bcf86cd799439011"
  global_secondary_index {
    name            = "auth0_subject-index"
    hash_key        = "auth0_subject"
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
    Name      = "${var.name_prefix}-${var.cell_id}-resources"
    Component = "dynamodb"
    Cell      = var.cell_id
    Purpose   = "Resource definitions"
  })
}

# ==================== nhp_ack_tokens Table ====================
# Stores short-lived ACK token validation metadata for the NHP server fleet.
#
# PK: token_hash (String) - SHA256 hash of the AC-issued ACK token
# Attributes: resource_id, user identity fields, knock_src_ip, run_id,
#             open_time, expires_at_nanos, ttl
#
# The raw token is never stored. /nhp/internal/token/validate first checks the
# in-process tokenStore, then uses this table on a local miss so validation is
# not pinned to the NHP instance that minted the ACK token.

resource "aws_dynamodb_table" "ack_tokens" {
  name         = "${var.name_prefix}-${var.cell_id}-ack-tokens"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "token_hash"

  attribute {
    name = "token_hash"
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

  # ACK tokens are intentionally short-lived. The app still enforces
  # ExpireTime at read time because DynamoDB TTL deletion is eventual.
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-${var.cell_id}-ack-tokens"
    Component = "nhp-server"
    Cell      = var.cell_id
    Purpose   = "ACK token validation metadata"
  })
}

# ==================== IAM Policy for Server Storage Access ====================
# This policy is attached to NHP Server IAM roles.
#
# The resource name stays `dynamodb_read` to avoid Terraform state churn from
# renaming a long-lived policy. The policy now also includes bounded server
# writes for AC assignments and ACK token metadata.

resource "aws_iam_policy" "dynamodb_read" {
  name        = "${var.name_prefix}-dynamodb-read"
  description = "Read access to NHP DynamoDB tables, plus bounded server writes for AC assignment and ACK token metadata"

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
        Resource = concat([
          aws_dynamodb_table.licenses.arn,
          "${aws_dynamodb_table.licenses.arn}/index/*",
          aws_dynamodb_table.ac_assignments.arn,
          "${aws_dynamodb_table.ac_assignments.arn}/index/*",
          aws_dynamodb_table.server_ac_index.arn,
          aws_dynamodb_table.resources.arn,
          "${aws_dynamodb_table.resources.arn}/index/*"
          ], var.deploy_qurl_tables ? [
          aws_dynamodb_table.qurl_domains[0].arn,
          "${aws_dynamodb_table.qurl_domains[0].arn}/index/*",
          aws_dynamodb_table.qurl_access_codes[0].arn,
          "${aws_dynamodb_table.qurl_access_codes[0].arn}/index/*",
          # Read-only for nhp-server's knock path; writes flow via
          # `qurl_table_arns` to the qurl-service task role.
          aws_dynamodb_table.qurl_agent_keys[0].arn,
          "${aws_dynamodb_table.qurl_agent_keys[0].arn}/index/*",
        ] : [])
      },
      {
        Sid    = "DynamoDBWriteACAssignments"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem"
        ]
        Resource = [
          aws_dynamodb_table.ac_assignments.arn
        ]
      },
      {
        Sid    = "DynamoDBAckTokenReadWrite"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem"
        ]
        Resource = [
          aws_dynamodb_table.ack_tokens.arn
        ]
      }
      ], var.kms_key_arn != null ? [{
        # Encrypt/GenerateDataKey are required for nhp-server PutItem calls
        # into KMS-encrypted DynamoDB tables (ack_tokens and ac_assignments).
        # ViaService + CallerAccount keep the broadened verbs scoped to this
        # account's DynamoDB service path, not arbitrary direct KMS use.
        Sid      = "KMSReadAndServerWrite"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]
        Resource = [var.kms_key_arn]
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id
            "kms:ViaService"    = "dynamodb.${data.aws_region.current.id}.amazonaws.com"
          }
        }
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
        Resource = concat([
          aws_dynamodb_table.licenses.arn,
          "${aws_dynamodb_table.licenses.arn}/index/*",
          aws_dynamodb_table.ac_assignments.arn,
          "${aws_dynamodb_table.ac_assignments.arn}/index/*",
          aws_dynamodb_table.server_ac_index.arn,
          aws_dynamodb_table.resources.arn,
          "${aws_dynamodb_table.resources.arn}/index/*"
          ], var.deploy_qurl_tables ? [
          aws_dynamodb_table.qurl_domains[0].arn,
          "${aws_dynamodb_table.qurl_domains[0].arn}/index/*",
          aws_dynamodb_table.qurl_access_codes[0].arn,
          "${aws_dynamodb_table.qurl_access_codes[0].arn}/index/*",
          # qurl_agent_keys intentionally excluded — writes are the
          # qurl-service path; add only when a Console support UX
          # (delete-agent, re-key) is explicitly designed.
        ] : [])
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
# GSIs (in declaration order below):
#   - owner-index            (owner_id → created_at)
#   - owner-expires-index    (owner_id → expires_at)
#   - owner-target-hash-index (owner_id → target_url_hash; find-or-create dedup)
#   - status-index           (status   → expires_at; KEYS_ONLY, expiring-soon scan)
#   - custom-domain-index    (custom_domain; domain routing)
#   - owner-alias-index      (owner_id → alias; sparse, tenant-scoped alias lookup)
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

  attribute {
    name = "expires_at"
    type = "S"
  }

  # GSI: Find resources by owner, sorted by creation time (newest first with ScanIndexForward=false)
  global_secondary_index {
    name            = "owner-index"
    hash_key        = "owner_id"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  # GSI: Find resources by owner, sorted by expiration time (soonest first with ScanIndexForward=true)
  global_secondary_index {
    name            = "owner-expires-index"
    hash_key        = "owner_id"
    range_key       = "expires_at"
    projection_type = "ALL"
  }

  attribute {
    name = "target_url_hash"
    type = "S"
  }

  # GSI: Find resource by owner + target URL hash for deduplication (find-or-create pattern)
  # Uses SHA-256 hash (64 bytes) instead of raw target_url to stay within DynamoDB's 1024-byte sort key limit
  global_secondary_index {
    name            = "owner-target-hash-index"
    hash_key        = "owner_id"
    range_key       = "target_url_hash"
    projection_type = "ALL"
  }

  attribute {
    name = "status"
    type = "S"
  }

  # GSI: Query active resources by expiration window (for expiring-soon gauge reconciliation)
  global_secondary_index {
    name            = "status-index"
    hash_key        = "status"
    range_key       = "expires_at"
    projection_type = "KEYS_ONLY"
  }

  attribute {
    name = "custom_domain"
    type = "S"
  }

  # GSI: Find resource by custom domain (for domain-based routing)
  global_secondary_index {
    name            = "custom-domain-index"
    hash_key        = "custom_domain"
    projection_type = "ALL"
  }

  attribute {
    name = "alias"
    type = "S"
  }

  # GSI: Find resource by owner + alias (sparse — only resources with an alias appear)
  # Used for tenant-scoped alias lookup (e.g., Slack /qurl get $<alias>).
  # Application layer enforces alias shape (slug, ≤ 64 chars, normalized
  # lowercase per qurl-service domain validation) — DynamoDB itself only
  # caps the range key at 1024 bytes, which is well above any product cap.
  #
  # Uniqueness on (owner_id, alias) is NOT enforced by this index. GSIs
  # are eventually consistent and don't accept conditional writes, and the
  # base-table PK is resource_id (not owner_id) — so query-then-write
  # against the GSI has a TOCTOU window, and a single-item
  # attribute_not_exists(resource_id) only fences resource_id collisions.
  # qurl-service is responsible for adding an atomic alias-reservation
  # mechanism (e.g., a sentinel item written via TransactWriteItems) so
  # concurrent creates for the same (owner_id, alias) collapse to one
  # resource. Without that, the by-alias GET surfaces whichever item the
  # GSI happens to materialize first. See qurl-service alias domain
  # (PR-3a.2) for the actual mechanism.
  global_secondary_index {
    name            = "owner-alias-index"
    hash_key        = "owner_id"
    range_key       = "alias"
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
    Name      = "${var.name_prefix}-${var.cell_id}-qurl-resources"
    Cell      = var.cell_id
    Component = "qurl-service"
    Purpose   = "QURL resource definitions"
  })
}

# qurl-access-tokens: Stores access tokens (hashed)
# PK: token_hash, SK: sk (single-table design with "TOKEN" sort key)
# GSI: resource-token-index (query tokens by resource)
# GSI: time-bucket-index (scanner Lambda, queried per minute-bucket)
#
# Two expiration-flavored attributes co-exist intentionally:
#   - `ttl`         (numeric epoch)    — DynamoDB auto-deletion attribute
#   - `expires_at`  (RFC3339 string)   — time-bucket-index GSI sort key
# Writer-enforced invariants (in qurl-service, not by DDB):
#   1. The wall-clock time `ttl` decodes to is later than the
#      wall-clock time `expires_at` decodes to — the scanner
#      Lambda sees the row before DDB TTL reaps it.
#   2. The .UTC() canonicalization in qurl-service's writer
#      (internal/service/qurl_token_service.go) keeps every
#      `expires_at` value at a UTC offset so RFC3339 lex order
#      equals chronological order on the GSI.
# The two fields use different encodings on purpose: DDB TTL
# requires a numeric epoch; the GSI's RFC3339 sort key requires
# string lex-order. They are not directly comparable as wire
# values, and each serves a different layer (qurl-service vs.
# DDB TTL reaper).
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

  # expires_at_bucket_shard / expires_at — the time-bucket-index GSI
  # composite PK (`{ExpiresAtBucket}#{ExpiresAtShard}`) and SK. See
  # the GSI block below for the sharding rationale; PK shape is
  # documented in the qurl-service schema registry comment for
  # GSITimeBucketIndex (internal/repository/dynamodb/schema.go).
  # SK uses type "S" because qurl-service marshals time.Time via
  # the dynamodbav default (RFC3339 string), and RFC3339 lex order
  # matches chronological order — so the scanner's "give me expired
  # qURLs" range query works against string AttributeValues.
  #
  # ASSUMES UTC: RFC3339 lex order only equals chronological order
  # when every row uses the same UTC offset. A single non-UTC
  # `time.Time` (e.g., from a future writer that forgot to
  # canonicalize a parsed user-supplied timestamp) would be
  # invisible to the scanner's range query. The canonicalization
  # is enforced in qurl-service's writer — see the LOAD-BEARING
  # UTC normalization in
  # internal/service/qurl_token_service.go's UpdateQurlToken
  # (.UTC() calls on both ExpiresAt and ExtendBy assignment paths,
  # added defensively for this exact invariant). Don't loosen
  # that without coordinating with this GSI's correctness.
  attribute {
    name = "expires_at_bucket_shard"
    type = "S"
  }

  attribute {
    name = "expires_at"
    type = "S"
  }

  # GSI: Find tokens by resource
  global_secondary_index {
    name            = "resource-token-index"
    hash_key        = "resource_id"
    projection_type = "ALL"
  }

  # GSI: Time-bucket scanner index. Queried by the qurl-service
  # expiry-scanner Lambda to find qURLs whose lifecycle just closed
  # (per minute-bucket). Sharded ×16 so a 1000-recipient `/qurl
  # send` to the same expiry minute doesn't hot-partition a single
  # PK. Both the hash function AND the shard count (16) are owned
  # by qurl-service — see `GSITimeBucketIndex` in
  # internal/repository/dynamodb/schema.go for the canonical algorithm
  # and `TimeBucketIndexShards` for the shard count. The GSI itself
  # only sees pre-hashed PK strings ({bucket}#{shard}), so changing
  # the shard count or hash on the qurl-service side does not
  # require a Terraform PR — both are free to change with their
  # own coordination. Writes are populated by qurl-service on every
  # qURL Create + Update, plus a one-shot backfill cmd for rows
  # that pre-date the introduction of the keys.
  #
  # SK is NOT unique by design: two qURLs minted in the same shard
  # at the same nanosecond have identical (PK, SK). DynamoDB GSIs
  # permit duplicate keys (base-table PK uniqueness is what enforces
  # row identity); the scanner Lambda's per-bucket pagination must
  # tolerate multiple items at the same `expires_at`.
  #
  # AWS only allows ONE GSI add/drop per UpdateTable call. Adding
  # a second GSI to this table in the same PR requires staging the
  # change across two applies; not applicable today, just a fence
  # for the next contributor.
  #
  # Projection ALL: the scanner Lambda needs the full row (per-row
  # marker fields, resource_id, etc.) to decide which qURLs still
  # need a qurl.expired webhook. KEYS_ONLY would save storage but
  # force a second GetItem per row. ALL also matches the existing
  # resource-token-index convention on this table. Cost trade-off:
  # storage and GSI write-capacity cost ~2× on bucketed rows (every
  # qURL with a positive ExpiresAt) — favors latency-per-scan over
  # storage at expected table sizes (1225 prod / 4092 sandbox items
  # today, ≤ 1M expected steady-state). qurl_resources' status-index
  # uses KEYS_ONLY for a similar expiring-soon pattern, so the
  # KEYS_ONLY/ALL precedent on this module is mixed; ALL is the
  # right call here because the scanner-Lambda hot path is
  # latency-sensitive (per-minute cadence).
  global_secondary_index {
    name            = "time-bucket-index"
    hash_key        = "expires_at_bucket_shard"
    range_key       = "expires_at"
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
    hash_key        = "owner_id"
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
    Name      = "${var.name_prefix}-${var.cell_id}-qurl-webhooks"
    Cell      = var.cell_id
    Component = "qurl-service"
    Purpose   = "QURL webhook configurations"
  })
}

# qurl-webhook-deliveries: Stores webhook delivery attempts
# PK: delivery_id
# GSI: webhook-index (query deliveries by webhook for history)
# GSI: status-date-index (query failed deliveries for retry processing, time-sharded)
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
    name = "status_date"
    type = "S"
  }

  attribute {
    name = "next_retry_at"
    type = "S"
  }

  # GSI: Find deliveries by webhook, sorted by creation time (for delivery history)
  global_secondary_index {
    name            = "webhook-index"
    hash_key        = "webhook_id"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  # GSI: Find deliveries by status for retry processing
  # Uses time-sharded partition key (status#YYYY-MM-DD) to avoid hot partitions.
  # Bare "status" has only 2-3 values, causing all items to hash to the same partition.
  # Query pattern: status_date = "retrying#YYYY-MM-DD" AND next_retry_at <= now()
  global_secondary_index {
    name            = "status-date-index"
    hash_key        = "status_date"
    range_key       = "next_retry_at"
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

# qurl-api-keys: Stores API key hashes and metadata
# PK: key_hash (SHA-256 of plaintext key)
# GSI: owner-index (list keys by owner), key-id-index (lookup by public key ID)
resource "aws_dynamodb_table" "qurl_api_keys" {
  count = var.deploy_qurl_tables ? 1 : 0

  name                        = "${var.name_prefix}-${var.cell_id}-qurl-api-keys"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "key_hash"
  deletion_protection_enabled = local.is_prod

  attribute {
    name = "key_hash"
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

  attribute {
    name = "key_id"
    type = "S"
  }

  # GSI: List API keys by owner, sorted by creation time
  global_secondary_index {
    name            = "owner-index"
    hash_key        = "owner_id"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  # GSI: Look up API key by public key ID (for CRUD operations)
  global_secondary_index {
    name            = "key-id-index"
    hash_key        = "key_id"
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

  # TTL for revoked key cleanup (30 days after revocation)
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-${var.cell_id}-qurl-api-keys"
    Cell      = var.cell_id
    Component = "qurl-service"
    Purpose   = "QURL API key storage"
  })
}

# qurl-agent-keys: sidecar agent registrations from the bootstrap path.
# PK=owner_id, SK=agent_id (regex ^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$ or
# server-generated UUIDv7). Bootstrap (qurl-service) writes the agent's
# X25519 public key; nhp-server Query's `pubkey-index` on knock receipt
# (60s LRU in front). Schema authored here so the qurl-service repo can
# mirror; full attribute list lives in the qurl-service schema-registry
# entry. `last_seen_at` is a separate RFC3339 string (second precision —
# fractional seconds break string-comparison sort order) so operators
# don't do epoch math; numeric `ttl` (last_seen + 90d) drives DDB
# eviction.
#
# Pubkey uniqueness is a SOFT invariant — DynamoDB GSIs don't enforce
# it. A re-bootstrap under a FRESH `agent_id` orphans the prior row's
# pubkey until TTL eviction, so the reader's Query could return >1 item.
#
# Defense posture today (writer-side soft + reader-side forensic):
#   - qurl-service AgentKeysRepository.Upsert reads the pubkey-index GSI
#     before every write and emits a WARN log on cross-tenant squat
#     detection (`agent bootstrap: cross-tenant pubkey squatting
#     detected`). It does NOT reject the write.
#   - nhp-server reader (endpoints/server/agent_peer_lookup.go::
#     queryAndCache) queries with Limit=2 and admits Items[0]
#     (multi-tenant separation is enforced at the qurl-service auth
#     layer where owner_id is the principal). When the GSI returns
#     >1 row for the same pubkey, the reader emits the
#     `MetricAgentLookupPubkeyCollision` counter + a WARN log so
#     operators see writer-side invariant violations in real time
#     without coupling to the qurl-service deploy. One extra
#     projected attribute set on the no-collision path is negligible.
#
# Hard uniqueness (TransactWriteItems against a claims sidecar table)
# is tracked in qurl-service #488; until it lands, an attacker that
# achieves the rare write-time race window can squat a pubkey and the
# reader will admit them — the collision counter is the only
# in-process signal of that until #488 ships.
# TODO: revisit DoS-amplification cost ceiling if billing_mode
# below moves off PAY_PER_REQUEST (unknown-pubkey lookups intentionally
# bypass the in-process LRU; the bound is rate_limit × 1 Query per
# distinct pubkey-per-window — see the godoc on `AgentPeerLookup`).
resource "aws_dynamodb_table" "qurl_agent_keys" {
  count = var.deploy_qurl_tables ? 1 : 0

  name                        = "${var.name_prefix}-${var.cell_id}-qurl-agent-keys"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "owner_id"
  range_key                   = "agent_id"
  deletion_protection_enabled = local.is_prod

  attribute {
    name = "owner_id"
    type = "S"
  }

  attribute {
    name = "agent_id"
    type = "S"
  }

  attribute {
    name = "public_key"
    type = "S"
  }

  # KEYS_ONLY so the hot `last_seen_at` keepalive write doesn't rewrite the
  # GSI on every knock (PAY_PER_REQUEST charges WCU per GSI item write).
  # Query on `public_key` returns the projected (owner_id, agent_id) in 1
  # RTT — the auth path doesn't need the base row. A follow-up GetItem
  # fetches aux metadata only when needed (hostname/version/last_seen_at).
  global_secondary_index {
    name            = "pubkey-index"
    hash_key        = "public_key"
    projection_type = "KEYS_ONLY"
  }

  point_in_time_recovery {
    enabled = local.is_prod
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  # qurl-service sets `ttl` = last_seen_at + 90d so dormant agents age out
  # without a GC reconciler. `last_seen_at` (RFC3339) is the human-readable
  # twin operators read.
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-${var.cell_id}-qurl-agent-keys"
    Cell      = var.cell_id
    Component = "qurl-service"
    Purpose   = "Sidecar agent X25519 public-key registry: bootstrap to knock"
  })
}

# qurl-customers: Stores customer records for quota and billing
# PK: auth0_subject (Auth0 user ID or "email:<sha256>" for bridge keys)
resource "aws_dynamodb_table" "qurl_customers" {
  count = var.deploy_qurl_tables ? 1 : 0

  name                        = "${var.name_prefix}-${var.cell_id}-qurl-customers"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "auth0_subject"
  deletion_protection_enabled = local.is_prod

  attribute {
    name = "auth0_subject"
    type = "S"
  }

  attribute {
    name = "stripe_customer_id"
    type = "S"
  }

  attribute {
    name = "email"
    type = "S"
  }

  # Webhook looks up auth0_subject (table PK) by stripe_customer_id.
  # KEYS_ONLY is sufficient — the PK is always projected.
  global_secondary_index {
    name            = "stripe-customer-id-index"
    hash_key        = "stripe_customer_id"
    projection_type = "KEYS_ONLY"
  }

  # Customer support lookup by email address.
  # ALL projection so the full customer record is returned without a table fetch.
  # Sparse index: only items with a non-empty email are indexed (M2M clients and
  # bridge keys won't appear).
  global_secondary_index {
    name            = "email-index"
    hash_key        = "email"
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
    Name      = "${var.name_prefix}-${var.cell_id}-qurl-customers"
    Cell      = var.cell_id
    Component = "qurl-service"
    Purpose   = "QURL customer records"
  })
}

# qurl-billing-audit: Stores billing event audit trail
# PK: owner_id, SK: event_id
resource "aws_dynamodb_table" "qurl_billing_audit" {
  count = var.deploy_qurl_tables ? 1 : 0

  name                        = "${var.name_prefix}-${var.cell_id}-qurl-billing-audit"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "owner_id"
  range_key                   = "event_id"
  deletion_protection_enabled = local.is_prod

  attribute {
    name = "owner_id"
    type = "S"
  }

  attribute {
    name = "event_id"
    type = "S"
  }

  attribute {
    name = "event_type"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  # GSI for cross-owner time-range queries (e.g. "all account_frozen events in the last hour")
  global_secondary_index {
    name               = "event-type-timestamp-index"
    hash_key           = "event_type"
    range_key          = "timestamp"
    projection_type    = "INCLUDE"
    non_key_attributes = ["owner_id"]
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

  # TTL for automatic cleanup (2-year retention)
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-${var.cell_id}-qurl-billing-audit"
    Cell      = var.cell_id
    Component = "qurl-service"
    Purpose   = "QURL billing audit trail"
  })
}

# qurl-domains: Stores custom domain registrations
# PK: domain (String) - the domain name (e.g., "secure.example.com")
# GSI: owner-index (query domains by owner)
# GSI: status-index (query domains by status for verification polling)
resource "aws_dynamodb_table" "qurl_domains" {
  count = var.deploy_qurl_tables ? 1 : 0

  name                        = "${var.name_prefix}-${var.cell_id}-qurl-domains"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "domain"
  deletion_protection_enabled = local.is_prod

  attribute {
    name = "domain"
    type = "S"
  }

  attribute {
    name = "owner_id"
    type = "S"
  }

  attribute {
    name = "status"
    type = "S"
  }

  attribute {
    name = "cert_status"
    type = "S"
  }

  # GSI: Find domains by owner
  global_secondary_index {
    name            = "owner-index"
    hash_key        = "owner_id"
    range_key       = "domain"
    projection_type = "ALL"
  }

  # GSI: Find domains by status (for verification polling)
  # Uses domain as sort key to distribute reads within status partitions
  # and enable efficient key-condition queries.
  global_secondary_index {
    name            = "status-index"
    hash_key        = "status"
    range_key       = "domain"
    projection_type = "ALL"
  }

  # GSI: Find domains by cert status (for renewal scanning and failure tracking)
  global_secondary_index {
    name            = "cert-status-index"
    hash_key        = "cert_status"
    range_key       = "domain"
    projection_type = "KEYS_ONLY"
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

  # TTL for cleaning up revoked domains after 30 days
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-${var.cell_id}-qurl-domains"
    Cell      = var.cell_id
    Component = "qurl-service"
    Purpose   = "Custom domain registrations"
  })
}

# qurl-access-codes: Access codes for resource sharing (redeemed via /login?tab=code)
# PK: access_code_id
# GSI: code-hash-index (lookup by hashed code), owner-index (list codes by owner)
resource "aws_dynamodb_table" "qurl_access_codes" {
  count = var.deploy_qurl_tables ? 1 : 0

  name         = "${var.name_prefix}-${var.cell_id}-qurl-access-codes"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "access_code_id"

  attribute {
    name = "access_code_id"
    type = "S"
  }

  attribute {
    name = "code_hash"
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

  global_secondary_index {
    name            = "code-hash-index"
    hash_key        = "code_hash"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "owner-index"
    hash_key        = "owner_id"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = var.environment == "prod"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-${var.cell_id}-qurl-access-codes"
    Component = "qurl"
    Table     = "access-codes"
  })
}

# qurl-idempotency: Distributed idempotency cache for multi-instance QURL
# PK: pk (SHA-256 hash of owner_id:key:method:path)
# TTL: ttl (auto-expire cached responses)
resource "aws_dynamodb_table" "qurl_idempotency" {
  count = var.deploy_qurl_tables ? 1 : 0

  name                        = "${var.name_prefix}-${var.cell_id}-qurl-idempotency"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "pk"
  deletion_protection_enabled = local.is_prod # Data is ephemeral but protect prod from accidental deletion

  attribute {
    name = "pk"
    type = "S"
  }

  point_in_time_recovery {
    enabled = local.is_prod
  }

  # TTL for automatic cleanup (entries expire after 24h by default)
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  # Server-side encryption with KMS
  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-${var.cell_id}-qurl-idempotency"
    Cell      = var.cell_id
    Component = "qurl-service"
    Purpose   = "Distributed idempotency cache"
  })
}

# qurl-apikey-idempotency: dedicated idempotency cache for the
# `POST /v1/api-keys` mint path. Separated from the generic
# `qurl-idempotency` table because:
#   1. The stored response envelope contains the plaintext API key (one-
#      time-only return on a successful mint). Tighter IAM blast radius
#      means the api-key-management code can read replays without
#      granting it access to every cached qurl-service response.
#   2. The mint path uses TransactWriteItems across (qurl-api-keys,
#      this table) so either both rows land or neither does — orphan-on-
#      crash becomes structurally impossible at the service layer.
#      Generic post-hoc response caching in the qurl-idempotency table
#      can't make that guarantee.
#
# PK: pk (SHA-256 hash of owner_id:idempotency_key, scoped per discord
#         OAuth state mint). TTL: 24h (matches qurl-idempotency).
resource "aws_dynamodb_table" "qurl_apikey_idempotency" {
  count = var.deploy_qurl_tables ? 1 : 0

  name                        = "${var.name_prefix}-${var.cell_id}-qurl-apikey-idempotency"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "pk"
  deletion_protection_enabled = local.is_prod

  attribute {
    name = "pk"
    type = "S"
  }

  point_in_time_recovery {
    enabled = local.is_prod
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-${var.cell_id}-qurl-apikey-idempotency"
    Cell      = var.cell_id
    Component = "qurl-service"
    Purpose   = "Idempotency cache for POST /v1/api-keys mint"
  })
}
