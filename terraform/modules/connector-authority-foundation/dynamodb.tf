locals {
  control_table_names = {
    api_keys            = "${local.control_table_prefix}-qurl-api-keys"
    agent_keys          = "${local.control_table_prefix}-qurl-agent-keys"
    customers           = "${local.control_table_prefix}-qurl-customers"
    api_key_idempotency = "${local.control_table_prefix}-qurl-apikey-idempotency"
    connector_authority = "${local.control_table_prefix}-connector-authority"
  }
}

resource "aws_dynamodb_table" "api_keys" {
  name                        = local.control_table_names.api_keys
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

  global_secondary_index {
    name            = "owner-index"
    hash_key        = "owner_id"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "key-id-index"
    hash_key        = "key_id"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = local.is_prod
  }
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.authority_data.arn
  }
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = merge(local.common_tags, {
    Name    = local.control_table_names.api_keys
    Purpose = "Canonical Connector credential registry"
  })
}

resource "aws_dynamodb_table" "agent_keys" {
  name                        = local.control_table_names.agent_keys
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
    kms_key_arn = aws_kms_key.authority_data.arn
  }
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = merge(local.common_tags, {
    Name    = local.control_table_names.agent_keys
    Purpose = "Canonical Connector X25519 identity registry"
  })
}

resource "aws_dynamodb_table" "customers" {
  name                        = local.control_table_names.customers
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

  global_secondary_index {
    name            = "stripe-customer-id-index"
    hash_key        = "stripe_customer_id"
    projection_type = "KEYS_ONLY"
  }

  global_secondary_index {
    name            = "email-index"
    hash_key        = "email"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = local.is_prod
  }
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.authority_data.arn
  }

  tags = merge(local.common_tags, {
    Name    = local.control_table_names.customers
    Purpose = "Canonical Connector owner and quota records"
  })
}

resource "aws_dynamodb_table" "api_key_idempotency" {
  name                        = local.control_table_names.api_key_idempotency
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
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.authority_data.arn
  }
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = merge(local.common_tags, {
    Name    = local.control_table_names.api_key_idempotency
    Purpose = "Canonical API-key mint idempotency"
  })
}

# One table owns cell catalog, sticky assignments, public-key claims, owner
# counters, consumed ticket JTIs, and completion-candidate sentinels. All
# access is exact PK/SK or a strongly consistent registry-partition query; no
# GSI is required by the frozen authority contract.
resource "aws_dynamodb_table" "connector_authority" {
  name                        = local.control_table_names.connector_authority
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "pk"
  range_key                   = "sk"
  deletion_protection_enabled = local.is_prod

  attribute {
    name = "pk"
    type = "S"
  }
  attribute {
    name = "sk"
    type = "S"
  }

  point_in_time_recovery {
    enabled = local.is_prod
  }
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.authority_data.arn
  }
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = merge(local.common_tags, {
    Name    = local.control_table_names.connector_authority
    Purpose = "Global Connector cell registry and assignment authority"
  })
}
