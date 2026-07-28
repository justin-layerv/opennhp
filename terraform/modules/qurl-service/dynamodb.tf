# qurl-service-owned DynamoDB tables. New qurl-service-owned tables go here;
# shared qurl tables consumed through var.dynamodb_table_arns live in
# modules/dynamodb/main.tf.

locals {
  # DATA-plane prefix, deliberately NOT local.resource_name_prefix.
  #
  # qurl-service resolves every table in its compiled schema registry as
  # "${DYNAMODB_TABLE_PREFIX}-<table>", and container_env in main.tf sets
  # DYNAMODB_TABLE_PREFIX from var.dynamodb_table_prefix. A table this module
  # OWNS is still addressed by the app through that same registry, so its
  # physical name must be built from the data prefix. local.resource_name_prefix
  # is the PHYSICAL prefix for ECS/ALB/SSM names and carries no promise of
  # matching the data prefix.
  #
  # The two are identical for every caller that leaves resource_name_prefix
  # unset -- cell0 passes name_prefix "layerv-nhp-sandbox" + cell_id "cell0" and
  # dynamodb_table_prefix "${name_prefix}-${cell_id}", so both render
  # "layerv-nhp-sandbox-cell0". That coincidence kept the bug latent.
  # sandbox-cell1 is the first caller to decouple them: it pins
  # resource_name_prefix to "layerv-nhp-sandbox" so cell_id appears exactly once
  # in ECS/ALB names, while its root name_prefix already contains "cell1" and so
  # its tables legitimately carry the "…-cell1-cell1" data prefix. Building this
  # table from the physical prefix produced a table the app never looks up and
  # the task role is never granted, so the readiness reconciler reported
  # permanent schema drift for "qurl-external-identities" and /health/ready
  # stayed 503.
  #
  # Fallback keeps the var's "" default working for callers that never set it
  # (module tests), reproducing the historical name byte-for-byte.
  dynamodb_owned_table_prefix = (
    var.dynamodb_table_prefix != ""
    ? var.dynamodb_table_prefix
    : "${local.resource_name_prefix}-${var.cell_id}"
  )
}

# qurl-external-identities: Stores external provider identity bindings
# for POST /v1/external-identity-bindings.
#
# Schema MUST mirror qurl-service PR #904 commit
# 7791fcc3cdddb8957ccaeb6c319f73d68372589b
# `internal/repository/dynamodb/schema.go::TableExternalIdentities`
# exactly. The table is part of qurl-service's compiled schema registry,
# so the readiness reconciler requires it even before the external-bindings
# endpoint is enabled.
#
# PK: pk ("{provider}#{external_id}")
# GSI: owner-index (owner_id + created_at; required by qurl-service #904
# schema and consumed by the binding-list/rotation surface tracked in
# qurl-service #910)
# qurl-service #904 writes created_at with a fixed-width nanosecond RFC3339
# layout so DynamoDB string ordering matches chronological ordering.
# No TTL: bindings are persistent until application-managed rotation/remediation.
resource "aws_dynamodb_table" "qurl_external_identities" {
  name                        = "${local.dynamodb_owned_table_prefix}-qurl-external-identities"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "pk"
  deletion_protection_enabled = local.is_prod

  attribute {
    name = "pk"
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
    name            = "owner-index"
    hash_key        = "owner_id"
    range_key       = "created_at"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = local.is_prod
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.secrets_kms_key_arn
  }

  lifecycle {
    precondition {
      condition     = var.secrets_kms_key_arn != null && var.secrets_kms_key_arn != ""
      error_message = "qurl_external_identities requires secrets_kms_key_arn to be non-empty. Wire module.kms.secrets_key_arn from the root into the qurl-service module so the table remains CMK-encrypted like the shared qurl DynamoDB tables."
    }
  }

  tags = merge(var.tags, {
    Name      = "${local.dynamodb_owned_table_prefix}-qurl-external-identities"
    Cell      = var.cell_id
    Component = "qurl-service"
    Purpose   = "External provider identity bindings"
  })
}
