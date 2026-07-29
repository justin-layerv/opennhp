locals {
  assignment_handshake_bucket_name    = "${var.name_prefix}-udp-proof-handshake-${data.aws_caller_identity.current.account_id}"
  assignment_handshake_bucket_arn     = "arn:${data.aws_partition.current.partition}:s3:::${local.assignment_handshake_bucket_name}"
  assignment_handshake_prefix         = "handshake/v1/"
  assignment_handshake_s3_via_service = "s3.${data.aws_region.current.region}.${data.aws_partition.current.dns_suffix}"
}

resource "aws_kms_key" "assignment_handshake" {
  description             = "One-run assignment proof checkpoints and receipts for ${var.name_prefix}"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  tags = merge(local.tags, { Name = "${var.name_prefix}-udp-proof-handshake" })
}

resource "aws_kms_alias" "assignment_handshake" {
  name          = "alias/${var.name_prefix}-udp-proof-handshake"
  target_key_id = aws_kms_key.assignment_handshake.key_id
}

resource "aws_s3_bucket" "assignment_handshake" {
  bucket = local.assignment_handshake_bucket_name
  tags   = merge(local.tags, { Name = local.assignment_handshake_bucket_name })
}

resource "aws_s3_bucket_ownership_controls" "assignment_handshake" {
  bucket = aws_s3_bucket.assignment_handshake.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "assignment_handshake" {
  bucket = aws_s3_bucket.assignment_handshake.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "assignment_handshake" {
  bucket = aws_s3_bucket.assignment_handshake.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "assignment_handshake" {
  bucket = aws_s3_bucket.assignment_handshake.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.assignment_handshake.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "assignment_handshake" {
  bucket = aws_s3_bucket.assignment_handshake.id

  rule {
    id     = "expire-proof-handshakes"
    status = "Enabled"

    filter {
      prefix = local.assignment_handshake_prefix
    }

    expiration {
      days = 1
    }

    noncurrent_version_expiration {
      noncurrent_days = 1
    }
  }

  depends_on = [aws_s3_bucket_versioning.assignment_handshake]
}

resource "aws_s3_bucket_policy" "assignment_handshake" {
  bucket = aws_s3_bucket.assignment_handshake.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Action    = "s3:*"
        Resource  = [local.assignment_handshake_bucket_arn, "${local.assignment_handshake_bucket_arn}/*"]
        Principal = "*"
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid       = "DenyUnencryptedWrites"
        Effect    = "Deny"
        Action    = "s3:PutObject"
        Resource  = "${local.assignment_handshake_bucket_arn}/${local.assignment_handshake_prefix}*"
        Principal = "*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      {
        Sid       = "DenyWrongEncryptionKey"
        Effect    = "Deny"
        Action    = "s3:PutObject"
        Resource  = "${local.assignment_handshake_bucket_arn}/${local.assignment_handshake_prefix}*"
        Principal = "*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.assignment_handshake.arn
          }
        }
      },
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.assignment_handshake]
}
