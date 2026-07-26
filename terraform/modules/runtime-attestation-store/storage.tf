# -----------------------------------------------------------------------------
# Immutable per-node runtime evidence: the storage boundary.
#
# Launch-template, SSM tag, AMI, or ECR lookups cannot prove what each current
# in-service instance is actually running. This store is the evidence channel
# that can.
#
# Deliberately NOT SSM custom Inventory: `ssm:PutInventory` is not
# resource-scoped, so a single compromised instance role could forge another
# instance's row. Here each node role may only `s3:PutObject` beneath
# `runtime/${aws:userid}/`, and for an EC2 role AWS defines `aws:userid` as
# `<role-id>:<instance-id>` — the prefix is self-bound, so an instance cannot
# name, let alone write, another instance's object. Nodes get no list, read,
# delete, or overwrite-by-shared-prefix authority at all.
#
# The bucket policy below is the single artifact that carries that self-binding,
# which is exactly why the published collector contract pins its canonical
# SHA-256: the producer re-reads the live policy, canonicalizes it, and fails
# closed when it differs.
# -----------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_region" "current" {}

locals {
  bucket_arn = "arn:${data.aws_partition.current.partition}:s3:::${var.bucket_name}"

  # `$${aws:userid}` is an IAM policy variable, not Terraform interpolation.
  # For an EC2 instance role AWS substitutes `<role-id>:<instance-id>`.
  self_bound_object_arn = "${local.bucket_arn}/runtime/$${aws:userid}/*"

  node_role_arns = sort([
    for role in values(var.attested_node_roles) :
    "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/${role}"
  ])

  s3_via_service = "s3.${data.aws_region.current.region}.${data.aws_partition.current.dns_suffix}"

  tags = merge(
    {
      Component = "runtime-attestation-store"
      ManagedBy = "terraform"
    },
    var.tags,
  )
}

# ==================== KMS ====================

resource "aws_kms_key" "attestations" {
  description             = "Canonical sandbox runtime-attestation object encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  # Node roles may only wrap a data key for THIS bucket, only through S3, and
  # only for writing. With S3 Bucket Keys enabled the encryption context is the
  # bucket ARN, so the object-level self-binding is enforced by the bucket
  # policy (which the producer digests), not by the encryption context.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DelegateToAccountIAM"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowNodeWriteWrappingForThisBucketOnly"
        Effect = "Allow"
        Principal = {
          AWS = local.node_role_arns
        }
        Action = [
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService"                   = local.s3_via_service
            "kms:EncryptionContext:aws:s3:arn" = local.bucket_arn
            "aws:PrincipalAccount"             = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "DenyNodeDecrypt"
        Effect = "Deny"
        Principal = {
          AWS = local.node_role_arns
        }
        Action = [
          "kms:Decrypt",
          "kms:ReEncryptFrom",
          "kms:ReEncryptTo",
        ]
        Resource = "*"
      },
    ]
  })

  tags = merge(local.tags, { Name = "${var.name_prefix}-runtime-attestations" })
}

resource "aws_kms_alias" "attestations" {
  name          = "alias/${var.name_prefix}-runtime-attestations"
  target_key_id = aws_kms_key.attestations.key_id
}

# ==================== Bucket ====================

resource "aws_s3_bucket" "attestations" {
  bucket = var.bucket_name

  tags = merge(local.tags, { Name = var.bucket_name })

  lifecycle {
    postcondition {
      condition     = self.arn == local.bucket_arn
      error_message = "The attestation bucket ARN must equal the ARN published to SSM."
    }
  }
}

resource "aws_s3_bucket_versioning" "attestations" {
  bucket = aws_s3_bucket.attestations.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "attestations" {
  bucket = aws_s3_bucket.attestations.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "attestations" {
  bucket = aws_s3_bucket.attestations.id

  rule {
    # ACLs are disabled outright: every object is bucket-owned, so a node role
    # cannot grant anyone else access to the row it wrote.
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "attestations" {
  bucket = aws_s3_bucket.attestations.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.attestations.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "attestations" {
  bucket = aws_s3_bucket.attestations.id

  # The collector rewrites one key per instance every five minutes. Only the
  # current version is ever evidence; superseded versions are retained briefly
  # for forensics and then expired so the store cannot grow without bound.
  rule {
    id     = "expire-superseded-attestations"
    status = "Enabled"

    filter {
      prefix = "runtime/"
    }

    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_version_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  depends_on = [aws_s3_bucket_versioning.attestations]
}

# ==================== The self-binding policy ====================

locals {
  bucket_policy = {
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [local.bucket_arn, "${local.bucket_arn}/*"]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid       = "DenyPrincipalsOutsideTheSandboxAccount"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [local.bucket_arn, "${local.bucket_arn}/*"]
        Condition = {
          StringNotEquals = {
            "aws:PrincipalAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid       = "DenyUnencryptedUploads"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${local.bucket_arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      {
        Sid       = "DenyUploadsUnderAnyOtherKey"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${local.bucket_arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.attestations.arn
          }
        }
      },
      {
        Sid    = "AllowSelfBoundNodeAttestationWrites"
        Effect = "Allow"
        Principal = {
          AWS = local.node_role_arns
        }
        Action   = "s3:PutObject"
        Resource = local.self_bound_object_arn
      },
      {
        # Nodes get PutObject and nothing else — no list, read, or delete.
        Sid    = "DenyNodeAuthorityBeyondPutObject"
        Effect = "Deny"
        Principal = {
          AWS = local.node_role_arns
        }
        NotAction = "s3:PutObject"
        Resource  = [local.bucket_arn, "${local.bucket_arn}/*"]
      },
      {
        # ...and that PutObject may only ever land under this instance's own
        # `aws:userid` prefix, so one instance can never overwrite another's row.
        Sid    = "DenyNodeWritesOutsideItsOwnPrefix"
        Effect = "Deny"
        Principal = {
          AWS = local.node_role_arns
        }
        Action      = "s3:*"
        NotResource = local.self_bound_object_arn
      },
    ]
  }

  # Terraform's jsonencode and the producer's canonical encoder agree byte for
  # byte on ASCII input: both sort object keys and emit no separator padding.
  # The producer re-reads the live policy, canonicalizes it the same way, and
  # rejects any drift from this digest.
  #
  # They diverge on exactly one input class: Terraform's jsonencode inherits
  # Go's HTML escaping, so it emits a unicode escape for the three characters
  # < > and &, while the producer's encoder writes them literally. No IAM
  # identifier, action, condition key, or digest can contain those, so the two
  # encodings agree here — and the precondition below keeps that true.
  bucket_policy_json   = jsonencode(local.bucket_policy)
  bucket_policy_sha256 = sha256(local.bucket_policy_json)
}

resource "aws_s3_bucket_policy" "attestations" {
  bucket = aws_s3_bucket.attestations.id
  policy = local.bucket_policy_json

  depends_on = [aws_s3_bucket_public_access_block.attestations]

  lifecycle {
    precondition {
      condition     = !strcontains(local.bucket_policy_json, "\\u")
      error_message = "The bucket policy must encode identically for Terraform and the producer: no \\u escapes."
    }
  }
}
