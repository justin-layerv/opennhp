# Bootstrap Module
# Creates S3 bucket and DynamoDB table for Terraform state
#
# ⚠️ ORPHANED — DO NOT APPLY AS-IS. This module declares an UNSUFFIXED bucket
# (`layerv-terraform-state`) that does not exist. The live state buckets are
# account-suffixed (`layerv-terraform-state-767397897469` /
# `layerv-terraform-state-235500187906`), were created out-of-band, and are
# referenced only by name in `environments/<env>/backend.tf`. Applying this
# module would create the wrong (unsuffixed) bucket + a `terraform-locks`
# table that nothing uses. Reconciling or removing this module is tracked in
# https://github.com/layervai/nhp/issues/2359. For state-bucket encryption
# (SSE-KMS), see `docs/runbooks/tfstate-kms-migration.md`.

provider "aws" {
  region = "us-east-2"
}

resource "aws_s3_bucket" "terraform_state" {
  bucket = "layerv-terraform-state"

  tags = {
    Name      = "Terraform State"
    ManagedBy = "Terraform"
  }
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    apply_server_side_encryption_by_default {
      # ⚠️ Do NOT copy this line: the live state buckets must use aws:kms
      # (#1128). This whole module is orphaned (see header); reconcile in #2359.
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_dynamodb_table" "terraform_locks" {
  name         = "terraform-locks"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  tags = {
    Name      = "Terraform Locks"
    ManagedBy = "Terraform"
  }
}

output "state_bucket" {
  value = aws_s3_bucket.terraform_state.id
}

output "lock_table" {
  value = aws_dynamodb_table.terraform_locks.name
}
