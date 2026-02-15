# Plugins Module
# Unified S3 bucket for NHP Server and Traefik plugins
#
# This module provides:
# - S3 bucket for plugin binaries (uploaded by plugin repo CI/CD)
# - S3 objects for plugin configs (rendered by Terraform)
# - IAM policies for plugin repos to upload binaries
# - IAM policies for EC2 instances to download plugins
#
# S3 Bucket Structure:
# s3://layerv-nhp-{env}-plugins/
# ├── nhp-server/
# │   ├── passcode/
# │   │   ├── v1.0.0/main.so
# │   │   └── latest/main.so
# │   └── oidc/
# │       ├── v1.0.0/main.so
# │       └── latest/main.so
# ├── traefik/
# │   └── nhp-token-validator/
# │       ├── v1.0.0/(plugin files)
# │       └── latest/(plugin files)
# └── configs/
#     ├── nhp-server/
#     │   ├── passcode/config.toml
#     │   └── oidc/config.toml
#     └── traefik/
#         └── nhp-token-validator/config.toml

# ==================== S3 Bucket ====================

resource "aws_s3_bucket" "plugins" {
  bucket = "${var.name_prefix}-plugins"

  tags = merge(var.tags, {
    Purpose   = "NHP plugin storage"
    Component = "plugins"
  })
}

resource "aws_s3_bucket_versioning" "plugins" {
  bucket = aws_s3_bucket.plugins.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "plugins" {
  bucket = aws_s3_bucket.plugins.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn != null ? "aws:kms" : "AES256"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = var.kms_key_arn != null
  }
}

resource "aws_s3_bucket_public_access_block" "plugins" {
  bucket = aws_s3_bucket.plugins.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lifecycle rule to clean up old versions (keep last 5)
resource "aws_s3_bucket_lifecycle_configuration" "plugins" {
  bucket = aws_s3_bucket.plugins.id

  rule {
    id     = "cleanup-old-versions"
    status = "Enabled"

    # Apply to all objects in bucket
    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    # Keep noncurrent versions for 30 days before transitioning
    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "STANDARD_IA"
    }
  }
}

# ==================== Plugin Configs (Rendered by Terraform) ====================

# Note: NHP Server plugins are now statically compiled into the server binary.
# No S3 storage or config files needed for server plugins.

# Traefik plugin configs (if any)
resource "aws_s3_object" "traefik_plugin_configs" {
  for_each = { for k, v in var.traefik_plugins : k => v if length(v.config) > 0 }

  bucket       = aws_s3_bucket.plugins.id
  key          = "configs/traefik/${each.key}/config.toml"
  content_type = "text/plain"

  content = join("\n", concat(
    ["# ${each.key} Traefik plugin configuration", "# Managed by Terraform - do not edit manually", ""],
    [for k, v in each.value.config : "${k} = \"${v}\""]
  ))

  tags = merge(var.tags, {
    Plugin = each.key
    Type   = "config"
  })
}

# ==================== IAM Policy for Plugin Repos (Upload) ====================

# Policy document for plugin repos to upload binaries
data "aws_iam_policy_document" "plugin_upload" {
  # Allow plugin repos to upload binaries
  statement {
    sid    = "PluginUpload"
    effect = "Allow"

    actions = [
      "s3:PutObject",
      "s3:PutObjectAcl",
      "s3:GetObject",
      "s3:ListBucket"
    ]

    resources = [
      aws_s3_bucket.plugins.arn,
      "${aws_s3_bucket.plugins.arn}/nhp-server/*",
      "${aws_s3_bucket.plugins.arn}/traefik/*"
    ]
  }

  # KMS permissions required when bucket uses KMS encryption
  dynamic "statement" {
    for_each = var.kms_key_arn != null ? [1] : []
    content {
      sid    = "PluginUploadKMS"
      effect = "Allow"
      actions = [
        "kms:GenerateDataKey",
        "kms:Decrypt",
        "kms:DescribeKey"
      ]
      resources = [var.kms_key_arn]
    }
  }
}

# Standalone policy that can be attached to GitHub Actions role
resource "aws_iam_policy" "plugin_upload" {
  name        = "${var.name_prefix}-plugin-upload"
  description = "Allows plugin repos to upload binaries to S3"
  policy      = data.aws_iam_policy_document.plugin_upload.json

  tags = var.tags
}

# ==================== IAM Policy for EC2 Instances (Download) ====================

# Policy document for EC2 instances to download plugins and configs
data "aws_iam_policy_document" "plugin_download" {
  statement {
    sid    = "PluginDownload"
    effect = "Allow"

    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:ListBucket"
    ]

    resources = [
      aws_s3_bucket.plugins.arn,
      "${aws_s3_bucket.plugins.arn}/*"
    ]
  }

  # KMS permissions required when bucket uses KMS encryption
  dynamic "statement" {
    for_each = var.kms_key_arn != null ? [1] : []
    content {
      sid       = "PluginDownloadKMS"
      effect    = "Allow"
      actions   = ["kms:Decrypt", "kms:DescribeKey"]
      resources = [var.kms_key_arn]
    }
  }
}

# Standalone policy that can be attached to EC2 instance roles
resource "aws_iam_policy" "plugin_download" {
  name        = "${var.name_prefix}-plugin-download"
  description = "Allows EC2 instances to download plugins from S3"
  policy      = data.aws_iam_policy_document.plugin_download.json

  tags = var.tags
}

# ==================== Plugin Manifest ====================

# Create a manifest file that lists all configured Traefik plugins
# Note: NHP Server plugins are now statically compiled - not in manifest
resource "aws_s3_object" "manifest" {
  bucket       = aws_s3_bucket.plugins.id
  key          = "manifest.json"
  content_type = "application/json"

  content = jsonencode({
    generated_at = timestamp()
    environment  = var.environment
    # NHP Server plugins are now statically compiled into the server binary
    # No S3 download needed - they're built into the Docker image
    traefik_plugins = {
      for k, v in var.traefik_plugins : k => {
        version    = v.version
        plugin_key = "traefik/${k}/${v.version}/"
        config_key = length(v.config) > 0 ? "configs/traefik/${k}/config.toml" : null
      }
    }
  })

  tags = merge(var.tags, {
    Type = "manifest"
  })

  lifecycle {
    ignore_changes = [content] # Timestamp changes every apply
  }
}
