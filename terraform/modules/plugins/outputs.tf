# Plugins Module Outputs

output "bucket_name" {
  description = "Name of the S3 bucket for plugins"
  value       = aws_s3_bucket.plugins.id
}

output "bucket_arn" {
  description = "ARN of the S3 bucket for plugins"
  value       = aws_s3_bucket.plugins.arn
}

output "bucket_regional_domain_name" {
  description = "Regional domain name of the S3 bucket"
  value       = aws_s3_bucket.plugins.bucket_regional_domain_name
}

# IAM Policies

output "upload_policy_arn" {
  description = "ARN of the IAM policy for uploading plugins (attach to GitHub Actions role)"
  value       = aws_iam_policy.plugin_upload.arn
}

output "download_policy_arn" {
  description = "ARN of the IAM policy for downloading plugins (attach to EC2 instance roles)"
  value       = aws_iam_policy.plugin_download.arn
}

# Plugin Information

# Note: NHP Server plugins are now statically compiled into the server binary.
# No S3 output needed - they're built into the Docker image.

output "traefik_plugins" {
  description = "Map of configured Traefik plugins with S3 keys"
  value = {
    for k, v in var.traefik_plugins : k => {
      version    = v.version
      plugin_key = "traefik/${k}/${v.version}/"
      config_key = length(v.config) > 0 ? "configs/traefik/${k}/config.toml" : null
    }
  }
}

output "manifest_key" {
  description = "S3 key for the plugin manifest file"
  value       = aws_s3_object.manifest.key
}
