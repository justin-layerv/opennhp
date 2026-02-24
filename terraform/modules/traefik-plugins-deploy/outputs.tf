# Traefik Plugins Deploy Module - Outputs

output "role_arn" {
  description = "ARN of the GitHub Actions IAM role for traefik-plugins deployments"
  value       = aws_iam_role.github_actions.arn
}

output "role_name" {
  description = "Name of the GitHub Actions IAM role"
  value       = aws_iam_role.github_actions.name
}

output "deploy_bucket_name" {
  description = "Name of the S3 bucket for staging plugin tarballs"
  value       = aws_s3_bucket.deploy.id
}

output "deploy_bucket_arn" {
  description = "ARN of the S3 deploy bucket"
  value       = aws_s3_bucket.deploy.arn
}

output "deploy_doc_name" {
  description = "Name of the SSM deploy document"
  value       = aws_ssm_document.deploy.name
}

output "rollback_doc_name" {
  description = "Name of the SSM rollback document"
  value       = aws_ssm_document.rollback.name
}
