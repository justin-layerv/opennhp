# Cost Analytics Module Outputs

output "athena_workgroup_name" {
  description = "Athena workgroup name for cost queries"
  value       = aws_athena_workgroup.cost.name
}

output "glue_database_name" {
  description = "Glue database name for cost data"
  value       = aws_glue_catalog_database.cost.name
}

output "grafana_athena_role_arn" {
  description = "IAM role ARN for Grafana Cloud Athena access (in mgmt account)"
  value       = aws_iam_role.grafana_athena.arn
}

output "cost_data_bucket_name" {
  description = "S3 bucket name for cost data"
  value       = aws_s3_bucket.cost_data.bucket
}

output "athena_region" {
  description = "AWS region where Athena resources live"
  value       = "us-east-1"
}
