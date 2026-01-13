# DynamoDB Module Outputs

# ==================== Table ARNs ====================

output "licenses_table_arn" {
  description = "ARN of the licenses DynamoDB table"
  value       = aws_dynamodb_table.licenses.arn
}

output "ac_assignments_table_arn" {
  description = "ARN of the AC assignments DynamoDB table"
  value       = aws_dynamodb_table.ac_assignments.arn
}

output "resources_table_arn" {
  description = "ARN of the resources DynamoDB table"
  value       = aws_dynamodb_table.resources.arn
}

# ==================== Table Names ====================

output "licenses_table_name" {
  description = "Name of the licenses DynamoDB table"
  value       = aws_dynamodb_table.licenses.name
}

output "ac_assignments_table_name" {
  description = "Name of the AC assignments DynamoDB table"
  value       = aws_dynamodb_table.ac_assignments.name
}

output "resources_table_name" {
  description = "Name of the resources DynamoDB table"
  value       = aws_dynamodb_table.resources.name
}

# ==================== IAM Policy ARNs ====================

output "read_policy_arn" {
  description = "ARN of the IAM policy for DynamoDB read access (for NHP Server)"
  value       = aws_iam_policy.dynamodb_read.arn
}

output "write_policy_arn" {
  description = "ARN of the IAM policy for DynamoDB write access (for Console)"
  value       = aws_iam_policy.dynamodb_write.arn
}
