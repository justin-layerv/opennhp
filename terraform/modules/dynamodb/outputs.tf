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

output "server_ac_index_table_arn" {
  description = "ARN of the server-AC index DynamoDB table"
  value       = aws_dynamodb_table.server_ac_index.arn
}

output "ack_tokens_table_arn" {
  description = "ARN of the ACK token metadata DynamoDB table"
  value       = aws_dynamodb_table.ack_tokens.arn
}

output "session_control_table_arn" {
  description = "ARN of the durable NHP session-control authority table"
  value       = aws_dynamodb_table.session_control.arn
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

output "server_ac_index_table_name" {
  description = "Name of the server-AC index DynamoDB table"
  value       = aws_dynamodb_table.server_ac_index.name
}

output "ack_tokens_table_name" {
  description = "Name of the ACK token metadata DynamoDB table"
  value       = aws_dynamodb_table.ack_tokens.name
}

output "session_control_table_name" {
  description = "Name of the durable NHP session-control authority table"
  value       = aws_dynamodb_table.session_control.name
}

output "all_table_names" {
  description = "List of all DynamoDB table names (for monitoring)"
  value = [
    aws_dynamodb_table.licenses.name,
    aws_dynamodb_table.ac_assignments.name,
    aws_dynamodb_table.server_ac_index.name,
    aws_dynamodb_table.resources.name,
    aws_dynamodb_table.ack_tokens.name,
    aws_dynamodb_table.session_control.name,
  ]
}

# ==================== IAM Policy ARNs ====================

output "read_policy_arn" {
  description = "ARN of the IAM policy for DynamoDB read access (for NHP Server)"
  value       = aws_iam_policy.dynamodb_read.arn
}

output "read_policy_doc_hash" {
  description = "sha256 of the DynamoDB read policy doc; trigger source for NHP server IAM-propagation shims."
  value       = sha256(aws_iam_policy.dynamodb_read.policy)
}

output "write_policy_arn" {
  description = "ARN of the IAM policy for DynamoDB write access (for Console)"
  value       = aws_iam_policy.dynamodb_write.arn
}

# ==================== QURL Service Table ARNs ====================

output "qurl_resources_table_arn" {
  description = "ARN of the QURL resources DynamoDB table"
  value       = length(aws_dynamodb_table.qurl_resources) > 0 ? aws_dynamodb_table.qurl_resources[0].arn : null
}

output "qurl_access_tokens_table_arn" {
  description = "ARN of the QURL access tokens DynamoDB table"
  value       = length(aws_dynamodb_table.qurl_access_tokens) > 0 ? aws_dynamodb_table.qurl_access_tokens[0].arn : null
}

output "qurl_sessions_table_arn" {
  description = "ARN of the QURL sessions DynamoDB table"
  value       = length(aws_dynamodb_table.qurl_sessions) > 0 ? aws_dynamodb_table.qurl_sessions[0].arn : null
}

output "qurl_audit_log_table_arn" {
  description = "ARN of the QURL audit log DynamoDB table"
  value       = length(aws_dynamodb_table.qurl_audit_log) > 0 ? aws_dynamodb_table.qurl_audit_log[0].arn : null
}

output "qurl_webhooks_table_arn" {
  description = "ARN of the QURL webhooks DynamoDB table"
  value       = length(aws_dynamodb_table.qurl_webhooks) > 0 ? aws_dynamodb_table.qurl_webhooks[0].arn : null
}

output "qurl_webhook_deliveries_table_arn" {
  description = "ARN of the QURL webhook deliveries DynamoDB table"
  value       = length(aws_dynamodb_table.qurl_webhook_deliveries) > 0 ? aws_dynamodb_table.qurl_webhook_deliveries[0].arn : null
}

output "qurl_api_keys_table_arn" {
  description = "ARN of the QURL API keys DynamoDB table"
  value       = length(aws_dynamodb_table.qurl_api_keys) > 0 ? aws_dynamodb_table.qurl_api_keys[0].arn : null
}

output "qurl_api_keys_table_name" {
  description = "Name of the QURL API keys DynamoDB table"
  value       = length(aws_dynamodb_table.qurl_api_keys) > 0 ? aws_dynamodb_table.qurl_api_keys[0].name : null
}

output "qurl_customers_table_arn" {
  description = "ARN of the QURL customers DynamoDB table"
  value       = length(aws_dynamodb_table.qurl_customers) > 0 ? aws_dynamodb_table.qurl_customers[0].arn : null
}

output "qurl_customers_table_name" {
  description = "Name of the QURL customers DynamoDB table"
  value       = length(aws_dynamodb_table.qurl_customers) > 0 ? aws_dynamodb_table.qurl_customers[0].name : null
}

output "qurl_billing_audit_table_arn" {
  description = "ARN of the QURL billing audit DynamoDB table"
  value       = length(aws_dynamodb_table.qurl_billing_audit) > 0 ? aws_dynamodb_table.qurl_billing_audit[0].arn : null
}

output "qurl_billing_audit_table_name" {
  description = "Name of the QURL billing audit DynamoDB table"
  value       = length(aws_dynamodb_table.qurl_billing_audit) > 0 ? aws_dynamodb_table.qurl_billing_audit[0].name : null
}

output "qurl_domains_table_arn" {
  description = "ARN of the QURL domains DynamoDB table"
  value       = length(aws_dynamodb_table.qurl_domains) > 0 ? aws_dynamodb_table.qurl_domains[0].arn : null
}

output "qurl_domains_table_name" {
  description = "Name of the QURL domains DynamoDB table"
  value       = length(aws_dynamodb_table.qurl_domains) > 0 ? aws_dynamodb_table.qurl_domains[0].name : null
}

output "qurl_access_codes_table_arn" {
  description = "ARN of the QURL access codes table"
  value       = length(aws_dynamodb_table.qurl_access_codes) > 0 ? aws_dynamodb_table.qurl_access_codes[0].arn : null
}

output "qurl_access_codes_table_name" {
  description = "Name of the QURL access codes table"
  value       = length(aws_dynamodb_table.qurl_access_codes) > 0 ? aws_dynamodb_table.qurl_access_codes[0].name : null
}

output "qurl_idempotency_table_arn" {
  description = "ARN of the QURL idempotency DynamoDB table"
  value       = length(aws_dynamodb_table.qurl_idempotency) > 0 ? aws_dynamodb_table.qurl_idempotency[0].arn : null
}

output "qurl_idempotency_table_name" {
  description = "Name of the QURL idempotency DynamoDB table"
  value       = length(aws_dynamodb_table.qurl_idempotency) > 0 ? aws_dynamodb_table.qurl_idempotency[0].name : null
}

output "qurl_apikey_idempotency_table_arn" {
  description = "ARN of the QURL API key idempotency DynamoDB table"
  value       = length(aws_dynamodb_table.qurl_apikey_idempotency) > 0 ? aws_dynamodb_table.qurl_apikey_idempotency[0].arn : null
}

output "qurl_apikey_idempotency_table_name" {
  description = "Name of the QURL API key idempotency DynamoDB table"
  value       = length(aws_dynamodb_table.qurl_apikey_idempotency) > 0 ? aws_dynamodb_table.qurl_apikey_idempotency[0].name : null
}

output "qurl_agent_keys_table_arn" {
  description = "ARN of the QURL agent keys DynamoDB table (sidecar bootstrap registry)"
  value       = length(aws_dynamodb_table.qurl_agent_keys) > 0 ? aws_dynamodb_table.qurl_agent_keys[0].arn : null
}

output "qurl_agent_keys_table_name" {
  description = "Name of the QURL agent keys DynamoDB table (sidecar bootstrap registry)"
  value       = length(aws_dynamodb_table.qurl_agent_keys) > 0 ? aws_dynamodb_table.qurl_agent_keys[0].name : null
}

# Note: All QURL tables are created together via the deploy_qurl_tables flag,
# so checking only qurl_resources is sufficient for the conditional.
output "qurl_table_arns" {
  description = "List of all QURL DynamoDB table ARNs (for IAM permissions)"
  value = length(aws_dynamodb_table.qurl_resources) > 0 ? [
    aws_dynamodb_table.qurl_resources[0].arn,
    aws_dynamodb_table.qurl_access_tokens[0].arn,
    aws_dynamodb_table.qurl_sessions[0].arn,
    aws_dynamodb_table.qurl_audit_log[0].arn,
    aws_dynamodb_table.qurl_webhooks[0].arn,
    aws_dynamodb_table.qurl_webhook_deliveries[0].arn,
    aws_dynamodb_table.qurl_webhook_event_dedupe[0].arn,
    aws_dynamodb_table.qurl_api_keys[0].arn,
    aws_dynamodb_table.qurl_customers[0].arn,
    aws_dynamodb_table.qurl_billing_audit[0].arn,
    aws_dynamodb_table.qurl_domains[0].arn,
    aws_dynamodb_table.qurl_idempotency[0].arn,
    aws_dynamodb_table.qurl_apikey_idempotency[0].arn,
    aws_dynamodb_table.qurl_access_codes[0].arn,
    aws_dynamodb_table.qurl_agent_keys[0].arn,
    aws_dynamodb_table.qurl_v2_admissions[0].arn,
    aws_dynamodb_table.qurl_resource_key_material[0].arn,
  ] : []
}
