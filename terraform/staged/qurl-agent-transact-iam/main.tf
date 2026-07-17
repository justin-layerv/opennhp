locals {
  qurl_task_role_name       = "layerv-nhp-prod-cell0-qurl-api-task"
  qurl_agent_keys_table_arn = "arn:aws:dynamodb:us-east-2:235500187906:table/layerv-nhp-prod-cell0-qurl-agent-keys"
}

# Temporary, separately-owned prerequisite for qurl-service's atomic
# registration-row + canonical-public-key-claim transaction. The legacy prod
# root cannot currently isolate this grant from unrelated state moves and
# infrastructure changes (nhp#3279), so this root owns a new inline policy
# rather than editing the legacy root's dynamodb-access policy.
resource "aws_iam_role_policy" "qurl_agent_keys_transact" {
  name = "qurl-agent-keys-transact-write"
  role = local.qurl_task_role_name

  # Keep this document in lockstep with EXPECTED_POLICY in
  # scripts/check-qurl-agent-transact-iam.py and the golden plan fixtures.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "QURLAgentKeysTransactWrite"
      Effect   = "Allow"
      Action   = ["dynamodb:TransactWriteItems"]
      Resource = [local.qurl_agent_keys_table_arn]
    }]
  })

  # Removal is separately reviewed and happens only after the transactional
  # writer is rolled back or this exact policy has transferred into main state.
  lifecycle {
    prevent_destroy = true
  }
}
