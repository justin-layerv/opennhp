# Pin the IAM-coverage lint's regex to handle indexed managed-policy
# attachments (count-gated `aws_iam_policy.X[<idx>].arn`). cr feedback
# round 1: without the indexed match, count-gated managed policies were
# silently dropped from the action union.
#
# Real-world example this models:
#   terraform/modules/ecr/main.tf:1802
#     aws_iam_role_policy_attachment ... policy_arn = aws_iam_policy.plugin_bucket_write[0].arn

data "aws_secretsmanager_secret" "lint_test" {
  name = "fixture-secret"
}
