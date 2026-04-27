# Sibling module: declares a managed policy and exposes its ARN as a
# module output. The parent attaches it to the canonical role via
# `module.shared.write_policy_arn`.

resource "aws_iam_policy" "write" {
  name = "fixture-shared-write"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Write"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "*"
      }
    ]
  })
}

output "write_policy_arn" {
  value = aws_iam_policy.write.arn
}
