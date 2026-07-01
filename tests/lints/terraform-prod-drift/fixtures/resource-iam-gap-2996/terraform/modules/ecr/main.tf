# Pre-fix state of the apply role: the CloudWatch grant enumerates the
# metric-alarm verbs plus read/delete/tag, but NOT
# `cloudwatch:PutCompositeAlarm`. This is the exact #2996 gap the
# composite-alarm RESOURCE_ACTIONS entry catches — the role isn't
# cloudwatch-empty, it just lacks the one distinct create verb.

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "cloudwatch" {
  name = "cloudwatch"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatch"
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricAlarm",
          "cloudwatch:DescribeAlarms",
          "cloudwatch:DeleteAlarms",
          "cloudwatch:ListTagsForResource",
          "cloudwatch:TagResource",
          "cloudwatch:UntagResource"
        ]
        Resource = "*"
      }
    ]
  })
}
