# Apply role granting the metric-alarm base verbs plus two of the three
# tag actions, deliberately omitting `cloudwatch:TagResource`. Because the
# alarm-family map requires the tag trio unconditionally (default_tags —
# see the map comment), the lint flags the single missing verb even though
# the alarm in main.tf carries no `tags` block.

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
          "cloudwatch:UntagResource"
        ]
        Resource = "*"
      }
    ]
  })
}
