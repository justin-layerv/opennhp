# Apply role granting the full alarm-family action set the map requires:
# the three create verbs (PutMetricAlarm / PutCompositeAlarm / PutDashboard),
# plus read/delete/tag. DeleteAlarms covers both metric and composite
# alarm destroy (there is no separate DeleteCompositeAlarms action).

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
          "cloudwatch:PutCompositeAlarm",
          "cloudwatch:PutDashboard",
          "cloudwatch:GetDashboard",
          "cloudwatch:DescribeAlarms",
          "cloudwatch:DeleteAlarms",
          "cloudwatch:DeleteDashboards",
          "cloudwatch:ListTagsForResource",
          "cloudwatch:TagResource",
          "cloudwatch:UntagResource"
        ]
        Resource = "*"
      }
    ]
  })
}
