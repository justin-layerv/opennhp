# Pre-fix state of the github_actions role: a sibling policy is here so
# the role isn't policy-empty, but NO `cloudformation:*` grant exists.
# This is the #1323 condition — the IAM-coverage lint must flag the
# data source's missing actions.

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "ecr_push" {
  name = "ecr-push"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ECRAuth"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      }
    ]
  })
}
