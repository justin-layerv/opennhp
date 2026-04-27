# Canonical role + a policy using the IAM single-dict Statement shorthand.

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "ssm_get_parameter" {
  name = "fixture-ssm-get-parameter"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = {
      Sid      = "GetParameter"
      Effect   = "Allow"
      Action   = ["ssm:GetParameter"]
      Resource = "*"
    }
  })
}
