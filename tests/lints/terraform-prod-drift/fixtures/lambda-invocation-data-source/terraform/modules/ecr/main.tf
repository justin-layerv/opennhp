resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "lambda_status" {
  name = "lambda-status"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "InvokeStatus"
      Effect   = "Allow"
      Action   = "lambda:InvokeFunction"
      Resource = "*"
    }]
  })
}
