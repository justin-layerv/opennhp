resource "aws_iam_role" "app" {
  name               = "fixture-app"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "kms_glob" {
  name = "kms-glob"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "KMSWildcardAction"
        Effect   = "Allow"
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })
}
