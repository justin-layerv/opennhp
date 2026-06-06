resource "aws_iam_user" "app" {
  name = "fixture-app"
}

resource "aws_iam_user_policy" "kms_user" {
  name = "kms-user"
  user = aws_iam_user.app.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "KMSDecryptUserPolicy"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = "*"
      }
    ]
  })
}
