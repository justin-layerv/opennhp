resource "aws_iam_group" "app" {
  name = "fixture-app"
}

resource "aws_iam_group_policy" "kms_group" {
  name  = "kms-group"
  group = aws_iam_group.app.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "KMSDecryptGroupPolicy"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = "*"
      }
    ]
  })
}
