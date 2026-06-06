resource "aws_iam_role" "app" {
  name               = "fixture-app"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "kms_ifexists" {
  name = "kms-ifexists"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "KMSDecryptIfExists"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = "*"
        Condition = {
          StringEqualsIfExists = {
            "aws:ResourceAccount" = "111122223333"
          }
        }
      }
    ]
  })
}
