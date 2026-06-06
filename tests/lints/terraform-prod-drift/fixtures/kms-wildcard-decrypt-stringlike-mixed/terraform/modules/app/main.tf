resource "aws_iam_role" "app" {
  name               = "fixture-app"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "kms_stringlike_mixed" {
  name = "kms-stringlike-mixed"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "KMSDecryptStringLikeMixed"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = "*"
        Condition = {
          StringLike = {
            "aws:ResourceAccount" = ["111122223333", "*"]
          }
        }
      }
    ]
  })
}
