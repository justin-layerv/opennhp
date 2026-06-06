resource "aws_iam_role" "app" {
  name               = "fixture-app"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "kms_viaservice" {
  name = "kms-viaservice"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "KMSDecryptViaService"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService"    = "secretsmanager.us-east-1.amazonaws.com"
            "kms:CallerAccount" = "111122223333"
          }
        }
      }
    ]
  })
}
