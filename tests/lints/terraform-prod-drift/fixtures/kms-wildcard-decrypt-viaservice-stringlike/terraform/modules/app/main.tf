resource "aws_iam_role" "app" {
  name               = "fixture-app"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "kms_viaservice_like" {
  name = "kms-viaservice-like"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "KMSDecryptViaServiceLike"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = "*"
        Condition = {
          StringLike = {
            "kms:ViaService" = "secretsmanager.*.amazonaws.com"
          }
        }
      }
    ]
  })
}
