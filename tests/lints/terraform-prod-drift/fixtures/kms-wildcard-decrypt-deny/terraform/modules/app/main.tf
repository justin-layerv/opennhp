resource "aws_iam_role" "app" {
  name               = "fixture-app"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "kms_deny" {
  name = "kms-deny"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyKMSDecryptWildcard"
        Effect   = "Deny"
        Action   = "kms:Decrypt"
        Resource = "*"
      }
    ]
  })
}
