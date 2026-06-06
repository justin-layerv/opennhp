resource "aws_iam_role" "app" {
  name               = "fixture-app"
  assume_role_policy = "{}"

  inline_policy {
    name = "kms-inline"

    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Sid      = "KMSDecryptInline"
          Effect   = "Allow"
          Action   = "kms:Decrypt"
          Resource = "*"
        }
      ]
    })
  }
}
