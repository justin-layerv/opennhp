resource "aws_iam_role" "app" {
  name               = "fixture-app"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "kms_notaction" {
  name = "kms-notaction"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "KMSDecryptNotAction"
        Effect    = "Allow"
        NotAction = ["s3:*"]
        Resource  = "*"
      }
    ]
  })
}
