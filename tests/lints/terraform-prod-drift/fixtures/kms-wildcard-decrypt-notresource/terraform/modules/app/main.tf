resource "aws_iam_role" "app" {
  name               = "fixture-app"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "kms_notresource" {
  name = "kms-notresource"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid         = "KMSDecryptNotResource"
        Effect      = "Allow"
        Action      = "kms:Decrypt"
        NotResource = ["arn:aws:kms:us-east-1:111122223333:key/abc-123"]
      }
    ]
  })
}
