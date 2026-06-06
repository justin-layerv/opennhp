resource "aws_kms_key" "app" {
  description = "fixture"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowServiceDecrypt"
        Effect    = "Allow"
        Principal = { Service = "logs.amazonaws.com" }
        Action    = "kms:Decrypt"
        Resource  = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = "111122223333"
          }
        }
      }
    ]
  })
}
