# Sibling-module declaration of the SAME bare resource name as the
# canonical side. The lint must warn about the collision so a future
# refactor that introduces the collision lands loud.

resource "aws_iam_policy" "shared_name" {
  name = "sibling-shared-name"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WrongActionForCollision"
        Effect   = "Allow"
        Action   = ["s3:DeleteBucket"]
        Resource = "*"
      }
    ]
  })
}
