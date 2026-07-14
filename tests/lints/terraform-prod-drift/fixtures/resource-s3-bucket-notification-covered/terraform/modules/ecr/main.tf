resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "s3_bucket_notification" {
  name = "s3-bucket-notification"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3BucketNotification"
        Effect = "Allow"
        Action = [
          "s3:GetBucketNotification",
          "s3:PutBucketNotification"
        ]
        Resource = "arn:aws:s3:::fixture-bucket"
      }
    ]
  })
}
