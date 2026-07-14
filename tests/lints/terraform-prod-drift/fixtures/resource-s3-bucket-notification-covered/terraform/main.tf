# Positive path: aws_s3_bucket_notification is action-mapped and the apply
# role grants the notification read/write verbs the provider needs.

resource "aws_s3_bucket_notification" "example" {
  bucket = "fixture-bucket"

  lambda_function {
    lambda_function_arn = "arn:aws:lambda:us-east-2:123456789012:function:fixture"
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "incidents.json"
  }
}
