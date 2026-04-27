# cr round 7 fence: `*IfExists` operators (e.g., StringEqualsIfExists)
# evaluate to true when the key is absent — the documented mitigation
# for unpopulated keys. The lint must NOT flag them alongside the bare
# StringEquals form. This fixture pairs `aws:SourceAccount` with
# `StringEqualsIfExists` and asserts both lints exit clean.

resource "aws_ecr_registry_policy" "replication" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowReplicationFromPrimaryWithIfExistsGuard"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::000000000000:root"
        }
        Action = [
          "ecr:CreateRepository",
          "ecr:ReplicateImage"
        ]
        Resource = "arn:aws:ecr:us-east-1:111111111111:repository/layerv/*"
        Condition = {
          StringEqualsIfExists = {
            "aws:SourceAccount" = "000000000000"
          }
        }
      }
    ]
  })
}
