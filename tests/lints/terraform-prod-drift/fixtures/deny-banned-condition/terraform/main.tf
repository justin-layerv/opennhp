# cr round 6 fence: an `aws_ecr_registry_policy` with a banned Condition
# key on a `Deny` statement. The runbook documents this as a deliberate
# false-positive shape (the lint flags Deny too — bypass-by-comment was
# explicitly rejected, and a Deny that no-ops on an unpopulated key
# signals confusion about how the key actually evaluates). This fixture
# locks in that documented behavior.

resource "aws_ecr_registry_policy" "replication" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowReplicationFromPrimary"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::000000000000:root"
        }
        Action = [
          "ecr:CreateRepository",
          "ecr:ReplicateImage"
        ]
        Resource = "arn:aws:ecr:us-east-1:111111111111:repository/layerv/*"
      },
      {
        Sid    = "DenyOutsideSourceAccount"
        Effect = "Deny"
        Principal = {
          AWS = "*"
        }
        Action   = ["ecr:*"]
        Resource = "arn:aws:ecr:us-east-1:111111111111:repository/layerv/*"
        Condition = {
          StringNotEquals = {
            "aws:SourceAccount" = "000000000000"
          }
        }
      }
    ]
  })
}
