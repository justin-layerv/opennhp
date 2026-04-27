# Reproduces #1316: an aws_ecr_registry_policy carries a Condition with
# aws:SourceAccount, which AWS does not populate for ECR's cross-account
# replication service-linked role. The policy-condition denylist lint
# must flag this.

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
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = "000000000000"
          }
        }
      }
    ]
  })
}

# Need a github_actions role definition so the IAM coverage lint runs to
# completion (it's a no-op here — no AWS data sources). The policy-condition
# lint operates only on the registry policy above.
resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}
