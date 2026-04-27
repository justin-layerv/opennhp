# Reproduces the sibling case of #1316: an aws_ecr_registry_policy
# carries a Condition with aws:SourceArn (instead of aws:SourceAccount).
# AWS does not populate either key for ECR's cross-account replication
# service-linked role — same failure mode. The denylist lint must catch
# both.

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
          ArnEquals = {
            "aws:SourceArn" = "arn:aws:iam::000000000000:root"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}
