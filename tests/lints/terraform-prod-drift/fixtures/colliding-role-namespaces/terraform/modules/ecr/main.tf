# Canonical `nhp-${env}-github-actions` role's home. The IAM-coverage
# lint considers `aws_iam_role.github_actions.{id,name}` references only
# from files under modules/ecr/. This module deliberately grants no
# `cloudformation:*` actions — the missing grant is what the lint must
# flag.

resource "aws_iam_role" "github_actions" {
  name               = "fixture-canonical-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "ecr_push" {
  name = "ecr-push"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ECRAuth"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      }
    ]
  })
}

output "github_actions_role_name" {
  value = aws_iam_role.github_actions.name
}
