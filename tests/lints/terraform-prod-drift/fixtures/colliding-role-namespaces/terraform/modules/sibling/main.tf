# Unrelated module that happens to declare its own
# `aws_iam_role.github_actions` for a different purpose. Within HCL, this
# module's `aws_iam_role.github_actions.id` resolves to ITS role, not the
# canonical one. The lint must NOT credit this grant to the canonical
# role. (Mirrors `terraform/modules/traefik-plugins-deploy/main.tf:33`.)

resource "aws_iam_role" "github_actions" {
  name               = "fixture-sibling-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "cloudformation_grant" {
  name = "cloudformation-grant"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "WouldSatisfyTheCanonicalGapButShouldnt"
        Effect = "Allow"
        Action = [
          "cloudformation:DescribeStacks",
          "cloudformation:GetTemplate"
        ]
        Resource = "*"
      }
    ]
  })
}
