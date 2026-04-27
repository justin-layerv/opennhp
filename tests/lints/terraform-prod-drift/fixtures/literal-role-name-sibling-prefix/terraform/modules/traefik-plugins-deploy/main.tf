# Sibling module: declares its own github_actions role with a
# different prefix (`traefik-plugins-prod-github-actions`). The
# attachment uses a literal-name string. Pre-fix, the substring
# match would credit this attachment's actions to the canonical NHP
# role; post-fix, the prefix anchor (`nhp-`) rules it out.

resource "aws_iam_role" "github_actions" {
  name               = "traefik-plugins-prod-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_policy" "cloudformation_grants" {
  name = "traefik-plugins-cloudformation"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "TraefikStackRead"
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

resource "aws_iam_role_policy_attachment" "cloudformation" {
  role       = "traefik-plugins-prod-github-actions"
  policy_arn = aws_iam_policy.cloudformation_grants.arn
}
