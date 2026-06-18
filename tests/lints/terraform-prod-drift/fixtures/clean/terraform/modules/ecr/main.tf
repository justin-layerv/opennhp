# Canonical github_actions role + matching cloudformation grant for the
# clean fixture's data source.

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "cloudformation_website_api" {
  count = var.deploy_website_api_dns ? 1 : 0

  name = "cloudformation-website-api"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "WebsiteAPIStackRead"
        Effect = "Allow"
        Action = [
          "cloudformation:DescribeStacks",
          "cloudformation:GetTemplate",
          "ec2:DescribePrefixLists"
        ]
        Resource = "*"
      }
    ]
  })
}

variable "deploy_website_api_dns" {
  type    = bool
  default = true
}
