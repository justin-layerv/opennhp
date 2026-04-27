# Canonical role + an `aws_iam_role_policy_attachments_exclusive`
# resource bound to the role via a hardcoded role-name string
# (`"nhp-prod-github-actions"`) instead of an HCL ref. The lint
# must recognize the `-github-actions` suffix and credit the
# attached policy's actions to the coverage union.

resource "aws_iam_role" "github_actions" {
  name               = "nhp-prod-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_policy" "cloudformation_grants" {
  name = "cloudformation-grants"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "WebsiteAPIStackRead"
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

resource "aws_iam_role_policy_attachments_exclusive" "github_actions" {
  role_name = "nhp-prod-github-actions"
  policy_arns = [
    aws_iam_policy.cloudformation_grants.arn,
  ]
}
