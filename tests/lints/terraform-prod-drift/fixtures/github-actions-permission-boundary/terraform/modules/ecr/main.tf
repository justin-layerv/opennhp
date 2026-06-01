resource "aws_iam_role" "github_actions" {
  name                 = "fixture-github-actions"
  assume_role_policy   = "{}"
  permissions_boundary = "arn:aws:iam::123456789012:policy/nhp-security-boundary"
}
