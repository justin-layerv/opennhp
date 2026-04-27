# Canonical role declaration so the iam-coverage lint resolves cleanly.
resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}
