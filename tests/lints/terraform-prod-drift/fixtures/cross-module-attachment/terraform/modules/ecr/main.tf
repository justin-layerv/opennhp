# Canonical module: declares the github_actions role and exposes its
# name as a module output that sibling modules can reference.

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

output "github_actions_role_name" {
  value = aws_iam_role.github_actions.name
}
