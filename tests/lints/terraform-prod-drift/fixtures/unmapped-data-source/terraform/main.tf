# Reproduces the fail-closed contract: a data source whose type isn't in
# DATA_SOURCE_ACTIONS must be flagged so the next #1323-class slip lands
# loud, not silent. Pick a type unlikely to ever be added to the map for
# this project (aws_eks_cluster — nhp doesn't run on EKS).

data "aws_eks_cluster" "lint_test" {
  name = "fixture-cluster"
}

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}
