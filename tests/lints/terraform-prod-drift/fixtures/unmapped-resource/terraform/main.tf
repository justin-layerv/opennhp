# Reproduces the resource fail-closed contract: a resource type in NEITHER
# RESOURCE_ACTIONS NOR RESOURCE_UNCHECKED_ACK must be flagged (exit 2) so
# the next #2996-class slip lands loud at PR time, not at apply. Pick a
# type nhp doesn't use and is unlikely to add (aws_db_instance — no RDS in
# this stack), mirroring the aws_eks_cluster choice in unmapped-data-source.

resource "aws_db_instance" "lint_test" {
  identifier        = "fixture-db"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  engine            = "postgres"
}

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}
