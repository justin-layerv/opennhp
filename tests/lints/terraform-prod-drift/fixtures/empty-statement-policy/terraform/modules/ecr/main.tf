# Canonical role with an empty-Statement inline policy. A degenerate but
# valid `jsonencode({Statement = []})` body — exercises the
# decoded-but-empty path in `_tf_lint_lib.extract_policy_body`. Pre-fix
# (cr round 10) this returned None and fired a misleading "policy
# attribute is not a `jsonencode({...})` expression" warning; post-fix
# returns `{"Statement": []}` and the warning stays silent.
#
# The fixture's only data source (`aws_caller_identity`) requires no
# IAM grants, so the role's empty grant set is consistent — no IAM gap.

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "intentionally_empty" {
  name = "intentionally-empty"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = []
  })
}
