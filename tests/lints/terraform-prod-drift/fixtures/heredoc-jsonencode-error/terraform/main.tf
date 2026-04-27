# heredoc-jsonencode-error fixture (cr round 17 hard-fail fence):
#
# Locks in the round-16 promotion of heredoc detection from a warn
# to a hard error (`sys.exit(2)`). Pre-round-16, a `jsonencode(<<EOF
# ...)` body emitted `::warning` and fell through to
# `_iter_jsonencode_args` (which yielded nothing for the heredoc
# leg); if the heredoc was the only grant for a data source's
# required action, the lint exited 0 silently. Post-round-16, the
# lint exits 2 immediately when the form is detected.
#
# This fixture asserts iam=2 + the `::error::` substring in stderr.
# A future grammar change in python-hcl2 that broke the heredoc
# detection regex would silently let the form through; this fixture
# fences against that.

data "aws_caller_identity" "current" {}

# Both lints must hard-fail on the heredoc form. iam-coverage walks
# `aws_iam_role_policy` (declared in `modules/ecr/`); policy-conditions
# walks `aws_ecr_registry_policy` (declared here). Each lint hits its
# own heredoc body and exits 2 via `extract_policy_body`'s shared
# detector.
resource "aws_ecr_registry_policy" "heredoc_body" {
  policy = jsonencode(<<-EOT
{
  "Version": "2012-10-17",
  "Statement": []
}
EOT
  )
}
