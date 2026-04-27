# cr round 6 fence: two modules each declare an `aws_iam_policy` with
# the same bare name. The lint keys managed_policies on bare name and
# would silently overwrite the first declaration's actions with the
# second's. The collision-detect warn the lint emits prevents the
# silent-miss class.

data "aws_secretsmanager_secret" "lint_test" {
  name = "fixture-secret"
}
