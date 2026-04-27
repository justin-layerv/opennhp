# role-policies-exclusive-noop fixture (cr round 16 test-coverage gap):
#
# Locks in the contract that `aws_iam_role_policies_exclusive` is a
# no-op for the lint's coverage union. The resource declares the
# exhaustive set of inline-policy NAMES on a role but doesn't carry
# the policy body — the actions still come from `aws_iam_role_policy`
# blocks, which the lint already walks. Exiting silently from the
# `aws_iam_role_policies_exclusive` branch is correct (not a
# silent-miss), but the silent-pass wasn't fixture-fenced before.
# This fixture asserts the lint exits 0 when the canonical role has
# both an `aws_iam_role_policy` body AND an
# `aws_iam_role_policies_exclusive` block referencing it.

data "aws_cloudformation_stack" "website_api" {
  name = "fixture-stack"
}
