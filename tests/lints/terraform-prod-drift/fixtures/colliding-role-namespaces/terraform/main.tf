# cr round 2 fence: two modules each declare their own
# `aws_iam_role.github_actions`. The lint walks files flat, so without
# module-scoping, a grant attached to the *sibling* module's role would
# silently satisfy a missing-grant check for the canonical module's role.
# Mirrors the real-world collision between
# `terraform/modules/ecr/main.tf:505` (canonical) and
# `terraform/modules/traefik-plugins-deploy/main.tf:33` (sibling).
#
# This fixture's data source needs `cloudformation:DescribeStacks` +
# `cloudformation:GetTemplate`. The canonical role (modules/ecr) has NO
# matching grant. The sibling role (modules/sibling) DOES grant the
# actions. Module-scoped attribution must flag the gap on the canonical
# role despite the sibling having the grant.

data "aws_cloudformation_stack" "lint_test" {
  name = "fixture-stack"
}
