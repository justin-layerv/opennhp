# cr round 9 fence: a data source's required action is satisfied by a
# wildcard glob in the role's grant set (e.g., `cloudformation:*` covers
# `cloudformation:DescribeStacks`). The lint uses `fnmatch.fnmatchcase`
# for IAM glob match; this fixture pins that the glob path actually
# resolves so a future regex-rewrite can't silently break wildcard
# coverage. Real-world example: `terraform/modules/ecr/main.tf:982-983`
# grants `cloudfront:Get*` + `cloudfront:List*` for the
# `aws_cloudfront_cache_policy` data source.

data "aws_cloudformation_stack" "lint_test" {
  name = "fixture-stack"
}
