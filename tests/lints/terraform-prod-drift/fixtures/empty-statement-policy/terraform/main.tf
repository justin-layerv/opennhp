# empty-statement-policy fixture (cr round 10):
#
# Regression fence for the "empty Statement misclassified as undecodable"
# bug — `extract_policy_body` previously returned None for a valid
# `jsonencode({Statement = []})` body, which fired the misleading
# "policy attribute is not a `jsonencode({...})` expression" warning
# against a perfectly valid (if degenerate) policy.
#
# The fixture's data source has no required actions, so the empty-grant
# role is consistent with the data source — no IAM gap. The shape
# under test is the inline-policy decode path itself: the fix returns
# `{"Statement": []}` so the caller's None-gate doesn't fire.

data "aws_caller_identity" "current" {}
