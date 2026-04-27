# mixed-allow-deny-warn fixture (cr round 10):
#
# A role policy that mixes `Effect = Allow` and `Effect = Deny` inside
# the same `Statement` array. The lint counts Allow grants and ignores
# Deny narrowing, so the role's effective permission set may be
# narrower than what the lint sees. The fixture asserts the lint emits
# a one-time warning so the Allow-only assumption stays load-bearing,
# not load-implicit.

data "aws_cloudformation_stack" "website_api" {
  name = "fixture-stack"
}
