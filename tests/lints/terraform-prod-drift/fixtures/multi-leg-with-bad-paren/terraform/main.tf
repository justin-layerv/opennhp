# multi-leg-with-bad-paren fixture (cr round 14 issue 1):
#
# Coverage for the `_iter_jsonencode_args` walker on a ternary
# policy whose first leg contains a `${fn(arg)}` interpolation
# inside a string literal. The interpolation pre-scan in
# `extract_policy_body` warns about the shape; the scanner's
# string-state machine respects the surrounding `"..."` and
# both legs balance correctly, so both reach the union (leg-2
# grants the canonical data source's required actions).
#
# The round-14 fix that yields `None` for genuinely unbalanced
# legs and advances past the bad needle is still defensive — the
# only way to trigger that path with valid HCL would be a
# construction terraform-validate already rejects. The fixture
# asserts the warn fires and the IAM coverage check stays clean
# (leg-2 grants what the data source needs).

data "aws_cloudformation_stack" "website_api" {
  name = "fixture-stack"
}

variable "use_interpolated" {
  type    = bool
  default = false
}

variable "suffix" {
  type    = string
  default = "fixture-foo"
}
