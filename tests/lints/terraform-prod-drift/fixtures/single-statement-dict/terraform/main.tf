# Pin behavior on the IAM-shorthand single-dict Statement form. AWS IAM
# accepts `Statement = { ... }` (single object, not wrapped in an array)
# as a valid policy. cr feedback round 1: the parser previously iterated
# the dict's keys when it saw this form, and the `isinstance(stmt, dict)`
# guard then dropped them silently.

data "aws_ssm_parameter" "lint_test" {
  name = "fixture-parameter"
}
