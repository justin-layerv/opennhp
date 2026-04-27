# interpolation-with-parens-warn fixture (cr round 12 substantive 2):
#
# Regression fence for the `${fn(...)}` interpolation inside a string
# literal limitation in `_iter_jsonencode_args`. The balanced-paren
# scanner would miscount and truncate the decoded body silently. The
# fixture asserts the lint emits a specific warn so the misleading
# generic "is not a jsonencode" warn doesn't fire instead.

data "aws_caller_identity" "current" {}
