# Pin behavior on the ternary policy form, where `policy` selects between
# two `jsonencode` calls based on a predicate. The shared lib walks both
# legs and unions their Statements.

data "aws_subnet" "lint_test" {
  id = "subnet-fixture"
}
