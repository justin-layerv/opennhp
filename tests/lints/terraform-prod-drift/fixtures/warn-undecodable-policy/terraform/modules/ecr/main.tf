# Canonical role with a policy whose body the parser can't decode (it's
# rendered from a data.aws_iam_policy_document instead of an inline
# jsonencode). The lint must emit a `::warning` (matched by the runner's
# stderr grep).

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

data "aws_iam_policy_document" "rendered" {
  statement {
    sid       = "Renderer"
    effect    = "Allow"
    actions   = ["ec2:DescribeInstances"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "from_data" {
  name   = "from-data"
  role   = aws_iam_role.github_actions.id
  policy = data.aws_iam_policy_document.rendered.json
}
