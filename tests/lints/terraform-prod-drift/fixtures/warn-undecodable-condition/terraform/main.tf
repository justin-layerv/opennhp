# cr round 3 fence: the policy-conditions lint emits a `::warning` when
# the policy body of a denylist-targeted resource type can't be decoded.
# Without this fence, a refactor that moves
# `aws_ecr_registry_policy.replication`'s body to
# `data.aws_iam_policy_document` would silently disable the regression
# fence.

data "aws_iam_policy_document" "rendered" {
  statement {
    sid       = "Renderer"
    effect    = "Allow"
    actions   = ["ecr:ReplicateImage"]
    resources = ["*"]
  }
}

resource "aws_ecr_registry_policy" "replication" {
  policy = data.aws_iam_policy_document.rendered.json
}

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}
