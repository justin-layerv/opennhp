# Canonical role with an attachment to an AWS-managed policy ARN whose
# body the lint can't enumerate. Triggers the warn-path covered by
# `external_arn_re`.

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy_attachment" "aws_managed" {
  role       = aws_iam_role.github_actions.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}
