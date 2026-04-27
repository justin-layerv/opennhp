# Canonical role with a `policy = jsonencode(<<EOF ... EOF)` body —
# the form `_iter_jsonencode_args` can't decode. Post-round-16 the
# lint exits 2 with a specific `::error::` rather than warning
# pass-through.

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "heredoc_body" {
  name = "heredoc-body"
  role = aws_iam_role.github_actions.id

  policy = jsonencode(<<-EOT
{
  "Version": "2012-10-17",
  "Statement": []
}
EOT
  )
}
