# Canonical NHP role — declared but no grants for the data source's
# required actions. Pre-fix, the sibling module's grant (a different
# role whose literal name ends in `-github-actions`) would silently
# get credited here.

resource "aws_iam_role" "github_actions" {
  name               = "nhp-prod-github-actions"
  assume_role_policy = "{}"
}

# Unrelated grant — exists only so `role_actions` isn't empty (which
# would trigger the empty-attribution exit-3 diagnostic instead of
# the missing-grant exit-1 the fixture is asserting).
resource "aws_iam_role_policy" "unrelated" {
  name = "unrelated"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Unrelated"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "*"
      }
    ]
  })
}
