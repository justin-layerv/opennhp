# Canonical role with an inline policy whose Resource string contains
# `${endswith(var.suffix, "-foo")}` — an interpolation with a function
# call whose parens unbalance the lint's balanced-paren scanner. The
# lint must warn loudly so the silent-miss / misleading-generic-warn
# case stays visible.

variable "suffix" {
  type    = string
  default = "fixture-foo"
}

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "interpolated" {
  name = "interpolated"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "InterpolatedResource"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "arn:aws:s3:::bucket-${endswith(var.suffix, "-foo")}/*"
      }
    ]
  })
}
