# Canonical role with a ternary policy: leg-1 has an interpolation
# that unbalances the scanner; leg-2 is well-formed. Post-round-14
# the lint walks both legs (yielding None for leg-1) and the
# coverage union still includes leg-2's actions.

variable "use_interpolated" {
  type    = bool
  default = false
}

variable "suffix" {
  type    = string
  default = "fixture-foo"
}

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "ternary" {
  name = "ternary"
  role = aws_iam_role.github_actions.id

  policy = var.use_interpolated ? jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "InterpolatedLeg"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "arn:aws:s3:::bucket-${endswith(var.suffix, "-foo")}/*"
      }
    ]
    }) : jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CleanLeg"
        Effect = "Allow"
        Action = [
          "cloudformation:DescribeStacks",
          "cloudformation:GetTemplate"
        ]
        Resource = "*"
      }
    ]
  })
}
