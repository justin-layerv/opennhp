# Canonical role + a ternary policy that selects between two jsonencode
# legs. The shared lib unions the Statements of both legs (mirrors
# `terraform/modules/ecr/main.tf`'s `ecr_push` policy that splits the
# primary-account vs secondary-account branches this way). The data
# source's required action lives in the FALSE leg, exercising the
# union-the-legs path.

resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

variable "is_primary_account" {
  type    = bool
  default = false
}

resource "aws_iam_role_policy" "ec2_describe" {
  name = "fixture-ec2-describe"
  role = aws_iam_role.github_actions.id

  policy = var.is_primary_account ? jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PrimaryAccountReads"
        Effect   = "Allow"
        Action   = ["ec2:DescribeAvailabilityZones"]
        Resource = "*"
      }
    ]
    }) : jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "SecondaryAccountReads"
        Effect   = "Allow"
        Action   = ["ec2:DescribeSubnets"]
        Resource = "*"
      }
    ]
  })
}
