resource "aws_iam_role" "github_actions" {
  name               = "fixture-github-actions"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "terraform_read" {
  name = "terraform-read"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "EC2Read"
      Effect   = "Allow"
      Action   = "ec2:Describe*"
      Resource = "*"
    }]
  })
}
