resource "aws_iam_role" "app" {
  name               = "fixture-app"
  assume_role_policy = "{}"
}

resource "aws_iam_role_policy" "kms_forallvalues_scope" {
  name = "kms-forallvalues-scope"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "KMSDecryptForAllValuesScope"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = "*"
        Condition = {
          "ForAllValues:StringEquals" = {
            "aws:ResourceAccount" = ["111122223333"]
          }
        }
      }
    ]
  })
}
