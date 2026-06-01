# Route53 wildcard record-change fixture for nhp#1146. Standalone managed
# policies are part of the Route53 guard surface and must not grant wildcard
# ChangeResourceRecordSets without a normalized-record-name condition.

resource "aws_iam_policy" "route53_wildcard" {
  name = "fixture-route53-wildcard"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "Route53WildcardManagedPolicy"
        Effect   = "Allow"
        Action   = "route53:ChangeResourceRecordSets"
        Resource = "*"
      }
    ]
  })
}
