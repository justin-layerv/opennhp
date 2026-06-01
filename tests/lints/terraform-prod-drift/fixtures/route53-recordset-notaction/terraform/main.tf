# Route53 NotAction fixture: no data sources needed. The condition lint should
# fail because Allow + NotAction = "s3:*" still grants Route53 record mutation
# unless a later Deny blocks it, and the lint checks grant shape.
