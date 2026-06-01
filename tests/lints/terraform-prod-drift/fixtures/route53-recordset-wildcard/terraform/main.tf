# Route53 wildcard record-change fixture: no data sources needed. The
# condition lint should fail on the canonical github_actions role policy under
# modules/ecr/ because ChangeResourceRecordSets is Resource="*" without
# route53:ChangeResourceRecordSetsNormalizedRecordNames.
