# Route53 partial hosted-zone wildcard fixture: no data sources needed. The
# condition lint should fail because `arn:aws:route53:::hostedzone/Z*` still
# permits record changes across an open-ended hosted-zone set.
