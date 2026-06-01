# Route53 broad-suffix fixture: no data sources needed. The condition lint
# should reject wildcard record-name suffixes such as *.com even when the
# Route53 normalized-record-name condition and Null=false guard are present.
