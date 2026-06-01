# Route53 plain-condition fixture: no data sources needed. The condition lint
# should fail because StringLike does not require every record in a multi-record
# ChangeResourceRecordSets batch to match the normalized-name pattern.
