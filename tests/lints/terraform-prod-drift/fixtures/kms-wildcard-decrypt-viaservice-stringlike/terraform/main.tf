# KMS wildcard-decrypt (#1523): StringLike kms:ViaService with a region
# wildcard (secretsmanager.*.amazonaws.com) is the documented AWS-managed-key
# multi-region pattern; the value is not a pure wildcard, so it scopes. Must NOT
# be flagged.
