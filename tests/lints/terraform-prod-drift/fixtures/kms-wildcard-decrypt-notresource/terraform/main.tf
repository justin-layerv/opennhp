# KMS wildcard-decrypt (#1523): Allow kms:Decrypt + NotResource is a broad
# complement (all keys except a few, still cross-account), so it is wildcard-
# equivalent. Mirrors the sibling Route53 NotResource handling. Must be flagged.
