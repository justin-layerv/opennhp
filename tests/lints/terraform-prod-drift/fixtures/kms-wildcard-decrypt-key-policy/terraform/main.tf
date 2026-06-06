# KMS wildcard-decrypt (#1523): a resource-based KMS *key* policy (aws_kms_key,
# carries a Principal) legitimately uses kms:CallerAccount. Out of scope; must
# NOT be flagged. This exercises the scanned_types filter in main() (aws_kms_key
# is never decoded); kms-wildcard-decrypt-identity-principal exercises the
# in-finder statement-level Principal guard.
