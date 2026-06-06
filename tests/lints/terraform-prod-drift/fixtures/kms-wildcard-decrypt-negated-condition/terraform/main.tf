# KMS wildcard-decrypt (#1523): a negated operator (StringNotEquals) on
# aws:ResourceAccount does not bind to the same account, so it must NOT count as
# scope. Must be flagged.
