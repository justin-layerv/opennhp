# KMS wildcard-decrypt (#1523): StringLike aws:ResourceAccount = ["<acct>", "*"]
# is a false bound — under StringLike OR-semantics the bare "*" matches every
# account, so the concrete sibling does not constrain it. Must be flagged.
