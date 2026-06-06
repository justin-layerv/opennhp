# KMS wildcard-decrypt (#1523): StringEquals aws:ResourceAccount = ["<acct>",
# "*"] still scopes — under StringEquals the "*" arm is a dead literal (account
# IDs are never the string "*"), so the concrete account binds. Must NOT be
# flagged. Pairs with kms-wildcard-decrypt-stringlike-mixed to fence the
# operator-aware value rule on both sides.
