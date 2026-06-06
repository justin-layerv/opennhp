# KMS wildcard-decrypt (#1523): aws:ResourceAccount under a *IfExists operator
# evaluates true when the key is absent, so it does not actually scope the
# grant. Must be flagged.
