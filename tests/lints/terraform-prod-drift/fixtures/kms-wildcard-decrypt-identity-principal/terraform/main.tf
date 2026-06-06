# KMS wildcard-decrypt (#1523): a statement-level Principal in an *identity*
# policy resource (aws_iam_role_policy, which IS scanned) is malformed/
# resource-policy-shaped; the in-finder Principal guard skips it directly. This
# exercises the in-finder guard, whereas kms-wildcard-decrypt-key-policy
# exercises the scanned_types filter in main(). Must NOT be flagged.
