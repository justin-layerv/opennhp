# KMS wildcard-decrypt (#1523): a Resource ARN whose account field is "*"
# (arn:aws:kms:*:*:key/*) reaches keys in every account, so it is as broad as
# Resource="*" for cross-account decrypt. Must be flagged.
