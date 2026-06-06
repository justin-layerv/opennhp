# KMS wildcard-decrypt (#1523): Allow + NotAction = ["s3:*"] allows kms:Decrypt
# (it is not excluded), and on Resource="*" that is a broad decrypt grant. Pins
# the _statement_allows_action NotAction branch. Must be flagged.
