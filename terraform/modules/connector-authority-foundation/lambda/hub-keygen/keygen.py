"""Seed the Connector Hub key material secret exactly once.

Invoked by aws_lambda_invocation with lifecycle_scope=CREATE_ONLY at Hub worker
create. It generates the Hub's long-lived private key and the active cookie key
as fresh 32-byte random values, base64-encodes them, and writes them plus an
empty previous cookie key into the pre-created Secrets Manager secret.

The generated key material is NEVER returned: aws_lambda_invocation records the
handler's return value in Terraform state, so returning any key byte would leak
it into tfstate. The handler returns only a {"seeded": true} marker.
"""

import base64
import json
import os

import boto3


def _fresh_key_b64():
    """A fresh 32-byte CSPRNG key, standard-base64 encoded."""
    return base64.standard_b64encode(os.urandom(32)).decode("ascii")


def handler(event, context):
    secret_id = os.environ["SECRET_ID"]

    # active_cookie_key is freshly minted; previous_cookie_key is intentionally
    # empty at seed time (there is no prior key to carry over on first create).
    secret_string = json.dumps(
        {
            "private_key": _fresh_key_b64(),
            "active_cookie_key": _fresh_key_b64(),
            "previous_cookie_key": "",
        }
    )

    boto3.client("secretsmanager").put_secret_value(
        SecretId=secret_id,
        SecretString=secret_string,
    )

    # No key material in the return value: it would land in Terraform state.
    return {"seeded": True}
