#!/usr/bin/env python3
"""A cell advertised as assignable must actually be able to serve an agent.

The Connector Authority picks a cell from its catalog by `status`: `active`
admits new assignments, `draining` serves only existing ones, `disabled` serves
none. Nothing checked that an `active` cell could do the things an assigned agent
immediately needs.

That gap is not theoretical. sandbox cell1 was listed `active` with
selection_weight 1 -- so it took its share of assignments -- while its NHP server
had booted with

    [AGENT] Plugin initialized: agent v0.1.0
    (NHP-native registration DISABLED - set AGENT_OTP_REGISTRATION_ENABLED to enable)

because the cell1 Terraform root never passed agent_otp_registration_enabled to
module.compute. Every agent placed there failed enrollment with errCode 52107 --
which is the fail-closed catch-all for server-side faults, so the failure never
named the missing flag.

This reads live state, deliberately: the defect was a disagreement between a
runtime catalog row and a rendered bootstrap script, and no static check over
Terraform source could have seen it. The server config is the S3 object the
launch template fetches, not the launch template's own user_data -- that is only
a bootstrap shim, and reading it instead is why this took so long to find.

Exit 0 when every active cell is capable, 1 otherwise.
"""

from __future__ import annotations

import argparse
import sys

import boto3
from botocore.exceptions import ClientError

# Env vars an assigned agent needs its cell's NHP server to have. Each maps to a
# concrete failure a customer would hit if the cell is assignable without it.
#
# The flags alone are not enough, and checking only them is how sandbox cell1
# stayed broken after #3739 turned its flags on: the flags say the server WILL
# handle native registration, the alias ARNs are what it handles it WITH. cell1
# had AGENT_OTP_REGISTRATION_ENABLED=true and no NHP_CONNECTOR_* line at all,
# so configureConnectorCellAuthority returned early and every enrollment placed
# there died. The OTP leg is the cruelest of these: NHP_OTP carries no
# acknowledgement, so a missing issuer alias is not an error the agent can see —
# it waits in its own OTP callback until the assignment ticket expires and no
# code is ever emailed.
REQUIRED_SERVER_CONFIG = {
    "AGENT_OTP_REGISTRATION_ENABLED": (
        "native agent registration (NHP_OTP -> NHP_REG -> NHP_RAK); "
        "without it enrollment fails 52107"
    ),
    "QURL_V2_ADMISSION_ENABLED": (
        "independent qURL v2 admission; without it the cell admits no v2 knock"
    ),
    "NHP_CONNECTOR_REGISTRATION_ISSUE_OTP_ALIAS_ARN": (
        "the Authority alias that emails the one-time code; without it NHP_OTP "
        "is silently dropped and the agent waits out its ticket with no code"
    ),
    "NHP_CONNECTOR_REGISTRATION_ACTIVATE_ALIAS_ARN": (
        "the Authority alias that activates a registration; without it "
        "assigned-cell NHP_REG cannot be served"
    ),
    "NHP_CONNECTOR_REGISTRATION_COMPLETE_ALIAS_ARN": (
        "the Authority alias that completes a registration; without it an "
        "activated agent can never be issued its device credential"
    ),
    "NHP_CONNECTOR_CREDENTIAL_RECOVERY_ALIAS_ARN": (
        "the Authority alias that replaces a revoked device credential; "
        "without it a recoverable agent on this cell is stranded"
    ),
}

# Values that are present but mean "off". `NAME=` with nothing after it renders
# whenever a Terraform local resolves to an empty string, and a flag can be
# rendered false. Both satisfy a presence-only test while leaving the capability
# just as absent, so treat them as missing.
DISABLED_VALUES = {"", "false", "0", "null", "none"}

ASSIGNABLE_STATUS = "active"


def server_init_script(s3, bucket: str, key: str) -> str | None:
    try:
        return s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8", "replace")
    except ClientError:
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authority-table", required=True)
    parser.add_argument("--region", default="us-east-2")
    parser.add_argument(
        "--cell-bucket", action="append", required=True, metavar="CELL=BUCKET",
        help="repeatable, e.g. --cell-bucket cell0=layerv-nhp-sandbox-plugins",
    )
    parser.add_argument("--script-key", default="scripts/server-init.sh")
    args = parser.parse_args()

    buckets = dict(pair.split("=", 1) for pair in args.cell_bucket)
    session = boto3.Session(region_name=args.region)
    ddb, s3 = session.client("dynamodb"), session.client("s3")

    items, kwargs = [], {"TableName": args.authority_table}
    while True:
        page = ddb.scan(**kwargs)
        items.extend(page.get("Items", []))
        if "LastEvaluatedKey" not in page:
            break
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]

    cells = {
        it["sk"]["S"].removeprefix("CELL#"): it["status"]["S"]
        for it in items
        if it.get("sk", {}).get("S", "").startswith("CELL#")
    }
    if not cells:
        print(f"no CELL# rows in {args.authority_table}; the check would pass vacuously")
        return 1

    failures = 0
    for cell_id, status in sorted(cells.items()):
        if status != ASSIGNABLE_STATUS:
            print(f"  {cell_id}: status={status} - not assignable, capability not required")
            continue
        bucket = buckets.get(cell_id)
        if not bucket:
            print(f"  {cell_id}: status=active but no --cell-bucket given; cannot verify")
            failures += 1
            continue
        script = server_init_script(s3, bucket, args.script_key)
        if script is None:
            print(f"  {cell_id}: status=active but s3://{bucket}/{args.script_key} is unreadable")
            failures += 1
            continue
        rendered = {}
        for line in script.splitlines():
            name, sep, value = line.strip().partition("=")
            if sep and name in REQUIRED_SERVER_CONFIG:
                rendered[name] = value.strip().strip("\"'")
        missing = [
            name for name in REQUIRED_SERVER_CONFIG
            if rendered.get(name, "").lower() in DISABLED_VALUES
        ]
        if missing:
            failures += 1
            print(f"  {cell_id}: status=ACTIVE but its NHP server is missing or has disabled:")
            for name in missing:
                print(f"      {name} - {REQUIRED_SERVER_CONFIG[name]}")
        else:
            print(f"  {cell_id}: status=active, capable")

    print()
    if failures:
        print(
            f"{failures} assignable cell(s) cannot serve an assigned agent.\n"
            "Either wire the missing config into that cell's Terraform root, or set the\n"
            "cell to 'draining' in the provisioned-cell catalog so the Authority stops\n"
            "placing agents on it. An agent assigned to an incapable cell fails with a\n"
            "catch-all error that does not name the cause."
        )
        return 1
    print("every assignable cell is capable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
