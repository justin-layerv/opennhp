"""Backfill the `email` attribute on customer rows that predate the Control contract.

Control identity mode refuses to mint credentials for an owner whose row fails
the canonical-owner shape, which requires `email` present with size > 0 (see
buildCanonicalExistingOwnerShapeCondition in qurl-service). Rows created by the
older cell-mode path cannot satisfy it: CustomerRepository.GetOrCreate takes only
an Auth0 subject -- there is no email parameter -- and the struct tag

    Email string `dynamodbav:"email,omitempty"`

then drops the attribute entirely when it is empty. `omitempty` is correct there,
because `email` keys the sparse email-index GSI and DynamoDB rejects an empty
string as an index key. Control mode simply made a previously-optional field
mandatory without migrating the rows that predate the rule.

Two populations, deliberately handled differently:

  * Machine accounts (Auth0 M2M "<id>@clients", and synthetic test fixtures) have
    no human mailbox by construction. They get a synthetic address on a
    LayerV-owned domain, matching the convention the UDP proof harness already
    uses for its own machine account (qurl-go@proof.notify.layerv.xyz).

  * Human accounts get their REAL address from Auth0, the identity source of
    truth. Synthesizing one would be worse than leaving the row broken: `email`
    is where a registration OTP is delivered, so a fabricated address either
    black-holes a customer's login code or sends it somewhere they do not
    control. This script refuses to invent one and refuses to write an
    unverified one.

Every write is conditional on the attribute still being absent or empty, so a
re-run cannot clobber a value someone else set in the meantime.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
import urllib.request

import boto3
from botocore.exceptions import ClientError

MACHINE_DOMAIN = "machine.notify.layerv.xyz"
SYNTHETIC_DOMAIN = "synthetic.notify.layerv.xyz"


def is_machine_subject(subject: str) -> bool:
    return subject.endswith("@clients") or subject.startswith("synthetic:")


def synthetic_address(subject: str) -> str:
    """A stable, non-deliverable address derived from the subject.

    Deterministic so a re-run produces the same value, and scoped to a LayerV
    domain so it can never collide with a real mailbox.
    """
    slug = "".join(c if c.isalnum() else "-" for c in subject).strip("-").lower()[:60]
    domain = SYNTHETIC_DOMAIN if subject.startswith("synthetic:") else MACHINE_DOMAIN
    return f"{slug}@{domain}"


def auth0_token(secrets, secret_id: str) -> tuple[str, str]:
    """Client-credentials grant for the Auth0 Management API."""
    raw = secrets.get_secret_value(SecretId=secret_id)["SecretString"]
    cfg = json.loads(raw)
    # The stored secret carries `audience` (https://<domain>/api/v2/) rather than
    # a bare domain, so derive the host from it instead of requiring operators to
    # keep a second, redundant field in sync.
    audience = cfg.get("audience") or ""
    domain = cfg.get("domain") or cfg.get("AUTH0_DOMAIN") or urllib.parse.urlparse(audience).netloc
    if not domain:
        raise RuntimeError(f"{secret_id} has neither `domain` nor a parseable `audience`")
    body = json.dumps({
        "grant_type": "client_credentials",
        "client_id": cfg.get("client_id") or cfg.get("AUTH0_CLIENT_ID"),
        "client_secret": cfg.get("client_secret") or cfg.get("AUTH0_CLIENT_SECRET"),
        "audience": audience or f"https://{domain}/api/v2/",
    }).encode()
    req = urllib.request.Request(
        f"https://{domain}/oauth/token", data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - fixed Auth0 host
        return json.loads(resp.read())["access_token"], domain


def auth0_email(token: str, domain: str, subject: str) -> tuple[str | None, bool, str]:
    """Return (email, verified, note) for an Auth0 subject."""
    url = f"https://{domain}/api/v2/users/{urllib.parse.quote(subject, safe='')}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310
            user = json.loads(resp.read())
    except urllib.error.HTTPError as err:
        return None, False, f"Auth0 lookup failed: HTTP {err.code}"
    email = (user.get("email") or "").strip()
    if not email:
        return None, False, "Auth0 has no email for this user either"
    return email, bool(user.get("email_verified")), "ok"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--table", required=True)
    parser.add_argument("--region", default="us-east-2")
    parser.add_argument("--auth0-secret", default="layerv-nhp-prod/developer-portal/auth0-mgmt")
    parser.add_argument(
        "--allow-unverified", action="store_true",
        help="write a human address Auth0 reports as unverified (default: refuse)",
    )
    parser.add_argument("--apply", action="store_true", help="perform the writes")
    args = parser.parse_args()

    session = boto3.Session(region_name=args.region)
    ddb = session.client("dynamodb")

    items, kwargs = [], {"TableName": args.table}
    while True:
        page = ddb.scan(**kwargs)
        items.extend(page.get("Items", []))
        if "LastEvaluatedKey" not in page:
            break
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]

    broken = [
        it["auth0_subject"]["S"] for it in items
        if not it.get("email", {}).get("S", "")
    ]
    print(f"{args.table}: {len(items)} customers, {len(broken)} missing a usable email\n")
    if not broken:
        print("nothing to do")
        return 0

    humans = [s for s in broken if not is_machine_subject(s)]
    token = domain = None
    if humans:
        try:
            token, domain = auth0_token(session.client("secretsmanager"), args.auth0_secret)
        except Exception as err:  # noqa: BLE001 - report and continue with machines
            print(f"  Auth0 unavailable ({err}); human accounts will be reported, not written\n")

    planned, skipped, failed = [], [], []
    for subject in broken:
        if is_machine_subject(subject):
            planned.append((subject, synthetic_address(subject), "synthetic (machine account)"))
            continue
        if not token:
            skipped.append((subject, "no Auth0 access; needs a real address"))
            continue
        email, verified, note = auth0_email(token, domain, subject)
        if not email:
            skipped.append((subject, note))
        elif not verified and not args.allow_unverified:
            skipped.append((subject, f"Auth0 email {email} is UNVERIFIED (pass --allow-unverified)"))
        else:
            planned.append((subject, email, "from Auth0" + ("" if verified else " (UNVERIFIED)")))

    print("PLAN:" if not args.apply else "APPLYING:")
    for subject, email, why in planned:
        print(f"  {subject[:46]:48s} -> {email}   [{why}]")
    for subject, why in skipped:
        print(f"  {subject[:46]:48s} -- SKIPPED: {why}")

    if not args.apply:
        print("\nDRY RUN — re-run with --apply to write")
        return 0

    for subject, email, _ in planned:
        try:
            ddb.update_item(
                TableName=args.table,
                Key={"auth0_subject": {"S": subject}},
                UpdateExpression="SET email = :e",
                # Only fill a genuinely missing value; never overwrite one that
                # appeared since the scan.
                ConditionExpression="attribute_exists(auth0_subject) AND (attribute_not_exists(email) OR email = :empty)",
                ExpressionAttributeValues={":e": {"S": email}, ":empty": {"S": ""}},
            )
            print(f"  wrote {subject[:46]}")
        except ClientError as err:
            code = err.response["Error"]["Code"]
            failed.append((subject, code))
            print(f"  FAILED {subject[:46]}: {code}", file=sys.stderr)

    print(f"\nwrote={len(planned) - len(failed)} skipped={len(skipped)} failed={len(failed)}")
    return 1 if failed or skipped else 0


if __name__ == "__main__":
    raise SystemExit(main())
