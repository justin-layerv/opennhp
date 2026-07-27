# Auth0 Identity Policy — dashboard-owned tenant, one qURL account per person

Status: accepted (nhp #3284). Terraform:
[`terraform/modules/auth0/removed.tf`](../../terraform/modules/auth0/removed.tf).
Fence: `tests/scripts/test_auth0_not_terraform_managed.py`.

## Decisions

1. **The Auth0 tenant is owned in the Auth0 dashboard, not in Terraform.** Every
   `auth0_*` resource is forgotten from state (`removed` + `destroy = false`) and
   the provider credential is deleted from CI.
2. **Canonical customer authentication methods are regular email/password
   (`Username-Password-Authentication`) and Google (`google-oauth2`)**, enabled
   uniformly on every first-party interactive client. Passwordless `email` is
   disabled. **GitHub is not supported.**
3. **Duplicate identities are prevented by Auth0's native account linking**,
   configured in the dashboard — not by a Terraform-provisioned Action.

Decisions 2 and 3 are now applied by hand in the dashboard. That is the point:
the tenant has one owner, and it is not Terraform.

## Why Terraform stopped managing Auth0

**It put a tenant-write credential inside PR-time code execution.**
`terraform-plan-pr.yml` fetched a Management API token and exposed it to PR-head
HCL, which runs on any same-repo pull request. The M2M client behind that token
held 37 Management API scopes (audited 2026-07-26): `create:connections`,
`update:connections`, `create`/`update`/`delete:clients`, `update:branding`,
`create:actions`, and `read:client_keys` — enough to read **every client secret
in the shared tenant, production included**. `terraform/CLAUDE.md` required that
grant to be read-only or explicitly accepted. It was neither. Retiring the
provider deletes the exposure instead of writing an acceptance for it.

**Terraform could never own the tenant completely anyway.** Writing a
connection's `options` needs `update:connections_options`, which the CI M2M does
not hold. The attempt in #2305 left read-after-create drift that failed *every
subsequent apply* — including changes with nothing to do with Auth0 — until
#2309 and then full un-management. Partial ownership of a shared tenant was a
standing outage risk on unrelated work.

**The provider could not read back what it wrote.** Without `read:client_keys`
it returns an empty `client_secret`. That is why every credential secret in
`modules/auth0/` already carried `ignore_changes = [secret_string]` plus an
operator `put-secret-value` step: those values were operator-owned in practice
long before this change.

### What Terraform still owns

`modules/auth0/` is now an AWS-only module: Secrets Manager containers, the SSM
parameters that publish Auth0 config to the website build, the SES IAM user, and
the (currently disabled) rotation Lambda. It takes Auth0 **client IDs** as tfvars
inputs — public identifiers, already published as plaintext SSM parameters and
shipped to browsers as `NEXT_PUBLIC_AUTH0_CLIENT_ID`. Client **secrets** are
never Terraform inputs; an operator writes them straight into Secrets Manager.

### Retirement mechanics

`removed { ... lifecycle { destroy = false } }` forgets state entries without
touching the live tenant. Verified by plan against real state: sandbox forgets 21
objects, prod 29, with **no Auth0 object created, changed, or destroyed** in
either.

The `provider "auth0"` stub in `environments/*/backend.tf` is transitional.
Terraform demands an explicit provider configuration to decode `auth0_*` state
entries even for a forget-only plan (without it: `Error: Invalid provider
configuration`), but it makes no API calls, so the stub holds a literal
placeholder token and no credential. Delete the stub, the `required_providers`
entry, and `removed.tf` once `terraform state list | grep auth0_` is empty in
both environments.

## The identity problem this had to solve

qurl-service keys the customer record on the JWT `sub`, and Auth0 mints a
**connection-scoped** `sub` with no cross-connection deduplication:

| Connection | `sub` shape |
| --- | --- |
| `Username-Password-Authentication` | `auth0\|<id>` |
| `google-oauth2` | `google-oauth2\|<id>` |
| `email` (passwordless) | `email\|<id>` |

One person with one email address reaching two connections owns two unrelated
qURL accounts — separate resources, API keys, agent keys, and usage. Their work
appears to vanish when they pick the other button on the login page.

### Live divergence found (2026-07-26)

Probed per `(client, connection)` pair against the shared `layerv.us.auth0.com`
tenant. ✓ = enabled, ✗ = rejected with `invalid_request: the connection is not
enabled`:

| Client | DB | passwordless `email` | Google | GitHub |
| --- | --- | --- | --- | --- |
| QURL Dashboard (sandbox) | ✓ | ✗ | ✓ | ✗ |
| qURL Dashboard (prod) | ✓ | ✗ | ✓ | ✗ |
| qURL Discord Bot (sandbox) | ✓ | ✗ | ✓ | ✗ |
| qURL Discord Bot (production) | ✓ | ✗ | ✓ | ✗ |
| **qurl-bot-slack (sandbox)** | **✗** | **✓** | ✓ | ✗ |
| qURL Slack Bot (production) | ✓ | ✗ | ✓ | ✗ |
| **qURL Desktop (Staging)** | ✓ | **✓** | ✓ | ✗ |

Two clients diverge from the canonical pair, and both mint duplicates: the
sandbox Slack bot is passwordless-only (the inverse of its own prod
counterpart), and qURL Desktop exposes passwordless *alongside* the database
connection for the same address. GitHub is enabled nowhere, which is why it is
recorded above as unsupported rather than completed.

### Existing duplicates (audited 2026-07-26)

Found by joining `qurl-customers` on `email` and grouping distinct
`auth0_subject`; owned-record counts from each table's `owner-index`.

**Production — 3 groups, all DB↔Google:**

| Email | `sub` | Connection | Resources | API keys |
| --- | --- | --- | --- | --- |
| `ca…@gmail.com` | `google-oauth2\|1064280772…` | Google | **54** | 0 |
| | `auth0\|69baac8729f…` | DB | 0 | 0 |
| `ke…@layerv.ai` | `auth0\|69b84b95d28…` | DB | 0 | 0 |
| | `google-oauth2\|1016378695…` | Google | 4 | 3 |
| `mi…@gmail.com` | `auth0\|69dcbeae8ad…` | DB | 0 | 0 |
| | `google-oauth2\|1006510443…` | Google | 0 | 0 |

In every production case the database-connection record is an **empty shadow** —
no resources, keys, or domains, no Stripe customer, zero usage.

**Sandbox — 1 three-way group, all populated:**

| `sub` | Connection | Resources | API keys | Agent keys |
| --- | --- | --- | --- | --- |
| `auth0\|69b84b95d28…` | DB | 2 | 1 | 0 |
| `google-oauth2\|1016378695…` | Google | **190** | 12 | 54 |
| `email\|6a1e5a0d709…` | passwordless | 16 | 7 | 6 |

The passwordless identity is the most recently created and owns real resources —
the concrete reason passwordless is disabled rather than merely discouraged.

**Note that all three production duplicates were created while the connection
policy was already effectively DB + Google.** Restricting which connections are
enabled therefore cannot prevent duplicates on its own: both canonical methods
are legitimately available everywhere. That is what account linking is for.

## Dashboard configuration (the operator runbook)

Applied in the Auth0 dashboard for `layerv.us.auth0.com`. Terraform will not
reconcile any of it, so drift is caught by review, not by `plan`.

1. **Connections → per-client enablement.** For each of the seven first-party
   interactive clients, enable exactly `Username-Password-Authentication` and
   `google-oauth2`. Concretely: enable the database connection on
   `qurl-bot-slack (sandbox)`, and disable passwordless `email` on both
   `qurl-bot-slack (sandbox)` and `qURL Desktop (Staging)`.
2. **Do not delete the passwordless `email` connection.** `email|…` identities
   exist and own live qURL resources; deleting the connection deletes those
   users. Disable it per-client instead.
3. **Authentication → Account Linking.** Enable native account linking, matching
   on **verified** email only. Verified-only is the security-relevant setting: an
   attacker who signs up email/password with an address they do not control must
   never be linked into the real owner's account.
4. **GitHub** stays disabled everywhere and is not advertised.
5. If passwordless is ever re-enabled, fix the challenge prompt copy first —
   #3284 notes it must say the code arrives by email, not from an authenticator
   app. It is unreachable by customers while the connection is disabled on every
   client.

## Migration for the existing duplicates

**No identity is created, linked, or deleted by this change.** Every step below
is destructive and user-visible, and needs explicit owner approval on the exact
identities before it runs.

Deleting a duplicate *qURL customer row* alone accomplishes nothing durable: the
Auth0 identity still exists and qurl-service re-provisions an empty customer on
the next token. Consolidation must act on the Auth0 identity.

- **Enabling account linking does not retroactively merge existing duplicates.**
  It links identities at the next login where the match applies. Whether the
  three production shadows get absorbed depends on which method their owners use
  next.
- **Choose the primary by which identity owns the data, not by age.** For all
  three production groups that is the Google identity; for the sandbox group it
  is `google-oauth2|1016378695…` (190 resources). Oldest-wins would strand those
  190 behind a record holding 2.
- **The three production shadows own nothing.** Doing nothing with them is safe
  and is the recommended option: they become unreachable once linking is on and
  their owners consistently reach their data-bearing identity. Prefer this over
  any bulk-delete script.
- **The sandbox group needs real work if consolidated**: 18 resources, 8 API
  keys, and 6 agent keys are split across the DB and passwordless identities and
  would need re-pointing per table.
- **Linking is not reversible.** Unlinking recreates a separate identity with a
  new `sub`.

## Downstream follow-ups

- **qurl-integrations** verifies the Slack `/qurl setup <email>` flow against the
  database connection in sandbox. No bot code change is expected — the bot sends
  `login_hint` and delegates method choice to Universal Login unless
  `AUTH0_EMAIL_CONNECTION` is set — but the flow needs a live pass.
- **qURL Desktop client provisioning** in Terraform was the scope of the closed
  PR #3277 / issue #2821. It is now moot in that form: desktop clients are
  dashboard-created like every other Auth0 client.
- **Delete the stub provider** and `removed.tf` after both environments apply
  (see the rollout-ledger entry).
