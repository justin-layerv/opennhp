# Internal qURL-v2 admission wire-contract fixtures

These golden JSON fixtures pin the **client (nhp-server) side** of the
**internal** nhp-server ↔ qurl-service qURL-v2 admission HTTP wire (the two-phase
`prepare` / `commit` / `cancel` flow plus the steady-state `authorize` re-knock).
They are consumed by `TestAdmissionWireContract` in
`../../admission_contract_test.go`, which decodes them into the client DTOs in
`../../resolver_admission.go` so a field-name / encoding / body-shape change
breaks CI at PR time, before deploy.

**Scope — this pins specific load-bearing fields, not the whole body shape.**
The request side is enforced by a sender-subset marshal check (every key a
client DTO emits must be present in the fixture with the same value, so a
client-side tag rename or dropped field fails). But a fixture key the client DTO
does not model is *not* asserted: dropping an unasserted field
(`session_duration`, `remaining_seconds`, `resource_public_key_b64`,
`revocation_epoch`, or the optional `user_agent` / `visitor_session_id` /
authorize `ac_id`) will **not** fail CI. Do not over-trust this as a full-schema
contract.

## Source of truth and sync requirement

- **Source of truth:** [`docs/design/QURL_V2_KEYED_IDENTITY.md`](../../../../../../../docs/design/QURL_V2_KEYED_IDENTITY.md)
  ("NHP Server Contract" section: the documented prepare/commit/cancel/authorize
  request and response bodies).
- These files are **byte-identical** with the qurl-service repo's own contract
  fixtures at `tests/contract/testdata/qurlv2_admission/`. Both repos test the
  same wire from opposite ends.
- **Any change to a fixture MUST be mirrored in all three places in the same
  change:** this directory, the qurl-service `tests/contract/testdata/qurlv2_admission/`
  directory, and the design doc. Drift between them is exactly the failure this
  contract exists to prevent.

## This is NOT the public conformance corpus

This is an **internal, per-repo** contract. It is deliberately **not** the public
cross-language crypto conformance corpus
(`endpoints/server/internal/qurlv2/vectors.go` / the `qurl-conformance` repo).
That corpus is cross-language crypto vectors only; the internal service-to-service
admission API is private and must never be published there.

## Files

| File | Wire message |
|------|--------------|
| `prepare_request.json`   | `POST /internal/v2/qurl/admissions/prepare` body |
| `prepare_response.json`  | prepare success response (`open_time`, `qurl_user_public_key_hash`, `ac_routing`, …) |
| `commit_request.json`    | `POST /internal/v2/qurl/admissions/{id}/commit` body |
| `commit_response.json`   | commit success response |
| `cancel_request.json`    | `POST /internal/v2/qurl/admissions/{id}/cancel` body |
| `authorize_request.json` | `POST /internal/v2/qurl/admissions/authorize` body |
| `authorize_response.json`| authorize success response |
| `_contract_meta.json`    | agent (qURL user) public key in unpadded base64url + its `hex(sha256(decode))` hash, pinning the #3028 base64url-not-std-base64 invariant |

Note: `_contract_meta.json` — **including its human-readable `note` string** — is
one of the `*.json` files in the canonical hashed set, so both repos must keep it
byte-identical (editing the `note` in one repo changes that repo's checksum and
diverges it from the other). It is not just a test aside.

## Bugs this guards (shipped for lack of a pre-deploy wire check)

- **#3028** — authorize/prepare key was std-base64, not base64url (breaks the
  hash preimage). Guarded by the `_contract_meta.json` hash + base64url cross-check.
- **#1096** — prepare response `open_time` read as `open_time_seconds`. Guarded by
  the field-name pin (`open_time` present, `open_time_seconds` absent).
- **#3029** — commit omitted the required `qurl_user_public_key_hash` body field.
  Guarded by the commit-request marshal/unmarshal assertions.
