# qurl-agent-keys Schema Contract

`qurl-agent-keys` is the DynamoDB boundary between qurl-service and
nhp-server. qurl-service is the writer. nhp-server is the hot-path reader on
agent knock receipt.

## Shared Go Contract

The shared contract lives in `github.com/layervai/nhp/internalauth`:

- `internalauth.QURLAgentKeyRow`
- `internalauth.QURLAgentKeysSchemaVersion`
- `internalauth.QURLAgentKeysPubkeyIndexName`
- `internalauth.QURLAgentKeys*Attr`

Writers and readers must import these names instead of duplicating string
literals for DynamoDB attributes or the `pubkey-index` GSI.

nhp-server resolves by querying the KEYS_ONLY `pubkey-index` GSI for
`public_key`, `owner_id`, and `agent_id`, then issuing a strongly-consistent
base-table `GetItem` by `(owner_id, agent_id)` to read `schema_version` and the
full row contract.

The reader intentionally keeps the GSI at KEYS_ONLY rather than projecting
`schema_version`: DynamoDB GSIs are eventually consistent, and the base-table
`GetItem` gives the schema gate a strongly-consistent read without making hot
`last_seen_at` updates rewrite extra projected attributes.

Cost model:

- Random unknown pubkeys stop after the `pubkey-index` `Query`; they do not
  issue a base-table `GetItem`.
- Cold registered-agent resolves normally perform two DynamoDB reads: one
  eventually consistent GSI `Query`, then one strongly-consistent base-table
  `GetItem`. The strong read is intentionally paid only on a GSI hit so the
  schema gate sees the current base row instead of an eventually-consistent GSI
  projection. Same-owner duplicate/anomaly paths may issue up to 16 `GetItem`
  calls while checking every bounded sibling before caching. The GSI `Query`
  asks for 17 projected rows (a 16-row inspection cap plus one sentinel); if the
  sentinel row appears or DynamoDB reports another page, nhp-server rejects
  fail-closed instead of admitting from an over-cap partition.
- Warm resolves hit `UdpServer.agentPeerMap` or the 60s LRU and do not read
  DynamoDB.

Current registration row attributes:

| Attribute | Required | Meaning |
|---|---:|---|
| `owner_id` | yes | Table partition key. Customer/owner namespace. |
| `agent_id` | yes | Table sort key. Stable agent identity within owner. |
| `public_key` | yes | Standard padded base64 X25519 public key; must be exactly Go `base64.StdEncoding` output, not URL-safe or unpadded base64; `pubkey-index` hash key. |
| `schema_version` | yes for new writes | Current explicit schema version. |
| `registered_at` | yes for qurl-service rows | First registration time. |
| `last_seen_at` | yes for qurl-service rows | Last bootstrap/touch time. |
| `hostname` | optional | Agent-reported host metadata. |
| `version` | optional | Agent-reported version metadata. |
| `ttl` | optional | DynamoDB TTL epoch seconds. |

## Schema Versioning

Current version: `1`.

Compatibility rules:

- Writers may add optional attributes without bumping `schema_version`.
- Writers must bump `schema_version` before renaming, removing, or changing the
  semantics of an existing attribute or GSI.
- Incompatible-version rollouts are reader-first: ship nhp-server that accepts
  the new version before qurl-service writes it. If the writer emits an
  unsupported version first, nhp-server rejects fail-closed and does not cache
  the row, so affected agents reissue `Query` + `GetItem` on every cold knock
  until the reader catches up or the data is rolled back.
- nhp-server rejects explicit unsupported versions with
  `MetricAgentLookupSchemaMismatch` and `event="agent_lookup_schema_mismatch"`.
  The version gate reads the base row through `GetItem`; it is not inferred from
  the KEYS_ONLY GSI projection.
- Missing `schema_version` is treated as legacy version `0` during rollout so a
  reader deploy cannot strand rows written before the shared contract existed.
  Remove legacy acceptance only after qurl-service writes v1 and any required
  backfill/lazy migration has completed.

## GSI Collision Posture

The `pubkey-index` GSI does not enforce uniqueness. qurl-service owns the
writer-side one-owner-per-pubkey invariant (#488, implemented by qurl-service PR
#1037). That invariant blocks different owners from writing the same public key,
but intentionally allows the same owner to hold one key under multiple
`agent_id` rows during re-bootstrap or sibling-agent flows.

nhp-server still queries a bounded candidate set as defense in depth: it requests
up to 17 projected rows so exactly 16 same-owner candidates can be inspected
unambiguously while a 17th row acts as an over-cap sentinel. If the bounded
result set contains rows for different `owner_id` values, nhp-server emits
`MetricAgentLookupPubkeyCollision`, logs
`event="agent_lookup_pubkey_collision"` at the knock layer, and rejects the knock
fail-closed instead of admitting an arbitrary owner. Same-owner duplicate rows
are not an auth ambiguity: nhp-server tries the projected `(owner_id, agent_id)`
candidates and accepts the first current, schema-compatible base row only after
checking every bounded current sibling for a supported `schema_version`. If the
sentinel row is returned or DynamoDB reports another page, nhp-server rejects
fail-closed with `MetricAgentLookupPubkeyCandidateOverflow` and
`event="agent_lookup_pubkey_candidate_overflow"` because an over-cap partition
could hide a distinct owner.

Any distinct-owner collision after #488 is legacy duplicate data, manual table
mutation, or a writer invariant regression. Treat it as an incident and
reconcile the duplicate rows before allowing the agent path to proceed.
Same-owner stale/orphan rows and rotated-key projections should still be
reconciled as data hygiene, but nhp-server skips them while looking for a
current sibling. A current same-owner sibling with an unsupported
`schema_version` strands the whole pubkey fail-closed until operators repair or
remove that sibling, because the reader checks every bounded current candidate
before caching.

The 16-row inspection cap and the 5s `DynamoDBOperationTimeout` are coupled:
the GSI `Query` plus all same-owner base-table `GetItem`s share one total
resolve budget. Do not raise the cap without also revisiting that latency and
availability budget.

A malformed projected key row also fails the whole candidate set instead of
being skipped. In particular, a row missing `public_key` is impossible for a
valid `pubkey-index` hit because `public_key` is the GSI hash key; treating the
remaining siblings as trustworthy after that contract violation would be less
conservative than an uncached fail-closed reject. nhp-server classifies missing
projected key attributes as malformed rows so operators see the schema/data
regression path instead of a generic unknown-pubkey auth miss.

A stale GSI projection can also point at a base row that has been deleted or
whose `public_key` rotated. nhp-server treats both as unknown pubkey outcomes,
does not cache them, and self-heals on a later cold resolve after the GSI has
converged.

## Revocation

Deleting a row from `qurl-agent-keys` is not an active revocation for already
resolved agents. Once an agent is admitted, `UdpServer.agentPeerMap` pins it
until process restart. Active revocation across the nhp-server process lifetime
is tracked by nhp #1943.

## IAM Audit

nhp-server's task role may read `qurl-agent-keys` only via:

- `dynamodb:GetItem`
- `dynamodb:Query`

Allowed resources:

- the `qurl-agent-keys` table ARN
- `${table_arn}/index/pubkey-index`

It must not receive `Scan`, `PutItem`, `UpdateItem`, wildcard table actions, or
`/index/*` for this table. The IAM regression test in
`tests/scripts/test_check_terraform_plan_pr_policy_readonly.py` fences this
shape.
