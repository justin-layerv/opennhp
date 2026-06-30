# qURL Expiry Cross-Service Harness

This e2e package covers the producer-side issue #2488 chain:

1. mint transit qURLs in sandbox,
2. replay the qurl-scanner expiry bucket,
3. verify `qurl.expired` and `resource.closed` were consumed by qurl-api through the webhook dedupe table,
4. verify the transit resource tombstone makes re-mint return `410 resource_tombstoned`,
5. assert resource-lifecycle DLQ depth and scanner Lambda errors stay clean.

The live bot DM tense-flip and qurl-s3-connector object-delete assertions are
tracked separately in #2670. They require bot/connector-owned setup and
cross-account S3 read access that this producer-side harness intentionally does
not require.

The harness also mirrors a few qurl-service/qurl-api storage contracts so it can
verify producer-side expiry effects from this repo: the webhook dedupe PK,
resource/session/access-token table key shapes, tombstone attributes, and the
`qurl_link` fragment formats (`at_` token or `qv1.` base64url bundle). Keep those
helpers in lockstep with qurl-service schema changes; #2932 tracks a more durable
shared contract/fixture so this live harness does not silently drift.

The harness is live-AWS only and skips unless explicitly enabled:

```bash
cd tests/e2e
QURL_EXPIRY_E2E=1 AWS_PROFILE=layerv go test -tags=e2e ./qurl-expiry -count=1 -timeout=35m
```

Useful overrides:

- `QURL_EXPIRY_E2E_ACCESS_TOKEN`: provide a bearer token directly instead of reading the sandbox Auth0 backend secret.
- `QURL_EXPIRY_E2E_AUTH0_SECRET_ID`, `QURL_EXPIRY_E2E_AUTH0_TOKEN_URL`: override the sandbox Auth0 client-credentials source used when `QURL_EXPIRY_E2E_ACCESS_TOKEN` is unset.
- `QURL_EXPIRY_E2E_TTL`: expiry for the single-resource qURLs, default `1m`.
- `QURL_EXPIRY_E2E_MASS_COUNT`: mass fan-out size, default `50`.
- `QURL_EXPIRY_E2E_MASS_TTL`: expiry for the batch-created mass qURLs, default `3m`. The harness creates independent transit resources in one batch so sandbox owner-tier per-resource qURL caps do not mask scanner fan-out behavior.
- `QURL_EXPIRY_E2E_SESSION_DURATION`: active-session precondition duration, default `90s` so the session stays live while the 1-minute expiry bucket closes and both deferral assertions run.
- `QURL_EXPIRY_E2E_TARGET_URL_BASE`: target URL prefix for minted qURLs, default `https://example.com/qurl-expiry-e2e`.
- `QURL_EXPIRY_E2E_RUN_ID`: stable suffix for labels, targets, and idempotency keys when re-running a diagnostic, defaulting to a timestamp-derived value.
- `QURL_EXPIRY_E2E_SETUP_TIMEOUT`: setup budget for AWS config, queue URL lookup, Secrets Manager, and Auth0 token minting, default `60s`.
- `QURL_EXPIRY_E2E_TEST_TIMEOUT`: whole-test context budget and effective per-test cap, default `20m`.
- `QURL_EXPIRY_E2E_WAIT_TIMEOUT`: per-polling-step budget for dedupe, tombstone, session, and queue checks, default `8m`.
- `QURL_EXPIRY_E2E_POLL_INTERVAL`: DynamoDB/SQS polling interval, default `3s`.
- `QURL_EXPIRY_E2E_HTTP_TIMEOUT`: per-request HTTP client timeout, default `30s`.
- `QURL_EXPIRY_E2E_API_RETRY_TIMEOUT`: qurl-service API retry budget for 429, 5xx, and transport errors, default `3m`.
- `QURL_EXPIRY_E2E_REQUEST_SPACING`: delay before qurl-service API calls, default `1.3s` to stay below owner-tier rate limits.
- `QURL_EXPIRY_E2E_DEFER_HOLD`: active-session negative-assertion window, default `20s`.
- `QURL_EXPIRY_E2E_INVOKE_SCANNER=false`: wait for the scheduled scanner instead of direct Lambda bucket replay.
- `QURL_EXPIRY_E2E_ALLOW_SHARED_DLQ_BACKLOG=true`: do not fail on unrelated DLQ backlog in a shared sandbox.
- `QURL_EXPIRY_E2E_ALLOW_SHARED_QUEUE_BACKLOG=true`: do not fail on unrelated main-queue backlog in a shared sandbox.
- `QURL_EXPIRY_E2E_SKIP_SCANNER_ERROR_CHECK=true`: skip the function-global, best-effort scanner Lambda error metric check in noisy shared sandboxes.
- `QURL_EXPIRY_E2E_NAME_PREFIX`, `QURL_EXPIRY_E2E_CELL_ID`, `QURL_EXPIRY_E2E_API_BASE_URL`: point the same harness at another environment.
- `QURL_EXPIRY_E2E_TABLE_PREFIX`, `QURL_EXPIRY_E2E_ACCESS_TOKENS_TABLE`, `QURL_EXPIRY_E2E_RESOURCES_TABLE`, `QURL_EXPIRY_E2E_SESSIONS_TABLE`, `QURL_EXPIRY_E2E_WEBHOOK_DEDUPE_TABLE`, `QURL_EXPIRY_E2E_SCANNER_FUNCTION`, `QURL_EXPIRY_E2E_QUEUE_NAME`, `QURL_EXPIRY_E2E_DLQ_NAME`, `QURL_EXPIRY_E2E_QUEUE_URL`, `QURL_EXPIRY_E2E_DLQ_URL`: override individual AWS resources when an environment does not follow sandbox naming.

Runs mint short-lived sandbox transit resources that tombstone automatically.
Avoid tight loops unless the target sandbox can absorb the temporary DDB churn.
