# Runbook: NHP ACK token shared-store failures

## What fired

One or more of these NHP server CloudWatch alarms or signals:

- `ACKTokenSharedStoreInitFailure` — a configured fleet-visible ACK token store could not initialize during server startup.
- `ACKTokenSharedStoreWriteFailure` — NHP completed AC operations but could not persist the AC-issued ACK token metadata to DynamoDB.
- `ACKTokenSharedStoreReadFailure` — `/nhp/internal/token/validate` missed the local process cache and could not read the shared ACK token store.
- Agent-visible error `52021` / `server token persistence failed` — AC operations succeeded, but the ACK token metadata write failed, so the server failed the knock response instead of returning a token that only one NHP process could validate.

## What it means

The `ack_tokens` DynamoDB table is the cross-instance fallback for short-lived AC-issued ACK tokens. It removes process affinity between the NHP server that handled the knock and the FRPS auth-plugin validation request that may land on a different NHP server.

`ACKTokenSharedStoreWriteFailure` has one subtle but important ordering detail: the AC has already opened the temporary pinhole (the temporary AC firewall/ipset allowance for the agent source) before NHP can persist the ACK token metadata. If the write fails, the agent sees `ErrServerTokenPersistFailed` and does not receive a usable token, but the AC-side opening may exist until the knock `OpenTime` expires. That is expected fail-closed behavior for the token path, not a persistent access leak. Do not spend incident time chasing "ghost" iptables rules unless they outlive the AC's configured open window.

`KnockPinholeOrphaned` increments once per failed ACK publication after AC operations succeeded. Use it to size the temporary AC-open/no-token window; `ACKTokenSharedStoreWriteFailure` remains the lower-level write-attempt signal and should track it 1:1 unless the shared-store writer grows internal retry behavior later.

If a multi-resource ACK publish fails partway through, rows written before the failed token can remain in `ack_tokens` until their TTL expires. Those rows contain only hashed opaque tokens that were never returned to the agent; they are expected bounded debris, not usable credentials.

## First five minutes

1. Check recent NHP deploys or Terraform applies that touched DynamoDB, IAM, KMS, or NHP server launch-template environment:
   ```bash
   gh run list -R layervai/nhp --limit 10
   ```
2. In NHP server logs, search for `server token persistence failed`, `persist ACK token metadata`, `ACKTokenSharedStoreWriteFailure`, and `ACKTokenSharedStoreReadFailure`.
3. Check DynamoDB health for the environment's `ack_tokens` table: throttling, `AccessDeniedException`, `ResourceNotFoundException`, and KMS errors are the most likely root causes.
4. If the first errors started immediately after an IAM/KMS policy edit, allow for the documented IAM evaluator propagation window, then confirm fresh instances can `PutItem` and `GetItem` against `ack_tokens`.
5. If validation is returning 503 from `/nhp/internal/token/validate`, verify qurl-reverse-tunnel-server is classifying non-2xx validator responses through its transport-error path (`event="knock_token_validator_error"` in [internal/tunnelauth/handler.go](https://github.com/layervai/qurl-reverse-tunnel-server/blob/main/internal/tunnelauth/handler.go), backed by [internal/tunnelauth/knock_validator.go](https://github.com/layervai/qurl-reverse-tunnel-server/blob/main/internal/tunnelauth/knock_validator.go)) rather than converting them to permanent `not_found` responses.
6. During a DynamoDB read outage, tunnel-server retries still create repeated `GetItem` attempts, though each validate request is bounded by the caller context and `DynamoDBOperationTimeout`; if NHP CPU or DynamoDB client saturation rises, reduce retry pressure at the tunnel-server edge before disabling the shared store.

## Mitigation

Prefer restoring the shared store dependency over disabling it. In a multi-instance NHP fleet, turning off `AckTokensTable` recreates the original cross-instance `not_found` failure mode.

Use these mitigations in order:

1. Restore DynamoDB/IAM/KMS access for the NHP server role.
2. Roll back the most recent NHP Terraform or server change if it introduced a bad table name, KMS condition, or role attachment.
3. If DynamoDB itself is regionally impaired, fail closed and communicate customer impact; local-only validation is not architecturally safe for the reverse tunnel fleet.

## After recovery

Confirm all three paths:

1. A fresh knock succeeds and returns an ACK token.
2. `/nhp/internal/token/validate` succeeds when it lands on a different NHP instance from the knock.
3. `ACKTokenSharedStoreHit` increments during the cross-instance validation test, while write/read failure counters stop increasing.
