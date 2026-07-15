# 2026-07-15 · PR #3264 · connector-auth env rename (enable qurl-service connector auth)

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/3264 · qurl-service `origin/main` `internal/config/config.go:1048` (`CONNECTOR_AUTH_ENABLED`, default false) + `:1053` (`QURL_CONNECTOR_ACTIVE_REGISTRATIONS_ENABLED`, default false)

qurl-service `origin/main` renamed its env gates "tunnel auth" → "connector auth"
and no longer reads the old `TUNNEL_AUTH_ENABLED` /
`QURL_TUNNEL_ACTIVE_REGISTRATIONS_ENABLED`. The nhp terraform still rendered the
old (now-dead) names, so both new gates defaulted **off** and the qURL API
returned `403 connector_disabled` ("qURL Connector operations are currently
unavailable"), blocking tunnel creates/registrations. This PR only renames the
rendered ECS env var names (values unchanged — still `true` in sandbox and prod)
so the intended `true` actually reaches the new code. This **is** a prod behavior
change: it enables connector auth + active registrations on the prod qurl-service,
which the dead vars had been silently defaulting off.

- [ ] Rollout: apply sandbox first, then prod. Confirm each target cell's
      qurl-service image is the renamed `origin/main` build (reads
      `CONNECTOR_AUTH_ENABLED` / `QURL_CONNECTOR_ACTIVE_REGISTRATIONS_ENABLED`)
      before apply, so the flip is meaningful and not a no-op against an old image.
- [ ] Post-rollout: confirm `POST /v1/resources` type=tunnel no longer returns
      `403 connector_disabled`, and the connector (reverse-tunnel) E2E round-trip
      passes — in sandbox, then prod.
- [ ] Post-rollout: verify the **prod cell** had the same dead-var gap and it is
      now closed — the rendered qurl-service task-def env shows
      `CONNECTOR_AUTH_ENABLED=true` + `QURL_CONNECTOR_ACTIVE_REGISTRATIONS_ENABLED=true`.
- [ ] Cross-repo: values-unchanged rename only; depends on qurl-service having
      shipped the connector-auth rename (config.go:1048/1053). Sequence the
      qurl-service deploy first per cell — a cell still on a pre-rename image reads
      the old names this PR removes, so it loses the gate until it updates.
- [ ] Rollback: revert this PR (re-renders the old names). Safe only against a
      qurl-service image that still reads the old names; a cell on renamed
      `origin/main` would fall back to the new gates' `false` defaults and 403 again.
