# 2026-07-26 · PR #3453 · Retire the one-time UDP source-fence migration allowance

> **Access policy superseded on 2026-08-03** by
> [`2026-08-03-open-sandbox-udp-edges.md`](2026-08-03-open-sandbox-udp-edges.md)
> and [qurl-go ADR 0001](https://github.com/layervai/qurl-go/blob/main/docs/decisions/0001-sandbox-nhp-access.md).
> The sandbox Hub, cell0 and cell1 edges now admit `0.0.0.0/0` on UDP 443. The
> SG-attached-NLB topology this rollout installed is retained and still
> enforced; only *who* is admitted changed.

- **Owner:** sandbox UDP rollout coordinator
- **Source:** [NHP PR #3453](https://github.com/layervai/nhp/pull/3453)

The rollout itself is done and was verified against live AWS on 2026-08-10:
`layerv-nhp-sandbox-edge`, `layerv-nhp-sandbox-cell1-edge` and
`layerv-nhp-sandbox-hub-edge` all exist with exactly one security group
attached, so the SG-less-NLB replacement converged. Its rollout runbook was
deleted with this rewrite; git history is the record. One task survives.

- [ ] Post-rollout: land the bounded cleanup that removes the remaining one-time
      source-fence migration allowance from
      `.github/scripts/check-relay-dmz-plan.py`. The migration it exists for is
      complete, but the allowance still widens a security fence for a transition
      that can no longer happen.

      Attempted on 2026-08-10 and backed out, so the next attempt starts
      informed. The allowance is not one constant — it is
      `EXPECTED_SANDBOX_PROOF_SOURCE_CIDR`, its use in
      `ACCEPTED_SANDBOX_PUBLIC_UDP_INGRESS_CIDRS`, the one-time source-fence
      replacement tolerance (grep `the one-time UDP source-fence migration
      REPLACES`), and the partial-retry phase logic. Grep the symbols rather
      than trusting line numbers; the file is ~5k lines and moves.
      Simply dropping the address from the accepted set fails **13 tests** in
      `tests/scripts/test_check_relay_dmz_plan.py`, including
      `test_fenced_topology_is_still_admitted`,
      `test_source_fence_migration_preserves_live_green_target` and
      `test_source_fence_partial_retry_accepts_only_exact_target_complement`
      (one of whose phases is literally `proof-runner UDP ingress creation`).

      The checker deliberately models a migration state machine in which that
      exact ingress rule is created and destroyed. The real change is to
      separate **an address a migration plan may mention** from **a source the
      edge may admit**, and to retire the whole fenced-topology branch now that
      no root can select it — all three roots are validation-pinned to `null` or
      exactly `["0.0.0.0/0"]`. That is a reviewed refactor of the fence, not a
      constant deletion.

      This also closes a live hazard: the address the allowance still accepts,
      `3.141.109.76/32`, was the UDP proof runner's EIP and was released when
      that runner was destroyed. See
      [`2026-08-03-open-sandbox-udp-edges.md`](2026-08-03-open-sandbox-udp-edges.md).

Delete this entry once that allowance is gone.
