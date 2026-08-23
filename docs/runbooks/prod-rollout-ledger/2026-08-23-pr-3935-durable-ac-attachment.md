# 2026-08-23 · PR #3935 · Durable AC attachment recovery

- **Owner:** prod rollout coordinator
- **Source:** [NHP #3935](https://github.com/layervai/nhp/pull/3935), [NHP #3928](https://github.com/layervai/nhp/pull/3928)

The same server and AC repair image must be part of the one attended durable-session
production cut. Do not activate this runtime independently or restore a receipt-free
server/AC pair after the minimum durable-profile floor is committed.

- [ ] Pre-rollout: require the sandbox recovery to reach `COMPLETE` with the exact #3935-derived server and AC image provenance, stable READY TARGET/OWNER rows with `pending_count=0`, repaired `/nhp-ac/ready`, cell0 knock readiness, the declared nonassignable/empty cell1 topology, and the protected qURL lifecycle smoke green.
- [ ] Pre-rollout: review a real refresh-enabled production plan and the attended forward-only cutover controller; confirm every prod mutation and rollback entry point enforces the minimum durable-profile floor and cannot reactivate the legacy server or AC image after the point of no return.
- [ ] Rollout: refresh and attest the matching server and AC images in the controller-defined order, require every AC instance to hold the durable admission lease, then run the production direct, forwarded, reconnect, exact-retirement, and sibling-continuity journeys before reopening admission.
- [ ] Post-rollout: confirm no repeated same-candidate PREPARING/version churn, failed RVA routing, pending close work, readiness false-positive, stale-authority, or lifecycle-recovery errors; record exact image digests and smoke run links on #3935.
- [ ] Rollback: before the point of no return, restore the paired prior server and AC capacity through the attended controller. After the minimum profile advances, stop admission and forward-fix only; never restore a receipt-free artifact.

