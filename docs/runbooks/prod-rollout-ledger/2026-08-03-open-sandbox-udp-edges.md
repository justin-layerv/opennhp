# 2026-08-03 · Open the sandbox UDP edges to developers

- **Owner:** sandbox UDP rollout coordinator
- **Decision:** [qurl-go ADR 0001](https://github.com/layervai/qurl-go/blob/main/docs/decisions/0001-sandbox-nhp-access.md)
- **Supersedes the access policy in:**
  [`2026-07-26-pr-3453-udp-source-fence.md`](2026-07-26-pr-3453-udp-source-fence.md)

Move the sandbox Hub, cell0, and cell1 public UDP-443 edges from the
proof-runner `/32` fence to `0.0.0.0/0`. Developers inside and outside the
company can then run qurl-go against sandbox from any network. This is the
"separate reviewed edge/source policy" that PR #3453's ledger required before
any change here.

Production is out of scope and unchanged. The prod roots keep their
`hub_public_udp_ingress_cidrs == null` and `public_nhp_udp_ingress_cidrs == null`
validations, so no production edge can be opened by this change.

## What changes

- All three sandbox roots move to `["0.0.0.0/0"]`. The environment-level pins are
  **retained, not deleted** — each now pins the open value, so drift still fails
  a plan and any future change to sandbox access remains a deliberate edit with
  an ADR behind it.
- The `connector-authority-foundation` and `compute` modules accept exactly one
  broad value, the literal `["0.0.0.0/0"]`. Every other broad CIDR — `10.0.0.0/8`,
  `0.0.0.0/1`, or the open value mixed with a `/32` — still fails validation, so
  opening an edge stays greppable and a fat-fingered supernet cannot slip in.
- `--require-udp-source-fenced-topology` keeps working and keeps its name. It no
  longer forbids an internet-wide rule on the **public NLB** security group, and
  it still forbids one anywhere else — in particular the server target SG, which
  must stay NLB-scoped. That is the invariant that protects the backend: the
  load balancer is public, the instances behind it are not.

## Why this is not a novel weakening

NHP is a network-hiding knock protocol built to sit on a public UDP port. It
never answers an unauthenticated packet, authenticates a Noise handshake against
a pinned server key, and enforces cookie-based return routability on both the
Hub LST and assigned-cell reknock paths. The fence was scaffolding for the
sandbox measurement phase, which is why the prod roots describe their own pins
as unset "throughout sandbox measurement" and why
`terraform/environments/prod/variables.tf` already anticipates "a future
reviewed production NHP public-edge migration."

## Risks accepted

- Sandbox becomes internet-reachable and will be scanned. Silent drop and the
  cookie challenge are the mitigations; NLB and Fargate capacity are finite, so
  a determined flood can still degrade sandbox. Sandbox carries no customer data.
- The proof pipeline loses its "timeout from an unrelated public source"
  negative control, because that is now a supported access path. The positive
  assertions — the proof runner completing a full authenticated lifecycle — are
  unaffected.
- Sandbox source attribution weakens. Sandbox evidence can no longer be used to
  argue anything about source provenance.

## The merge-to-apply window

The live-state checkers pin the expected ingress in lockstep with the Terraform,
so between merging and applying they expect an open edge that live state does
not yet have. Every invocation was checked and none runs against unmigrated live
state:

- `build-and-push.yml` triggers on push to `main` and runs
  `check-relay-dmz-live.py --mode structural` **after** its own
  `terraform apply`, so the cell0 edge is already open when the check reads it.
- `control-sandbox-update.yml` (the Hub root) is `workflow_dispatch` only.
- `udp-edge-readiness.yml` is `workflow_dispatch` only.
- `validate-workflows.yml` only `py_compile`s the checkers.

No scheduled job invokes either live checker. Still apply promptly after merge:
the guarantee above is about automation, not about a human dispatching a verify
against a half-migrated estate.

## Rollout

- [ ] Pre-rollout: produce Terraform 1.14.3 saved plans for sandbox main,
      Control, and sandbox cell1. Each plan's only security-group delta must be
      on the public NLB SG: create the `0.0.0.0/0` UDP-443 ingress rule and
      destroy the `3.141.109.76/32` one. Require no NLB, listener, or target
      group replacement, and no change to any server/target SG rule. Confirm the
      trusted checker accepts each plan with
      `--require-udp-source-fenced-topology`.
- [ ] Rollout: apply Control (Hub), then sandbox main (cell0), then cell1. Order
      is not load-bearing — each edge is independent and every step only widens
      ingress, so there is no window in which a previously working client breaks.
- [ ] Post-rollout: read back exactly one security group on every public UDP
      NLB; Hub and cell1 ingress exactly `0.0.0.0/0` UDP 443; cell0 ingress
      `0.0.0.0/0` plus the seven managed AC EIP `/32`s, which the `ac` module
      still owns and which become redundant but are left in place. Confirm
      healthy targets and a successful UDP lifecycle from the proof runner.
      Confirm a successful lifecycle from an ordinary developer network — this
      replaces the former timeout check as the access assertion.
      Record a refresh-enabled no-op for every applied root.
- [ ] Production exclusion: verify the production plans contain no UDP-edge
      change. Production activation still requires its own reviewed edge/source
      policy, saved-plan sequence, negative probe, and rollback contract.
- [ ] Rollback: **do not use the address this entry originally named.** It said
      to revert the three roots to `["3.141.109.76/32"]`. That was the UDP proof
      runner's EIP, and the runner was destroyed on 2026-08-10 (#3804): the
      address was released and is back in the AWS public pool, so re-admitting
      it would allowlist whichever account now holds it. Verified 2026-08-10
      that no live security-group rule and no committed root still carries it.

      A re-fence must therefore allocate a **new EIP we own** and set the three
      roots to that `/32`. The module validation still accepts an exact `/32`
      list, so this needs no module change. Note it re-breaks developer access
      by design and should supersede ADR 0001 rather than be done silently.

      Nothing enforces this yet, which is the residual risk.
      `.github/scripts/check-relay-dmz-plan.py` still lists the retired address
      in `ACCEPTED_SANDBOX_PUBLIC_UDP_INGRESS_CIDRS`, so a plan that re-admits
      it would pass the fence. That acceptance cannot simply be dropped: the
      checker's source-fence migration and partial-retry paths model plans that
      create and destroy that exact rule, and removing it fails 13 tests in
      `tests/scripts/test_check_relay_dmz_plan.py` including
      `test_fenced_topology_is_still_admitted`. Separating "an address a
      migration plan may mention" from "a source the edge may admit" is a real
      change to that state machine and wants its own reviewed PR.
