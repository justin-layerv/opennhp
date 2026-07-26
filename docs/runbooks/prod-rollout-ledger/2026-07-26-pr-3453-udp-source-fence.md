# 2026-07-26 · PR #3453 · Source-fence sandbox UDP edges

- **Owner:** sandbox UDP rollout coordinator
- **Source:** [NHP PR #3453](https://github.com/layervai/nhp/pull/3453)

Replace the three sandbox SG-less public UDP NLBs with SG-attached,
proof-runner-only edges. Production remains unchanged and dark.

- [ ] Pre-rollout: after the unrelated Control Authority/catalog transitions
      converge, produce complete Terraform 1.14.3 saved plans for sandbox main,
      Control, sandbox cell1, and sandbox Hub DNS. Cell1's `10.102.0.0/16` to
      `10.104.0.0/16` relocation (#3459) is already applied, so cell1 takes an
      ordinary standalone source-fence plan in the VPC it already occupies —
      there is no combined relocation-plus-fence graph and no relocation checker
      in this rollout.
      Require every trusted checker to accept only the reviewed envelopes and
      confirm the proof runner still owns exactly `3.141.109.76/32`. Pause the
      cell0 blue/green lane and prove the managed active-color parameter,
      Terraform state, and live public listener all identify the exact green
      UDP target group before sealing the cell0 plan.
- [ ] Rollout: follow
      [`sandbox-udp-source-fence-replacement.md`](../sandbox-udp-source-fence-replacement.md)
      from the merged commit, applying only its reviewed cell0, Control, cell1,
      and DNS saved plans. Accept only the documented brief sandbox listener
      handoffs; stop on any unreviewed plan participant. If an apply is
      interrupted, discard its stale saved plan and apply only a fresh
      refresh-enabled Terraform 1.14.3 plan that the trusted checker accepts as
      the exact remaining subset with exact target no-ops or the bounded
      deposed-NLB/listener continuation. Never recover with `-target`, state
      edits/imports, or a widened checker.
- [ ] Post-rollout: read back exactly one security group on every public UDP
      NLB, NLB-SG-only target ingress, healthy targets, successful UDP lifecycle
      from the proof runner, and timeout from an unrelated public source. Record
      that cell0 remains green-to-green across replacement, then resume normal
      blue/green ownership. Record
      a refresh-enabled no-op for every applied root using the permanent
      `--require-udp-source-fenced-topology` contract, then land the bounded
      cleanup that removes the remaining pre-apply one-time replacement
      allowance.
- [ ] Production exclusion: before merge, verify the production plans contain
      no UDP-edge replacement or activation. Record that any future production
      activation requires a separate reviewed edge/source policy, saved-plan
      sequence, negative probe, and rollback contract.
- [ ] Rollback: stop proof traffic and use a forward replacement. Repoint DNS
      only to a previously verified source-fenced edge; never restore the
      SG-less NLB or reopen UDP 62206 to `0.0.0.0/0`.
