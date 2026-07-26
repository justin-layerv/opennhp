# Sandbox UDP edge source-fence replacement

The existing Hub, cell0, and cell1 Network Load Balancers were created without
security groups. AWS cannot attach a security group to such an NLB later, so
this change deliberately gives every fenced NLB a new physical name and requires
replacement. Do not attempt an in-place `set-security-groups` workaround.

This runbook is sandbox-only. Production compute keeps its existing edge shape,
and the production Hub remains dark.

Cell1's reviewed `10.102.0.0/16` to `10.104.0.0/16` relocation (NHP PR #3459) is
already applied: cell1 runs in `10.104.0.0/16` today. There is therefore no
combined relocation-plus-fence plan to build, and
`.github/scripts/check-sandbox-cell1-cidr-relocation-plan.py` is not part of this
rollout. Cell1's fence is an ordinary source-fence replacement identical in shape
to cell0's — the NLB name flips `-nlb` to `-edge` inside the VPC it already
occupies. Do not re-run the relocation checker or a relocation plan against
cell1; a VPC move is no longer pending.

## Apply order

1. Confirm the proof runner still owns `3.141.109.76` and its Terraform output is
   exactly `3.141.109.76/32`. Pause the sandbox NHP blue/green deployment lane
   before sealing any cell0 plan. Read `/sandbox/nhp/server/active-color`, the
   live public UDP listener target, and Terraform's managed active-color value;
   all three must say `green` / name the exact green UDP target group. The
   replacement listener derives its create-time target from that managed record
   and exposes no operator-supplied target override. The checker pins the exact
   Terraform 1.14.3/AWS provider 6.54.0 green-to-green listener envelope.
2. Apply the sandbox main root from a reviewed saved plan. It must create the
   replacement cell0 NLB with one SG attached, perform the bounded UDP listener
   handoff, and retire the old NLB. The listener is intentionally
   destroy-before-create: AWS does not permit the existing target group to be
   used by listeners on both old and new NLBs simultaneously
   ([AWS target-group rule](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/create-target-group.html)).
   A brief cell0 proof-edge interruption is expected during this handoff. No
   target SG may retain public UDP ingress.
   The sandbox main workflow admits only this exact replacement graph through
   `--allow-udp-source-fence-replacement`; its post-apply plan omits that flag
   and uses `--require-udp-source-fenced-topology` to prove both the complete
   fenced topology and relay/UDP boundary are back to no-op.
3. Apply the Control root from its reviewed saved plan. The Hub NLB replacement
   must attach its SG at creation; the Hub worker SG must change from public/VPC
   CIDR ingress to the Hub NLB SG on UDP 62206 and TCP 62207.
4. Apply the sandbox proof-edge DNS root so `hub.nhp.layerv.xyz` and
   `cell0.nhp.layerv.xyz` alias the replacement NLBs.
5. Apply the sandbox cell1 root from its own reviewed, refresh-enabled Terraform
   1.14.3 saved plan. Because cell1 is already in `10.104.0.0/16`, this is a
   plain source-fence replacement with no VPC move: it creates the dedicated
   cell1 NLB SG and its exact ingress/egress rules, replaces the public NLB with
   the SG attached at creation, performs the same bounded destroy-before-create
   listener handoff, and removes the legacy public target-SG ingress. The same
   trusted source-fence checker that gates cell0 gates this plan; no relocation
   invariants apply. Cell1 DNS follows that root's replacement-NLB output
   directly.
6. Read back all three NLBs. Each must have exactly one SG. That SG must admit
   only UDP 62206 from `3.141.109.76/32`; target and health egress must be only
   UDP 62206 and TCP 8888 (cells) or TCP 62207 (Hub) to the target SG.
7. Prove a UDP lifecycle succeeds from the proof runner and times out from an
   unrelated public source. Confirm every target remains healthy, the cell0
   listener still names the exact green target group, and the managed active
   color remains `green`. Only then resume the blue/green deployment lane;
   ordinary traffic switches again own the listener target.
8. After all three roots and DNS have converged, remove
   `--allow-udp-source-fence-replacement` from both pre-apply cell0 checks and
   replace it with `--require-udp-source-fenced-topology`. The one-time
   destructive authorization must not remain as the steady-state workflow
   contract.

## Interrupted apply recovery

Terraform replacement is not atomic. An apply can stop after some security
resources converge, while the new NLB is current and the SG-less NLB remains as
a deposed delete, or after the old listener is deleted but before the new one is
created.

Do not re-use a stale saved plan. With the blue/green lane still paused, create a
fresh refresh-enabled Terraform 1.14.3 saved plan from the same reviewed commit
and run the same trusted checker before applying it. The one-time allowance
admits only:

- the exact remaining migration actions plus an exact target no-op for every
  participant that already converged;
- absence of the deleted public target-SG rule (a no-op legacy rule is rejected);
- the captured SG-less legacy NLB as one provider deposed delete, paired with
  the fenced current NLB no-op; and
- the exact destroy/create listener continuation or create-only listener
  continuation, still targeting the managed green target group.

The Control checker applies the same rule to the Hub and additionally pins its
persisted NLB, listener, target-group, worker-SG, and listener-parameter provider
envelopes. Any missing complement, duplicate/deposed resource, foreign change,
changed active target, malformed provider metadata, or wider drift is a hard
stop. Do not use `-target`, import/state edits, a checker bypass, or a broadened
allowance to force convergence; repair the source and obtain a newly reviewed
plan instead. After a successful retry, require the ordinary refresh-enabled
source-fenced no-op/readback before continuing to DNS or cell1.

## Rollback

Rollback is a forward replacement, not re-opening `0.0.0.0/0`. Revert DNS to a
known-good NLB only if that NLB was itself created with the reviewed source
fence. If no fenced prior edge exists, stop the proof and repair the new edge;
never restore the unfenced NLB as a convenience.
