# 2026-07-05 · PR #3088 · qURL one-time browser opens need AZ fanout coverage

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/3088

Fresh one-time sandbox qURL browser opens timed out because the shared sandbox
ACId assignment collapsed to one current-color server during a blue/green
straddle. Sandbox runs one public AC per AZ. The relay/origin server can only
open pinholes on every AZ if the stored assignment preserves one dialable server
per AZ for bounded `NHP_FWD` fanout. Each origin knock should forward to at most
one non-local assigned server per AZ; a singleton assignment sends the admission
to one server/AC path while the viewer's `qurl.site` GET can land on a different
active AC. Fresh qURL v2 links also use a public-key resource identifier that a
peer server may not resolve from its local catalog, so `NHP_FWD` must carry the
origin-resolved routing snapshot for the receiver to open the same AC route.
ACs run `FilterMode = EBPFXDP`, so every successful eBPF admission must mirror
the same tuple into ipset or the kernel DROP gate can still block the packet
before Traefik.

Load-bearing coverage precondition: bounded fanout opens one selected server's
local AC slice per non-local AZ, plus the origin server's local slice. The
public qurl.site NLB must therefore have no active AC target outside that
selected per-AZ coverage set for the shared ACId. Sandbox satisfies this with
one active public AC per AZ and one assigned server per AZ. If any assignment
has multiple eligible peer-server candidates in a non-local AZ,
`MetricKnockFanoutDuplicateAZCandidate` must be treated as a pre-promotion
warning: keep the one-peer-per-AZ bound, but investigate topology before relying
on the browser proof for prod.

Functional side effects to verify with the AC rollout:

- EBPFXDP mode now requires the ipset mirror writer at AC startup; if `ipset` is
  unavailable, AC startup fails closed instead of admitting eBPF-only traffic
  through a default-DROP iptables gate.
- Range-mode ICMP eBPF entries now use the same temporary TTL as the existing
  ipset tempset mirror and the IPTABLES-mode range ICMP path. TCP/UDP range
  admissions fail closed on any per-IP eBPF insert failure instead of returning
  success without the net-level mirror.

- [ ] Pre-rollout (sandbox): deploy the server build that suppresses
      cross-color assignment migrations when the current-color target set would
      reduce dialable server or AZ coverage. Confirm no shared ACId row for the
      active AC fleet has fewer than three dialable assigned-server AZs and no
      `MetricKnockFanoutDuplicateAZCandidate` growth during fresh qURL opens.
      Keep the old-color server fleet registered and Cloud Map-healthy until the
      new-color fleet has reached equal dialable/AZ coverage and the browser
      proof below has passed; suppression redirects ACs back to those old-color
      peers during propagation.
- [ ] Pre-rollout (sandbox): deploy/refresh the AC build with the eBPF-to-ipset
      mirror before relying on `FilterMode = EBPFXDP` qurl.site ingress; confirm
      the AC image/user_data path has `ipset` available before flipping traffic.
- [ ] Post-rollout (sandbox): mint a fresh one-time qURL from outside the VPC,
      open it through qurl.link in a browser, and confirm it reaches the target
      URL instead of stalling on `qURL Verifying access`.
- [ ] Post-rollout (sandbox): for the browser client IP, confirm the active ACs
      show one effective `{client_ip,443,ac_local_ip}` pinhole per AZ during the
      open window and no `[NHP-DENY]` for the admitted tuple.
- [ ] Post-rollout (sandbox): confirm `NHP_FWD` fanout was attempted for the
      bounded one-peer-per-non-local-AZ target set, that peer receivers used the
      origin-resolved qURL v2 route when needed, and that the assignment row
      still covers the active AC AZ set after the browser proof.
- [ ] Prod sign-off: do not promote until the sandbox browser proof, assignment
      AZ-coverage proof, bounded FWD fanout proof, qURL v2 forward-route proof,
      AC ipset-mirror proof, and zero duplicate-AZ-candidate metric growth are
      linked on the PR.
- [ ] Rollout (prod): promote server and AC changes together, then refresh the
      affected fleets so assignment suppression and AC ipset mirroring are both
      present before prod qURL browser traffic relies on the path.
- [ ] Post-rollout (prod): run a prod-safe fresh qURL browser smoke and confirm
      the same assignment AZ coverage, bounded FWD fanout, qURL v2 forward-route
      fallback, and per-AZ AC pinhole evidence.
- [ ] Rollback: if qURL browser ingress still stalls, roll back the server
      assignment/fanout build or temporarily restore the affected AC assignment
      to a full dialable AZ set; if AC ipset evidence is absent, roll back the AC
      build or flip the affected environment back to `FilterMode = IPTABLES`
      before retrying prod qURL traffic.
