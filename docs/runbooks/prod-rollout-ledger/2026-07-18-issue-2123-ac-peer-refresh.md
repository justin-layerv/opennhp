# 2026-07-18 · issue #2123 · AC shared-key peer convergence

- **Owner:** NHP rollout coordinator
- **Source:** [NHP #2123](https://github.com/layervai/nhp/issues/2123), [qurl-service #1272](https://github.com/layervai/qurl-service/pull/1272)

Deploy the AC peer-convergence fix before treating the qURL v2 smoke as an
activation signal. The failed qurl-service #1272 smoke exposed rotating assigned
server subsets accumulating in the bounded shared-key peer group until live
servers were refused.

- [ ] Sandbox rollout: deploy the exact merged NHP image to the full AC fleet, exercise at least eight assignment epochs across both three-server color sets, and wait for every instance to complete at least one configured periodic NLB refresh. After each epoch, confirm the existing `ServersConnected` gauge returns to the assignment target count and AC logs report the corresponding successful connections, with no `MaxPeerGroupSize` refusal or `peer does not match its previous address`.
- [ ] Cross-repo proof: after the sandbox AC rollout is stable, build qurl-service current `main` into an exact-image qURL v2 smoke run; require successful portal admission instead of 52005 and link the run on the NHP PR and #2123.
- [ ] Production rollout: promote the same NHP image through the normal AC rollout, then observe at least one periodic NLB refresh on every AC and confirm assigned-server connectivity remains healthy without peer-group refusals or address-mismatch errors.
- [ ] Rollback: restore the preceding AC image through the normal fleet rollout, keep connector activation blocked, and treat qURL v2 admission as unproven until a corrected image completes the same sandbox checks.
