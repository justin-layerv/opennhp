# 2026-06-18 · PR #2707 · Relay security group lockdown

- **Owner:** prod rollout coordinator
- **Source:** [PR #2707](https://github.com/layervai/nhp/pull/2707), [issue #2680](https://github.com/layervai/nhp/issues/2680)

Applies the relay security-group posture needed for the relay-only qURL path: public ingress terminates at the relay ALB, and relay nodes only reach private NHP servers on UDP 62206 plus the minimum AWS endpoint traffic needed for boot and telemetry. Sandbox has relay enabled today; prod relay remains dark until a later rollout flips `deploy_relay`.

- [ ] Sandbox apply: confirm relay nodes no longer have broad `0.0.0.0/0` egress, have UDP 62206 egress only to the private subnet CIDRs, and receive UDP ACK-return ingress only from the NHP server security group.
- [ ] Sandbox apply: verify relay instances can still pull their ECR image, fetch required SSM/Secrets Manager inputs, publish CloudWatch metrics through the new Monitoring interface endpoint, and serve `/health/live` behind the relay ALB.
- [ ] Rollout: before enabling prod relay, confirm the prod plan keeps `deploy_relay = false` until the JS-agent qURL cutover PRs are ready, then re-check the same relay SG shape as sandbox when prod relay is enabled.
- [ ] Post-rollout: run a qURL relay-path smoke that proves the browser reaches `relay.qurl.link.layerv.xyz`, relay forwards only to NHP over UDP 62206, and no resolve-path or relay-node security group rule reintroduces direct broad ingress/egress.
- [ ] Rollback: if relay health or control-plane bootstrapping fails after the SG lockdown, revert this PR or temporarily restore the previous relay egress rule, then re-apply and confirm the relay ASG target group returns healthy before retrying the lockdown.
