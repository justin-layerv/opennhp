# Relay CloudWatch Alarms

The relay fleet is the internet-facing NHP edge for browser HTTPS only. Fleet
alarms live in `terraform/modules/relay/monitoring.tf`; the dedicated DMZ DNS
alarm is rooted beside the relay-network module. Both page through the shared
alerts SNS topic. Production remains dark with `deploy_relay=false`. Sandbox
has `deploy_relay=true`, but the DMZ becomes the deployed boundary only after
the apply and live gates in the
[sandbox relay DMZ replacement runbook](sandbox-relay-dmz-replacement.md).

## Alarms

| Alarm | Meaning | First checks |
| --- | --- | --- |
| `relay-tg-unhealthy-hosts` | At least one relay target was unhealthy for two consecutive one-minute windows. | Check the ALB target health reason and HTTPS backend TCP 8080, the instance's relay container logs, `/var/log/user-data.log`, and the SSM relay image tag. |
| `relay-tg-zero-healthy-targets` | The relay target group had zero healthy targets for two consecutive one-minute windows. | Check target registration, ASG activity history, instance boot progress, relay container logs, and `/var/log/user-data.log`. |
| `relay-bootstrap-failure` | A relay instance emitted `BootstrapFailure` during user-data. | Search `/var/log/user-data.log` for `BOOTSTRAP FAILED:`; verify SSM Agent is at least 3.3.40.0, DNS allows the required name, the matching VPC endpoint/policy is healthy, and the image-tag, ECR pull, or relay-secret read is authorized. |
| `relay-capacity-below-baseline` | In-service relay instances stayed below `relay_min_capacity` for two consecutive five-minute windows. | Check ASG activity history, instance refresh state, target health, and per-instance user-data logs. |
| `relay-shedding` | The relay emitted `RelayShed` after rejecting an HTTPS relay request at the application boundary. | Check relay logs for `relay: shed N request(s) to <cell>`, the per-cell `RelayShed` breakdown, target cell NHP server/AC health, and WAF/ALB request volume. |
| `relay-shedding-unknown-environment` | The relay emitted `RelayShed` with `Environment=unknown`, so the process likely missed `NHP_ENVIRONMENT` and the primary shed alarm will not match. | Check the `nhp-relayd` systemd unit for `-e NHP_ENVIRONMENT`, then inspect the relay boot path before trusting the primary shed alarm. |
| `relay-dmz-dns-blocked` | DNS Firewall blocked a relay-DMZ query. | Inspect `/layerv/nhp/sandbox/relay-dmz/resolver` for query name, source address, rule type/action, and threat category. Correlate the source ENI to the relay ASG and check whether a controlled rollout probe was running. |

## DMZ Network Triage

Relay nodes have no public address, NAT gateway, or default route. A bootstrap
or management timeout is not a reason to add internet egress. Check in this
order:

1. Run the structural detector and keep its failure hard:
   `python3 scripts/check-relay-dmz-live.py --mode structural --environment sandbox --wait-seconds 300`.
   Confirm exact peering routes, SG rules, endpoint private DNS/policies,
   fail-closed DNS Firewall, the absence of any relay UDP listener/NLB, the
   assigned-cell server NLB's sole UDP 62206 listener, and active Flow and
   Resolver logs.
2. Resolve the failed hostname and identify its expected endpoint. The supported
   interface services are ECR API/Docker, Secrets Manager, SSM, SSM Messages,
   Logs, Monitoring, and guardduty-data; S3 uses the relay route tables' gateway
   endpoint. There is no ec2messages or KMS endpoint.
3. Use the DMZ Flow Logs group `/layerv/nhp/sandbox/relay-dmz/flow` to distinguish
   SG/routing rejection from an allowed TCP 443 path. AmazonProvidedDNS is not
   present there; use the Resolver group for DNS.
4. Confirm guardduty-data is exactly one endpoint and uses only the
   Terraform-owned endpoint SG. Do not widen relay egress to a second
   GuardDuty-managed SG.
5. Keep OS repair immutable. The relay disables unattended apt timers because
   Ubuntu repositories are unreachable; rebuild the shared server/relay AMI,
   apply the launch-template change, and refresh the canonical relay ASG.

## Expected Transients

Terraform intentionally ignores changes to the relay node security group's
`description` attribute. Security group descriptions are ForceNew in AWS, and a
wording-only edit can otherwise create a replacement SG whose deposed predecessor
cannot be deleted until live relay ENIs move. Future intentional description
rewording requires a deliberate manual recreate/taint plan or an out-of-band
description edit; Terraform still reconciles ingress and egress rule resources.

Deposed relay security-group recovery can also roll the relay fleet onto the
first date-ordered recent CI-built relay image found in ECR, matching the deploy
leg that a blocked app-changing apply never reached. The workflow emits a warning
if that infra-only recovery would replace a different current SSM image tag;
during an incident, confirm this is not overwriting an intentional hotfix pin.
After the relay instance refresh reaches `Successful`, EC2 can still take a short
tail to delete terminated-instance ENIs. The recovery gate waits for that cleanup
before retrying Terraform's deposed SG delete; if it fails closed on lingering
ENIs after an otherwise healthy refresh, re-run the workflow so the next plan can
observe the now-detached security group.

`relay-tg-unhealthy-hosts` can briefly alarm while a newly launched relay target
is still pulling the image, starting the container, and passing its first target
group health checks. This is most likely during instance refreshes or server AMI
rolls because the relay rides the server AMI.

`relay-tg-zero-healthy-targets` can briefly alarm on first sandbox enable, a
terminate-first full-fleet roll, or target-registration churn if the target
group has no healthy relay targets for more than the two-minute alarm window.
Treat it as transient only for a known rollout and only after healthy target
count returns above zero.

When every registered relay target is unhealthy, `relay-tg-unhealthy-hosts` and
`relay-tg-zero-healthy-targets` can page together. Treat that as one incident:
there are no healthy relay targets, and the unhealthy-host alarm explains why.

`relay-capacity-below-baseline` can briefly alarm on the first `deploy_relay`
enable or a terminate-first full-fleet roll if in-service capacity takes longer
than the alarm window to climb back to baseline.

`relay-shedding` and `relay-shedding-unknown-environment` are single-event
detectors. They page on the first shed in the lookback and return to OK
silently after a quiet period; OK means no new sheds arrived, not that the
overloaded cell recovered.

`relay-shedding-unknown-environment` is account-wide because the fallback stream
has no `Cell` dimension. If more than one cell's copy of the alarm fires, treat
them as one incident: the firing alarm name does not localize the relay that
missed `NHP_ENVIRONMENT`; use the relay logs and per-cell `RelayShed` breakdown
to identify the affected path.

`relay-bootstrap-failure` is a single-event detector. The first failed boot
transitions the alarm to ALARM and emits one notification. Additional failures
while the alarm is already ALARM do not send another ALARM notification; the
target-health and capacity alarms are the backstops for a sustained loop. The
alarm can return to OK silently after the next quiet five-minute period because
missing data is treated as not breaching. That OK state means no new bootstrap
failures arrived in the lookback window; it does not prove the failed instance
was healthy.

Treat either case as transient only after the ASG returns to baseline, target
health is green, and `relay-bootstrap-failure` did not fire. A persistent alarm,
a concurrent bootstrap failure, or a zero-healthy-target state is page-worthy
until the bad image/tag, IAM/secret access, or stuck refresh is fixed.

If the failure happens before the bootstrap script can publish metrics, such as
missing AWS CLI, IMDS/network failure, or CloudWatch API unreachability,
`relay-bootstrap-failure` may not emit. In that path, the target-health and
capacity alarms are the backstop.

The controlled functional rollout lookup of `example.com` is retained in
Resolver query logs but deliberately excluded from `relay-dmz-dns-blocked`, so
routine verification does not page. Any alarm therefore represents a different
blocked query and is actionable until the dependency is explicitly reviewed and
allowlisted or the suspected workload is contained.

## Follow-ups

- Server-side "relay enabled but forwards rejected" coverage belongs to the
  server monitoring surface because `MetricRelayForwardReject` is emitted by
  `endpoints/server`; the parity lint verifies the current shared server
  dimension builder still emits `Environment` and `Cell`, so revisit that fence
  if `RelayForwardReject` ever moves to a separate publisher path. It is tracked in
  [#2643](https://github.com/layervai/nhp/issues/2643).
- #6-time alarm tuning, including the zero-healthy-target alarm window and
  statistic, is tracked in
  [#2682](https://github.com/layervai/nhp/issues/2682), after real relay boot
  and traffic baselines exist.
