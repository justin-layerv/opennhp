# Relay CloudWatch Alarms

The relay fleet is the internet-facing NHP surface for browser knocks. Its
alarms live in `terraform/modules/relay/monitoring.tf` and page through the
shared alerts SNS topic. The relay is dark in prod until the #2208/#6 browser
path carries traffic, but sandbox has `deploy_relay=true`; the next sandbox
apply creates these alarms and routes relay pages to the shared topic while the
fleet still boots, health checks, and emits bootstrap failure metrics.

## Alarms

| Alarm | Meaning | First checks |
| --- | --- | --- |
| `relay-tg-unhealthy-hosts` | At least one relay target was unhealthy for two consecutive one-minute windows. | Check the ALB target health reason, the instance's relay container logs, `/var/log/user-data.log`, and the SSM relay image tag. |
| `relay-tg-zero-healthy-targets` | The relay target group had zero healthy targets for two consecutive one-minute windows. | Check target registration, ASG activity history, instance boot progress, relay container logs, and `/var/log/user-data.log`. |
| `relay-bootstrap-failure` | A relay instance emitted `BootstrapFailure` during user-data. | Search `/var/log/user-data.log` for `BOOTSTRAP FAILED:` and verify IMDS, the relay image tag, ECR pull, and Secrets Manager relay key access. |
| `relay-capacity-below-baseline` | In-service relay instances stayed below `relay_min_capacity` for two consecutive five-minute windows. | Check ASG activity history, instance refresh state, target health, and per-instance user-data logs. |

## Expected Transients

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

## Follow-ups

- Server-side "relay enabled but forwards rejected" coverage belongs to the
  server monitoring surface because `MetricRelayForwardReject` is emitted by
  `endpoints/server`; it is tracked in
  [#2643](https://github.com/layervai/nhp/issues/2643).
- #6-time alarm tuning, including the zero-healthy-target alarm window and
  statistic, plus dim-set parity linting are tracked in
  [#2644](https://github.com/layervai/nhp/issues/2644), after real relay boot
  and traffic baselines exist.
