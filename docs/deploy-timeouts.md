# Blue/Green Deploy Timeouts

Reference for the timeout knobs in `.github/workflows/blue-green-deploy.yml`.
Each input maps to exactly one gate; the budgets are sized for different
things and should not be conflated.

## At a glance

| Input | Default | Bounds | Gate | Budget kind |
|---|---|---|---|---|
| `refresh_timeout_minutes` | 15 min | 5–60 | ASG instance refresh completion | Infra boot |
| `standby_health_timeout_minutes` | 15 min | 2–60 | Standby SSM probe (`curl /ping` on standby instances) | Application boot |
| `pre_switch_knock_ready_timeout_minutes` | 5 min | 2–30 | Pre-switch knock-ready (active server fleet sees new AC peers) | Knock protocol convergence |
| `post_switch_knock_ready_timeout_minutes` | 5 min | 2–30 | Post-switch knock-ready (new active fleet after NLB flip) | Regression detection |

Boot-budget inputs (`refresh`, `standby_health`) share the 2–60 / 5–60
window because they both scale with instance launch + user_data. The
two knock-ready inputs are capped at 30 min — a convergence or
regression budget above 30 is almost certainly masking an upstream bug,
not solving one.

Budgets fall into three categories:

- **Boot budgets** must cover the worst-case wall time for new instances
  to finish `user_data` and bind their service ports. These are the
  ones that get long, because stock-AMI boot variance on shared-tenant
  VPC NAT can be measured in minutes.
- **Convergence budgets** cover the time for the knock protocol to
  settle after both sides are already up. In practice this is sub-second
  once the booted AC can reach the server; the 5 min is padding.
- **Regression-detection budgets** cover the time we're willing to wait
  for a problem to manifest before failing the deploy. Traffic is live,
  so these should be tight — a slow fail keeps the fleet degraded longer.

## Standby ASG target-group invariant

Before server or AC standby scale-up, `blue-green-deploy.yml` runs the
stale-target-group preflight in
`.github/scripts/prune-missing-asg-target-groups.sh`. Server and AC
standby ASGs must have at least one ELBv2-valid target group attached.
If the preflight reports no target groups, or reports that every
attached target group was already deleted, the deploy fails closed by
design, including dry-run dispatches; run Terraform to reattach valid
target groups before scaling or switching traffic. The TG-less frps ASG
is not passed to this preflight.

### AC readiness path cutovers

When a PR changes the AC public TLS/qURL target-group health-check path
(for example, PR #3050 changed `ac_tcp`/`ac_tcp_green` from `/ping` to
`/nhp-ac/ready`), treat the path flip as a staged deploy, not an ordinary
standalone Terraform apply. Target-group health-check paths update in
place against the currently registered AC instances, but Traefik routes
from `user_data` only appear after new instances boot.

Refresh or canary AC instances to a build/user_data that serves the new
path on `:8080` first, verify that path through SSM/curl while the active
target group is still healthy, then apply/switch the target-group
health-check path. Applying the path against old AC instances makes every
old target return 404 and can drain qURL/TLS ingress after
`interval * unhealthy_threshold` (about 90s for PR #3050). Rollback
reverses the order: restore the previous health path first, then roll
instances back.

## `refresh_timeout_minutes` (default 15)

Bounds how long the workflow waits for `aws autoscaling
start-instance-refresh` to reach `Successful`. A 3-instance refresh with
per-instance warmup + health-check grace consistently takes 9–10 min in
sandbox; 15 min is a ~5-minute safety margin over that.

An earlier 10-minute deadline tipped over by ~1 second on one run and
CI marked the step failed even though the refresh itself was healthy
seconds later.

## `standby_health_timeout_minutes` (default 15)

Drives `[Parallel] Verify Standby Health` at
`.github/scripts/verify-asg-instances-healthy.sh`. The probe runs SSM
`AWS-RunShellScript` against every InService standby instance and
retries a component-specific liveness check until every instance
responds 200 or the budget expires:

- **AC**: `curl -sfS http://127.0.0.1:8080/ping` (Traefik admin ping).
  This is the slow one — see below.
- **Server**: `curl -sfS http://127.0.0.1:8888/health/live` (nhp-server
  with `--net=host`). Historically fast, thanks to a pre-built AMI
  (`packer/nhp-server-docker.pkr.hcl`).

**Single shared clock.** The workflow fans out both probes as
background processes and `wait`s on each PID, but they share the same
`standby_health_timeout_minutes` ceiling — there is no separate Server
vs AC budget. That's load-bearing today because AC is the slow component
(no golden AMI) and Server always finishes first. If that ever inverts,
split into `standby_health_server_timeout_minutes` and
`standby_health_ac_timeout_minutes` rather than bumping the shared
ceiling.

### Why this is the long one

ASG instance refresh reports `Successful` once each new instance passes
EC2 status checks + `InstanceWarmup` (60s) has elapsed. That is
decoupled from application readiness. On AC the application-ready time
is dominated by `user_data`:

- three sequential `apt-get install` runs (jq, curl, docker.io,
  iptables, ipset, unzip, gettext-base, iptables-persistent, then
  `iptables-persistent` alone, then `python3-cryptography`)
- AWS CLI v2 download (`curl … awscli-exe-linux-x86_64.zip` + unzip)
- CloudWatch Agent `.deb` download + `dpkg -i` with up to 10 lock-retry
  attempts (unattended-upgrades contention)
- `aws ecr get-login-password | docker login`
- `docker pull` of the AC image
- `docker cp` binaries out of the image
- `aws s3 sync` plugins
- `systemctl start traefik` in `terraform/modules/ac/user_data.sh.tpl`

All of the above runs on whatever Canonical publishes to the
`/aws/service/canonical/ubuntu/server/noble/stable/current/amd64/hvm/ebs-gp3/ami-id`
SSM parameter (wired in `terraform/modules/ac/main.tf`). There is no
golden AMI for the AC today; the server has one
(`/<env>/nhp/server/ami-id` from `packer/nhp-server-docker.pkr.hcl`)
but the AC path was never wired up.

### Sizing evidence (snapshot; disposable)

> The numbers in this sub-section are the one-time measurement that
> justified the 15 min default. They are not kept in sync. If the
> default changes, re-measure from `gh run list` and update; if it
> doesn't, ignore.

15 recent sandbox runs of `blue-green-deploy.yml`, AC-Standby iteration
when the last instance returned `ok`:

| metric | value |
|---|---|
| passed iter 1 (~10s) | 12 / 15 (p50 ≈ 10s) |
| passed iter 2–4 | 3 / 15 (p95 ≈ 3m33s) |
| timed out at prior 5 min default | 2 |
| slowest individual-instance Traefik-ready | **10m35s** |

15 min mirrors `refresh_timeout_minutes` — same "~5 min margin over a
9–10 min observed actual" reasoning.

### When to drop back to 5

Once the AC AMI port ([issue #1086](https://github.com/layervai/nhp/issues/1086))
lands, `user_data` collapses to ~60–90 s (just EIP claim + `docker pull`
+ config render + `systemctl start`). This default can then return to 5
and the inline comment should be updated to delete the distribution
reference.

## `pre_switch_knock_ready_timeout_minutes` (default 5)

Drives `[Server] Verify Knock Readiness (AC Peers Connected)` via
`.github/scripts/verify-knock-ready.sh`. Polls every InService instance
in the *active* server ASG (not the standby) for
`/health/knock-ready`, which returns 200 only after every expected AC
peer has completed its NHP-AOL/NHP-AAK handshake with that server.

### Why 5 min, not 15

This gate runs *after* the standby health gate has already passed,
which means:

- standby AC's `Traefik` is bound on `:8080/ping`
- standby AC's `nhp-acd` is bound (started immediately after traefik
  in `user_data.sh.tpl`)
- standby AC has sent NHP-AOL to the server and received NHP-AAK
  (observed <1 s after `nhp-acd` start in instance logs)

So once standby health passes, the server side sees the new peers
within seconds. The 5-minute budget is generous padding for NLB/DNS
propagation and SSM polling interval; it is not a boot budget.

If you find yourself tempted to raise this above 5, the real bug is
probably upstream — either the standby health gate let an unhealthy
instance through, or the active servers are themselves degraded.

## `post_switch_knock_ready_timeout_minutes` (default 5)

Drives `[Server] Verify Post-Switch Knock Readiness`, which runs
*after* the NLB listener has flipped to the newly-active color.
Traffic is already live on the new servers at this point, so this
window is a regression-detection budget — the time we're willing to
wait for a problem to surface before failing the deploy.

### Keep this tight

A slow fail here means the fleet sits in a known-broken state while
we're still patiently probing. 5 min is enough to absorb NHP
re-registration churn after the AC restart step forces reconnects; it
is not enough to mask a real problem.

If the post-switch gate fails, the standard response is a rollback
(switch traffic back to the previous color) via
`blue-green-deploy.yml action=rollback`. This is fast (<1 s listener
flip) and returns to a known-good state.

### Interaction with the AC's NLB re-registration cadence

If an AC's first registration after restart lands on the old color
(NLB UDP listener propagation race), the `nhp-acd` keepalive path
goes direct-to-IP and stays latched on the wrong color until the
periodic NLB re-registration safety net fires. That safety net's
cadence (`DefaultNLBReregistrationInterval` in
`endpoints/ac/registration.go`) must fit inside this gate so the
latch heals before the gate gives up — see PR #1726 and
`TestNLBReregistration_BoundedByDeployGate` for the compile-time
fence.

The workflow's lower bound on `post_switch_knock_ready_timeout_minutes`
is **3 min**, raised from 2 in PR #1726 so the safety net's worst-case
fire interval (90 s + 25 % jitter = 112.5 s) plus the gate's own
2-consecutive-iterations convergence cost (~12-20 s) fits inside the
budget. The compile-time fence
`worst_case_fire_plus_convergence_fits_workflow_minimum_gate`
asserts this relationship so a future PR that lowers either side
past the safe envelope fails before shipping.

### Manual escape hatch: AC re-bounce after a stuck deploy

If the post-switch gate fails because ACs latched onto the
old-color server fleet (race window described above), the
remediation is to restart `nhp-acd` on the active AC ASG so each
AC re-registers fresh through the NLB. Once the new color is
serving the listener, the fresh registration lands on the new
color and the gate clears on the next iteration.

Sandbox:

```
AWS_PROFILE=layerv aws ssm send-command \
  --document-name AWS-RunShellScript \
  --targets Key=tag:Name,Values=layerv-nhp-sandbox-ac \
  --parameters 'commands=["systemctl restart nhp-acd"]' \
  --comment "PR #1726 chicken-and-egg AC bounce"
```

Prod:

```
AWS_PROFILE=layerv-prod aws ssm send-command \
  --document-name AWS-RunShellScript \
  --targets Key=tag:Name,Values=layerv-nhp-prod-ac \
  --parameters 'commands=["systemctl restart nhp-acd"]' \
  --comment "PR #1726 chicken-and-egg AC bounce"
```

Then re-run `verify-knock-ready` against the active server ASG
(or just dispatch `blue-green-deploy.yml` again — the new binary
self-heals via the periodic NLB safety net within ~2 min).

## Precedence

When the standby health gate is the bottleneck, the order of magnitude
is 5–10 min today. All other gates are sub-minute. The budgets above
are ceilings, not floors — a fast deploy will pass every gate on
iteration 1 and spend the full budget only on the slow tail.
