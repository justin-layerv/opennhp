# Runbook: L3 flush scheduler — circuit breaker open

## What fired

One of:

- **AC log line `[ExpirySched] circuit breaker OPEN: N errors in <window>`** — the L3 flush scheduler observed `L3FlushErrorThreshold` flusher errors within `L3FlushErrorWindowSec`. Subsequent NHP-AOP admissions fail closed with error code `53010` (`ErrACSchedulerBreakerOpen`).
- **AC log line `[HandleAccessControl] L3 flush scheduler breaker OPEN — refusing new NHP-AOP (fail-closed admission)`** — confirms a customer-visible admission denial.
- **Customer report: new qURL access fails** with NHP-AOP timeout / 503 from qurl-router. Trace the request to the AC, look for the admission-gate log line above.

The implementation lives in `endpoints/ac/expiry_scheduler.go` (breaker state + `IsBreakerOpen()`) and `endpoints/ac/msghandler.go` (admission gate at `HandleAccessControl` top). PR #2164 is the original context.

## Why the breaker exists

Under the L3-only enforcement contract (post-L7-removal target), a stuck flusher means kernel allow-rule entries persist past their intended deadline — equivalent to admitting traffic past session end. Fail-closed admission converts that latent security issue into a loud, customer-visible refusal so on-call sees it immediately and acts. The breaker does NOT auto-recover; manual operator review is required because an opened breaker indicates a security-relevant flusher failure.

## Triage gauges — what to look at first

The AC publishes gauges via the SSM-readable metrics endpoint and CloudWatch (`L3Flush*` family in the AC namespace). On a fresh breaker open, read these in order:

1. **`L3FlushBreakerOpen` (0/1)** — confirms the trip. If 0 on every AC in the active color, the trip already cleared (the breaker only auto-resets on a full reload, so a 0 here means the AC was restarted out from under the page).
2. **`L3FlushErr` rate (per-min)** — the immediate driver. If `L3FlushErr / L3FlushTotal > 0.1` sustained, the flusher path itself is faulting; jump to step 2 of "First five minutes" (kernel-side health). If the ratio is near zero but the breaker is still open, the trip was historical and step 3 (decide reset) applies.
3. **`L3FlushDropped`** — backpressure-driven drops. Non-zero indicates the dispatch path is rejecting flushes (worker pool saturated AND the bounded queue full AND `maxConsecutiveDefers` exceeded). Often a *symptom* of slow flushers rather than a root cause; correlate with `L3FlushErr`.
4. **`L3FlushDeferred`** — soft backpressure (re-bucketed for next tick). Increasing without a corresponding `L3FlushDropped` rise means the queue is keeping up; healthy. Increasing alongside `L3FlushDropped` means saturation.
5. **`L3FlushKeyMalformed + L3FlushBpfSkipped + L3FlushScheduleRejected`** — combined "upstream regression" indicator. Any of these going non-zero means a caller is shipping garbage at the Schedule boundary (programmer bug, not flusher fault). Investigate the corresponding caller from the file that owns the metric.

**CloudWatch query (upstream regression — combined indicator):**

```
SELECT SUM(L3FlushKeyMalformed) + SUM(L3FlushBpfSkipped) + SUM(L3FlushScheduleRejected)
FROM SCHEMA("LayerV/NHP", InstanceId)
WHERE FilterMode IN ('iptables','ebpfxdp')
GROUP BY bin(5m)
```

A non-zero result here for any 5-min bucket = grep the AC logs for the matching `[ExpirySched]` / `[BpfFlusher]` Warning lines and trace back to the calling site in `msghandler.go`.

## First five minutes

1. **Confirm scope.** SSM the active-color AC ASG and tail the AC log:
   ```bash
   AWS_PROFILE=layerv aws ssm start-session --target $(...)
   tail -200 /opt/layerv/nhp-ac/logs/ac-$(date +%Y-%m-%d).log | grep -E 'ExpirySched|HandleAccessControl'
   ```
   Look for the trip line + the flusher errors that preceded it. The error text identifies whether `ConntrackFlusher` (iptables mode) or `BpfFlusher` (eBPF/XDP mode) is failing.

2. **Check kernel-side health** matching the failing flusher mode:
   - **iptables mode (`ConntrackFlusher`):** `conntrack -L | wc -l` — runaway conntrack table is the usual cause; if at limit, `sysctl net.netfilter.nf_conntrack_max`. `dmesg | grep conntrack` for kernel-side ENOBUFS.
   - **eBPF mode (`BpfFlusher`):** `bpftool map list` — pinned maps `/sys/fs/bpf/spp`, `/sys/fs/bpf/sdwhitelist`, `/sys/fs/bpf/icmpwhitelist` must exist. `bpftool map show pinned /sys/fs/bpf/spp` — verify the program is loaded. ENOENT on map open is the most common failure.

3. **Decide: real fault or transient.** If kernel health is OK and the error rate stopped, the breaker is holding open on stale state — safe to reset (step 4). If errors continue, escalate to the fault: kernel state issue, BPF program crash, or `conntrack` binary missing.

## Recovering the breaker

The scheduler exposes `ResetBreaker()` for manual recovery; there is no operator-facing endpoint yet (filed as #2169 — a `/internal/v1/l3-flush/reset-breaker` POST that's allowlisted to the operator subnet). Until that lands, recovery requires either:

- **AC restart** — `systemctl restart nhp-ac` on the affected instance. The boot enumeration in `expiry_scheduler.go` re-tracks all live kernel allow-rules, so no admission state is lost. Customer-visible: brief admission-gate denial during restart (~5s). Prefer this for clean recovery.
- **Wait for the ASG to roll** — if the underlying fault is the AMI / package mismatch, a normal ASG instance refresh fixes the new instances without operator action. Acceptable when the breaker tripped on a known-deployable problem.

**Do NOT** disable `EnableL3FlushOnExpiry` to "make the alarm stop" — that defeats the security primitive. The breaker exists precisely to prevent silent erosion of the L3 enforcement boundary.

## Configuration knobs (operator-tunable via config.toml reload)

| Knob | Default | Reload semantics |
|---|---|---|
| `EnableL3FlushOnExpiry` | `false` | Live; first false→true reload also forces `L3FlushDryRun=true` as safety (see `endpoints/ac/config.go`). |
| `L3FlushDryRun` | `false` | Live via `Scheduler.SetDryRun` — flips on next processEntry. |
| `L3FlushErrorThreshold` | `DefaultL3FlushErrorThreshold` | Live via `Scheduler.SetBreakerParams`, BUT capped at the breaker-ring size constructed at boot. If new threshold exceeds the constructed ring, AC restart is required — the reload emits a `Warning` flagging this. |
| `L3FlushErrorWindowSec` | `DefaultL3FlushErrorWindowSec` | Live via `Scheduler.SetBreakerParams`. |

Reloading config.toml goes through `endpoints/ac/config.go::updateBaseConfig`.

## Common patterns

| Symptom | Likely cause | Action |
|---|---|---|
| `[ExpirySched] flush <key>: exit status 1` repeating | conntrack: kernel state filled past `nf_conntrack_max`, `conntrack -D` returns no-match-but-error variants | Raise `nf_conntrack_max` in `terraform/modules/ac/user_data.sh.tpl` — open PR with the change. Restart AC after AMI rebuild. |
| `[ExpirySched] flush <key>: ENOENT` from BpfFlusher | Pinned map missing — XDP program unloaded or not yet loaded at boot | Check `ip link show dev <iface>` for `xdpgeneric` attachment. If absent, BPF program failed to load; check `dmesg`. |
| Breaker trips immediately after AC start | Boot enumeration scheduled entries for kernel state that doesn't actually exist (parser drift in `expiry_enumerate_iptables_linux.go` / `expiry_enumerate_ebpf_linux.go`) | File a bug. Check the parser test fixtures match the current `ipset save` / BPF map shapes. Restart AC after the parser is patched — boot enum is the only re-entry point. |
| Breaker trips after sandbox enable, none in prod | Sandbox kernel version drift — `conntrack` binary or BPF map layout differs from prod AMI | Compare `uname -r` and `dpkg -l | grep conntrack` between sandbox and prod ACs. Pin both AMIs to the same kernel via `terraform/environments/*/main.tfvars`. |
| Customer reports "new session denied immediately after session expiry" — BPF mode only, no flusher errors | **Known race** — `processEntry` releases `shard.mu` before calling `Flush`, so a re-admission can write a kernel rule that the in-flight `Flush` then tears down. See **nhp#2168**. Conntrack mode self-heals on next packet; BPF mode silently denies until next admission (which on the customer side means re-knocking). Acceptable during the 4+4-week rollout while L7 enforcement is still active; **must close before L7 removal**. | Customer instruction: retry the request after a brief delay. Long-term: track #2168. |
| Customer reports "/refresh that shortens session_duration didn't actually shorten" — BPF mode | **Known limitation** — `Cancel()` is implemented but **not wired** into `/refresh` or token-revoke (acknowledged in #2172). A phantom scheduled flush still fires on the now-gone allow-rule; the ENOENT-no-op makes it harmless for metrics, but it races against re-admission of the same key. BPF mode silently denies the new session until next admission. **Operationally-visible signal during rollout.** | Customer instruction: re-knock. Long-term: land #2172 before L7 removal. |
| Worker stuck mid-flush in BPF mode — `L3FlushTotal` plateaus, `L3FlushErr` doesn't grow, breaker eventually trips on backpressure | **Known limitation** — `BpfFlusher.Flush` honors the scheduler-supplied ctx only at entry, not during `cilium/ebpf` `LoadPinnedMap` + `Delete` + `Close`. A wedged BPF subsystem (kernel-side hang on map lock, file-handle exhaustion) can pin a worker past `defaultFlushCallTimeout` until the kernel itself recovers. The bounded backpressure path (re-bucket → drop → breaker) is the eventual mitigation. Tracked: `BpfFlusher.Flush` ctx-during-call is part of #2165 (netlink swap obviates entirely). | `bpftool prog show` + `dmesg | grep bpf` to identify the wedge. Restart the AC if the kernel-side hang persists (boot-enum recovers). Long-term: #2165. |
| Breaker trip cadence looks "compressed" or "stretched" recently | **Wall-clock breaker window** — `recordBreakerErr` uses `time.Now()` (wall clock) rather than monotonic time, by design (operator semantic: "errors per minute" should match operator wall-clock intuition). An NTP step (clock-jump correction) can make the active error-window appear compressed (if clock stepped forward) or stretched (if stepped backward). Self-corrects within one window after the step. | Confirm an NTP step happened (`journalctl -u chrony` / `journalctl -u systemd-timesyncd`); if yes, no action needed — the cadence normalizes within `L3FlushErrorWindowSec`. If no NTP step, escalate as a real cadence anomaly. |

## Don't

- **Don't reset the breaker without identifying the root cause.** The breaker exists to surface a real security boundary failure; reset-without-diagnosis turns the safety into a noise filter.
- **Don't disable `EnableL3FlushOnExpiry` as recovery.** That trades a customer-visible admission denial (the right behavior) for a silent session-past-expiry leak (the wrong behavior).
- **Don't bypass the admission gate in qurl-router as a workaround.** The gate fail-closed is the contract the L3-only end-state depends on. Any "I'll route around the gate while the scheduler recovers" change in qurl-router or upstream is a security regression — file an issue with the actual flusher fault instead.

## See also

- [`docs/design/SCHEDULER_SCALING.md`](../design/SCHEDULER_SCALING.md) — scheduler architecture + capacity ceilings.
- [`docs/design/QUIET_STREAM_RESIDUAL.md`](../design/QUIET_STREAM_RESIDUAL.md) — the ~25 s quiet-stream gap the L3 flusher cannot close from the AC, and the backend-keepalive recipe operators must apply.
- [`docs/design/SESSION_ENFORCEMENT_ARCHITECTURE.md`](../design/SESSION_ENFORCEMENT_ARCHITECTURE.md) — three-clock model.
- `endpoints/ac/expiry_scheduler.go` — scheduler godoc.
- nhp #2168 — processEntry/re-admission race (acceptable during rollout; must close before L7 removal).
