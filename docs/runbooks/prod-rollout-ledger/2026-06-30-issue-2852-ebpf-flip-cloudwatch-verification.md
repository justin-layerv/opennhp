# 2026-06-30 · Issue #2852 · eBPF flip: CloudWatch bucketing + metric-filter verification

- **Owner:** EBPFXDP FilterMode-flip (E5) coordinator
- **Source:** https://github.com/layervai/nhp/issues/2852, https://github.com/layervai/nhp/pull/2851

PR #2851 (E3 v6 eBPF telemetry) emits two log shapes that go live in CloudWatch
only at the E5 `FilterMode` flip: 0-address DENYs (`SRC=:: DST=::` /
`SRC=0.0.0.0`) at the truncated-header / `iph->ihl < 5` early-DENY sites, and v6
action tokens that drop the `6` suffix (`[NHP-DENY]`/`[NHP-ACCEPT]`, not
`[NHP-DENY6]`/`[NHP-ACCEPT6]`). Both are intended and v4-parity-justified. This
gate confirms nothing in the CloudWatch bucketing/metric/alarm path mis-handles
them once the eBPF datapath goes hot. **No code change is required.**

- [x] Pre-flip (2026-06-30): no metric filter keys on the `6` suffix or consumes
      the AC firewall streams. Terraform: every `aws_cloudwatch_log_metric_filter`
      targets a *non-AC* log group (CloudTrail CIS/custom/console-MFA,
      qurl-service bootstrap outcomes, FRPS reverse-tunnel, NHP-**server**
      stderr/log panic filters) — none target `/layerv/nhp/<env>/ac` or match
      `[NHP-DENY`/`[NHP-ACCEPT`. Live confirmation: `describe-metric-filters
      --log-group-name /layerv/nhp/<env>/ac` returned `[]` in **both** `layerv`
      (sandbox) and `layerv-prod`; account-wide, none of the metric filters
      (7 sandbox / 6 prod) reference an `/ac` log group or a `NHP/DENY/ACCEPT`
      token. The firewall streams are consumed only by the Grafana CloudWatch
      Logs Insights queries, which key on the log-stream name.
- [x] Pre-flip (2026-06-30): no dashboard panel / alarm mis-buckets or chokes on
      a 0-address DENY. `nhp-logs.json` "Firewall Actions" buckets by the
      *log-stream-derived* action (`parse @logStream "*/*" as instance_id,
      action`; stream = `nhp-accept|deny|forward`), never by SRC; "Firewall Deny
      Log" renders `@message` verbatim. No dashboard (all 6) has a
      top-talkers / per-SRC / geo attribution panel, and no query parses `SRC=`,
      so a `::` / `0.0.0.0` value cannot be mis-attributed or error a parser. No
      CloudWatch alarm is fed by a firewall-stream-derived metric (there is no
      such metric filter). Decode is panic-safe: `decodeEventV4/V6` error on
      short samples; zero addresses render as `0.0.0.0` / `::` via the standard
      formatters (covered by `endpoints/ac/ebpf/event_format_test.go`).
- [x] Pre-flip (2026-06-30): **decision recorded — leave 0-address DENYs as-is**
      (not filtered, not re-labeled). They are honest denies, v4-parity
      consistent, already volume-capped by the #2849 in-kernel token bucket on
      exactly those sites, and correctly counted by the stream-keyed panel. See
      "Decision" below for the binding forward-looking constraint.
- [ ] At-flip (E5): immediately before flipping `FilterMode` → `EBPFXDP` in prod,
      re-run `aws logs describe-metric-filters --log-group-name
      /layerv/nhp/prod/ac` (expect `[]`) and re-scan
      `grafana-dashboards/dashboards/*.json` for any newly-added per-SRC /
      top-talkers panel — to catch anything created out-of-band (ClickOps) or
      merged between this gate and the flip. Then delete this entry.

## Decision (issue #2852 task 3)

Leave the malformed / early-DENY 0-address events as-is in every current
observability surface. **Binding constraint for whoever adds attribution next:**
any future top-talkers / per-SRC panel, metric filter, or alarm that buckets by
source address MUST exclude or distinctly bucket the `SRC=::` and `SRC=0.0.0.0`
pseudo-sources (the "address-unparseable" malformed-packet denies) rather than
attribute that volume to a single phantom source. Until such a view exists there
is nothing to mis-bucket, so no emission-side change is made here.
