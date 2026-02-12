# Grafana Dashboard Improvement Plan

Comprehensive improvement plan for all 5 Grafana dashboards in `terraform/modules/grafana-dashboards/dashboards/`. All phases (0-3) are in scope — this covers infrastructure prerequisites, dashboard JSON edits, and application-level instrumentation changes needed to bring dashboards to full coverage.

---

## Table of Contents

1. [Metrics Reality Check](#metrics-reality-check)
2. [Cross-Dashboard Issues](#cross-dashboard-issues)
3. [NHP Infrastructure Dashboard](#nhp-infrastructure-dashboard)
4. [QURL Operations Dashboard](#qurl-operations-dashboard)
5. [QURL Business Metrics Dashboard](#qurl-business-metrics-dashboard)
6. [QURL Webhooks Dashboard](#qurl-webhooks-dashboard)
7. [AWS Cost Dashboard](#aws-cost-dashboard)
8. [Implementation Phases](#implementation-phases)
9. [Implementation Notes](#implementation-notes)

---

## Metrics Reality Check

Before any dashboard work, we need to understand what data actually exists vs. what's aspirational. Several items in the original plan recommended panels for metrics that aren't being published.

### What Actually Exists Today

| Source | Metrics | Notes |
|--------|---------|-------|
| AWS/NetworkELB | ActiveFlowCount, ProcessedBytes, HealthyHostCount, UnHealthyHostCount, TCP resets | Always available for NLBs |
| AWS/EC2 (basic) | CPUUtilization, NetworkIn/Out, EBS metrics | Basic monitoring enabled in launch template |
| AWS/AutoScaling | GroupInServiceInstances, GroupDesiredCapacity, GroupMinSize, GroupMaxSize | Always available |
| AWS/DynamoDB | ThrottledRequests, SystemErrors, SuccessfulRequestLatency, ConsumedRCU/WCU | Available for 3 tables: licenses, ac-assignments, resources |
| NHP/AC (custom) | DiskUsagePercent | Collected every 15min via SSM State Manager script |
| LayerV/NHP (custom) | KnockLatency, AuthSuccess, AuthFailure, KnockRequests | **DEFINED in TF alarms but NOT PUBLISHED by application code** |
| Prometheus/Mimir | QURL API HTTP metrics, DynamoDB client metrics, Go runtime | Published by QURL API (ECS/ADOT) |
| Tempo | Distributed traces | Published by QURL API (ECS/ADOT) |

### What Does NOT Exist

| Metric | Why | Prerequisite |
|--------|-----|-------------|
| Memory/disk on server EC2 | CloudWatch Agent not installed | Install CW Agent in user_data.sh.tpl |
| Memory/disk on AC EC2 | Only AC disk via SSM script (no CW Agent) | Install CW Agent or extend SSM script |
| Custom NHP knock metrics | Go server code has no `PutMetricData` calls | Add CloudWatch metric publishing to server |
| DeploymentEvent metric | No CI step publishes it | Add `aws cloudwatch put-metric-data` to deploy workflows |
| Loki log aggregation | Datasource declared in variables.tf but no `grafana_data_source.loki` resource | Wire up Grafana Cloud Loki datasource |
| etcd metrics | **etcd is not used in cloud** — DynamoDB is the storage backend, CloudMap handles discovery | N/A (remove references) |

### Implications for This Plan

Every recommendation below is tagged with its data availability to sequence the work correctly:
- **[READY]** — metric exists today, panel can be added immediately (Phase 1)
- **[PREREQ: X]** — requires prerequisite X before the panel will show data (Phase 2, after Phase 0 completes X)
- **[APP CHANGE]** — requires application-level code changes to emit new metrics (Phase 3)

---

## Cross-Dashboard Issues

### CRITICAL: Ghost Metrics — Alarms for Unpublished Data

The monitoring module (`terraform/modules/monitoring/main.tf`) defines CloudWatch alarms for `KnockLatency`, `AuthSuccess`, `AuthFailure`, and `KnockRequests` in the `LayerV/NHP` namespace. The NHP Infrastructure dashboard has panels querying these metrics. **But the NHP server never calls `PutMetricData`.** These alarms sit in `INSUFFICIENT_DATA` permanently and the dashboard panels show nothing.

**Impact:** The dashboard gives a false sense of monitoring. An operator glancing at empty panels may assume "no knocks happening" rather than "metrics aren't published."

**Fix (Phase 0 — before any dashboard work):**
1. Add CloudWatch metric publishing to the NHP server Go code (or sidecar/CW Agent custom metrics config)
2. Alternatively, add prominent "No Data" annotations to these panels explaining the gap, and track the instrumentation work as a separate issue

### Percentile Coverage: Add p999

All dashboards that track latency use p50/p95/p99. Adding p99.9 (p999) provides better tail latency visibility.

**Affected panels:**
- NHP Infrastructure: "NHP Knock Latency" (id:5) — p50/p95/p99
- NHP Infrastructure: "Knock Latency p99" stat (id:6) — p99 only
- QURL Operations: "Latency Percentiles (with SLO)" (id:30) — p50/p95/p99
- QURL Operations: "p99 Latency" stat (id:6) — p99 only
- QURL Operations: "Slowest Endpoints (p99)" table (id:32) — p99 only
- QURL Operations: "DynamoDB Latency by Operation" (id:40) — p95 only
- QURL Webhooks: "Delivery Latency" (id:11) — p50/p95/p99
- QURL Webhooks: "p95 Latency" stat (id:6) — p95 only

**Fix for each:**
- Add p99.9 (0.999) series to every latency timeseries panel
- Change stat panels to p999 (they show a single "worst-case" number — make it actually worst-case)
- Change the slowest endpoints table from p99 to p999
- Add p99 AND p999 to DynamoDB latency (currently only has p95)

**Note:** p999 on NHP Infrastructure panels is tagged [PREREQ: metric publishing] since the underlying CloudWatch metrics aren't being published yet. QURL Operations/Webhooks panels are [READY] since they use Prometheus histograms.

### Missing: Consistent Panel Descriptions

Most panels have no `description` field. Only QURL Operations has some (burn rate, 5xx count, CPU/memory/network, Go heap). Every panel should have a short description explaining what the metric means and what to do if it looks bad.

**Fix:** Add `"description"` field to every panel. Format: "What this shows. Action: what to do if abnormal."

### Missing: Deployment Annotations

Only QURL Operations has a deployment annotation (using `process_start_time_seconds` to detect restarts). NHP Infrastructure, Business, and Webhooks dashboards have none.

**Fix:**
- QURL Business + Webhooks: Copy the deployment annotation from Operations (same Prometheus datasource, same metric) **[READY]**
- NHP Infrastructure: Requires either (a) a custom `DeploymentEvent` CloudWatch metric published by CI, or (b) an EventBridge-based annotation. **[PREREQ: CI pipeline change]**

### Missing: Cross-Dashboard Links are Incomplete

Current state:
- NHP Infrastructure → QURL Operations (one-way)
- QURL Operations → Business, Webhooks
- Business → Operations, Webhooks
- Webhooks → Operations, Business
- AWS Cost → (none)

**Fix:**
- Add link to NHP Infrastructure from QURL Operations
- Add link from NHP Infrastructure to Webhooks and AWS Cost
- Add link from AWS Cost to NHP Infrastructure
- All dashboards should have a path to AWS Cost for financial context

### Style Inconsistency: Default Time Range

| Dashboard | Default Range | Refresh |
|-----------|--------------|---------|
| NHP Infrastructure | 6h | 1m |
| QURL Operations | 1h | 30s |
| QURL Business | 24h | 1m |
| QURL Webhooks | 6h | 30s |
| AWS Cost | 30d (implicit) | 5m |

These are reasonable for their domains. No change needed.

---

## NHP Infrastructure Dashboard

**File:** `nhp-infrastructure.json`
**Current State:** 15 panels across 4 rows (NLB, NHP Protocol, Compute, CloudWatch Alarms). Uses CloudWatch datasource only.

### CRITICAL

1. **[PREREQ: metric publishing] Add application-level metric publishing to NHP server**
   - The `LayerV/NHP` namespace metrics (KnockLatency, AuthSuccess, AuthFailure, KnockRequests) are referenced by alarms and dashboard panels but never published by the Go server code. This is the single highest-priority gap.
   - Until this is done, NHP Protocol row panels show empty data.
   - Track as a separate engineering issue. In the meantime, add `"description"` to affected panels noting "Requires server instrumentation — see issue #XXX."

2. **[READY] Add NLB TargetResponseTime panel**
   - `TargetResponseTime` is a native NLB metric (no custom publishing needed). Shows actual end-to-end time the NLB measures.
   - Panel: timeseries, p50/p95/p99, unit: seconds. Add to NLB row.
   - Note: NLBs only report this for TCP/TLS listeners, not UDP. The knock port (62206/UDP) won't have this metric, but the HTTP endpoint (8888/TCP via TLS listener) will.

3. **[READY] Add NLB UnhealthyHostCount timeseries**
   - The current unhealthy targets panel (id:13) is a stat showing "last value". Add a timeseries showing unhealthy count over time so you can see when targets started failing, not just the current state.

4. **[READY] Wire or remove unused `component` template variable**
   - The variable exists with values `server, ac` but no panel references `$component`. This confuses users.
   - **Recommended:** Wire it into NLB panel dimensions to filter by server vs AC load balancer. If the dimension values don't align, remove the variable.

### IMPORTANT

5. **[READY] Add NLB NewFlowCount and ConsumedLCUs**
   - `NewFlowCount` — connection establishment rate (detects DDoS or connection storms)
   - `ConsumedLCUs` — NLB capacity/billing usage
   - Both are native NLB metrics. Add as a 2-panel row or add to existing NLB timeseries.

6. **[PREREQ: CW Agent install] Add memory metrics to Compute row**
   - CPU is tracked but memory is not. CloudWatch basic monitoring doesn't include memory.
   - **Prerequisite:** Install CloudWatch Agent in `terraform/modules/compute/user_data.sh.tpl` and `terraform/modules/ac/user_data.sh.tpl` with a config that publishes `mem_used_percent`.
   - Add panel to Compute row once available.

7. **[READY] Add AC DiskUsagePercent from NHP/AC namespace**
   - The AC already publishes `DiskUsagePercent` via SSM State Manager every 15min to the `NHP/AC` namespace. This is an existing metric that's not on any dashboard.
   - Panel: stat + timeseries, threshold at 80% (matches existing alarm).

8. **[READY] Improve CloudWatch Alarms panel (id:14)**
   - Currently uses `queryMode: "Annotations"` which is limited. Consider switching to a CloudWatch `DescribeAlarms` query that shows alarm name, state, last transition time.
   - Add color-coded state column (ALARM=red, OK=green, INSUFFICIENT_DATA=gray).
   - Note: Several alarms will show INSUFFICIENT_DATA due to unpublished custom metrics (see Critical #1). This is useful — it makes the gap visible.

9. **[READY] Add DynamoDB table metrics**
   - Three DynamoDB tables exist (licenses, ac-assignments, resources) with native CloudWatch metrics.
   - Add panels for: `ThrottledRequests`, `SuccessfulRequestLatency` (p50/p99), `ConsumedReadCapacityUnits`, `ConsumedWriteCapacityUnits`.
   - Group by TableName dimension.

10. **[READY] Add "Overview" row with stat panels at the top**
    - Follow QURL Operations pattern: a row of stat panels for at-a-glance health.
    - Suggested stats: Healthy Targets (server), Healthy Targets (AC), CPU % (server ASG avg), Active NLB Flows, Auth Success Rate (if/when metric available).
    - Currently the dashboard jumps straight into timeseries — Overview row reduces time-to-understand.

### ADDITIONAL

11. **[PREREQ: CW Agent] Add disk usage to Compute row (server)**
    - Docker containers on the server can fill up disk. Requires CW Agent for server EC2 (AC already has disk monitoring via SSM).

12. **[PREREQ: CI change] Add ASG Instance Refresh status annotation**
    - Show whether an instance refresh is in progress. Requires CI to publish a marker (custom metric or EventBridge event).

13. **[PREREQ: metric publishing] Add p999 to Knock Latency panels**
    - Once the server actually publishes KnockLatency, add `p99.9` extended statistic. Blocked on Critical #1.

---

## QURL Operations Dashboard

**File:** `qurl-operations.json`
**Current State:** 27 panels across 7 rows. Best-structured dashboard with SLO integration, burn rate, exemplar support, heatmap, traces. Uses Prometheus and Tempo.

### CRITICAL

14. **[READY] Add p999 to "Latency Percentiles (with SLO)" (id:30)**
    - Add a 4th target: `histogram_quantile(0.999, ...) * 1000` with `legendFormat: "p999"`
    - **Important:** Verify histogram bucket boundaries are fine-grained enough in the 100ms-10s range. Coarse buckets make p999 unreliable. Check the QURL API's Prometheus histogram configuration.

15. **[READY] Change "p99 Latency" stat (id:6) to p999**
    - Update expr to `histogram_quantile(0.999, ...)`
    - Update title to "p999 Latency"
    - Adjust thresholds: green < 800ms, yellow 800-2000ms, red > 2000ms

16. **[READY] Change "Slowest Endpoints (p99)" table (id:32) to p999**
    - Update title to "Slowest Endpoints (p999)"
    - Update expr: `histogram_quantile(0.999, ...)`

17. **[READY] Add p99 AND p999 to "DynamoDB Latency by Operation" (id:40)**
    - Currently only shows p95. Add two more targets:
      - `histogram_quantile(0.99, ...) * 1000` as "{{operation}} p99"
      - `histogram_quantile(0.999, ...) * 1000` as "{{operation}} p999"
    - Consider a side-by-side layout (p95+p99 left, p999 right) to avoid visual clutter.

### IMPORTANT

18. **[READY] SLO burn rate needs multi-window**
    - Currently only 1h burn rate. SRE best practice (Google SRE Workbook ch5) recommends multi-window, multi-burn-rate:
      - Add 6h burn rate (threshold >6 = page)
      - Add 3d burn rate (threshold >1 = ticket)
    - These catch both fast burns (outage) and slow burns (gradual degradation).

19. **[READY] Error Budget panel should show consumption over time**
    - Currently a single gauge. Add a timeseries showing error budget remaining over the last 30 days. This shows burn trajectory — are we about to run out?

20. **[READY] Add per-endpoint p999 latency timeseries**
    - The "Slowest Endpoints" table shows a snapshot. Add a timeseries showing p999 latency per endpoint over time to catch regressions.
    - Group by `http_route` with `topk(5, ...)` to keep it readable.

21. **[READY] Add per-endpoint error rate timeseries**
    - "Top Errors by Endpoint" (id:21) is a table snapshot. Add a timeseries showing per-endpoint 5xx rate over time.

22. **[READY] "Requests by Endpoint" table (id:11) needs error rate column**
    - Currently shows request count only. Add a second query for error rate per endpoint so high-traffic AND high-error endpoints are visible in one view.

23. **[READY] Add DynamoDB throttle events**
    - DynamoDB throttling is a common hidden cause of 5xx errors. If QURL API exposes `ThrottledRequests` via Prometheus client metrics, add a panel. If not, consider adding a CloudWatch-sourced panel.

24. **[READY] Add Apdex score panel**
    - Calculate from histogram buckets: `(satisfied + tolerating/2) / total`
    - Satisfied = requests < 200ms, Tolerating = 200ms-1s, Frustrated = >1s
    - Single 0-1 score that's easier to reason about than raw percentiles.

### ADDITIONAL

25. **[READY] Add Go runtime panels to Infrastructure row**
    - "Go Heap" panel (id:86) exists. Add goroutine count (`go_goroutines`), GC pause duration (`go_gc_pause_seconds`), and open file descriptors. These help diagnose memory leaks and goroutine leaks.

26. **[READY] Traces section: add "Slow by Endpoint" trace query**
    - Current trace panels filter by error or >500ms globally. Add a trace panel filtered by the selected endpoint via `http.route` TraceQL filter.

27. **[PREREQ: Loki datasource] Add log panels using Loki**
    - `loki_datasource_uid` is declared in variables.tf but no `grafana_data_source.loki` resource exists in main.tf. Prerequisite: wire up the Grafana Cloud Loki datasource in Terraform, then add a "Recent Error Logs" collapsed row.

28. **[READY] Add request size distribution**
    - If `http_server_request_content_length` or similar metric exists, add a heatmap. Large request bodies can cause latency spikes.

---

## QURL Business Metrics Dashboard

**File:** `qurl-business.json`
**Current State:** 13 panels across 5 rows (Overview, Resource Lifecycle, Tokens & Access, Quotas, Batch Operations). Clean business KPI layout.

### No latency panels — this is correct for a business dashboard.

### IMPORTANT

29. **[READY] Add conversion funnel visualization**
    - Track: QURL Created → Token Minted → Token Validated (valid) → Access Granted
    - This is the core business story: "of QURLs created, how many lead to successful access?"
    - Implementation: bar gauge or stat panel showing each stage's count with drop-off percentages.

30. **[READY] "vs Yesterday" panel (id:2) is too narrow at 2 grid units**
    - At w:2, the percentage is barely readable. Increase to w:3 or w:4, and add a trend sparkline (`graphMode: "area"`).

31. **[READY] Add deployment annotations**
    - Copy the `process_start_time_seconds` annotation from QURL Operations. Deployments can cause temporary dips in business metrics — annotations prevent misinterpretation.

32. **[READY] Quota section needs utilization percentage**
    - "Quota Limit Hits" counts enforcement events, but doesn't show how close users are to their limits. If `qurl_quota_utilization` (gauge) exists, show percentage of quota consumed by tier.

33. **[READY] "Top Quota Offenders" table (id:31) needs action context**
    - Add a column showing the user's tier limit so operators know if the user needs an upgrade vs. is abusing the system.

### ADDITIONAL

34. **[READY] Add daily/weekly/monthly aggregate panels**
    - Business stakeholders want longer-term views. Add a collapsed "Trends" row with:
      - QURLs created per day (bar chart, 30d window)
      - Weekly active QURLs trend
      - Monthly token mint rate

35. **[APP CHANGE] Add time-to-first-access metric**
    - How long between QURL creation and first successful access? Key business metric showing time-to-value. Requires application-level tracking.

36. **[APP CHANGE] Add QURL expiration tracking**
    - QURLs expiring in the next 24h/7d. Requires a gauge metric or query against DynamoDB TTL data.

37. **[READY] Uncollapse Batch Operations row**
    - If batch operations represent significant QURL creation volume, keep the row expanded. Collapsed state implies secondary importance.

---

## QURL Webhooks Dashboard

**File:** `qurl-webhooks.json`
**Current State:** 18 panels across 6 rows (Overview, Delivery Performance, Events, Retries & Failures, Webhook Health). Well-structured for webhook monitoring.

### CRITICAL

38. **[READY] Add p999 to "Delivery Latency" timeseries (id:11)**
    - Add 4th target: `histogram_quantile(0.999, ...) * 1000` with `legendFormat: "p999"`

39. **[READY] Change "p95 Latency" stat (id:6) to p999**
    - p95 for webhooks is far too lenient — a webhook that takes 30s at p999 is a major problem.
    - Update expr to `histogram_quantile(0.999, ...)`
    - Update title to "p999 Latency"
    - Adjust thresholds: green < 2000ms, yellow 2-10s, red > 10s (webhooks are inherently slower due to external HTTP calls)

### IMPORTANT

40. **[READY] Add delivery latency heatmap**
    - QURL Operations has a latency heatmap but Webhooks does not. Webhook delivery latency has a bimodal distribution (fast local + slow remote) that heatmaps reveal better than percentile lines.
    - Add: `sum(increase(qurl_webhook_delivery_duration_seconds_bucket{...}[1m])) by (le)` as heatmap panel.

41. **[READY] Add webhook delivery SLO**
    - Define an SLO (e.g., 99% delivered within 30s on first attempt).
    - Add burn rate and error budget panels matching QURL Operations pattern.

42. **[READY] Add per-destination health tracking**
    - Currently failures are aggregated. If `destination_host` or similar label exists, add a panel showing failure rate per destination. This distinguishes "our webhooks are broken" from "one customer's endpoint is down."

43. **[READY] "Event Queue Depth" stat (id:9) needs a timeseries companion**
    - A growing queue over time means we're falling behind — a point-in-time stat hides this trend.

44. **[READY] Add deployment annotations**
    - Copy `process_start_time_seconds` annotation from QURL Operations.

45. **[READY] Uncollapse "Webhook Health" row**
    - "Webhooks with Consecutive Failures" and "Recently Disabled Webhooks" are critical operational panels. They should be visible without clicking.

46. **[READY] Retry Distribution (id:30) should show cumulative retry percentage**
    - Add a panel showing what percentage of deliveries required retries. If 50% need retries, that's systemic.

### ADDITIONAL

47. **[READY] Add webhook response code distribution**
    - If the metric includes HTTP status code from the destination, show a breakdown (4xx vs 5xx vs timeout).

48. **[APP CHANGE] Add DLQ metrics**
    - If webhooks that exhaust retries go to a DLQ, add panels for DLQ depth, age, and drain rate.

49. **[APP CHANGE] Add "Time Since Last Successful Delivery" per webhook**
    - Catches zombies that appear "active" but haven't delivered in days.

50. **[READY] Add delivery attempt latency vs. end-to-end latency**
    - If metrics distinguish first-attempt from total (including retries), show both. Total delivery time including retries is what customers experience.

---

## AWS Cost Dashboard

**File:** `aws-cost.json`
**Current State:** 8 panels in a flat layout. Uses Athena datasource querying CUR 2.0 data. Variables: billing_period, account, service.

### IMPORTANT

51. **[READY] Add row organization**
    - 8 panels in a flat layout with no rows. Group into:
      - "Overview" row: Total Cost stat, Cost by Account pie, Cost by Service pie, Daily Cost Trend
      - "Details" row: Component Tag Breakdown, Top Line Items table
    - This matches the organizational pattern of the other dashboards.

52. **[READY] Add cross-dashboard links**
    - Currently isolated — no links to any other dashboard. Add link to NHP Infrastructure (for compute costs context).

53. **[READY] Add cost anomaly highlighting**
    - Add a panel or threshold on the daily cost trend that highlights days where cost exceeds 2x the 7-day moving average. Catches runaway resources.

54. **[READY] Add per-service cost trend timeseries**
    - The existing pie chart shows current breakdown but not trends. Add a stacked area chart showing cost by service over time to catch growing costs early.

55. **[READY] Add panel descriptions**
    - None of the 8 panels have descriptions. Add descriptions explaining what each panel shows and what actions to take on anomalies.

### ADDITIONAL

56. **[READY] Add cost per QURL or cost per knock**
    - If QURL volume metrics are available alongside cost data, calculate unit economics: cost-per-QURL-created, cost-per-token-validated. Requires joining Athena cost data with Prometheus volume data (may need a custom metric or Lambda).

57. **[READY] Add Reserved/Savings Plan coverage**
    - If using RIs or Savings Plans, show coverage percentage. CUR 2.0 includes these columns.

---

## Implementation Phases

All phases will be executed. Work is sequenced by dependencies — each phase unblocks the next.

### Phase 0: Fix Foundational Gaps (Infrastructure + Application)

These are not dashboard changes — they're the infrastructure and application changes that unblock Phases 2 and 3. **Start these immediately in parallel with Phase 1** so that by the time Phase 1 dashboard work is complete, Phase 0 deliverables are ready.

| Item | Work Required | Deliverable | Unblocks |
|------|--------------|-------------|----------|
| **0a.** Publish NHP custom metrics | Add CloudWatch `PutMetricData` calls to NHP server Go code for KnockLatency, AuthSuccess, AuthFailure, KnockRequests. Emit on every knock processing cycle. | PR to `endpoints/server/` | Phase 2: #1, #13 |
| **0b.** Publish DeploymentEvent metric | Add `aws cloudwatch put-metric-data --namespace LayerV/NHP --metric-name DeploymentEvent --value 1` step to `blue-green-deploy.yml`, `canary-deploy.yml`, and `build-and-push.yml` (after instance refresh) | PR to `.github/workflows/` | Phase 2: #12 |
| **0c.** Install CloudWatch Agent | Add CW Agent install + config to `terraform/modules/compute/user_data.sh.tpl` and `terraform/modules/ac/user_data.sh.tpl`. Config: publish `mem_used_percent`, `disk_used_percent` to `CWAgent` namespace. Add IAM permissions for `cloudwatch:PutMetricData` in compute and AC modules. | PR to `terraform/modules/compute/`, `terraform/modules/ac/` | Phase 2: #6, #11 |
| **0d.** Wire up Loki datasource | Add `grafana_data_source.loki` resource in `terraform/modules/grafana-dashboards/main.tf` using the existing `var.loki_datasource_uid`. Verify Grafana Cloud Loki is receiving logs from QURL API. | PR to `terraform/modules/grafana-dashboards/` | Phase 2: #27 |

**Create a GitHub issue for each item.** Phase 0 items run in parallel with Phase 1 dashboard work.

### Phase 1: Dashboard-Only Changes — All [READY] Items

All items tagged [READY]. No infrastructure changes needed. Pure JSON edits to the 5 dashboard files.

**Estimated scope:** ~60 panel modifications across 5 dashboards.

Execute in this order (critical first, then by dashboard):

| Step | Items | Dashboard | Scope |
|------|-------|-----------|-------|
| 1a | #14-17 | Operations | Add p999 to all latency panels |
| 1b | #38-39 | Webhooks | Add p999 to latency panels |
| 1c | #2-5, #7-10 | NHP Infra | NLB metrics, AC disk, DynamoDB tables, overview row, fix component var |
| 1d | #18-24 | Operations | Multi-window SLO burn rate, per-endpoint timeseries, Apdex, DynamoDB throttle |
| 1e | #29-33 | Business | Conversion funnel, widen vs-yesterday panel, annotations, quota utilization |
| 1f | #40-46 | Webhooks | Heatmap, SLO, per-destination health, queue depth, annotations, uncollapse health row |
| 1g | #51-55 | AWS Cost | Row organization, cross-links, anomaly detection, per-service trends, descriptions |
| 1h | All | All 5 dashboards | Panel descriptions for every panel |
| 1i | All | All 5 dashboards | Complete cross-dashboard links (including AWS Cost) |
| 1j | #25-26, #28, #34, #37, #47, #50, #56-57 | Various | Go runtime panels, request size, trends, batch row, response codes, retry %, cost metrics |

### Phase 2: Infrastructure-Enabled Dashboards — All [PREREQ] Items

Start as each Phase 0 item completes. Each row notes which Phase 0 deliverable unblocks it.

| Item | Dashboard Change | After Phase 0 Item |
|------|-----------------|-------------------|
| **#1:** NHP Protocol row panels show real knock/auth data | Verify panels populate, adjust thresholds based on real data | 0a (metric publishing) |
| **#13:** Add p999 to Knock Latency timeseries + stat | Add `p99.9` extended statistic, update stat title/thresholds | 0a (metric publishing) |
| **#6:** Add server memory metrics panel | Add `mem_used_percent` from `CWAgent` namespace to Compute row | 0c (CW Agent) |
| **#11:** Add server disk metrics panel | Add `disk_used_percent` from `CWAgent` namespace to Compute row | 0c (CW Agent) |
| **#12:** Add ASG Instance Refresh annotation to NHP Infra | Add `DeploymentEvent` CloudWatch annotation (see Implementation Notes) | 0b (DeploymentEvent metric) |
| **#27:** Add Loki log panels to Operations | Add collapsed "Logs" row with "Recent Error Logs" panel, filter `service_name="qurl-api"` level="error" | 0d (Loki datasource) |

### Phase 3: Application-Enabled Features — All [APP CHANGE] Items

These require new metrics or features in the QURL API or NHP server application code. Each item includes the application change needed alongside the dashboard change.

| Item | Application Change | Dashboard Change |
|------|-------------------|-----------------|
| **#35:** Time-to-first-access | Add a Prometheus histogram tracking duration between QURL creation timestamp and first successful token validation. Emit in the token validation handler when `first_access=true`. | Add stat panel (median time-to-first-access) + timeseries to Business dashboard |
| **#36:** QURL expiration tracking | Add a Prometheus gauge `qurl_expiring_soon{window="24h"}` and `{window="7d"}` updated on a periodic sweep or computed from DynamoDB TTL scan. | Add stat panels to Business dashboard showing QURLs expiring in 24h/7d |
| **#48:** DLQ metrics | Implement dead-letter queue for exhausted webhook retries. Emit `qurl_webhook_dlq_depth` gauge and `qurl_webhook_dlq_age_seconds` histogram. | Add DLQ row to Webhooks dashboard: depth stat, depth timeseries, age heatmap, drain rate |
| **#49:** Time since last success per webhook | Add a Prometheus gauge `qurl_webhook_last_success_seconds` per webhook ID, updated on each successful delivery. | Add "Stale Webhooks" table panel to Webhooks dashboard showing webhooks with last_success > 24h |

---

## Implementation Notes

### CloudWatch Extended Statistics for p999

CloudWatch supports percentile statistics using the syntax `p99.9`. In the Grafana CloudWatch datasource, set:

```json
"statistics": ["p99.9"]
```

This works for any CloudWatch metric. Note: extended statistics have slightly higher cost than standard statistics.

**Caveat for NHP Infrastructure:** This only works once the server actually publishes the `KnockLatency` metric. Until then, extended statistics on a nonexistent metric return no data.

### Prometheus histogram_quantile for p999

For Prometheus-based panels, use:

```promql
histogram_quantile(0.999, sum(rate(metric_bucket{...}[5m])) by (le))
```

**Important:** p999 accuracy depends on histogram bucket boundaries. If the histogram has coarse buckets (e.g., 0.1, 0.5, 1, 5, 10), p999 will be interpolated between buckets and may be inaccurate. Verify that the QURL API's histogram boundaries are fine-grained enough in the 100ms-10s range. If not, update the application's histogram bucket configuration first.

### Threshold Guidelines for p999

p999 values are typically 2-5x higher than p99. Suggested threshold adjustments:

| Metric | p99 Yellow | p99 Red | p999 Yellow | p999 Red |
|--------|-----------|---------|-------------|----------|
| NHP Knock Latency | 200ms | 500ms | 400ms | 1000ms |
| HTTP API Latency | 500ms | 1000ms | 1000ms | 3000ms |
| Webhook Delivery | 1000ms | 5000ms | 3000ms | 15000ms |
| DynamoDB | 50ms | 200ms | 100ms | 500ms |

### Adding Descriptions in Bulk

Each panel's JSON needs a `"description"` field at the top level:

```json
{
  "id": 5,
  "title": "NHP Knock Latency",
  "description": "End-to-end knock processing time by percentile. p999 is the primary SLI. Action: If p999 > 1s, check server CPU, NLB target health, and network latency.",
  "type": "timeseries",
  ...
}
```

### Adding Deployment Annotations

**QURL dashboards (Prometheus-based):**

Copy the existing annotation from QURL Operations. It uses `process_start_time_seconds` to detect service restarts, which correlates with deployments:

```json
{
  "name": "Deployments",
  "datasource": {"uid": "${datasource_uid}", "type": "prometheus"},
  "enable": true,
  "iconColor": "blue",
  "expr": "changes(process_start_time_seconds{service_name=\"qurl-api\"}[2m]) > 0"
}
```

**NHP Infrastructure (CloudWatch-based):**

Requires CI to publish a custom metric first (Phase 0). Once available:

```json
{
  "name": "Deployments",
  "datasource": {"uid": "${cloudwatch_uid}", "type": "cloudwatch"},
  "enable": true,
  "iconColor": "blue",
  "namespace": "LayerV/NHP",
  "metricName": "DeploymentEvent",
  "statistics": ["Sum"],
  "period": "60"
}
```

### NLB TargetResponseTime Availability

NLBs only report `TargetResponseTime` for TCP and TLS listeners. The NHP knock port (62206/UDP) won't have this metric. The server HTTP endpoint (8888/TCP via TLS listener on port 443) will. Make sure the panel description notes this applies to the HTTP/TLS path only.
