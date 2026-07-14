# Status Page Module

The public, customer-facing LayerV status page: `status.layerv.ai` (prod) and
`status.layerv.xyz` (sandbox). Modeled on githubstatus.com / status.anthropic.com,
styled to match layerv.ai's production design system.

## Architecture

```
                       ┌────────────────────────────────────────┐
 viewer ── CloudFront ─┤ S3 public keys: index.html, favicon.svg,│
            (60s TTL)  │     wordmark.svg, fonts/*, status.json │
                       └────────────────────────────────────────┘
 page JS ── CloudFront/S3 ── status.json
   polls every 30s; user-visible freshness is minute-scale
 API GW ── Lambda (status_aggregator.py)
   compatibility           │  reads cached status.json and overlays
                           │  latest sanitized incidents.json
 EventBridge ──────────────┤
 rate(5 minutes)           │  live checks: NLB target health, active
                           │  CloudWatch alarms, HTTP HEAD/GET of public
                           │  endpoints
                           │  (DEPENDENT_SERVICE_URLS)
                           │  + reads history.json / incidents.json
 {"task":"snapshot"}     writes status.json + history.json
 S3 ObjectCreated
 incidents.json          refreshes incidents in status.json
```

The payload returned in `status.json` (and by compatibility `GET /status`) is
**public by design** and carries only
`environment`, `timestamp`, `overall`,
`components[{id,status,display_only}]`, `history`, and `incidents`. It must
never expose infrastructure detail (ARNs, image tags, commits, host counts,
capacity, alarm names, regions).
`environment` is public JSON even when the frontend hides the chip for prod.
`test_status_aggregator.py::TestPublicPayloadIsLeakFree` is the enforcement —
extend it when you extend the payload.

The compatibility `GET /status` API is secondary to the CloudFront/S3 viewer
path. It serves a short in-memory cache, falls back to the stale cached payload
on a transient `status.json` read miss, and returns an empty `unknown` payload
only before any status snapshot/cache exists. If `enable_nhp_auth` is true, the
CloudFront viewer is QURL-gated but this exported compatibility API remains
public and unauthenticated by design; it serves the same redacted status
payload and should not be treated as a confidential surface.
On each cache miss the compatibility API also reads `incidents.json` once and
overlays the latest sanitized incidents; this is intentional fallback coverage
for a dropped S3 notification or a warm cache predating an operator edit, and
viewer traffic still reads only CloudFront/S3 `status.json`.
The API stage is throttled to 2 rps with a 3-request burst so a couple of
low-rate integrations or operators can read the cached secondary surface while
accidental direct traffic still leaves two reserved-concurrency slots in the
Lambda's shared `reserved_concurrent_executions = 5` pool for scheduled
snapshot/incident invokes. It is not the high-fanout polling path; pollers
should use the CloudFront/S3 `status.json` object, and 429s under direct API
bursts are intentional protection. The burst/rate limit is one shared global
API Gateway budget across all direct callers, which is acceptable because
viewers use CloudFront/S3 and supported pollers should do the same. The function
keeps this public API on the same reserved-concurrency pool rather than
allowing direct callers to borrow unreserved account concurrency. Five is
intentional capacity math here: the three-request API burst can drain while two
async slots remain for a scheduled snapshot plus an incident publish. A lower
reserved pool can let direct API bursts consume all slots; a higher one is
unnecessary until this compatibility API becomes a supported polling integration
or the async producers/probe fanout grow. Do not market this endpoint as a
high-rate integration API without revisiting the API throttle, reserved
concurrency, and async retry/event-age budget together.
The API 5xx alarm still pages even though viewers read CloudFront/S3
`status.json`: it means compatibility API consumers have lost the secondary
cached public-status surface.

## Components

Two kinds:

- **NHP infrastructure** (`nhp_server`, `nhp_ac`) — derived from NLB
  target-group health plus any active CloudWatch alarm whose name contains
  `-server-` / `-ac-` under `alarm_name_prefix`. All targets healthy and no
  alarms = operational; partial health or an active alarm = degraded; zero
  healthy targets = major_outage; lookup failure = unknown (never a false
  outage). In blue/green environments the Lambda reads the active-color SSM
  parameter and checks only the active public target group. If active-color
  lookup or mapping fails, the component publishes `unknown` instead of
  aggregating idle-color target groups into a false customer-facing degradation.
  If one active target-health read fails but another active group returns a
  healthy target, the public component remains operational by design; CloudWatch
  alarms are the backstop for the unobserved group, and zero healthy described
  targets with read errors fail safe to `unknown`/`degraded` rather than red.
  If `DescribeAlarms` fails, already-read active alarm pages still count, but
  unread alarms are treated as inactive so CloudWatch telemetry flakiness does
  not create a false public outage; target-group health remains the primary
  signal.
- **Public HTTP checks** (`dependent_service_urls`: `qurl_api`, `qurl_link`,
  `website`, ...) — HTTP HEAD with GET fallback when HEAD is unsupported or
  rejected by a proxy/CDN client error, plus one retry; 2xx/3xx = operational,
  4xx = degraded immediately (429 is retried), and repeated 5xx or
  connection-level failure starts as degraded and escalates to major_outage only
  after a consecutive hard-fail snapshot. Wired in the root module from
  `qurl_service_domain` / `qurl_link_domain` plus
  `status_page_additional_service_urls` in tfvars. Configure probe URLs to
  return 2xx/3xx when healthy; a reachable 4xx is intentionally customer-amber.
  Probe endpoints must be unauthenticated: auth-protected 401/403 responses
  stay degraded until the URL returns 2xx/3xx. A repeated 429 stays degraded
  after the retry and is treated as customer-visible throttling rather than
  ignored as probe noise. A URL that alternates between hard failures
  (5xx/unreachable) and reachable degraded responses (4xx) stays amber until it
  produces two consecutive hard-fail snapshots; this is intentional anti-flap
  behavior, not a red-outage trigger.
  Redirects are followed by the Python HTTP client; a final 2xx/3xx is healthy.
  `qurl_link` intentionally targets `/index.html`, not the token-less root, so
  the check proves the static redemption shell is reachable; dynamic qURL
  backend readiness is represented by the `qurl_api` tile and by operator
  incidents. qURL Link `/index.html` should answer HEAD with 2xx/3xx in steady
  state; the GET fallback is a compatibility path, not the expected hot path.
  The Lambda also emits `LayerV/NHP/StatusPage/HTTPComponentNonOperational`
  per HTTP component on each snapshot before customer-facing hard-outage
  debounce is applied, and Terraform creates a sustained non-operational alarm
  for each configured URL so a persistent 403/404, WAF user-agent mismatch, or
  mis-pointed health path does not stay silently amber. Invalid or otherwise
  unprobeable URLs publish `unknown` publicly but still count as
  non-operational for this operator alarm. That includes Lambda-side egress,
  DNS, or reachability failures; a persistently `unknown` probe URL pages even
  while the public tile stays gray, and display-only components still page after
  the three-snapshot alarm window because the operator needs to know the probe
  path is no longer proving that ancillary surface.
  `status_page_additional_service_urls` rejects reserved built-in ids
  (`qurl_api`, `qurl_link`, `nhp_server`, `nhp_ac`) so tfvars cannot shadow
  canonical checks. The module caps total HTTP checks at 8, including built-in
  qURL API/link checks, so snapshots probe every URL in a single worker wave
  under the 35s Lambda duration alarm even with the DNS guard and the rare
  non-retried range-reject plain-GET fallback, while still leaving timeout
  headroom.
  These URLs are operator-owned public HTTPS endpoints, not a private health-check relay;
  the Lambda has no VPC config and should not be used to probe private resources.
  Terraform validates the `https://` boundary, and the Lambda enforces it again
  at runtime, rejecting non-HTTPS URLs, localhost, non-global IP literals,
  hostnames that resolve to non-global addresses, and redirects outside that
  same public HTTPS boundary. DNS resolution is a best-effort SSRF guard, not
  an authorization boundary. It runs before the urllib probe timeout; urllib
  still resolves again while connecting, and redirect validation resolves each
  redirect target again. The duplicate DNS work is intentional so every network
  handoff re-checks the public boundary; resolver work uses a shared DNS pool
  isolated from the URL probe pool, and URL fanout remains capped at 8. Keep
  the URL list bounded and watch p99 Lambda Duration when adding
  slow-resolving dependencies, and do not wire user-supplied URLs into
  `dependent_service_urls` or `status_page_additional_service_urls`.

Only HTTP hard-fail outages use cross-snapshot debounce. NLB-derived
`nhp_server` / `nhp_ac` health is not debounced here because target-group health
checks and CloudWatch alarms are already smoothed at the infrastructure layer.
An intervening `unknown` HTTP probe does not clear a pending hard-fail streak;
only a reachable degraded or operational probe resets it, so flapping
unreachable dependencies can still turn red after a repeated hard failure.
Alternating 5xx/unreachable and 4xx responses are treated as customer-visible
degradation until the hard-fail samples become consecutive; that keeps a
flapping app from painting the headline red unless the hard outage persists.
If every active-color target is unhealthy at snapshot time, the public status
can publish red for that snapshot cadence; this is intentional so real
infrastructure outages are not hidden by an app-level debounce.
The Lambda stores a private raw HTTP status map in `history.json` so the second
consecutive hard-fail snapshot can publish red even though the first public
snapshot is intentionally downgraded to amber. This accepts up to one snapshot
cadence of red-outage lag for HTTP dependencies to avoid customer-visible false
reds from single-probe failures.

The top-level `overall` field rolls up core platform components plus active
operator-published incidents. Ancillary display-only components configured via
`display_only_component_ids` (such as `website`) still render as component rows
with an informational marker and still collect uptime history, but they do not
escalate the whole-platform component rollup. Operator-published incidents are
manual severity signals and can still escalate `overall` even when their
`components` list names only display-only component ids. `unknown` component
statuses render as gray tiles and no-data history samples. A non-display-only
`unknown` component can surface the headline as unknown, while any known
degraded/outage signal still takes precedence. Terraform rejects display-only
ids that are not configured HTTP components so a typo cannot silently produce
no tile.

Display names, descriptions, and ordering live in `frontend/index.html`
(`COMPONENT_META` / `COMPONENT_ORDER`). Adding a component = one tfvars entry
plus (optionally) a `COMPONENT_META` entry; unknown ids render with a
prettified id.

Display-only controls the public whole-platform rollup only. Display-only HTTP
components still emit per-component non-operational metrics and SNS alarms,
including for persistent reachable 4xx responses, so ancillary surfaces such as
`website` page operators even though they do not turn the overall customer
banner red.

## Uptime history

EventBridge invokes the Lambda with `{"task": "snapshot"}` every 5 minutes.
Each scheduled snapshot publishes the current public payload to `status.json` and
increments per-day counters `[operational, degraded, outage]` per component in
`history.json` (S3, 92-day retention, 90 shown). Public page reads fetch
`status.json` from CloudFront/S3, so viewer traffic does not fan out into ELB,
CloudWatch, or HTTP health checks during incidents. `unknown` samples are
skipped so monitoring gaps render as "no data" rather than as uptime or
downtime. History starts accumulating at deploy time. Before the first
snapshots exist, component rows render an explicit "Uptime history collecting"
note instead of a blank bar; once any samples exist, the same rows switch to
the 90-day bars with missing days marked as not collected. `history.json` is not
public; besides the `days` counters, it also carries private raw HTTP component
statuses used only for hard-outage debounce. Because that debounce is applied
before history is counted, a one-snapshot hard HTTP outage records as degraded,
matching what customers saw during that snapshot. On a brand-new history file,
the first hard HTTP outage sample is likewise counted as degraded because the
debounce has no previous hard-fail marker yet; that is intentionally slightly
optimistic for one snapshot and matches the amber customer-facing state before
the second hard-fail snapshot. A real outage that starts immediately after a
deploy can therefore read amber until the first and second scheduled snapshots
land, up to two snapshot intervals (about 10 minutes at the default cadence).
If `history.json` is
accidentally deleted, the next snapshot starts fresh history instead of failing
the public page; that trades historical bars for continued status publication.
If `history.json` becomes malformed, the Lambda logs the malformed read,
`status.json` remains current, and the next snapshot starts a fresh history
window rather than freezing component/incident publication behind bad uptime
counters.

The browser's percentage label is intentionally "fully operational": it is
`operational / (operational + degraded + outage)`. Amber degraded samples and
red outage samples both reduce that percentage, while the per-day bars show the
affected degraded/outage minutes.

The snapshot cadence is `local.snapshot_cadence_minutes` in `main.tf`; the
EventBridge schedule and frontend tooltip estimates are rendered from that one
value. EventBridge and S3 invoke the Lambda asynchronously; Terraform pins an
async retry config so transient reserved-concurrency throttles retry instead of
silently dropping snapshot or incident-refresh events. The one-hour async event
age is deliberate headroom over any plausible throttle-drain window. The
compatibility API uses the same small reserved-concurrency pool as those async
invokes, but its stage throttle stays below that pool; if snapshot-freshness
alarms fire during direct `/status` API traffic, check for API throttling or
consumers bypassing the CloudFront/S3 viewer path. This intentionally trades
possible direct-API throttling during incident edits for keeping public direct
callers inside the bounded function pool; the CloudFront/S3 read model remains
the authoritative viewer path. A slow snapshot can hold one reserved-concurrency
slot until the 45s Lambda timeout, so the three-request API burst plus two
async slots is the overlap case this pool is sized around; the 35s duration
alarm is the early warning before timeout. If the snapshot cadence, async
producer count, or API rate limits grow, or if the compatibility API becomes a
supported polling path, review `reserved_concurrent_executions`, the API
throttle, the snapshot-invocation-gap alarm, and async retry/event age together.

Snapshots write `status.json` before private `history.json`. If the public
write fails, history does not advance and an EventBridge retry cannot
double-count that bucket. If the later history write fails, the current public
read model is already published; the Lambda error alarm fires and the next
successful snapshot self-heals the private counters.

The frontend compares the payload `timestamp` with the current time and shows a
delayed-data notice when the published snapshot is stale. Terraform also alarms
on Lambda runtime errors, near-timeout duration, EventBridge snapshot invocation
gaps, and failed target delivery, so a disabled or broken snapshot rule is
visible even if the last `status.json` was green. The duration alarm is set
above the initial DNS guard plus ordinary per-URL HEAD-to-GET retry budget and
the rare non-retried range-reject fallback, so dependency probe behavior should
not also page as Lambda slowness; the range-reject plain-GET fallback is not
retried because origin range support is deterministic. Redirect revalidation can
still push p99 toward the alarm; that is an intentional near-timeout signal. The
threshold remains below the function timeout. After launch, watch p99 Lambda
Duration alongside the 35s alarm because a pathological URL can spend most of
the probe budget and target-health/alarm reads share the same invocation. The
snapshot invocation-gap
alarm treats missing data as breaching, so a fresh deploy can remain noisy until
the first three scheduled snapshots land.
Per-HTTP-component sustained
non-operational alarms cover the case where the page stays amber or gray because
a health URL is consistently returning a reachable 4xx or is invalid/unprobeable.

## Incident publish runbook

The page renders sanitized incident fields from `status.json`. This section is
the operator runbook for publishing the source `incidents.json` object in the
bucket. Terraform seeds an empty object and then ignores it (`ignore_changes`),
so operators own its content — the same pattern as the CI/CD-owned SSM
parameters.
CloudFront is allowed to read only the public read model (`status.json`) plus
static assets; it cannot fetch raw `incidents.json` or `history.json` directly.
The Lambda reads the operator source object, sanitizes it, and publishes the
allowed fields into `status.json`.

Schema:

```json
{
  "incidents": [
    {
      "id": "2026-06-10-qurl-link-errors",
      "title": "Elevated errors on qURL link redemption",
      "status": "investigating | identified | monitoring | resolved",
      "impact": "minor | major | critical",
      "components": ["qurl_link"],
      "started_at": "2026-06-10T17:20:00Z",
      "resolved_at": null,
      "updates": [
        {
          "at": "2026-06-10T17:25:00Z",
          "status": "investigating",
          "body": "We are investigating elevated error rates on qurl.link."
        }
      ]
    }
  ]
}
```

Use full ISO-8601 date-times with a `T` separator and timezone (`Z` or an
offset such as `+00:00`) for `started_at`, `resolved_at`, and update `at`
values. Date-only values fail closed and the incident/update is skipped.
Incident-level timestamps more than 1 day in the future are rejected, and
future-dated updates are filtered, so a typo cannot publish a long-lived
future incident banner.
For operator UX, `impact: "critical"` is the only incident impact that turns
the headline banner red:

| Incident impact | Public headline |
| --- | --- |
| `critical` | Red outage banner / `major_outage` |
| `major` | Amber degraded banner |
| `minor` | Amber degraded banner |

Publish flow (operator with account access):

```bash
aws s3 cp incidents.json s3://<name_prefix>-status-page-<account_id>/incidents.json \
  --content-type application/json
```

Notes:

- Anything with `status != "resolved"` shows as an active incident banner and
  escalates the top-level `overall` field (critical → outage, otherwise →
  degraded). This is intentional even for `impact: "major"` or `impact:
  "minor"`: use `critical` when the headline banner should go red / major
  outage, use minor or major for customer-visible incidents with reduced
  impact, and resolve or omit FYI-only updates that should not move the
  headline banner. Do not use `major` when the intended public headline is
  "Service disruption"; use `critical` for that case. In operator runbooks and
  incident comms, describe `critical` as the only incident impact that turns the
  public banner red; `major` remains amber by design.
  Resolved incidents appear under "Past incidents" for 14 days (grouped by
  `resolved_at` day, with `started_at` as a fallback). Resolve stale active
  incidents promptly; active incidents do not auto-expire, so a forgotten
  investigating/monitoring entry keeps the banner elevated until edited or
  resolved.
- Uploading `incidents.json` triggers the aggregator Lambda immediately, so the
  CloudFront-served `status.json` reflects operator updates without waiting for
  the next 5-minute scheduled snapshot. This incident refresh does not increment
  uptime history; history remains on the scheduled snapshot cadence. Terraform
  configures the notification after the seeded `status.json`/`incidents.json`
  objects exist so the initial read model is not overwritten during first apply.
- If `incidents.json` is missing or malformed, the Lambda keeps the previous
  sanitized public incidents rather than clearing banners from a typo or
  accidental delete. Clear active incidents by editing them to `resolved`;
  resolved incidents then age out of the public read model after 14 days.
- The Lambda passes incidents through a strict field and value allowlist; unknown
  fields (internal notes, runbook links) are stripped before they reach the page,
  and entries missing required schema fields (`id`, `title`, `status`,
  `impact`, `started_at`), using unknown `status`/`impact` values, invalid
  timestamps, non-string or unknown `components`, or oversized strings/lists
  are skipped or trimmed from the public payload. Component ids must be one of
  the built-ins (`nhp_server`, `nhp_ac`, `qurl_api`, `qurl_link`) or a configured
  `dependent_service_urls` / `status_page_additional_service_urls` key such as
  `website`. Duplicate public incident ids are ignored after the first valid
  entry; do not rely on last-write-wins ordering when editing the operator
  file. Keep the operator file newest-first and trimmed: the public read model
  processes only the first 100 raw entries before selecting the newest public
  incidents, then caps active incidents to the newest 25 entries and resolved
  incidents to the newest 50 entries. It strips control/format characters from
  public title/body copy and enforces a 4 MiB serialized incident JSON budget,
  dropping resolved/oldest entries first, so a malformed operator file cannot
  grow `status.json` beyond the Lambda proxy response headroom. S3 JSON source
  objects are also capped before decoding so an oversized operator/private read
  model cannot exhaust Lambda memory. The leak-free guarantee means the Lambda
  adds no infrastructure detail; operators are still responsible for keeping
  incident copy free of infrastructure detail and secrets.
- The Lambda runtime is pinned to Python 3.12 in `main.tf`; the timestamp parser
  normalizes trailing `Z` to `+00:00` before `datetime.fromisoformat`, so
  operator timestamps should use full ISO-8601 date-times with timezone offsets.
- Keep resolved incidents in the file for at least 14 days; pruning older
  entries is optional because the Lambda trims older resolved incidents from
  `status.json`.
- The public read model uses a 60s cache policy. CloudFront default/max TTL and
  the `status.json` object `Cache-Control` all cap edge caching at 60 seconds.
  Incident uploads update the S3 read model immediately, but viewers can see the
  previous edge copy until that TTL expires or an operator runs an invalidation.
  The page polls more often than that, but user-visible freshness should be
  described as roughly minute-scale.

## Frontend

`frontend/index.html` is a single self-contained page (inline CSS/JS, vendored
OFL fonts, no third-party dependencies, hash-pinned inline CSS/JS). It is
rendered through Terraform `templatefile()` — the only interpolation is
`${status_feed_url}` and `${snapshot_cadence_minutes}`, so any literal `${`
added to the file must be escaped as `$${` (the JS deliberately avoids template
literals).
When NHP auth is disabled, CloudFront maps S3/OAC 403 and 404 responses to
`/index.html` while preserving HTTP 404, so typo paths see the branded status
shell instead of raw S3 XML and missing public objects still fail as not found
for monitors. When NHP auth is enabled, the 403 rewrite is disabled so
CloudFront Function loop-detection responses keep their cookie-domain diagnostic
body.
If the inline `<style>` or `<script>` changes, update the matching
`style-src 'sha256-...'` or `script-src 'sha256-...'` value in `main.tf` in the
same commit.
The CSP intentionally relies on `default-src 'self'` for same-origin fonts,
favicon, and wordmark assets; add explicit `font-src` / `img-src` directives if
any future asset moves off-origin.

The CI public-surface guard prints the expected hash when either CSP directive
drifts. To print both hashes locally:

```bash
cd ../../..
python3 .github/scripts/check-status-page-public-surface.py --print-hashes
```

Local preview:

```bash
cd terraform/modules/status-page
sed -e 's|${status_feed_url}|http://localhost:8089/status|' \
    -e 's|${snapshot_cadence_minutes}|5|' \
    frontend/index.html > /tmp/status-preview/index.html
cp -r frontend/favicon.svg frontend/fonts /tmp/status-preview/
# serve /tmp/status-preview plus representative /status JSON on :8089
```

## Tests

```bash
cd lambda
pip install -r requirements-dev.txt
AWS_ACCESS_KEY_ID=unit-test AWS_SECRET_ACCESS_KEY=unit-test \
AWS_REGION=us-east-2 AWS_EC2_METADATA_DISABLED=true \
python -m pytest test_status_aggregator.py -v
```

CI runs the suite in `build-and-push.yml`'s `test-lambdas` job.

## Rollout checks

Before cutting traffic or treating the page as authoritative, verify from the
target environment that the configured public health URLs return a plain
2xx/3xx response to the Lambda user agent (`LayerV-StatusPage/2.0`) on HEAD or
the GET fallback: qURL API `/health/ready`, qURL Link `/index.html`, and any
`status_page_additional_service_urls` such as `website`. This prevents a CDN/WAF
or auth mismatch from rendering a healthy service as degraded. For qURL Link,
prefer a clean HEAD 2xx/3xx on `/index.html` so the ranged/plain GET fallback
stays exceptional rather than steady-state snapshot work.

After the first sandbox snapshot, inspect `status.json` and confirm
`nhp_server` / `nhp_ac` are not stuck at `unknown`; an `AccessDenied` on scoped
`DescribeTargetHealth` would otherwise fail safe and show up there.
