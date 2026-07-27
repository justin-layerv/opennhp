# 2026-07-26 · Connector Authority operator alerts + full runtime alarm set

- **Owner:** UDP proof rollout coordinator
- **Issue:** [NHP #3455](https://github.com/layervai/nhp/issues/3455) · follows #3454
- **Related:** [NHP #3280](https://github.com/layervai/nhp/issues/3280) (prod alert recipient reconciliation)

NHP #3454 deployed the complete 11-function sandbox Authority graph with a
per-function `ProvisionedConcurrencySpilloverInvocations` alarm and deliberately
did not guess an operator notification destination. This slice completes the
observability: it routes every alarm to the reviewed operator destination and
adds the rest of the runtime alarm set.

## Alarm inventory

| | before | after |
| --- | --- | --- |
| `ProvisionedConcurrencySpilloverInvocations` | 11 | 11 |
| `Errors` / `Throttles` / `Duration` (p99) / `ConcurrentExecutions` / `AsyncEventsReceived` | 0 | 55 |
| Non-provisioned-initialization composite | 0 | 11 |
| Terminal invocation outcome (`internal`, `unavailable`) | 0 | 22 |
| Admission rejection (`limited`, `unavailable`) | 0 | 8 |
| Registration-adapter contract violation | 0 | 4 |
| Registration-adapter late result | 0 | 4 |
| Completion identity rejected (`authority_fence`) | 0 | 2 |
| **Total** | **11** | **117** |
| **Alarms with an operator action** | **0** | **117** |

Verified live before the change (`aws cloudwatch describe-alarms
--alarm-name-prefix layerv-nhp-sandbox-ca-`): all 11 spillover alarms exist with
`AlarmActions: []`.

## Operator routing

`operator_alarm_topic_arns` is a new **address input**, not a module-owned
resource. The sandbox Control root pins it to
`arn:aws:sns:us-east-2:767397897469:layerv-nhp-sandbox-cell0-alerts` — the
`terraform/modules/monitoring` topic that is the only sandbox SNS topic with a
confirmed subscription today (an AWS Chatbot HTTPS subscriber; no email
subscribers). The module never creates a topic: an isolated topic with no
confirmed subscription is indistinguishable from a working one until the first
real fault, which is exactly the condition #3280 is reconciling in production.

**Relationship to #3280.** #3280 is **not a blocker for this sandbox slice** —
the sandbox destination already delivers. It *is* the owner of the production
destination: the prod Control root's `operator_alarm_topic_arns` is
validation-locked empty and must stay that way until #3280 confirms the
production recipients and the production runtime slice opens. The module's
`foundation_contract` precondition makes that safe in both directions — an
enabled runtime with an empty destination list is a hard plan error.

## Co-occurring transition: the pending Hub UDP source fence

The sandbox Control root carries an **un-applied** Hub UDP source-fence
transition: the live NLB `layerv-nhp-sandbox-control-hub` reports
`SecurityGroups: null`, so `aws_security_group.hub_nlb[0]` plans as a create and
`aws_lb.hub[0]` / `aws_lb_listener.hub[0]` as replacements on every plan of this
root. It is a reviewed, admitted transition (`hub-udp-source-fence-replacement`)
waiting on an attended apply, and it is not this slice's to apply.

The alarm slice is observability-only and its address space is **disjoint** from
the fence's, so a plan legitimately carries both. The checker composes them
under the contract already used for the fence and the Hub identity migration:
the alarm addresses are excluded from the fence subset test **only** once they
form their own exact transition (`authority_alarm_slice_exact`), they are
separately create-shape proved, and their contents are validated regardless by
`_check_authority_alarm_routing`. A non-exact alarm move leaves the predicate
false and the whole plan falls through to the fail-closed fallback.

The composed plan mode is
`hub-udp-source-fence-replacement-with-authority-alarm-routing`.

- [ ] Pre-rollout: confirm the plan reports exactly the composed shape — 106
      alarm creates, 11 in-place spillover updates, the 8 reviewed fence
      actions, and the pending Hub identity publication (126 changed). Anything
      else is a stop condition.
- [ ] The fence half is **not** applied by this slice. Apply it on its own
      reviewed schedule; the alarm apply neither depends on it nor blocks it.

## Rollout

- [ ] Pre-rollout — prod plan confirmation: run the prod Control plan at this
      head and confirm **no resource changes**. The prod runtime slice is
      validation-locked dark, so no alarm is planned there; the only prod-facing
      effect is one new validation-locked variable.
- [ ] Pre-rollout — sandbox plan confirmation: the plan must report exactly 106
      creates and 11 in-place updates, and nothing else. The 11 updates are the
      existing spillover alarms gaining `alarm_actions`. **No Lambda function,
      alias, execution role, provisioned-concurrency config, endpoint, or
      security group may move** — this slice is observability-only by
      construction. The first-apply checker names this shape
      `authority-alarm-routing` and fails closed on anything else.
- [ ] Rollout — apply the sandbox Control root.
- [ ] Post-rollout — inventory receipt: `aws cloudwatch describe-alarms
      --alarm-name-prefix layerv-nhp-sandbox-ca-` returns 117 alarms and **zero**
      with an empty `AlarmActions`. Record the count in this entry.
- [ ] Post-rollout — **page receipt (acceptance criterion 3, blocking).** Alarm
      state alone proves nothing here: every alarm uses
      `treat_missing_data = "notBreaching"`, so an alarm whose dimension set
      selects a stream nothing writes to sits in a permanently green `OK`,
      indistinguishable from a healthy one. Prove delivery with a synthetic
      failure and record the receipt:
      1. `aws cloudwatch set-alarm-state --alarm-name
         layerv-nhp-sandbox-ca-ia-errors --state-value ALARM --state-reason
         "NHP #3455 synthetic operator-alert proof"` and confirm the
         notification arrives at the operator destination. This proves the
         **routing**.
      2. Routing is not dimension correctness. For the **dim-set** proof, drive
         one real fault per publisher and confirm the alarm transitions on its
         own: invoke an Authority alias with a payload that produces an
         `internal` terminal outcome (proves the `LayerV/ConnectorAuthority` EMF
         dim set `{EnvironmentID, AuthorityOperation, [CellID], Outcome}`), and
         confirm a real `Errors` datapoint moves the platform alarm (proves the
         `{FunctionName}` dim set). Record which alarms transitioned and the
         `MetricDataResults` that backed them.
      3. Return every alarm touched in step 1 to `OK` and confirm no alarm is
         left in a manually-forced state.
- [ ] Post-rollout — record in this entry: the 117-alarm inventory, the empty
      `AlarmActions` count (must be 0), and the page-receipt timestamps.

## Threshold basis

- **Zero-tolerance counters** (spillover, `Errors`, `Throttles`,
  `AsyncEventsReceived`, and every custom EMF counter): threshold `0`. The
  request path has a zero baseline by construction — a clean protocol rejection
  is a successful invocation carrying an error envelope, so it does not reach
  `Errors`, and the custom counters only emit on the fault they name.
- **`Duration`**: p99 over 2×5-minute periods at 8000 ms = **80% of the reviewed
  10-second Lambda timeout**, derived in Terraform from the same
  `local.authority_runtime_timeout_seconds` the function resource uses. This is
  a **structural** threshold, not an empirical percentile: no Authority function
  has ever carried traffic, so no `Duration` datapoint exists to calibrate
  against. The POST-STEP-3 FLAG on the timeout/memory pair in
  `authority_runtime.tf` owns the empirical recalibration; tightening the
  timeout there tightens this alarm automatically.
- **`ConcurrentExecutions`**: `>=` the bound contract's
  `steady_reserved_concurrency` (2 today), read from the contract rather than
  typed in, so a capacity change cannot silently desynchronize the alarm.

## Rollback

Set `operator_alarm_topic_arns = []` **and** `authority_runtime_functions_enabled
= false` together, or revert this change. Setting the destination empty alone is
a deliberate hard plan error while the runtime is live — the Authority may not
run with an unrouted alarm set. Reverting destroys the 106 new alarms and
returns the 11 spillover alarms to `alarm_actions = []`; no function, role, or
network resource is touched in either direction.
