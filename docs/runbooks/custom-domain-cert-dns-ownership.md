# Custom-Domain Cert DNS Ownership Alarms

Use this when prod fires custom-domain certificate alarms, especially these
immediate provisioning alarms:

- `layerv-nhp-prod-cert-failure-dns-ownership`
- `layerv-nhp-prod-custom-domain-cert-provisioning-failures`

Or these scheduled renewal aggregate alarms:

- `layerv-nhp-prod-cert-renewal-dns-ownership-failures`
- `layerv-nhp-prod-cert-renewal-orphaned-certs`
- `layerv-nhp-prod-cert-renewal-processing-failures`
- `layerv-nhp-prod-cert-renewal-scan-missing`

## What This Means

The cert Lambda renews existing customer certs from `/nhp/certs/<domain>/meta`.
Before issuing a renewed cert, it re-verifies public DNS ownership by comparing
`_layerv-verify.<domain>` TXT with the environment's `verification_token` in the
`qurl-domains` DynamoDB row.

If the TXT record is missing or belongs to another environment, renewal is
blocked by design. Do not weaken the Lambda check; decide which environment owns
the domain.

The NHP smoke fence blocks only the cross-environment shape where public TXT
contains another `lv_verify_*` token. Missing TXT, arbitrary non-Layerv TXT,
orphan cert metadata, harness read failures, managed-token format drift, and
incomplete fleet sweeps are logged by smoke as renewal-risk context but are left
to the cert Lambda alarms and this runbook, so unrelated prod promotes are not
blocked on ordinary customer-controlled DNS drift, infrastructure noise, token
format churn, or fleet size. If every attempted `qurl-domains` read fails after
the minimum-attempt floor, smoke blocks because the cross-environment fence has
no trusted row evidence and cell/table/IAM drift may have disabled it. The
cross-environment token case blocks smoke by design because it means a domain
now claimed by one Layerv environment still has certificate state in another.
To unblock a promote, use the fix path below: offboard/delete the stale
environment's domain state, or restore that environment's verification TXT. Do
not suppress the smoke failure without accepting the stale-renewal risk.

Scheduled renewal scans publish scan-level counts for DNS ownership failures,
orphaned cert metadata, and other processing failures. They do not publish one
`ProvisioningFailures` datapoint or SNS message per affected cert; the matching
CloudWatch alarms keep their previous state while no scan datapoint exists and
clear only after a later scan reports zero. The Lambda still updates the
per-domain `qurl-domains` status and `failure_reason` during scheduled renewal
failures so support can diagnose the affected domain without paging once per
cert. The scan metrics and alarms are dimensioned by `Environment` and `CellID`
so future cells do not aggregate into the same alarm stream.
If scan count metric publishing fails after the Lambda's in-process retries, the
Lambda Errors alarm may be the only renewal page for that cycle; use the Lambda
logs to find any per-category renewal failures and confirm the next scan
publishes the aggregate count metrics. A persistent CloudWatch publish failure
can still make Lambda's async retry re-run the full scheduled scan, so treat
repeated Lambda Errors as a telemetry/IAM outage before manually retrying and
check ACME rate-limit exposure if many in-window renewals ran during the outage.
The scan also publishes a `RenewalScanRuns` heartbeat at the start of each scan,
before listing or processing certs. If three consecutive 15-minute periods have
no heartbeat, `cert-renewal-scan-missing` pages because the scheduled scan may be
disabled, unable to invoke, or unable to publish the start heartbeat. A scan that
starts but later times out should leave the heartbeat present and trip Lambda
Errors instead of the missing-scan alarm. On a first deploy or alarm replacement,
the heartbeat metric may not exist until the first scheduled scan runs; it should
move to OK after the first heartbeat. The three-period window gives the first run
one extra scheduled interval of margin before paging; an ALARM after three missed
periods means the scan or heartbeat telemetry path did not start normally.
Because missing heartbeat data is breaching, a first deploy or alarm replacement
can page before the first healthy scan datapoint if the first EventBridge tick is
delayed. Acknowledge a one-time first-deploy heartbeat page and wait one scan
interval; escalate if it does not clear within an hour or re-enters ALARM after
reaching OK.

DNS ownership renewal alarms page on the first non-zero scan and clear on the
first explicit zero scan because customer DNS ownership drift stays broken until
DNS or stale cert state is fixed. `RenewalOrphanedCerts` pages after two
consecutive non-zero scheduled scans: normal offboarding deletes the
`qurl-domains` row before the cleanup Lambda deletes SSM cert metadata, and that
short handoff can look orphaned for one scan. `RenewalProcessingFailures` also
pages after two consecutive non-zero scheduled scans, so a single cert's
transient ACME/KMS/DDB/SSM blip can self-clear while recurring processing
failures still page once per environment/cell instead of once per cert.
It covers non-ownership renewal processing faults, including ACME challenge
setup or validation problems, so the name does not mean DNS can never be
involved. If the single post-renewal cert sync fails after successful renewal
work, the Lambda still emits the existing generic SNS/`ProvisioningFailures`
path once for the invocation; that is intentionally loud AC sync drift, not a
per-cert scheduled-renewal page. If scan metric publishing stops while a count
alarm is already in
ALARM, `treat_missing_data = ignore` lets that ALARM persist until a later scan
publishes an explicit zero; use Lambda Errors and the heartbeat alarm to
separate stale alarm state from live renewal drift. If a single transient
dependency fault self-clears and metric publishing is healthy, expect the alarm
to return to OK on the next zero scan. Because EventBridge `rate(15 minutes)`
and CloudWatch 900-second period boundaries are not guaranteed to align, a
non-zero scan and a later zero scan can occasionally land in the same period;
with `Maximum` aggregation, the OK transition may wait for one more scan period.
For `RenewalProcessingFailures`, two consecutive failing scans can also land in
one CloudWatch period; in that case, the initial page may wait for one more
failing scan.

## Diagnose

Find the failing domain in the cert Lambda logs:

```bash
START_MS="$(( ($(date +%s) - 7200) * 1000 ))"

AWS_PROFILE=layerv-prod aws logs filter-log-events \
  --region us-east-2 \
  --log-group-name /aws/lambda/layerv-nhp-prod-custom-domain-cert-manager \
  --filter-pattern '"DNS ownership re-verification failed"' \
  --start-time "${START_MS}"
```

Read the prod row and public DNS:

```bash
DOMAIN=dashboard.example.com
AWS_PROFILE=layerv-prod aws dynamodb get-item \
  --region us-east-2 \
  --table-name layerv-nhp-prod-cell0-qurl-domains \
  --key "{\"domain\":{\"S\":\"${DOMAIN}\"}}" \
  --projection-expression '#s,verification_token,failure_reason,updated_at' \
  --expression-attribute-names '{"#s":"status"}'

dig +short TXT "_layerv-verify.${DOMAIN}"
dig +short CNAME "${DOMAIN}"
dig +short CNAME "_acme-challenge.${DOMAIN}"
```

If the public TXT matches sandbox or another environment, confirm that row too:

```bash
AWS_PROFILE=layerv aws dynamodb get-item \
  --region us-east-2 \
  --table-name layerv-nhp-sandbox-cell0-qurl-domains \
  --key "{\"domain\":{\"S\":\"${DOMAIN}\"}}" \
  --projection-expression '#s,verification_token,updated_at' \
  --expression-attribute-names '{"#s":"status"}'
```

## Fix

If DNS belongs to another environment, remove stale prod ownership through the
normal qurl-service domain delete/offboard flow. That flow removes the prod
`qurl-domains` row and publishes `domain.cleanup`; the cert Lambda then deletes
`/nhp/certs/<domain>/{key,chain,meta}` and triggers per-domain AC cert eviction.

Do not publish `domain.cleanup` directly while the prod row still has a non-empty
`verification_token`. The Lambda will treat that as a re-registration race and
abort cleanup.

If the domain should stay in prod, update public DNS to match prod:

- `_layerv-verify.<domain>` TXT equals the prod `verification_token`
- `_acme-challenge.<domain>` CNAME points at the prod ACME zone
- `<domain>` CNAME points at the prod custom-domain AC target

Then wait for DNS TTL and the next renewal scan, or retry through the normal
custom-domain UI/API path.

## Verify

```bash
DOMAIN=dashboard.example.com

AWS_PROFILE=layerv-prod aws ssm get-parameters-by-path \
  --region us-east-2 \
  --path "/nhp/certs/${DOMAIN}" \
  --recursive

AWS_PROFILE=layerv-prod aws cloudwatch describe-alarms \
  --region us-east-2 \
  --alarm-names \
    layerv-nhp-prod-cert-failure-dns-ownership \
    layerv-nhp-prod-custom-domain-cert-provisioning-failures \
    layerv-nhp-prod-cert-renewal-dns-ownership-failures \
    layerv-nhp-prod-cert-renewal-orphaned-certs \
    layerv-nhp-prod-cert-renewal-processing-failures \
    layerv-nhp-prod-cert-renewal-scan-missing
```

For stale-prod cleanup, the SSM path should be absent. The immediate
`cert-failure-dns-ownership` and `custom-domain-cert-provisioning-failures`
alarms return to OK once failure datapoints stop arriving; the three
`cert-renewal-*` alarms return to OK only after a later renewal scan publishes
zero. For prod DNS restoration, the next renewal scan should log DNS ownership
re-verification and renewal success.
