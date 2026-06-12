# Runbook: Triaging a GuardDuty finding

You reached this page from a GuardDuty alert (email to `security@layerv.ai` /
the on-call individuals, a Slack message via AWS Chatbot, or a weekly
stale-finding re-alert). This runbook is the triage procedure for that alert.

There is **no pager** for security alerts. The compensating control against a
finding being silently missed is the **stale-finding watchdog** (tracked under
[#1211](https://github.com/layervai/nhp/issues/1211), split from the
[#1137](https://github.com/layervai/nhp/issues/1137) incident): a Lambda that
re-alerts weekly on any non-archived finding at or above the alert severity
threshold and older than `stale_finding_age_days` (default 7). That means an
un-triaged alerted finding keeps nagging — but it also means **triage is not
optional**: archiving is the only thing that stops the re-alert, and archiving
without investigating defeats the control.

The staleness clock uses GuardDuty `UpdatedAt`, not `CreatedAt`: new activity on
the same finding can bump `UpdatedAt` and delay the weekly re-alert.

## How a finding reaches you

```
GuardDuty detector
  └─ EventBridge rule  <name_prefix>-guardduty-findings
       (fires on detail.severity >= guardduty_alert_severity_threshold; default 4)
       ├─ target: <name_prefix>-guardduty-email  SNS topic
       │            └─ email → security@layerv.ai + individual subscribers
       └─ target: main alerts SNS topic (alerts_sns_topic_arn)
                    └─ AWS Chatbot → Slack
```

The weekly watchdog (`terraform/modules/security/stale_finding_watchdog.tf`)
publishes to the same two topics, so stale re-alerts land in the same places.

Source of truth for this wiring:
`terraform/modules/security/main.tf` (`GuardDuty Alerting` section) and
`terraform/modules/security/stale_finding_watchdog.tf`.

## Severity scale

GuardDuty severity runs `1.0`–`10.0`. The EventBridge filter only forwards
`>= guardduty_alert_severity_threshold`, so at the default threshold of 4
anything you receive is at least Medium:

| Band | Severity | Posture |
|------|----------|---------|
| Low | 1.0–3.9 | Not alerted on by default (below the default threshold). |
| Medium | 4.0–6.9 | Triage within one business day. |
| High | 7.0–8.9 | Triage same day; treat as a potential active incident. |
| Critical | 9.0–10.0 | Newer top band AWS emits for some finding types; treat as an active incident; see step 5 for the no-pager escalation path. |

## Triage steps

1. **Open the finding.** Click the console link in the alert, or:
   ```bash
   ENV=prod   # or "sandbox"
   PROFILE=$([ "$ENV" = "prod" ] && echo "layerv-prod" || echo "layerv")
   AWS_PROFILE=$PROFILE aws guardduty list-detectors --query 'DetectorIds[0]' --output text
   # then, with that detector id and the finding id from the alert:
   AWS_PROFILE=$PROFILE aws guardduty get-findings \
     --detector-id <detector-id> --finding-ids <finding-id>
   ```

2. **Classify the finding type.** The `Type` field (e.g.
   `UnauthorizedAccess:IAMUser/...`, `Recon:EC2/...`,
   `CryptoCurrency:EC2/...`) tells you what GuardDuty observed. Cross-reference
   the AWS finding-type reference:
   <https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html>.

   Capture these fields before taking action:

   | Finding class | Fields to record |
   |---------------|------------------|
   | All findings | Finding ID, `Type`, `Severity`, `Title`, `CreatedAt`, `UpdatedAt`, `Service.Archived` (especially on watchdog re-alerts), account, region, detector ID, console URL. |
   | IAM credential findings | `Resource.AccessKeyDetails.UserName`, `Resource.AccessKeyDetails.AccessKeyId`, principal ID, `Service.Action.*`, API names, source IP, ASN/ISP, country/city, user agent. |
   | EC2 / network findings | Instance ID, ENI/private IP, public IP, security groups, VPC/subnet, remote IP/domain, remote ASN/ISP/country/city, port/protocol, direction, flow/action metadata. |
   | S3 / RDS / Lambda findings | Resource ARN/name, action/API, caller principal, source IP/user agent, object/key or database/function identifier if present. |

   `get-findings` output uses PascalCase fields; `ListFindings` criteria use
   lowercase dotted paths such as `service.archived`.

3. **Decide true vs. false positive.** Correlate the `Service.Action.*`,
   resource (`Resource.*`), and actor against CloudTrail and the expected
   behavior of that resource. Known-benign sources (a scheduled scanner, a
   developer's expected API call) get suppression-rule treatment, not archive
   (see below).

4. **Contain if true.** Scope containment to the finding type. Common cases:
   - **Compromised IAM credential** (`UnauthorizedAccess:IAMUser/*`,
     `*Credentials*`): disable/rotate the access key, review CloudTrail for the
     credential's recent calls, revoke active sessions. This is the exact class
     of finding behind #1137 (an access key flagged and left un-rotated).
   - **EC2 instance signal** (`Backdoor:EC2/*`, `CryptoCurrency:EC2/*`,
     `Trojan:EC2/*`): isolate the instance's security group, snapshot for
     forensics, then terminate/replace via the ASG rather than mutating in
     place.
   - **Recon/Discovery** (`Recon:*`, `Discovery:*`): usually no host
     compromise; confirm the targeted resource isn't unexpectedly exposed,
     then archive.

5. **Escalate if it's a real incident.** No pager exists — escalate by pinging
   the security owner directly and posting in the security Slack channel with
   the finding link and what you've done so far. For a High finding you can't
   contain quickly, treat it as a P0 and pull in whoever owns the affected
   resource. For Critical severity, do all of the above immediately before
   continuing analysis.

6. **Archive once resolved.** Archiving is what stops the watchdog re-alert.
   Only archive after you've investigated and (if needed) remediated:
   ```bash
   AWS_PROFILE=$PROFILE aws guardduty archive-findings \
     --detector-id <detector-id> --finding-ids <finding-id>
   ```
   For a recurring known-benign pattern, prefer a **suppression rule / filter**
   (GuardDuty console → Findings → Save / Suppress) over repeatedly archiving —
   suppression auto-archives future matches so they never re-alert.

## If the watchdog keeps re-alerting

A finding you believe is handled is still re-alerting → it is not archived.
Re-check `Service.Archived` on the finding (`get-findings` output). The watchdog
uses the GuardDuty `ListFindings` criterion `service.archived` with `Eq` set to
the single-element list `["false"]`, so any nag means the archive didn't take or
a new finding of the same type was generated. Do not silence the watchdog by
lowering its cadence; archive the underlying finding instead.

## IR ticket template

Open an incident ticket for every confirmed incident and for any High/Critical
finding that remains unclear after the first pass. Use one ticket per GuardDuty
finding unless multiple findings clearly describe the same incident.

```text
# GuardDuty IR: <finding type> / <resource or principal>

## Summary
- Finding ID:
- Account / region:
- Severity:
- First observed:
- Last updated:
- Current archived state:
- Current disposition: true positive / false positive / unclear

## GuardDuty details
- Type:
- Title:
- Resource:
- Actor / principal:
- Access key ID, if any:
- Source IP / ASN / country:
- User agent:
- GuardDuty console URL:

## Timeline
- <UTC timestamp> - Alert received in Slack/email/watchdog.
- <UTC timestamp> - Finding pulled with `aws guardduty get-findings`.
- <UTC timestamp> - CloudTrail / resource-owner correlation started.
- <UTC timestamp> - Containment or archive decision.

## Evidence
- GuardDuty fields reviewed:
- CloudTrail query:
- Resource-owner confirmation:
- Related deploy, scanner, or operator activity:

## Decision
- Known-intentional: yes / no / unknown
- If true positive: containment taken and owner notified:
- If false positive: suppression rule needed:
- Archive decision and reason (match steps 3 and 6):

## Follow-ups
- Credential rotation:
- Resource hardening:
- Suppression rule:
- Runbook or alert changes:
```

## Related

- [#1211](https://github.com/layervai/nhp/issues/1211) — structural
  GuardDuty alert-routing, stale-finding watchdog, and runbook closure.
- [#1137](https://github.com/layervai/nhp/issues/1137) — the un-triaged
  access-key finding that motivated the watchdog.
- [#2334](https://github.com/layervai/nhp/issues/2334) — security alert-routing
  hardening (this runbook, the `security@layerv.ai` alias, runbook links in
  alert bodies).
- `terraform/modules/security/` — GuardDuty detector, EventBridge alerting,
  and the stale-finding watchdog Lambda.
