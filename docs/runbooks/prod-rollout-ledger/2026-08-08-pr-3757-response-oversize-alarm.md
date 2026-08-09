# 2026-08-08 · PR #3757 · Alarm the Hub's undeliverable-reply metric

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/3757

PR #3757 adds `HubWorkerOutcome` value `response_oversize`, emitted when the Hub
seals an assignment reply larger than one unfragmented UDP datagram. Such a
reply is written successfully — the kernel fragments it — so `write_failed`
stays zero and `response_sent` still increments, while any path that drops IP
fragments (every NLB) discards it. The metric is the only local evidence that a
reply cannot arrive, and it is inert until something alarms on it.

- [ ] Post-rollout: add a CloudWatch alarm on `LayerV/NHP` `HubWorkerOutcome`
      with `Outcome=response_oversize`, `Environment=prod`, treating any nonzero
      sum over 5 minutes as breaching. Sustained nonzero means agents are being
      sent replies they cannot receive.
- [ ] Post-rollout: when writing the alert, note the metric counts replies the
      Hub SEALED oversize, not replies it sent. It is not a subset of
      `response_sent` (it fires even when the reply is then dropped by a full
      queue, an expired budget, or a failed write), and an oversize reply that
      IS written increments both -- so a "delivered = response_sent" dashboard
      over-counts by exactly this metric.
- [ ] Post-rollout: check the same metric in sandbox once deployed. It is
      expected to be NONZERO there until layervai/qurl-service#1367 deploys its
      issuer, which moves the signed ticket off the wire behind a handle and
      drops the reply to roughly 817 bytes. That is the defect the metric exists
      to expose, not an alarm misfire. If it stays nonzero after that issuer
      deploy, the reply is still oversize and the two rollouts have diverged.
