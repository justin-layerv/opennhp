# 2026-07-06 · PR #3089 · AC Traefik heredoc bootstrap unblock

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/3089

Sandbox blue/green for PR #3088 reached the new standby AC image, but every
standby AC hung in user-data before Traefik and nhp-acd started. This PR fixes
the AC bootstrap command-substitution bug and must be deployed before qURL
browser proof can validate the AZ-fanout fix.

- [ ] Pre-rollout (sandbox): confirm PR CI passed, especially
      `Terraform Validate (PR) (sandbox)` with the AC Traefik heredoc guard and
      the prod-rollout body gate.
- [ ] Rollout (sandbox): merge and let the next `Build and Deploy NHP` run
      complete sandbox blue/green; verify standby AC health reaches
      `127.0.0.1:8080/ping` on all three AZ instances before traffic switch.
- [ ] Post-rollout (sandbox): mint a fresh one-time sandbox qURL, open it from
      a browser outside the VPC, and confirm it reaches the target URL instead
      of stalling on qURL verification.
- [ ] Prod sign-off: do not promote PR #3088/#3089 behavior until sandbox has
      green blue/green, sandbox smoke/validate completion, and linked browser
      proof for a fresh one-time qURL.
- [ ] Rollout (prod): promote the fixed AC bootstrap before relying on any AC
      image carrying the PR #3088 Traefik comments.
- [ ] Rollback: if standby AC bootstrap still hangs, revert this PR and PR
      #3088's AC user-data/image change together or pin AC image tags back to
      the last healthy deployed commit before retrying qURL browser validation.
