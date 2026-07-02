# 2026-06-25 · Issue #2800 · Base-image pebble CVEs — prod server/AC redeploy

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/issues/2800,
  https://github.com/layervai/nhp/issues/3002, and the code-side fixes
  (#2802, #2914, #2944)

Code-side #2800 fixes are merged; #3002 owns the remaining patched-image prod
server/AC redeploy, current prod-state checks, and post-rollout evidence.

Prod relay remains dark (`deploy_relay = false`); do not auto-promote prod from
this issue-cleanup PR.

- [ ] Rollout: choose and execute a safe prod server/AC image redeploy strategy
      in #3002.
- [ ] Post-rollout: confirm a deployed prod server/AC image digest no longer
      carries pebble — `docker run <digest> ls /usr/bin/pebble` returns
      not-found, or `trivy image <digest>` shows the HIGH CVEs gone.
- [ ] Closeout: record the verification evidence on #2800 or #3002, delete this
      ledger entry, then close #2800.
