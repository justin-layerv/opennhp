# 2026-06-25 · Issue #2800 · Base-image pebble CVEs — rebuild + redeploy prod

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/issues/2800 (and the PR that adds this entry)

The `ubuntu:26.04` base image (pinned by digest in all three Dockerfiles) bakes
in Canonical's `pebble` service manager at `/usr/bin/pebble` — an unused Go
binary built with `golang.org/x/net v0.40.0` + Go stdlib `1.26.2` (7 HIGH CVEs).
trivy flags it and fails `Build {server,ac,relay}` repo-wide. Our own binaries
(`nhp-serverd` / `nhp-acd` / `nhp-relayd`) were always clean (`x/net v0.55.0`,
`go 1.26.4`); the original "stale buildx cache" diagnosis was a misattribution
of the SARIF `x/net v0.40.0` line, which actually pointed at `/usr/bin/pebble`.
This PR removes pebble in each runtime stage, so a rebuild produces clean images.

Prod server/ac/relay images built before this PR merges still contain the
vulnerable `/usr/bin/pebble`. They must be rebuilt and redeployed.

- [ ] Rollout: after merge, the main build rebuilds + pushes patched
      server/ac/relay images. Redeploy prod (instance refresh per the deploy
      runbook) so the running containers no longer contain `/usr/bin/pebble`.
- [ ] Post-rollout: confirm a deployed prod image digest no longer carries
      pebble — `docker run <digest> ls /usr/bin/pebble` returns not-found, or
      `trivy image <digest>` shows the 7 HIGH CVEs gone.
- [ ] Note: the 2026-06-25 buildx gha cache purge done during triage was
      unnecessary for this bug (the caches regenerate; no harm). It is not a
      required rollout step.
