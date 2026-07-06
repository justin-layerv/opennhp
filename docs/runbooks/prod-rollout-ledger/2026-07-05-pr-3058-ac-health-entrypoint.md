# 2026-07-05 · PR #3058 · AC readiness off Traefik internal entrypoint

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/3058

Binds the AC NLB readiness route (`/nhp-ac/ready`) to a dedicated Traefik
`nhp-health` entrypoint on the same health-check port (`:8080`) and sets
`api.insecure = false`, so the file-provider `nhp-ac-ready` router serves the
readiness path instead of Traefik's reserved `traefik` API/dashboard entrypoint
returning its own 404. Depends on PR #3050 (the `/nhp-ac/ready` target-group
cutover): without this fix, post-#3050 AC instances 404 the NLB probe and every
public `ac_tcp`/`ac_tcp_green` target goes unhealthy. Traefik config lives in AC
user data, so it takes effect on the next AC refresh; no target-group change.

- [ ] Pre-rollout (sandbox, REQUIRED): refresh/canary the AC instances (or the
      blue/green standby color before switch) until each candidate public target
      renders `[entryPoints.nhp-health]` and serves `GET /nhp-ac/ready` = `200`
      `ready` on `:8080` through Traefik. Keep at least one readiness-healthy
      public target throughout the refresh — AC ASGs use EC2 health checks, so
      instance refresh will not wait on `/nhp-ac/ready`.
- [ ] Post-rollout (sandbox): confirm `ac_tcp`/`ac_tcp_green` targets are healthy
      on `/nhp-ac/ready`, and SSM-probe an active AC — `:8080/nhp-ac/ready`
      returns `200 ready` through Traefik and `:8888/nhp-ac/ready` still returns
      `200 ready` from `nhp-acd`. Confirm public `:443` still returns the hidden
      constant 404 for the same path.
- [ ] Post-rollout (sandbox): smoke a fresh one-time qURL link in a browser and
      confirm the click reaches the target instead of timing out.
- [ ] Rollout (prod): stage AC user data/refresh first, confirm the nhp-health
      readiness route is green on the standby color, then switch. Do not promote
      to prod until the sandbox target-health and qURL browser-smoke evidence
      above is recorded here.
- [ ] Rollback: reverting this PR alone restores `insecure = true` and the
      `traefik` entrypoint, which re-404s `/nhp-ac/ready` and removes public AC
      targets. To keep ACs in rotation during rollback, pair it with the #3050
      `/nhp-ac/ready` → `/ping` target-group path revert so health checks fall
      back to Traefik `/ping` liveness; then refresh ACs. Pair with a qv2 smoke
      and deny-log check.

Pre-merge sandbox evidence: the active green AC fleet already renders
`insecure = false`, `[ping] entryPoint = "nhp-health"`, `[entryPoints.nhp-health]`
on `:8080`, and the `nhp-ac-ready` router on `nhp-health`; an SSM probe returned
`GET :8080/nhp-ac/ready = 200 ready` and `ac_tcp_green` reported 3/3 healthy
targets. `main` still renders the `insecure = true` / `entryPoints = ["traefik"]`
config, so a clean deploy from `main` reproduces the 404 until this PR lands.
