# 2026-07-05 · PR #3055 · AC qurl.site Proxy Protocol removal

- **Owner:** prod rollout coordinator
- **Source:** https://github.com/layervai/nhp/pull/3055, https://github.com/layervai/nhp/issues/3052

Remove Proxy Protocol v2 from the public AC `:443` target groups while keeping
NLB client-IP preservation. The target-group change applies in place; the
Traefik user-data cleanup takes effect on the next AC refresh.

- [ ] Pre-rollout: in sandbox, confirm both AC TCP target groups report `proxy_protocol_v2.enabled=false` and `preserve_client_ip.enabled=true`, and confirm no new public listener or port was added.
- [ ] Pre-rollout: before prod apply, repeat the existing-fleet health-check
  safety probe from a VPC source to a running AC `:8080/ping` without a Proxy
  Protocol header and record `200 OK` evidence on the PR.
- [ ] Pre-rollout: before prod apply, repeat the existing-fleet qurl.site data-path
  safety probe from a VPC source to a running AC `:443` with a qurl.site Host
  header and no Proxy Protocol header; any HTTP response from Traefik/qurl-router
  is sufficient to prove TLS reached the old entrypoint config.
- [ ] Rollout: apply the Terraform change to prod and verify both prod AC TCP target groups report `proxy_protocol_v2.enabled=false` and `preserve_client_ip.enabled=true`.
- [ ] Post-rollout: exercise a fresh qURL through qurl.link into qurl.site and confirm the browser reaches the target plus qurl-api records the expected qurl-router authorize call.
- [ ] Rollback: revert this PR and re-apply Terraform as one unit so `proxy_protocol_v2=true` and the Traefik Proxy Protocol entrypoints return together; expect the #3052 pre-HTTP qurl.site stall risk to return until a replacement fix lands.

Pre-merge sandbox evidence: SSM on a running sandbox AC reached its VPC `:8080/ping` with no Proxy Protocol header and got `200 OK`. The same AC reached qurl.site TLS/HTTP on its VPC `:443` with a qurl.site Host header and no Proxy Protocol header, returning HTTP `404 Resource not found`; that proves existing old-config entrypoints accept header-less trusted-VPC traffic through Traefik/qurl-router during the in-place target-group flip window.

Untrusted browser-source `:443` safety before sandbox apply is reasoned, not directly measured: with the browser public IP as the TCP peer, Traefik's old Proxy Protocol trusted-IP policy does not trust the peer, so a header-less TLS stream should proceed to the same qurl.site entrypoint. Sandbox apply plus a fresh qURL click remains the required end-to-end confirmation before prod promotion.
