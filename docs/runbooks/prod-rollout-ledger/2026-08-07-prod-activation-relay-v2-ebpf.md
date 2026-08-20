# 2026-08-07 · Prod activation — relay, qURL v2, js-agent, eBPF

- **Owner:** prod rollout coordinator
- **Source:** this PR

Turns on the customer-facing surfaces for the release: the NHP relay, qURL v2
keyed identity, the qurl.link browser js-agent, and the AC eBPF/XDP datapath.

**This is a two-apply rollout.** `promote-to-prod` runs `terraform-apply` before
`deploy-server`, so anything Terraform publishes for browsers goes live before
the fleet that serves it. Apply 1 therefore ships everything that does not
depend on a rolled fleet; apply 2 is the customer-visible cutover.

| | apply 1 | apply 2 |
| --- | --- | --- |
| `deploy_relay` | true | — |
| `ac_filter_mode` | 1 (template only) | — |
| `qurl_v2_issuer_key_enabled` / `resource_keys` | true | — |
| `qurl_v2_admission_enabled` | true | — |
| `qurl_v2_issuance_enabled` | **false** | true |
| `qurl_link_js_agent_enabled` | **false** | true |

Issuance and the js-agent flip together because both `qurl_browser_relay_base_url`
and the portal's `server_public_key_b64` are gated on `qurl_link_js_agent_enabled`
— minting qv2 links while the portal is qv1-only produces links nothing can
open. Admission stays on in apply 1 because the plan enforces only
issuance -> admission, so the fleet can be ready to admit before the first link
exists.

- [ ] Pre-rollout (**relay DNS is cross-account and new**): the relay's cert
      validation records and A-alias are written into the layerv.ai zone in
      layerv-mgmt by `aws.route53_mgmt`. Confirm the prod apply role can assume
      `cross_account_route53_role_arn`
      (`arn:aws:iam::165115313779:role/nhp-ac-route53-access`) before the apply;
      the relay root has never exercised that path in any environment.
- [ ] Pre-rollout: confirm `relay.layerv.ai` does not already exist in the
      layerv.ai zone. The alias is `allow_overwrite`-free, so a pre-existing
      record fails the apply rather than silently taking it over.
- [ ] Rollout (**live VPC surgery — read before approving the plan**):
      `deploy_relay = true` also flips
      `enable_extensible_private_route_tables`, which calls
      `ReplaceRouteTableAssociation` on the live prod private subnets, creates a
      peered DMZ VPC on `10.201.0.0/16`, and stands up a Route53 Resolver
      firewall. The IAM for it is `count`-gated on the same variable, so the
      apply grants itself the permission and waits on
      `time_sleep.relay_dmz_iam_propagation`. That ordering is designed for a
      single apply but has never run outside sandbox — review the rendered plan
      for the association replacements specifically.
- [ ] Rollout: the four qURL v2 gates flip together and the plan enforces it
      (`terraform_data.qurl_v2_flag_invariants`). Confirm the prod issuer kid
      `qurl-issuer-prod-2026-08` is the kid the NHP-server trust store renders,
      and that `qurl_v2_relay_url` / `qurl_v2_relay_allowlist` / `relay_dns_name`
      / `agent_registration_relay_base_url` all read `relay.layerv.ai`. A
      mismatch mints links whose relay the issuer's own allowlist rejects.
- [ ] Rollout (**eBPF is NOT live at apply**): `ac_filter_mode = 1` only updates
      the AC launch template. Roll the AC ASG afterwards or the datapath stays
      on iptables while the config claims otherwise. Invoke the Tier 1 smoke
      with `allow_ssm_probes=true` — the AC eBPF object gate skips by policy
      without it and proves nothing.
- [ ] **Apply 2 (after the fleet and AC rolls are healthy):** flip
      `qurl_v2_issuance_enabled` and `qurl_link_js_agent_enabled` to true
      together and apply. This publishes the protocol-1.1 browser bundle and its
      SRI, and starts minting qv2 links. Do not run it before the server fleet
      reports 1.1 and the relay target group is healthy — that ordering is the
      whole reason for the split.
- [ ] Post-rollout: mint a qURL and confirm the link is
      `https://qurl.link/#qv2t1.<counts>.<chunks...>`, that the portal unwraps to
      the canonical `qv2.<claims>.<secret>.<sig>` artifact and verifies
      the issuer signature locally, knocks through `relay.layerv.ai`, and the
      `*.qurl.site` resource loads protected content rather than the invalid-access
      page.
- [ ] Post-rollout: confirm the relay ALB target group is healthy over HTTPS on
      `/health/live` and that no relay `BootstrapFailure` alarm fired during the
      ELB-health replacement churn.
- [ ] **Follow-up apply — qurl-scanner (cannot be done here).** Prod has never
      had its first scanner apply, so
      `/layerv-nhp-prod/qurl-scanner-lambda-image-tag` does not exist. Terraform
      creates it seeded `"latest"` with `ignore_changes = [value]` and reads its
      CURRENT value through a plan-time data source, so enabling the gate in the
      same apply that creates it fails plan on `ParameterNotFound` — and
      `"latest"` is not a tag in the prod repository anyway. After this release:
      (1) this apply creates the parameter with the gate off, (2) write the
      replicated SHA — `c13be39` is already in the prod
      `layerv/qurl-scanner-lambda` repository, pushed 2026-08-05, (3) a
      follow-up apply flips `qurl_scanner_lambda_enabled`, then
      `qurl_scanner_sqs_emit_enabled`, then
      `qurl_scanner_tombstone_write_enabled`, each after its own burn-in.
- [ ] Rollback: `deploy_relay = false` tears the DMZ back down but does NOT
      restore the prior private route-table associations — those are replaced
      forward. `ac_filter_mode = 0` plus an ASG roll is symmetric. The v2 gates
      revert cleanly only if no qv2 link has been minted yet; once minted, links
      signed under `qurl-issuer-prod-2026-08` stop admitting when the kid leaves
      the trust store, so treat v2 rollback as re-mint, not revert.
