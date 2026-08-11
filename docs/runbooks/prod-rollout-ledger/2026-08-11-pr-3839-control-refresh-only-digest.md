# 2026-08-11 · PR #3839 · Control refresh-only admits the published image digest

- **Owner:** prod rollout coordinator
- **Source:** layervai/nhp#3839, root cause layervai/nhp#3761, blocked apply layervai/nhp#3797

Sandbox Control is wedged: `apply` refuses any drift and `plan-refresh-only`
rejects the refresh because `authority_image_uri` moves whenever an Authority
image is published. #3839 narrows the normalizer to admit exactly that move.
**Prod Control runs the same checker and the same publish-tracking digest**, so
prod will hit this the first time it needs to normalize after an image publish.

- [ ] Rollout: after #3839 merges, dispatch `control-sandbox-update.yml` with
      `operation=plan-refresh-only` to absorb the two drifted resources
      (`aws_ssm_parameter.authority_image_digest`,
      `aws_iam_role_policy.authority_proof_controller_invoke`), then `plan` and
      `apply` to land #3797's ticket-handle grants.
- [ ] Post-rollout: confirm the grants are LIVE rather than trusting the run —
      `aws iam get-role-policy --role-name layerv-nhp-sandbox-ca-ia-exec ...`
      must show `AuthorityTicketHandleWrite`, and both `ca-iro-cell*-exec` must
      show `AuthorityTicketHandleRead`.
- [ ] Post-rollout: re-run layervai/qurl-go#167's gate; it should go green with
      no change on that side, proving the sandbox enrollment path end to end.
- [ ] Prod: expect the same normalizer failure on the next prod Control refresh
      that follows an Authority image publish. #3839 fixes it for both roots, so
      no separate prod change is needed — but do not assume prod Control is
      applied just because it merged (see the attended-dispatch note below).
- [ ] Rollback: revert #3839. That restores the stricter check and re-wedges
      Control, so only do it if the allowance is found to be too broad.

Note for whoever picks this up: the Control root applies ONLY via the attended
`control-sandbox-update.yml` dispatch, never on merge, so a merged Control
change is not a deployed one.
