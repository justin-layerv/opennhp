# Discord bot prod DNS — now owned IN-ACCOUNT by qurl-integrations, not nhp.
#
# `discord.connector.layerv.ai` (the public A-alias) and its ACM-validation
# CNAME are served from the `connector.layerv.ai` Route53 subzone in the
# qurl-integrations prod account (886375649402), which the layerv-mgmt
# `layerv.ai` parent NS-delegates to (one-time manual delegation, 2026-06-08).
# Post-delegation the child zone is authoritative and the parent's own copies
# of these records are OCCLUDED — recursive resolvers follow the referral to
# the child zone. See qurl-integrations-infra
# `docs/runbooks/connector-dns-delegation.md` (fleet DNS convergence) and PR
# #945, which created the in-account `discord.connector.layerv.ai` A-alias
# (→ the v2 ALB) and the matching `_077a5990…` validation CNAME.
#
# This file therefore DROPS nhp's management of the parent copies. Both
# `removed {}` blocks below use `destroy = false` deliberately: nhp forgets the
# records from its state but LEAVES the occluded records in AWS during the
# post-cutover soak, because —
#   - the occluded parent records remain the rollback fallback: deleting the
#     parent `connector.layerv.ai` NS delegation un-occludes them (→ the legacy
#     discord ALB), exactly as connector-dns-delegation.md (Rollback) documents.
#     A `destroy = true` here would silently break that documented rollback
#     (parent-NS removal → NXDOMAIN, not fallback);
#   - it avoids touching the prevent_destroy'd validation CNAME and keeps ACM
#     renewal doubly-safe (the child zone holds its own validation CNAME, so
#     the cert validates via the delegation regardless of this parent copy).
#
# Deleting the now-orphaned AWS records is deferred to the old discord stack
# teardown, tracked in qurl-integrations-infra
# `docs/runbooks/prod-rollout-ledger/2026-06-07-pr-932-discord-prod-rehome-v2.md`
# (its Post-cutover task) and the connector-dns-delegation.md Cleanup section —
# done only once we are confident no rollback is needed and the legacy ALB is
# torn down in the same change. At that point this ENTIRE FILE (these `removed`
# blocks plus the inert `moved`/`_legacy` chain below) should be deleted — it
# manages no resources and is pure state-bookkeeping for the soak window.

# Pre-existing state-only drop of the pre-migration validation record (inert
# post-apply). Left untouched this round to avoid re-touching legacy state.
moved {
  from = aws_route53_record.discord_bot_cert_validation
  to   = aws_route53_record.discord_bot_cert_validation_legacy
}

removed {
  from = aws_route53_record.discord_bot_cert_validation_legacy

  lifecycle {
    destroy = false
  }
}

# Drop nhp's management of the now-occluded parent ACM-validation CNAME
# (`_077a5990….discord.connector.layerv.ai`). `destroy = false` → state-only:
# the AWS record stays (rollback fallback + renewal safety; see header).
removed {
  from = aws_route53_record.discord_bot_cert_validation_v2

  lifecycle {
    destroy = false
  }
}

# Drop nhp's management of the now-occluded parent A-alias
# (`discord.connector.layerv.ai` → the legacy discord ALB). `destroy = false`
# → state-only: the AWS record stays as the rollback fallback (see header).
removed {
  from = aws_route53_record.discord_bot_alias

  lifecycle {
    destroy = false
  }
}
