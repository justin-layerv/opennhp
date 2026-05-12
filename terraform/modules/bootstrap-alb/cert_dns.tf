# ACM certificate + DNS-validation CNAMEs.
#
# Default in BOTH envs is `provision_certificate=false` because the
# parent zone (`layerv.xyz` or `layerv.ai`) lives in a different AWS
# account in BOTH cases — so DNS-validation CNAME writes have to land
# out-of-band by an operator with the right account creds. The cert
# itself MUST live in the same account as the ALB (AWS does not allow
# cross-account cert attachment).
#
# Operator runbook for the cross-account first-apply (cert request →
# DNS-validation CNAMEs → wait for ISSUED → land cert ARN in env
# tfvars) lives in `README.md` ("Step 0 — cross-account cert + DNS").
# Don't duplicate it here — the README is the canonical source; this
# file is the resource declarations.
#
# `provision_certificate=true` is supported for any future env where
# the parent zone IS in the same account — the resources below render
# only when that flag flips.

# Resolve the supplied zone ID to its actual zone name so we can
# precondition on `dns_name` belonging to the zone. A typoed zone ID
# (correct shape, wrong zone) would otherwise plan cleanly and ACM
# validation would hang ~75min before giving up; for the alias path,
# an alias written to a zone that doesn't own `dns_name` resolves to
# nothing and the operator chases a DNS-broken report. Both cheaper
# to catch at plan time.
#
# Read both when `provision_certificate=true` (the cert needs the
# subdomain-of-zone check) AND when `manage_dns_alias=true` (the
# alias path needs the same check). When BOTH flags are false the
# zone lookup is skipped entirely (no Route53 read on every plan).
#
# **Path #1 fence-omission**: today's posture in both envs is
# `provision_certificate=false + manage_dns_alias=false` —
# operator-managed cert + alias, both out-of-band in the parent-
# zone account. The dot-boundary subdomain check below DOES NOT
# fence path #1 (data source is `count=0`, the precondition is
# never evaluated). The operator is the gate there: they
# pre-provision the cert against the right zone in Step 0, and
# write the A-alias into the right zone in Step 2. A typoed zone
# on path #1 surfaces at the operator's `aws route53 change-
# resource-record-sets` call, not at terraform plan. Deliberate;
# the operator-out-of-band gating is the trust boundary.
#
# **Plan-role permission requirement.** Once an env flips either flag
# to `true`, the terraform principal needs `route53:GetHostedZone` on
# the parent zone — typically cross-account (the parent zone lives
# in a different AWS account in both sandbox and prod, see README's
# Account topology table). Laptop plans from operators without that
# cross-account grant will fail at refresh, not at the precondition.
# Same shape as the `nhp_internal_auth` plan-role callout in
# CLAUDE.md.
#
# The precondition lives on the data source itself (not just on the
# downstream cert / alias resources) so an empty `route53_zone_id`
# fails with the helpful error message BEFORE the data source
# attempts the AWS API call with `zone_id=""` — which would otherwise
# surface as a generic `InvalidParameter` from AWS at refresh.
data "aws_route53_zone" "selected" {
  count = (var.provision_certificate || var.manage_dns_alias) ? 1 : 0

  zone_id = var.route53_zone_id

  lifecycle {
    precondition {
      condition     = var.route53_zone_id != ""
      error_message = "provision_certificate=true or manage_dns_alias=true requires a non-empty route53_zone_id. At nhp's root tfvars: set `bootstrap_alb_route53_zone_id = \"<Z...>\"` (the parent zone for `bootstrap_alb_dns_name`)."
    }
  }
}

resource "aws_acm_certificate" "this" {
  count = var.provision_certificate ? 1 : 0

  domain_name       = var.dns_name
  validation_method = "DNS"

  # ACM cert renewal/expansion (e.g. adding SANs) destroys the in-place
  # cert before the new one validates, breaking the HTTPS listener.
  # `create_before_destroy` plus the listener's
  # `certificate_arn = local.effective_certificate_arn` (a string, not
  # a hard ref) lets the new cert come up validated, the listener
  # repoint, and only then the old cert tear down.
  lifecycle {
    create_before_destroy = true

    # Anchored on the cert (single resource) rather than on the for_each'd
    # validation records, so a missing zone ID surfaces as ONE plan-time
    # error, not N.
    precondition {
      condition     = var.route53_zone_id != ""
      error_message = "provision_certificate=true requires a non-empty route53_zone_id (ACM needs a hosted zone for DNS validation). At nhp's root tfvars: set `bootstrap_alb_route53_zone_id = \"<Z...>\"`."
    }

    # Catch the typo'd-zone-ID class: correct shape, wrong zone. ACM
    # would hang validation ~75min before giving up; this fails plan.
    #
    # Dot-boundary required: bare `endswith(dns_name, zone)` would
    # false-pass on inputs like `dns_name="bootstraplayerv.ai"`,
    # `zone="layerv.ai"` (literal suffix match without label
    # boundary). Either an exact match (`dns_name == zone`, apex) or
    # a proper subdomain (`dns_name` ends with `.<zone>`) is valid.
    precondition {
      condition     = var.dns_name == trimsuffix(data.aws_route53_zone.selected[0].name, ".") || endswith(var.dns_name, ".${trimsuffix(data.aws_route53_zone.selected[0].name, ".")}")
      error_message = "var.dns_name must be the apex of, or a subdomain of, the zone resolved from var.route53_zone_id. Got dns_name=`${var.dns_name}` but zone=`${trimsuffix(data.aws_route53_zone.selected[0].name, ".")}`."
    }
  }

  # Cert tags use the bare `local.tags` map (Project + Environment),
  # NOT `merge(local.tags, { Name = ... })`. Adding a `Name` key
  # wouldn't break tag-scoping in the common case (`StringEquals` on
  # individual keys like `aws:RequestTag/Project` ignores other keys),
  # but the stricter `ForAllValues:StringEquals` shape — which
  # constrains `aws:TagKeys` to a subset of an allowlist — would
  # reject a `Name` addition silently and 403 the
  # `acm:RequestCertificate`. nhp's CI role isn't tag-scoped on
  # ACMRequest today, so this is cosmetic / future-proofing rather
  # than load-bearing.
  tags = local.tags
}

# Lay down the DNS-validation CNAMEs in the same hosted zone the alias
# record uses. `domain_validation_options` is keyed on the validation
# record name (NOT the domain name) because `*.example.com` and
# `example.com` both produce a `_validation.example.com` CNAME — keying
# on `dvo.domain_name` would key-collide. SAN-safe by construction.
#
# The for_each ranges over `aws_acm_certificate.this[*]` (a splat over
# the count-gated cert) rather than guarding `[0]` behind
# `var.provision_certificate`. Conditional-expression branch lazy-eval
# is documented Terraform behavior, but a `[0]` index against a
# count-0 tuple has surfaced as `Invalid index` at plan time in
# practice (provider/core interaction bugs over the years). The splat
# form makes the for_each natively collapse to `{}` when the cert
# resource is count-0 — same end state, no conditional, no [0].
resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in flatten([for c in aws_acm_certificate.this : c.domain_validation_options]) :
    dvo.resource_record_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  zone_id = var.route53_zone_id
  name    = each.value.name
  type    = each.value.type
  # 300s minimum is the AWS-recommended TTL for ACM validation
  # CNAMEs. Lower TTLs add Route53 query cost in steady state
  # without measurable validation benefit — the validation poll
  # is on the order of minutes, not seconds.
  ttl     = 300
  records = [each.value.record]

  # `allow_overwrite = true`: these `_validation.<domain>` CNAMEs are
  # Terraform-written but ACM-read; the values are derived from ACM's
  # `domain_validation_options` so a cert renewal that rotates the
  # validation token would normally fail on "record already exists"
  # without this flag. ACM-managed records can also outlive the cert
  # (cert rotation period > Route53 record TTL), making overwrite the
  # safe default for this specific record-name pattern.
  #
  # **Cross-zone scope caveat**: this resource uses the module's
  # default AWS provider, which writes to the apply target's
  # account. Path #2 (`provision_certificate=true` + this resource
  # active) is supported ONLY when the parent zone lives in the
  # SAME account as the apply target. A future env where the
  # parent zone lives in a DIFFERENT account from the apply target
  # CANNOT use path #2 as-is — this module does not declare an
  # aliased cross-account provider for Route 53 writes. Three
  # workarounds for that future env, in order of preference:
  #   1. Stay on path #1 (`provision_certificate=false`); the
  #      operator pre-provisions the cert + validation CNAMEs
  #      out-of-band, same as today's posture in both envs.
  #   2. Move the cert into the parent-zone account and use
  #      `existing_certificate_arn` — but ALBs can't attach
  #      cross-account ACM certs, so this requires also moving
  #      the apply target.
  #   3. Add an aliased `provider "aws"` block to this module
  #      (a real module change) so the validation records can
  #      write to the cross-account zone via role assumption.
  # Today's `provision_certificate=false` path makes all of this
  # dormant; this resource is count-0 in both envs.
  #
  # **IAM caveat (same-account path #2 only)**: even when the
  # zone is same-account, the apply-target role needs
  # `route53:ChangeResourceRecordSets` permitting `UPSERT`/`DELETE`
  # on the validation record names. A tighter zone policy that
  # disallows overwrites would let initial validation succeed and
  # then silently fail on cert rotation.
  #
  # **SAN-collision caveat**: `allow_overwrite = true` also means
  # that if two callers ever apply against overlapping SANs into
  # the same zone (e.g., a future env shares the cert with this
  # one, or this cert expands to cover multiple bootstrap
  # hostnames), the second apply silently clobbers the first's
  # validation token. Today's posture (one cert per env, single
  # SAN) makes this hypothetical — flagging in case the cert
  # expansion happens.
  allow_overwrite = true

  # `create_before_destroy` matches the cert + cert_validation
  # resources above. On a SAN-expansion (e.g., adding a wildcard
  # subdomain), `domain_validation_options` changes and the for_each
  # diff would otherwise destroy-then-recreate the affected records.
  # That brief gap can race ACM's validation poll on the new SAN.
  # CBD here keeps validation continuous across renewal/expansion.
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_acm_certificate_validation" "this" {
  count = var.provision_certificate ? 1 : 0

  # `[0]` direct-index here is safe because both this resource and
  # `aws_acm_certificate.this` use the SAME `count = var.provision_certificate ? 1 : 0`
  # gate — when this resource is evaluated (count=1), the cert
  # resource is also count=1 and `[0]` resolves. The splat-with-`one`
  # philosophy in `main.tf::local.effective_certificate_arn` is for a
  # different shape (ternary across both branches of the gate);
  # within a same-gate cross-resource ref the `[0]` is canonical.
  certificate_arn         = aws_acm_certificate.this[0].arn
  validation_record_fqdns = [for r in aws_route53_record.cert_validation : r.fqdn]

  # No `create_before_destroy`. This resource is a waiter — it has
  # no AWS-side state of its own beyond "the cert is validated".
  # CBD here was a no-op at best and could produce noisy
  # `(known after apply)` diff cycles when ACM's
  # `domain_validation_options` shifted during a SAN expansion.
  # Seamless rotation is already covered by CBD on
  # `aws_acm_certificate.this` + the listener's string-typed
  # `certificate_arn` ref (via `local.effective_certificate_arn`),
  # so the waiter itself doesn't need CBD.
}

# Public DNS pointer to the ALB. Alias records (vs CNAME) work at the
# zone apex and don't double-charge for resolution. Count-gated so a
# cross-account caller (where the parent zone lives outside this state)
# can publish their own alias against the module's exported
# `alb_dns_name` + `alb_zone_id`.
resource "aws_route53_record" "alb_alias" {
  count = var.manage_dns_alias ? 1 : 0

  zone_id = var.route53_zone_id
  name    = var.dns_name
  type    = "A"

  # No `ttl` argument on `aws_route53_record` for alias records:
  # alias records inherit the target's TTL (the ALB's default
  # Route53-managed TTL, typically 60s). Setting `ttl` here would
  # fail apply with `cannot specify both alias and ttl`.

  alias {
    name    = aws_lb.this.dns_name
    zone_id = aws_lb.this.zone_id
    # `evaluate_target_health = false` is deliberate.
    #
    # When true, Route 53 evaluates the ALB's TG-health (collapses to
    # NXDOMAIN/SERVFAIL when no TG target is healthy). This is the
    # wrong shape for the dark-launch window: between this stack's
    # first apply and the paired follow-up that registers qurl-service
    # ECS, the TG has zero healthy targets, and `true` would mean
    # `https://bootstrap.layerv.{xyz,ai}` returns NXDOMAIN — not the
    # 503 the README's verification step expects, and a confusing
    # signal during the paired PR's rollout (an operator can't tell
    # NXDOMAIN-because-dark-launch from NXDOMAIN-because-DNS-broken).
    #
    # The contract this alias publishes is "the ALB is up" (the
    # platform's first-contact surface exists). Target health is
    # surfaced via the ALB itself (503 when TG empty / unhealthy) and
    # via `alb_unhealthy_hosts` CloudWatch alarm. If a future caller
    # wants DNS-level failover that bypasses an unhealthy ALB, this
    # variable should grow to be configurable rather than the default
    # flipping — that's the consumer choice, not the producer default.
    #
    # **Runbook coupling**: the README's Step 3 verification curl
    # (`https://bootstrap.layerv.{xyz,ai}/v1/agent/bootstrap` →
    # expect 503 during dark-launch) DEPENDS on this setting being
    # false. A future flip to `true` silently invalidates that
    # runbook step — update the runbook in the same PR if this ever
    # becomes configurable.
    evaluate_target_health = false
  }

  lifecycle {
    # No `create_before_destroy`. Two reasons:
    #   1. Route53 records are name-keyed; two `aws_route53_record`
    #      resources with the same `name + type + set_identifier`
    #      cannot coexist transiently, so CBD on this resource
    #      would fail with a `RRSet already exists` error rather
    #      than provide a clean cutover.
    #   2. The realistic attribute changes that could trigger
    #      replacement (e.g., flipping `alias.evaluate_target_health`
    #      after the data plane attaches) are IN-PLACE updates in
    #      Terraform's plan, not forced replacements — so the
    #      "brief NXDOMAIN window" concern doesn't apply.
    # A `name` or `type` change WOULD force replacement, but that's
    # a configuration-level break (the surface URL itself changes)
    # and warrants explicit operator handling, not CBD masking.

    precondition {
      condition     = var.route53_zone_id != ""
      error_message = "manage_dns_alias=true requires a non-empty route53_zone_id. At nhp's root tfvars: set `bootstrap_alb_route53_zone_id = \"<Z...>\"`."
    }

    # Same dot-boundary subdomain check the cert resource carries —
    # otherwise an operator with `manage_dns_alias=true,
    # provision_certificate=false` and a typo'd zone ID writes an
    # alias into a zone that doesn't own `dns_name`, and the
    # bootstrap surface silently doesn't resolve. Apex match
    # (`dns_name == zone_name`) and proper-subdomain match
    # (`endswith(dns_name, ".${zone_name}")`) both accepted.
    precondition {
      condition     = var.dns_name == trimsuffix(data.aws_route53_zone.selected[0].name, ".") || endswith(var.dns_name, ".${trimsuffix(data.aws_route53_zone.selected[0].name, ".")}")
      error_message = "manage_dns_alias=true requires var.dns_name to be the apex of, or a subdomain of, the zone resolved from var.route53_zone_id. Got dns_name=`${var.dns_name}` but zone=`${trimsuffix(data.aws_route53_zone.selected[0].name, ".")}`."
    }
  }
}
