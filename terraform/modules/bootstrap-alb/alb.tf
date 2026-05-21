# Bootstrap ALB. Internet-facing, TLS-terminating, narrow surface:
# only `/v1/agent/bootstrap` is forwarded; everything else returns
# fixed-response 404 at the listener. Distinct from `api.layerv.ai`
# (the broad qurl-service customer-admin surface).

resource "aws_lb" "this" {
  name               = local.alb_name
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids

  # `ipv4` (provider default) — IPv6 dualstack tracked at #1901.
  # Customer sidecars in IPv6-only networks (k8s with
  # `ipFamilies: [IPv6]`, AWS dualstack-without-public-IPv4, HE
  # tunnels) currently fail at TCP-level with no signal.
  # Flipping to `dualstack` requires the networking module to
  # assign IPv6 CIDR blocks to public subnets first — without
  # that, `dualstack` hard-fails at apply with
  # `InvalidSubnet: The following subnets do not have associated
  # IPv6 CIDR blocks`. #1901 ships both modules' IPv6 wiring + the
  # smoke-test probe in lockstep.
  ip_address_type = "ipv4"

  # Bootstrap calls are short-lived JSON POSTs (sidecar registers a
  # public key, gets a server-peer info blob back). 30s idle is plenty.
  idle_timeout = 30

  drop_invalid_header_fields = true

  # `defensive` is the provider default, but pinning explicitly
  # matches the same fail-loud philosophy as
  # `drop_invalid_header_fields = true` and
  # `xff_header_processing_mode = "append"`. Three modes exist:
  #   - `monitor` — log desync requests, do not block (audit-only)
  #   - `defensive` (chosen) — keep ambiguous requests routable but
  #     close the egregious smuggling patterns (CL.TE / TE.CL)
  #   - `strictest` — reject any RFC 7230 ambiguity outright (more
  #     false-positives on edge cases)
  # `defensive` covers the realistic HTTP smuggling threat without
  # rejecting tolerably-noncompliant legitimate clients (legacy curl
  # versions, some k8s-side proxies).
  desync_mitigation_mode = "defensive"

  # Explicit `append` so a provider-default flip can't silently change
  # the bootstrap audit log's recorded client IP (load-bearing for the
  # geo-anomaly + bootstrap-rate detection in qurl-service's audit
  # writer).
  #
  # **WARN: rightmost-XFF contract is unfenced until #1894 lands.**
  # Until the paired smoke test exists, a regression in either this
  # mode flag OR the qurl-service audit writer's parsing logic would
  # silently produce spoofable audit rows. Don't touch this line
  # until #1894 is in place — or if you must, manually re-run the
  # forged-leftmost-XFF curl in README Step 3 #6 to verify.
  #
  # **Downstream contract**: with `append`, the ALB appends the
  # observed client IP to the END of `X-Forwarded-For`. The RIGHTMOST
  # entry is the AWS-injected real client IP; entries to its left are
  # attacker-controllable (the caller can send any `X-Forwarded-For`
  # header it wants — ALB appends to it rather than replacing). The
  # qurl-service audit writer MUST take the rightmost XFF entry; a
  # naive leftmost parser produces a trivially spoofable audit log
  # and defeats the geo-anomaly + bootstrap-rate detection this mode
  # exists to enable. The paired qurl-service rollout's smoke test
  # forges a leftmost XFF and asserts the audit row records the
  # AWS-injected rightmost entry — a future refactor of
  # `xff_header_processing_mode` here must keep that test green.
  #
  # **Interaction with `drop_invalid_header_fields = true` above**:
  # belt-and-suspenders. An attacker-supplied `X-Forwarded-For`
  # containing control characters / non-7-bit content / RFC 7230
  # violations is dropped at the ALB ingress BEFORE the `append`
  # logic runs — so the rightmost-IP audit contract holds even
  # against adversaries who would otherwise inject smuggled XFF
  # values to confuse the audit writer. The two settings are
  # independently load-bearing; both flipped to `false` would
  # produce a trivially spoofable audit log.
  xff_header_processing_mode = "append"

  # Production ALB gets deletion protection; an operator must explicitly
  # disable the flag before destroy can succeed. Sandbox stays
  # destructible so the env can be rebuilt cheaply during iteration.
  # `prod` (not `production`) — nhp's canonical environment value; see
  # `variable.environment` validation in variables.tf.
  enable_deletion_protection = var.environment == "prod"

  # Per-request access logs power post-incident forensics on the
  # bootstrap surface; can't be backfilled. The bucket policy `Resource`
  # ARN scope (`<bucket>/AWSLogs/${account_id}/*` at
  # `access_logs.tf::data.aws_iam_policy_document.alb_access_logs`)
  # matches the default empty-`prefix` log-key shape — setting
  # `prefix` here without widening the policy `Resource` in lockstep
  # would silently break log delivery with `AccessDenied` from the
  # ELB log-delivery service.
  access_logs {
    bucket  = aws_s3_bucket.alb_access_logs.bucket
    enabled = true
  }

  tags = merge(local.tags, { Name = local.alb_name })

  # Bucket policy must exist before ALB tries its first log write;
  # otherwise the parallel-apply scheduler can race ALB's
  # ModifyLoadBalancerAttributes against bucket-policy creation
  # (manifests as `Access Denied for bucket`).
  depends_on = [aws_s3_bucket_policy.alb_access_logs]

  # No `create_before_destroy`: same constraint as the target group
  # below — AWS caps ALB names at 32 chars AND a deterministic
  # `bootstrap-alb-<env>` name + CBD would fail any future replacement
  # on `DuplicateLoadBalancerName`. Destructive teardown (apply with
  # `enable_deletion_protection=false` first in prod) is the only
  # replacement path.
}

# Target group for qurl-service. Empty on first apply (no targets
# attached) — the data-plane wiring (qurl-service ECS service ↔ this
# target group attachment) lands in a paired follow-up PR. Until then,
# the TG health checks all fail and the listener returns 503 on
# `/v1/agent/bootstrap` (rather than 404) — that's the expected dark-
# launch state during the bootstrap window between this PR's apply and
# the follow-up rollout.
resource "aws_lb_target_group" "qurl_service" {
  name        = local.target_group_name
  port        = var.target_port
  protocol    = "HTTP"
  target_type = "ip" # Fargate ENI; instance-id targets are EC2-only
  vpc_id      = var.vpc_id

  # 30s matches the ALB idle_timeout above. Asymmetry would let an
  # in-flight request get torn down by ALB idle while the target is
  # still draining toward the bootstrap response.
  deregistration_delay = 30

  # Settings deliberately left at provider defaults (visibility note,
  # since the rest of the resource is heavily commented):
  #   - `connection_termination = false` — for `ip` target types this
  #     is the default. Long-lived HTTP/2 connections to a deregistering
  #     target are allowed to drain naturally on bootstrap POSTs
  #     (short-lived JSON requests, the drain finishes within seconds).
  #
  # Client-IP visibility note: ALB target groups do NOT have a
  # `preserve_client_ip` attribute (that's NLB-only). Client IP
  # reaches qurl-service via XFF; see `aws_lb.this.xff_header_processing_mode`
  # for the rightmost-entry audit contract.

  health_check {
    enabled             = true
    path                = var.health_check_path
    protocol            = "HTTP"
    port                = "traffic-port"
    matcher             = "200-299"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }

  tags = merge(local.tags, { Name = local.target_group_name })

  # No `create_before_destroy`: AWS caps target-group names at 32 chars
  # AND `name_prefix` at 6 chars, so CBD + a deterministic name like
  # `bootstrap-alb-prod-tg` would fail any future replacement on
  # `DuplicateTargetGroupName`.
}

# HTTPS listener — TLS terminates here. Modern TLS-1.3 policy; AWS
# renames these periodically, so the SSL policy name should be the
# version-stamped form rather than an alias.
#
# **Policy intent.** `ELBSecurityPolicy-TLS13-1-2-2021-06`:
#   - TLS 1.3 supported (preferred)
#   - TLS 1.2 minimum (older clients still negotiate)
#   - TLS 1.0 / 1.1 / SSLv3 all rejected (downgrade attacks blocked)
# When AWS publishes a newer policy (e.g. dropping TLS 1.2 floor or
# adding a future cipher suite mandate), bump this version-stamped
# string in lockstep with the README's "Step 3 verification" curl —
# the cert-chain check would otherwise pass against an outdated
# policy without surfacing the gap.
#
# Default action: fixed-response 404. NO default forward to a target
# group — only the explicit listener rule for `/v1/agent/bootstrap`
# (declared below) reaches the qurl-service TG. This is the load-
# bearing narrowness invariant; the WAF + access-log triage simplicity
# rests on it. Adding any other forward action here breaks the
# "narrow surface" contract that justifies the stack's existence as
# distinct from `api.layerv.ai`.
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = local.effective_certificate_arn

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "application/json"
      # JSON body with `error: not_found` matches the canonical error
      # shape that qurl-service emits via its OpenAPI-typed handlers
      # (`internal/api/handlers/error.go`). A sidecar (or scanner)
      # hitting any non-bootstrap path on this ALB sees a consistent
      # error envelope rather than the default ALB plain-text page —
      # one less footprint surface AND one less footprint difference
      # to fingerprint.
      #
      # Body intentionally omits a docs URL until `docs.layerv.ai/agent` exists.
      # Built via `jsonencode(...)` rather than hand-concat string
      # interpolation so the envelope stays valid JSON even if
      # `var.bootstrap_path`'s validation regex ever relaxes to
      # accept characters that would need JSON-escaping (`"`, `\`,
      # control chars). Today's validation forbids those, but the
      # invariant should live in this file rather than across two
      # files coupled only by an unwritten convention.
      message_body = jsonencode({
        error   = "not_found"
        message = "This endpoint serves only POST ${var.bootstrap_path}."
      })
      status_code = "404"
    }
  }

  # Catch the misconfigured combos at plan time. Without these, the
  # `provision_certificate=false + existing_certificate_arn=""` combo
  # plans cleanly and apply fails mid-roll with `CertificateNotFound`
  # after creating the ALB and SGs.
  lifecycle {
    precondition {
      condition     = var.provision_certificate || var.existing_certificate_arn != ""
      error_message = "Either set provision_certificate=true (this stack provisions ACM cert) or supply existing_certificate_arn (cross-account or operator-pre-provisioned cert). At nhp's root tfvars: set `bootstrap_alb_provision_certificate = true` OR `bootstrap_alb_existing_certificate_arn = \"<ARN>\"`."
    }

    precondition {
      condition     = !var.provision_certificate || var.existing_certificate_arn == ""
      error_message = "provision_certificate=true and existing_certificate_arn must not both be set — pick one (the existing_certificate_arn would be silently ignored). At nhp's root tfvars: unset one of `bootstrap_alb_provision_certificate` (true→false) or `bootstrap_alb_existing_certificate_arn` (set→empty)."
    }

    # Catch the cert-in-wrong-partition-or-region-or-account foot-gun
    # at plan. An operator who pre-provisions the cert in `us-east-1`
    # (wrong region) or in a different account and pastes that ARN
    # into env tfvars otherwise plans cleanly, then the ALB listener
    # apply fails mid-roll with a generic `CertificateNotFound` —
    # ACM certs are region-, partition-, AND account-scoped. ALBs
    # cannot attach a cert from a different account. Same shape as
    # the other listener-side preconditions (fail plan, not mid-apply
    # after the ALB + SGs land).
    #
    # Partition, region, AND account ID are all pinned to the apply
    # target via `data.aws_partition.current.partition` /
    # `data.aws_region.current.id` / `data.aws_caller_identity.current.account_id`.
    # Stricter than `variables.tf::existing_certificate_arn`'s
    # syntactic validation (which only checks ARN shape) — the
    # variable's check is "is this an ARN-shaped string"; this
    # precondition's check is "does this cert actually land at the
    # apply target". Distinct concerns, distinct shapes.
    precondition {
      condition     = var.provision_certificate || var.existing_certificate_arn == "" || can(regex("^arn:${data.aws_partition.current.partition}:acm:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:", var.existing_certificate_arn))
      error_message = "existing_certificate_arn partition+region+account must match the apply target (arn:${data.aws_partition.current.partition}:acm:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:...); ACM certs are region-, partition-, AND account-scoped and can't be cross-region/partition/account-attached to an ALB."
    }

    # Belt-and-suspenders on `local.effective_certificate_arn`: the
    # ternary in `main.tf` resolves to `null` on the
    # `provision_certificate=false` + empty `existing_certificate_arn`
    # path. The two preconditions above already gate this on the
    # input variables, but anchoring on the resolved local surfaces
    # the misconfig with a clear message — `certificate_arn = null`
    # at the listener would otherwise produce a less-helpful
    # `Invalid value` error.
    precondition {
      condition     = local.effective_certificate_arn != null && local.effective_certificate_arn != ""
      error_message = <<-EOT
        local.effective_certificate_arn resolved to null/empty.

        This means `provision_certificate=false` AND `existing_certificate_arn`
        is empty. Either:

          - Populate `existing_certificate_arn` with the operator-pre-provisioned
            cert ARN (Path 1 — cross-account zone), or
          - Flip to `provision_certificate=true` + set `route53_zone_id` so the
            module manages the cert in-account (Path 2 — same-account zone).

        See `modules/bootstrap-alb/README.md` "Account topology" for the
        per-env mapping.
      EOT
    }
  }

  tags = merge(local.tags, { Name = "${local.alb_name}-https" })
}

# The ONLY forwarding listener rule. Path-pattern match on
# `var.bootstrap_path` (default `/v1/agent/bootstrap`) → forward to
# qurl-service TG. Priority 1 — only one rule on this listener, but
# ALB requires a non-default priority on every rule.
#
# Path-pattern match is character-for-character exact AND
# case-sensitive (per AWS ALB listener-rule docs): a request to
# `/v1/agent/bootstrap` matches; `/v1/agent/bootstrap/` (trailing
# slash) does NOT match and falls through to the default 404.
# `/v1/agent/bootstrapxxx` does NOT match. `/V1/agent/bootstrap`
# (mixed case) does NOT match. `?` and `*` are the only wildcards.
# The reverse-tunnel-client sidecar emits `POST /v1/agent/bootstrap`
# exactly with no trailing slash and lowercase; if a future client
# deviates on EITHER axis, extend `path_pattern.values` AND the WAF
# scope-down byte_match in `waf.tf` together — both must agree on the
# matching set or the rate-limit aggregator stops counting probes
# against the non-canonical variant.
resource "aws_lb_listener_rule" "bootstrap" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 1

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.qurl_service.arn
  }

  condition {
    path_pattern {
      values = [var.bootstrap_path]
    }
  }

  # Method-restrict at the listener — `POST` is the only valid verb
  # the sidecar contract emits. `GET/PUT/DELETE/HEAD/OPTIONS` on the
  # same path fall through to the default 404 fixed-response and never
  # reach the qurl-service handler. Strengthens the narrow-surface
  # invariant: the qurl-service bootstrap handler doesn't need to
  # write defensive method-rejection code, and the rate-limit
  # aggregator counts only canonical-method probes (not random GET
  # scanners burning the budget).
  #
  # **404 vs 405 for wrong-method on the bootstrap path: deliberately
  # 404.** A `GET /v1/agent/bootstrap` falls through to the default
  # fixed-response 404 (path-and-method both not matching = same
  # response as path-only-not-matching). RFC-conformant would be 405
  # Method Not Allowed, but that would require splitting into two
  # listener rules (path-match-with-POST → forward; path-match-with-
  # non-POST → fixed-response 405). The added rule cost isn't worth
  # the conformance: a wrong-method scanner gets less information
  # from a 404 ("no such endpoint at all") than from a 405 ("endpoint
  # exists, try POST"). Pinning the decision here so the paired
  # smoke test (#1894) asserts 404, not 405, for the wrong-method
  # case.
  #
  # No `OPTIONS` preflight is needed — the sidecar is a non-browser
  # HTTP client making a same-origin POST, not a CORS-policed browser
  # XHR. A future browser-initiated caller (which the threat model
  # explicitly does NOT include — see security_groups.tf header) would
  # need its own listener rule extension.
  condition {
    http_request_method {
      values = ["POST"]
    }
  }

  # Host-header restrict — defense in depth. Today this ALB is
  # dedicated to a single hostname so the SNI + cert flow already
  # rejects anything else. But if a future PR ever attaches a second
  # hostname/cert via `aws_lb_listener_certificate`, this condition
  # keeps the forwarding rule bound to ONLY the bootstrap hostname
  # rather than silently matching `POST /v1/agent/bootstrap` on either
  # hostname. Cheap to declare now while there's exactly one valid
  # value; awkward to retrofit later.
  condition {
    host_header {
      values = [var.dns_name]
    }
  }

  tags = merge(local.tags, { Name = "${local.alb_name}-bootstrap-rule" })
}
