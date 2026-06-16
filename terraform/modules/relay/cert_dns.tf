# ACM cert + DNS validation + Route53 alias for the relay ALB.
# Mirrors modules/bootstrap-alb/cert_dns.tf (trimmed).
#
# Per-env posture:
#   - Sandbox: same-account (`layerv.xyz` in the sandbox account) →
#     provision_certificate=true + manage_dns_alias=true (module owns cert +
#     validation CNAMEs + the A-alias).
#   - Prod: cross-account (`layerv.ai` in layerv-mgmt) →
#     provision_certificate=false + manage_dns_alias=false; the operator
#     pre-provisions the regional cert in-account and writes DNS out-of-band.

locals {
  # provision → the in-stack validated cert (CBD lets the listener repoint
  # before the old cert tears down). Otherwise the operator-supplied existing
  # ARN. one(<splat>) is null-safe against the count-0 branch.
  effective_certificate_arn = var.provision_certificate ? one(aws_acm_certificate_validation.relay[*].certificate_arn) : var.existing_certificate_arn
}

# Resolve the zone name for the dns_name-subdomain-of-zone precondition. Read
# only when a flag needs it; skipped (no Route53 read) when both are false.
data "aws_route53_zone" "selected" {
  count   = (var.provision_certificate || var.manage_dns_alias) ? 1 : 0
  zone_id = var.route53_zone_id

  lifecycle {
    precondition {
      condition     = var.route53_zone_id != ""
      error_message = "provision_certificate=true or manage_dns_alias=true requires a non-empty route53_zone_id (the parent zone for dns_name)."
    }
  }
}

# Same-account record writes consume the parent CI role's scoped Route53
# record-change grants; wait for those to propagate on a cutover apply.
resource "time_sleep" "route53_record_change_iam_propagation" {
  count = (var.provision_certificate || var.manage_dns_alias) && length(var.route53_record_change_iam_propagation_triggers) > 0 ? 1 : 0

  triggers        = var.route53_record_change_iam_propagation_triggers
  create_duration = var.route53_record_change_iam_propagation_duration
}

resource "aws_acm_certificate" "relay" {
  count = var.provision_certificate ? 1 : 0

  domain_name       = var.dns_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true

    precondition {
      condition     = var.route53_zone_id != ""
      error_message = "provision_certificate=true requires a non-empty route53_zone_id (ACM needs a hosted zone for DNS validation)."
    }

    # Dot-boundary subdomain check: apex match or proper subdomain. Catches the
    # typo'd-zone class (correct shape, wrong zone) that would otherwise hang
    # ACM validation ~75min before failing.
    precondition {
      condition     = var.dns_name == trimsuffix(data.aws_route53_zone.selected[0].name, ".") || endswith(var.dns_name, ".${trimsuffix(data.aws_route53_zone.selected[0].name, ".")}")
      error_message = "dns_name must be the apex of, or a subdomain of, the zone resolved from route53_zone_id. Got dns_name=`${var.dns_name}` but zone=`${trimsuffix(data.aws_route53_zone.selected[0].name, ".")}`."
    }

    # Single-SAN assumption fence for the [0] index below.
    postcondition {
      condition     = length(self.domain_validation_options) == 1
      error_message = "cert has ${length(self.domain_validation_options)} domain_validation_options; this file assumes exactly 1 (single SAN)."
    }
  }

  tags = local.tags
}

locals {
  # [0] safe via the postcondition above; ternary avoids [0]-against-count-0.
  cert_dvo = var.provision_certificate ? tolist(aws_acm_certificate.relay[0].domain_validation_options)[0] : null
}

resource "aws_route53_record" "cert_validation" {
  for_each = var.provision_certificate ? toset([var.dns_name]) : toset([])

  zone_id         = var.route53_zone_id
  name            = local.cert_dvo.resource_record_name
  type            = local.cert_dvo.resource_record_type
  ttl             = 300
  records         = [local.cert_dvo.resource_record_value]
  allow_overwrite = true

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [time_sleep.route53_record_change_iam_propagation]
}

resource "aws_acm_certificate_validation" "relay" {
  count = var.provision_certificate ? 1 : 0

  certificate_arn         = aws_acm_certificate.relay[0].arn
  validation_record_fqdns = [for r in aws_route53_record.cert_validation : r.fqdn]
}

# Public A-alias: dns_name → relay ALB. Count-gated so a cross-account caller
# (parent zone outside this state) publishes their own alias against the
# module's alb_dns_name/alb_zone_id outputs.
resource "aws_route53_record" "alb_alias" {
  count = var.manage_dns_alias ? 1 : 0

  zone_id = var.route53_zone_id
  name    = var.dns_name
  type    = "A"

  alias {
    name                   = aws_lb.relay.dns_name
    zone_id                = aws_lb.relay.zone_id
    evaluate_target_health = false
  }

  lifecycle {
    precondition {
      condition     = var.route53_zone_id != ""
      error_message = "manage_dns_alias=true requires a non-empty route53_zone_id."
    }

    precondition {
      condition     = var.dns_name == trimsuffix(data.aws_route53_zone.selected[0].name, ".") || endswith(var.dns_name, ".${trimsuffix(data.aws_route53_zone.selected[0].name, ".")}")
      error_message = "manage_dns_alias=true requires dns_name to be the apex of, or a subdomain of, the zone resolved from route53_zone_id. Got dns_name=`${var.dns_name}` but zone=`${trimsuffix(data.aws_route53_zone.selected[0].name, ".")}`."
    }
  }

  depends_on = [time_sleep.route53_record_change_iam_propagation]
}
