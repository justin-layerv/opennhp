# DNS Module
# Route 53 records for NHP infrastructure

locals {
  # Support both zone name lookup and direct zone ID (for cross-account zones)
  has_zone      = var.hosted_zone_id != null || var.hosted_zone_name != null
  resolved_zone = var.hosted_zone_id != null ? var.hosted_zone_id : try(data.aws_route53_zone.main[0].zone_id, null)
}

data "aws_route53_zone" "main" {
  count = var.hosted_zone_id == null && var.hosted_zone_name != null ? 1 : 0
  name  = var.hosted_zone_name
}

# Main A record pointing to NLB (for UDP NHP protocol)
# Skip this when AC module is managing the domain (AC provides TLS termination)
resource "aws_route53_record" "nhp" {
  count   = local.has_zone && !var.skip_main_record ? 1 : 0
  zone_id = local.resolved_zone
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = var.nlb_dns_name
    zone_id                = var.nlb_zone_id
    evaluate_target_health = true
  }
}

# Wildcard A record for subdomains (login.*, api.*, etc.)
resource "aws_route53_record" "wildcard" {
  count   = local.has_zone && var.create_wildcard ? 1 : 0
  zone_id = local.resolved_zone
  name    = "*.${var.domain_name}"
  type    = "A"

  alias {
    name                   = var.alb_dns_name != null ? var.alb_dns_name : var.nlb_dns_name
    zone_id                = var.alb_zone_id != null ? var.alb_zone_id : var.nlb_zone_id
    evaluate_target_health = true
  }
}

# HTTPS record pointing to ALB/Traefik (if enabled)
resource "aws_route53_record" "https" {
  count   = local.has_zone && var.alb_dns_name != null ? 1 : 0
  zone_id = local.resolved_zone
  name    = "api.${var.domain_name}"
  type    = "A"

  alias {
    name                   = var.alb_dns_name
    zone_id                = var.alb_zone_id
    evaluate_target_health = true
  }
}
