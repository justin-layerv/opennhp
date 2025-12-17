# DNS Module
# Route 53 configuration (optional)

data "aws_route53_zone" "main" {
  count = var.hosted_zone_name != null ? 1 : 0
  name  = var.hosted_zone_name
}

resource "aws_route53_record" "nhp" {
  count   = var.hosted_zone_name != null ? 1 : 0
  zone_id = data.aws_route53_zone.main[0].zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = var.nlb_dns_name
    zone_id                = var.nlb_zone_id
    evaluate_target_health = true
  }
}
