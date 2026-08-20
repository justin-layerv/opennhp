# Production Hub DNS is staged source-locked dark. The production Hub NLB does
# not exist before the governed Control rollout, so both its lookup and the
# Route 53 record are gated. Removing the validation source lock and flipping
# the tfvars value must be one later reviewed activation.

# Resolve the NLB by its immutable production naming contract rather than by
# reading Control state. The disabled root performs no lookup; when unlocked,
# a missing or wrong-shaped edge fails the plan before Route 53 can change.
data "aws_lb" "hub" {
  count = var.hub_dns_enabled ? 1 : 0
  name  = var.hub_nlb_name

  lifecycle {
    postcondition {
      condition     = self.load_balancer_type == "network"
      error_message = "Production Hub DNS must target a network load balancer, got ${self.load_balancer_type}."
    }
    postcondition {
      condition     = self.internal == false
      error_message = "Production Hub DNS must target an internet-facing load balancer."
    }
  }
}

# The explicit record overrides *.nhp.layerv.ai, which serves the unrelated AC
# NLB. There is deliberately no wildcard record and no AC fallback in this root.
resource "aws_route53_record" "hub" {
  provider = aws.route53_mgmt
  count    = var.hub_dns_enabled ? 1 : 0

  zone_id = var.hosted_zone_id
  name    = var.hub_dns_name
  type    = "A"

  alias {
    name                   = data.aws_lb.hub[0].dns_name
    zone_id                = data.aws_lb.hub[0].zone_id
    evaluate_target_health = true
  }
}
