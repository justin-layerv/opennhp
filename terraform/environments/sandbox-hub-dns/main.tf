# -----------------------------------------------------------------------------
# Hub DNS — hub.nhp.layerv.xyz A-alias -> the Connector Hub public UDP:62206 NLB.
# Step 5 slice 5c of the two-cell UDP substrate for the qURL Connector.
#
# The Hub NLB is created + owned by the Control root
# (terraform/control/environments/sandbox, module.control.aws_lb.hub). We do NOT
# import or remote-read that state; we resolve the NLB by its stable name so
# this root stays fully decoupled from Control's convergence contract and the
# lookup survives an NLB replacement.
# -----------------------------------------------------------------------------

locals {
  name_prefix = "layerv-nhp-sandbox-hub-dns"

  common_tags = merge(
    {
      Project     = "LayerV-NHP"
      Environment = var.environment
      ManagedBy   = "terraform"
      Component   = "connector-hub-dns"
    },
    var.tags,
  )
}

# The live Connector Hub public UDP NLB, resolved by name. Fails the plan loudly
# if the Hub edge (slice 5a) is not yet deployed, and the postconditions assert
# we aliased the intended public UDP network load balancer rather than some other
# same-named resource.
data "aws_lb" "hub" {
  name = var.hub_nlb_name

  lifecycle {
    postcondition {
      condition     = self.load_balancer_type == "network"
      error_message = "Hub NLB ${var.hub_nlb_name} must be a network load balancer (UDP 62206 edge), got ${self.load_balancer_type}."
    }
    postcondition {
      condition     = self.internal == false
      error_message = "Hub NLB ${var.hub_nlb_name} must be internet-facing so hub.nhp.layerv.xyz resolves to a public edge."
    }
  }
}

# One A-alias record: hub.nhp.layerv.xyz -> Hub NLB. skip_main_record=false emits
# exactly the single main record; no wildcard, no HTTPS/ALB record.
module "dns" {
  source = "../../modules/dns"

  environment    = var.environment
  domain_name    = var.hub_dns_name # hub.nhp.layerv.xyz
  hosted_zone_id = var.hosted_zone_id
  nlb_dns_name   = data.aws_lb.hub.dns_name
  nlb_zone_id    = data.aws_lb.hub.zone_id
  name_prefix    = local.name_prefix
  tags           = local.common_tags

  skip_main_record = false
  create_wildcard  = false
}
