terraform {
  required_version = ">= 1.8.0"
}

variable "require_connector_routing_id" {
  type    = bool
  default = false
}

locals {
  rendered = chomp(templatefile("${path.module}/../../../terraform/modules/ac/qurl_router_connector_routing_gate.toml.tpl", {
    require_connector_routing_id = var.require_connector_routing_id
  }))
}

output "rendered" {
  value = local.rendered
}

output "anchored_render" {
  # Keep this literal in lockstep with the splice anchor in
  # terraform/modules/ac/user_data.sh.tpl. The module-level render fence is
  # the production backstop; this focused test gives the byte contract a fast
  # provider-free failure.
  value = "  enableQurlSiteAuthz = false${local.rendered}"
}
