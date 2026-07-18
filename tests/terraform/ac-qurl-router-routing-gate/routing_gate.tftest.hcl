run "default_off" {
  command = plan

  assert {
    condition     = output.rendered == ""
    error_message = "The default-off AC qurl-router gate must render no bytes so an unset flag cannot change the launch-template plan before cutover."
  }

  assert {
    condition     = output.anchored_render == "  enableQurlSiteAuthz = false"
    error_message = "The default-off splice must leave its qurl-router anchor line byte-identical."
  }
}

run "explicit_on" {
  command = plan

  variables {
    require_connector_routing_id = true
  }

  assert {
    condition     = output.rendered == "\n  requireConnectorRoutingID = true"
    error_message = "An explicit gate enable must render requireConnectorRoutingID = true."
  }

  assert {
    condition     = output.anchored_render == "  enableQurlSiteAuthz = false\n  requireConnectorRoutingID = true"
    error_message = "The enabled gate must render immediately after the qurl-router anchor line."
  }
}
