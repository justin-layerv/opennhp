# Sandbox Hub-DNS root — one public A-alias for the Connector Hub UDP edge.
# Step 5 slice 5c. Every value here is also the variable default (variables.tf);
# pinned explicitly so the record's identity is legible in one place.

environment = "sandbox-hub-dns"
aws_region  = "us-east-2"

# hub.nhp.layerv.xyz -> layerv-nhp-sandbox-control-hub NLB, in the layerv.xyz zone.
hub_dns_name   = "hub.nhp.layerv.xyz"
hosted_zone_id = "Z10394893FM38A1RXLL32" # layerv.xyz hosted zone (same account)
hub_nlb_name   = "layerv-nhp-sandbox-control-hub"
