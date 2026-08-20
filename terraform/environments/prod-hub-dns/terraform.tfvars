# Production Hub DNS is intentionally inert until the Control Hub edge exists.
# Activation removes the variable validation source lock and flips this value in
# one reviewed PR; setting true in a dispatch alone must remain impossible.
hub_dns_enabled = false

environment = "prod-hub-dns"
aws_region  = "us-east-2"

hub_dns_name   = "hub.nhp.layerv.ai"
hosted_zone_id = "Z0748438C8EK6UAW94ST"
hub_nlb_name   = "layerv-nhp-prod-hub-edge"

management_route53_role_arn = "arn:aws:iam::165115313779:role/nhp-ac-route53-access"
