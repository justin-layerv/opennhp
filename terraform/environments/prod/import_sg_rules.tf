# Temporary import blocks for SG rule migration from inline to standalone resources.
# These adopt existing AWS SG rules into the new resource addresses so Terraform
# doesn't destroy+recreate them (which would cause a brief outage).
#
# 12 rules imported (4 server + 8 AC). server_qurl_resolve[0] is intentionally
# NOT imported — the rule does not exist in AWS (state drift: TF state has it as
# an inline rule but it was never created in prod). Terraform will create it fresh.
#
# Safe to delete after the first successful `terraform apply` with these imports.
# Rule IDs fetched via: aws ec2 describe-security-group-rules --filters Name=group-id,Values=<sg-id>

# --- Server SG Rules (sg-0808ce68a65f0889a) ---

import {
  to = module.nhp.module.compute.aws_vpc_security_group_ingress_rule.server_nhp_udp
  id = "sgr-00fe0c33c23c586a3"
}

import {
  to = module.nhp.module.compute.aws_vpc_security_group_ingress_rule.server_http_traefik
  id = "sgr-06d85f592799cbe38"
}

import {
  to = module.nhp.module.compute.aws_vpc_security_group_ingress_rule.server_http_plugins
  id = "sgr-0d48cbed8cd28bd04"
}

import {
  to = module.nhp.module.compute.aws_vpc_security_group_egress_rule.server_all
  id = "sgr-0871ded04ff181f4f"
}

# --- AC SG Rules (sg-0c87b519c22c3adda) ---

import {
  to = module.nhp.module.ac[0].aws_vpc_security_group_ingress_rule.ac_https
  id = "sgr-033aa0c61da2dbb88"
}

import {
  to = module.nhp.module.ac[0].aws_vpc_security_group_ingress_rule.ac_http
  id = "sgr-0886e0486cbc0d700"
}

import {
  to = module.nhp.module.ac[0].aws_vpc_security_group_ingress_rule.ac_portal
  id = "sgr-0cbc80d43aa071b3d"
}

import {
  to = module.nhp.module.ac[0].aws_vpc_security_group_ingress_rule.ac_nhp_connector
  id = "sgr-093d6b07fcbbe80d5"
}

import {
  to = module.nhp.module.ac[0].aws_vpc_security_group_ingress_rule.ac_nhp_knock
  id = "sgr-015647c613e168b86"
}

import {
  to = module.nhp.module.ac[0].aws_vpc_security_group_ingress_rule.ac_ssh
  id = "sgr-03657d7b70942c2ac"
}

import {
  to = module.nhp.module.ac[0].aws_vpc_security_group_ingress_rule.ac_traefik_health
  id = "sgr-04056fdb5f99803ea"
}

import {
  to = module.nhp.module.ac[0].aws_vpc_security_group_egress_rule.ac_all
  id = "sgr-067cdce27abef47e0"
}
