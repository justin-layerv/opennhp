# Temporary import blocks for SG rule migration from inline to standalone resources.
# These adopt existing AWS SG rules into the new resource addresses so Terraform
# doesn't destroy+recreate them (which would cause a brief outage).
#
# Safe to delete after the first successful `terraform apply` with these imports.
# Rule IDs fetched via: aws ec2 describe-security-group-rules --filters Name=group-id,Values=<sg-id>

# --- Server SG Rules ---

import {
  to = module.nhp.module.compute.aws_vpc_security_group_ingress_rule.server_nhp_udp
  id = "sgr-02c61429b01d9b850"
}

import {
  to = module.nhp.module.compute.aws_vpc_security_group_ingress_rule.server_http_traefik
  id = "sgr-0ded77abe9a015f52"
}

import {
  to = module.nhp.module.compute.aws_vpc_security_group_ingress_rule.server_http_plugins
  id = "sgr-0fa5b716da242d01f"
}

import {
  to = module.nhp.module.compute.aws_vpc_security_group_ingress_rule.server_qurl_resolve[0]
  id = "sgr-04fb2ba868ed1ef46"
}

import {
  to = module.nhp.module.compute.aws_vpc_security_group_egress_rule.server_all
  id = "sgr-07cbf67a051913a94"
}

# --- AC SG Rules ---

import {
  to = module.nhp.module.ac[0].aws_vpc_security_group_ingress_rule.ac_https
  id = "sgr-03b6859f6d49276b4"
}

import {
  to = module.nhp.module.ac[0].aws_vpc_security_group_ingress_rule.ac_http
  id = "sgr-075747fcaed268d49"
}

import {
  to = module.nhp.module.ac[0].aws_vpc_security_group_ingress_rule.ac_portal
  id = "sgr-0d3126dbd36514c41"
}

import {
  to = module.nhp.module.ac[0].aws_vpc_security_group_ingress_rule.ac_nhp_connector
  id = "sgr-07d40dd9a6735c870"
}

import {
  to = module.nhp.module.ac[0].aws_vpc_security_group_ingress_rule.ac_nhp_knock
  id = "sgr-0138b3d627ca8e33d"
}

import {
  to = module.nhp.module.ac[0].aws_vpc_security_group_ingress_rule.ac_ssh
  id = "sgr-01b698ee2264a67ac"
}

import {
  to = module.nhp.module.ac[0].aws_vpc_security_group_ingress_rule.ac_traefik_health
  id = "sgr-0611948f9ba72823f"
}

import {
  to = module.nhp.module.ac[0].aws_vpc_security_group_egress_rule.ac_all
  id = "sgr-054c73c6f2b3da1f0"
}
