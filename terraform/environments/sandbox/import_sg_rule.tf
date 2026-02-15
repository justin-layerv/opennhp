# One-time import: SG rule was removed outside Terraform during debugging.
# The rule was recreated via CLI and needs to be imported back into state.
# This file can be deleted after the next successful terraform apply.
import {
  to = module.nhp.module.compute.aws_security_group_rule.server_https_from_internet[0]
  id = "sg-0cdaa7545a55baad4_ingress_tcp_8888_8888_0.0.0.0/0"
}
