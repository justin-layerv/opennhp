# Temporary import: re-import the server_https_from_internet SG rule.
# The original rule was removed from TF state after the stale import block
# in PR #534 caused it to be deleted. A replacement rule was created manually
# via AWS CLI. This import reconciles TF state with the actual AWS resource.
#
# DELETE THIS FILE after successful terraform apply.

import {
  to = module.nhp.module.compute.aws_security_group_rule.server_https_from_internet[0]
  id = "sg-0cdaa7545a55baad4_ingress_tcp_8888_8888_0.0.0.0/0"
}
