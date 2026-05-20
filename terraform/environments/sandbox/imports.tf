# Import blocks for pre-existing resources that Terraform needs to adopt.
# These are safe to leave in place — Terraform treats them as no-ops after
# the first successful import.

# The acme.layerv.xyz NS delegation record was created manually in Route53
# before the custom-domain-cert module added it as a managed resource.
import {
  to = module.custom_domain_cert[0].aws_route53_record.acme_ns_delegation
  id = "Z10394893FM38A1RXLL32_acme.layerv.xyz_NS"
}

# The qurl-reverse-tunnel-server ASG was created by the pre-#2040
# sandbox apply (run 26185062901) that errored on
# `EnableMetricsCollection` with the invalid `GroupUnHealthyInstanceCount`
# metric (fixed in PR #2040). `CreateAutoScalingGroup` succeeded
# before that error, so AWS holds the resource; Terraform rolled
# state back on the partial-create error, so state does not. The
# post-#2040 apply then hit `AlreadyExists` on Create (run
# 26189175322). Adopt the existing ASG into state.
#
# Remove this block after the first successful apply — the
# `Terraform Validate (PR) (sandbox)` job flags stale import
# blocks (re-run on every apply).
import {
  to = module.nhp.module.qurl_reverse_tunnel_server[0].aws_autoscaling_group.frps
  id = "layerv-nhp-sandbox-frps"
}
