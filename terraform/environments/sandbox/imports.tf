# Import blocks for pre-existing resources that Terraform needs to adopt.
# These are safe to leave in place — Terraform treats them as no-ops after
# the first successful import.

# The acme.layerv.xyz NS delegation record was created manually in Route53
# before the custom-domain-cert module added it as a managed resource.
import {
  to = module.custom_domain_cert[0].aws_route53_record.acme_ns_delegation
  id = "Z10394893FM38A1RXLL32_acme.layerv.xyz_NS"
}
