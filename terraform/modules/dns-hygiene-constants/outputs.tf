# Shared DNS-hygiene constants — single source of truth for the CAA issuer
# building blocks and record TTL consumed by BOTH env root modules
# (`terraform/environments/{prod,sandbox}/dns_hygiene.tf`).
#
# These were previously duplicated verbatim across the two root modules, which
# created a drift hazard: a CA added to one file but forgotten in the other
# silently breaks that env's next cert renewal — the exact failure the CAA
# records exist to prevent. Terraform can't share `locals` across separate root
# modules, but an outputs-only module (no inputs, no providers, no resources) is
# the lightweight way to give both roots one authoritative copy.
#
# CAA value format is `<flags> <tag> "<value>"` (flags=0). Issuer sets are
# derived from each domain's live certificate-transparency (crt.sh) history; see
# the consuming files' headers and the prod-rollout ledger's CAA re-check task.
# When a new CA appears in any LayerV domain's CT-log history, add it HERE and it
# lands in every env at once.

output "caa_acm" {
  description = "CAA issue identifiers for AWS ACM (all four are interchangeable; list all)."
  value = [
    "0 issue \"amazon.com\"",
    "0 issue \"amazontrust.com\"",
    "0 issue \"awstrust.com\"",
    "0 issue \"amazonaws.com\"",
  ]
}

output "caa_letsencrypt" {
  description = "CAA issue identifier for Let's Encrypt (centralized acme-cert module + AC per-resource ACME certs)."
  value       = ["0 issue \"letsencrypt.org\""]
}

output "caa_godaddy" {
  description = "CAA issue identifiers for GoDaddy/Starfield (layerv.ai + layerv.xyz only — e.g. email.layerv.ai)."
  value = [
    "0 issue \"godaddy.com\"",
    "0 issue \"starfieldtech.com\"",
  ]
}

output "caa_iodef" {
  description = "CAA iodef contact for CA policy-violation reports."
  value       = ["0 iodef \"mailto:security@layerv.ai\""]
}

output "ttl" {
  description = "TTL (seconds) for DNS-hygiene records. Low for fast rollback during initial rollout."
  value       = 300
}
