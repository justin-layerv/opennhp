# -----------------------------------------------------------------------------
# The canonical collector contract: what is installed on every attested node.
#
# This used to be published to two SSM parameters under
# /<env>/nhp/udp-proof/, read by the attended UDP proof's deployment-manifest
# producer. That producer was deleted with the proof in #3799, leaving the
# parameters published for nobody, so they were retired. The contract itself is
# still the evidence of what the repair document installs and re-verifies, so it
# stays as a computed value on the `collector_contract` output.
#
# The retired parameters also carried producer-shaped preconditions — a
# 4096-byte canonical-JSON bound and a no-\u-escapes check, both of which
# existed because the producer re-encoded what it parsed and rejected any byte
# that differed. Those bounds had no subject once nothing consumed the value.
# If a future consumer reads this contract over a wire, re-derive its encoding
# constraints from that consumer rather than restoring these.
# -----------------------------------------------------------------------------

locals {
  collector_contract = {
    schema_version          = 1
    bucket_policy_sha256    = local.bucket_policy_sha256
    collector_sha256        = local.collector_sha256
    service_unit_sha256     = local.service_unit_sha256
    timer_unit_sha256       = local.timer_unit_sha256
    repair_document_name    = local.repair_document_name
    repair_document_sha256  = local.repair_document_sha256
    repair_document_version = aws_ssm_document.repair.document_version
  }
}
