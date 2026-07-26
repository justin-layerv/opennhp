# -----------------------------------------------------------------------------
# The two public parameters the deployment-manifest producer reads.
#
# Both are plain `String` parameters holding public identifiers and digests —
# no secret material. The producer parses the collector contract with its
# canonical-JSON reader, so the value must be exact canonical JSON: sorted keys,
# no separator padding, ASCII. Terraform's jsonencode produces precisely that.
# -----------------------------------------------------------------------------

locals {
  parameter_prefix = "/${var.environment}/nhp/udp-proof"

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

  collector_contract_json = jsonencode(local.collector_contract)
}

resource "aws_ssm_parameter" "runtime_attestation_bucket_arn" {
  name        = "${local.parameter_prefix}/runtime-attestation-bucket-arn"
  description = "Exact ARN of the canonical sandbox runtime-attestation bucket."
  type        = "String"
  value       = aws_s3_bucket.attestations.arn

  tags = merge(local.tags, { Name = "${var.name_prefix}-runtime-attestation-bucket-arn" })

  lifecycle {
    precondition {
      condition     = startswith(local.bucket_arn, "arn:${data.aws_partition.current.partition}:s3:::layerv-nhp-sandbox-")
      error_message = "The producer only accepts an exact layerv-nhp-sandbox-* attestation bucket ARN."
    }
  }
}

resource "aws_ssm_parameter" "runtime_attestation_collector_contract" {
  name        = "${local.parameter_prefix}/runtime-attestation-collector-contract"
  description = "Canonical collector, unit, repair-document, and bucket-policy digests for runtime attestations."
  type        = "String"
  value       = local.collector_contract_json

  tags = merge(local.tags, { Name = "${var.name_prefix}-runtime-attestation-collector-contract" })

  lifecycle {
    precondition {
      # The producer reads this value with a 4096-byte canonical-JSON bound.
      condition     = length(local.collector_contract_json) <= 4096
      error_message = "The collector contract must fit the producer's 4096-byte canonical bound."
    }

    precondition {
      # The producer re-encodes what it parses and rejects any byte that
      # differs. Terraform's jsonencode escapes < > and & where the producer's
      # encoder does not, so a value carrying one would silently fail closed.
      condition     = !strcontains(local.collector_contract_json, "\\u")
      error_message = "The collector contract must encode identically for Terraform and the producer: no \\u escapes."
    }

    precondition {
      condition     = can(regex("^[1-9][0-9]{0,9}$", aws_ssm_document.repair.document_version))
      error_message = "The repair document version must be a positive decimal document version."
    }
  }
}
