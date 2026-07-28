# -----------------------------------------------------------------------------
# One canonical, root-owned collector.
#
# The exact collector and unit bytes are installed and re-verified by one pinned
# State Manager document. User-data may invoke the unit once after a healthy
# start; a root-owned systemd timer then publishes every five minutes. State
# Manager's 30-minute minimum association schedule repairs and verifies the
# units and their hashes — it is deliberately NOT the freshness clock.
#
# The repair step also runs the collector with `--verify` synchronously and lets
# the exit status stand, so an association cannot report Success for a fleet
# whose collector can no longer observe anything. qRTS nodes additionally need
# the boot capture written by modules/qurl-reverse-tunnel-server's user-data,
# because their ECR provenance is only observable before the extraction image is
# removed. Both are documented in README.md.
#
# The producer requires an object no older than ten minutes carrying the exact
# current boot/instance/role/ASG/launch-template identity, the exact collector
# and unit hashes published here, and a healthy exact document/association
# result. It stays read-only and fails closed on missing, stale, S3-fallback,
# mixed-fleet, or instance-mismatch evidence.
# -----------------------------------------------------------------------------

locals {
  repair_document_name = "${var.name_prefix}-runtime-attestation-repair"

  collector_path    = "${path.module}/assets/collect-runtime-attestation.py"
  service_unit_path = "${path.module}/assets/layerv-runtime-attestation.service"
  timer_unit_path   = "${path.module}/assets/layerv-runtime-attestation.timer"

  collector_sha256    = filesha256(local.collector_path)
  service_unit_sha256 = filesha256(local.service_unit_path)
  timer_unit_sha256   = filesha256(local.timer_unit_path)

  install_script = templatefile("${path.module}/assets/install-runtime-attestation.sh.tftpl", {
    repair_document_name = local.repair_document_name
    bucket_name          = var.bucket_name
    kms_key_arn          = aws_kms_key.attestations.arn
    collector_sha256     = local.collector_sha256
    service_unit_sha256  = local.service_unit_sha256
    timer_unit_sha256    = local.timer_unit_sha256
    collector_b64        = filebase64(local.collector_path)
    service_unit_b64     = filebase64(local.service_unit_path)
    timer_unit_b64       = filebase64(local.timer_unit_path)
  })

  repair_document = {
    schemaVersion = "2.2"
    description   = "Install and re-verify the exact LayerV runtime-attestation collector, units, and timer."
    parameters    = {}
    mainSteps = [
      {
        action = "aws:runShellScript"
        name   = "installRuntimeAttestationCollector"
        inputs = {
          timeoutSeconds = "600"
          runCommand     = [local.install_script]
        }
      },
    ]
  }

  # The producer parses the live document with `ssm get-document` and hashes its
  # canonical JSON encoding, so this digest binds the exact installed bytes.
  repair_document_json   = jsonencode(local.repair_document)
  repair_document_sha256 = sha256(local.repair_document_json)
}

resource "aws_ssm_document" "repair" {
  name            = local.repair_document_name
  document_type   = "Command"
  document_format = "JSON"
  content         = local.repair_document_json

  tags = merge(local.tags, { Name = local.repair_document_name })
}

data "aws_ssm_parameter" "asg_name" {
  # Keyed by the parameter path itself, so a parameter shared by two fleets is
  # read exactly once.
  for_each = toset(flatten(values(var.asg_name_ssm_parameters)))

  name = each.value
}

resource "aws_ssm_association" "repair" {
  for_each = var.asg_name_ssm_parameters

  name                = aws_ssm_document.repair.name
  association_name    = "${local.repair_document_name}-${each.key}"
  document_version    = aws_ssm_document.repair.document_version
  schedule_expression = var.repair_schedule_expression

  # Exactly one target selector — the producer rejects any other target shape.
  # Its values are EVERY colour's ASG for this fleet, sorted so the plan does
  # not churn on input order. The producer pins this exact set and additionally
  # requires the colour it resolved as active to be a member, so widening from
  # one name to the fleet's full colour set does not loosen what is proven.
  targets {
    key = "tag:aws:autoscaling:groupName"
    values = sort(distinct([
      for parameter in each.value :
      nonsensitive(data.aws_ssm_parameter.asg_name[parameter].value)
    ]))
  }

  # Fail closed: one node that cannot prove the exact installed bytes fails the
  # association, and the producer then refuses to emit a manifest at all.
  compliance_severity = "CRITICAL"
  max_concurrency     = "100%"
  max_errors          = "0"

  lifecycle {
    precondition {
      condition     = contains(keys(var.attested_node_roles), each.key)
      error_message = "Every attested ASG must have a matching attested node role."
    }
  }
}

# ==================== Node-side read grants ====================
#
# S3 and KMS authority for the nodes lives in the bucket and key policies —
# the artifacts the producer digests — so nothing here grants storage access.
# These roles are owned by the sandbox / sandbox-cell1 roots; this module adds
# only the exact describe calls the collector makes to bind its own identity
# and repair status, each scoped to this region and, where SSM supports it, to
# this fleet's own association.

resource "aws_iam_role_policy" "node_collector_reads" {
  for_each = var.attested_node_roles

  name = "runtime-attestation-collect"
  role = each.value

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DescribeOwnFleetPlacement"
        Effect = "Allow"
        Action = [
          "autoscaling:DescribeAutoScalingInstances",
          "ec2:DescribeInstances",
          "ssm:ListAssociations",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = data.aws_region.current.region
          }
        }
      },
      {
        Sid      = "DescribeOwnRepairExecutions"
        Effect   = "Allow"
        Action   = "ssm:DescribeAssociationExecutions"
        Resource = "arn:${data.aws_partition.current.partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:association/${aws_ssm_association.repair[each.key].association_id}"
      },
    ]
  })
}
