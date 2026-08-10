mock_provider "aws" {
  mock_data "aws_region" {
    defaults = {
      region = "us-east-2"
    }
  }

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "767397897469"
    }
  }

  mock_data "aws_partition" {
    defaults = {
      partition  = "aws"
      dns_suffix = "amazonaws.com"
    }
  }

  mock_resource "aws_kms_key" {
    defaults = {
      arn    = "arn:aws:kms:us-east-2:767397897469:key/33333333-aaaa-bbbb-cccc-444444444444"
      key_id = "33333333-aaaa-bbbb-cccc-444444444444"
    }
  }

  mock_resource "aws_s3_bucket" {
    defaults = {
      arn    = "arn:aws:s3:::layerv-nhp-sandbox-runtime-attestations"
      bucket = "layerv-nhp-sandbox-runtime-attestations"
      id     = "layerv-nhp-sandbox-runtime-attestations"
    }
  }

  mock_resource "aws_ssm_document" {
    defaults = {
      name             = "layerv-nhp-sandbox-runtime-attestation-repair"
      document_version = "1"
      latest_version   = "1"
      default_version  = "1"
    }
  }
}

variables {
  environment = "sandbox"
  name_prefix = "layerv-nhp-sandbox"
}

run "storage_boundary_contract" {
  command = apply

  # The live values, verified in 767397897469/us-east-2. Note that cell0's
  # blue-asg-name and /sandbox/nhp/server/asg-name hold the SAME name --
  # that identity is exactly why asg-name is useless as an active-colour
  # pointer and why the green fleet went unattested.
  override_data {
    target = data.aws_ssm_parameter.asg_name["/sandbox/nhp/server/blue-asg-name"]
    values = {
      value = "layerv-nhp-sandbox-server"
    }
  }

  override_data {
    target = data.aws_ssm_parameter.asg_name["/sandbox/nhp/server/green-asg-name"]
    values = {
      value = "layerv-nhp-sandbox-server-green"
    }
  }

  override_data {
    target = data.aws_ssm_parameter.asg_name["/sandbox-cell1/nhp/server/blue-asg-name"]
    values = {
      value = "layerv-nhp-sandbox-cell1-server"
    }
  }

  override_data {
    target = data.aws_ssm_parameter.asg_name["/sandbox-cell1/nhp/server/green-asg-name"]
    values = {
      value = "layerv-nhp-sandbox-cell1-server-green"
    }
  }

  override_data {
    target = data.aws_ssm_parameter.asg_name["/sandbox/nhp/reverse-tunnel-server/asg-name"]
    values = {
      value = "layerv-nhp-sandbox-frps"
    }
  }

  # ---------------------------------------------------------------------------
  # Bucket controls the producer re-reads live and fails closed on.
  # ---------------------------------------------------------------------------

  assert {
    condition = (
      aws_s3_bucket.attestations.bucket == "layerv-nhp-sandbox-runtime-attestations" &&
      aws_s3_bucket_versioning.attestations.versioning_configuration[0].status == "Enabled" &&
      aws_s3_bucket_ownership_controls.attestations.rule[0].object_ownership == "BucketOwnerEnforced" &&
      aws_s3_bucket_public_access_block.attestations.block_public_acls &&
      aws_s3_bucket_public_access_block.attestations.block_public_policy &&
      aws_s3_bucket_public_access_block.attestations.ignore_public_acls &&
      aws_s3_bucket_public_access_block.attestations.restrict_public_buckets
    )
    error_message = "The attestation bucket must stay versioned, bucket-owner-enforced, and fully public-blocked."
  }

  assert {
    condition = (
      one(one(aws_s3_bucket_server_side_encryption_configuration.attestations.rule).apply_server_side_encryption_by_default).sse_algorithm == "aws:kms" &&
      one(one(aws_s3_bucket_server_side_encryption_configuration.attestations.rule).apply_server_side_encryption_by_default).kms_master_key_id == aws_kms_key.attestations.arn &&
      one(aws_s3_bucket_server_side_encryption_configuration.attestations.rule).bucket_key_enabled
    )
    error_message = "Attestation objects must be encrypted with the dedicated CMK and an S3 Bucket Key."
  }

  # ---------------------------------------------------------------------------
  # The self-bound prefix. This is the whole security argument: for an EC2 role
  # AWS substitutes aws:userid with <role-id>:<instance-id>, so one instance
  # cannot name, let alone overwrite, another instance's row.
  # ---------------------------------------------------------------------------

  assert {
    condition = (
      ({ for statement in jsondecode(aws_s3_bucket_policy.attestations.policy).Statement : statement.Sid => statement })["AllowSelfBoundNodeAttestationWrites"].Effect == "Allow" &&
      ({ for statement in jsondecode(aws_s3_bucket_policy.attestations.policy).Statement : statement.Sid => statement })["AllowSelfBoundNodeAttestationWrites"].Action == "s3:PutObject" &&
      ({ for statement in jsondecode(aws_s3_bucket_policy.attestations.policy).Statement : statement.Sid => statement })["AllowSelfBoundNodeAttestationWrites"].Resource == "arn:aws:s3:::layerv-nhp-sandbox-runtime-attestations/runtime/$${aws:userid}/*" &&
      ({ for statement in jsondecode(aws_s3_bucket_policy.attestations.policy).Statement : statement.Sid => statement })["AllowSelfBoundNodeAttestationWrites"].Principal.AWS == [
        "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-cell1-server",
        "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-frps",
        "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-server",
      ]
    )
    error_message = "Node roles must hold exactly one PutObject grant, self-bound to runtime/$${aws:userid}/."
  }

  assert {
    condition = (
      ({ for statement in jsondecode(aws_s3_bucket_policy.attestations.policy).Statement : statement.Sid => statement })["DenyNodeAuthorityBeyondPutObject"].Effect == "Deny" &&
      ({ for statement in jsondecode(aws_s3_bucket_policy.attestations.policy).Statement : statement.Sid => statement })["DenyNodeAuthorityBeyondPutObject"].NotAction == "s3:PutObject" &&
      ({ for statement in jsondecode(aws_s3_bucket_policy.attestations.policy).Statement : statement.Sid => statement })["DenyNodeWritesOutsideItsOwnPrefix"].Effect == "Deny" &&
      ({ for statement in jsondecode(aws_s3_bucket_policy.attestations.policy).Statement : statement.Sid => statement })["DenyNodeWritesOutsideItsOwnPrefix"].NotResource == "arn:aws:s3:::layerv-nhp-sandbox-runtime-attestations/runtime/$${aws:userid}/*"
    )
    error_message = "Nodes must be denied every action but PutObject, and every key outside their own prefix."
  }

  assert {
    condition = (
      ({ for statement in jsondecode(aws_s3_bucket_policy.attestations.policy).Statement : statement.Sid => statement })["DenyInsecureTransport"].Condition.Bool["aws:SecureTransport"] == "false" &&
      ({ for statement in jsondecode(aws_s3_bucket_policy.attestations.policy).Statement : statement.Sid => statement })["DenyPrincipalsOutsideTheSandboxAccount"].Condition.StringNotEquals["aws:PrincipalAccount"] == "767397897469" &&
      ({ for statement in jsondecode(aws_s3_bucket_policy.attestations.policy).Statement : statement.Sid => statement })["DenyUnencryptedUploads"].Condition.StringNotEquals["s3:x-amz-server-side-encryption"] == "aws:kms" &&
      ({ for statement in jsondecode(aws_s3_bucket_policy.attestations.policy).Statement : statement.Sid => statement })["DenyUploadsUnderAnyOtherKey"].Condition.StringNotEquals["s3:x-amz-server-side-encryption-aws-kms-key-id"] == aws_kms_key.attestations.arn
    )
    error_message = "The bucket must deny plaintext transport, foreign principals, and any non-CMK upload."
  }

  # ---------------------------------------------------------------------------
  # Nodes may write but never read: no Decrypt anywhere on the CMK.
  # ---------------------------------------------------------------------------

  assert {
    condition = (
      ({ for statement in jsondecode(aws_kms_key.attestations.policy).Statement : statement.Sid => statement })["AllowNodeWriteWrappingForThisBucketOnly"].Condition.StringEquals["kms:ViaService"] == "s3.us-east-2.amazonaws.com" &&
      ({ for statement in jsondecode(aws_kms_key.attestations.policy).Statement : statement.Sid => statement })["AllowNodeWriteWrappingForThisBucketOnly"].Condition.StringEquals["kms:EncryptionContext:aws:s3:arn"] == "arn:aws:s3:::layerv-nhp-sandbox-runtime-attestations" &&
      !contains(({ for statement in jsondecode(aws_kms_key.attestations.policy).Statement : statement.Sid => statement })["AllowNodeWriteWrappingForThisBucketOnly"].Action, "kms:Decrypt") &&
      ({ for statement in jsondecode(aws_kms_key.attestations.policy).Statement : statement.Sid => statement })["DenyNodeDecrypt"].Effect == "Deny" &&
      contains(({ for statement in jsondecode(aws_kms_key.attestations.policy).Statement : statement.Sid => statement })["DenyNodeDecrypt"].Action, "kms:Decrypt")
    )
    error_message = "Node roles must be able to wrap a data key for this bucket only, and must never decrypt."
  }

  # ---------------------------------------------------------------------------
  # Node identity policies must add reads only — never storage authority. The
  # bucket and key policies are the artifacts the producer digests, so a widened
  # identity grant here would be invisible to it.
  # ---------------------------------------------------------------------------

  assert {
    condition = alltrue([
      for role_key in keys(var.attested_node_roles) : alltrue([
        for statement in jsondecode(aws_iam_role_policy.node_collector_reads[role_key].policy).Statement : alltrue([
          for action in flatten([lookup(statement, "Action", [])]) :
          !startswith(action, "s3:") && !startswith(action, "kms:") && !startswith(action, "iam:")
        ])
      ])
    ])
    error_message = "Node collector policies must grant describe-only reads, never S3, KMS, or IAM authority."
  }

  assert {
    condition = (
      jsondecode(aws_iam_role_policy.node_collector_reads["nhp_cell0"].policy).Statement[1].Action == "ssm:DescribeAssociationExecutions" &&
      jsondecode(aws_iam_role_policy.node_collector_reads["nhp_cell0"].policy).Statement[1].Resource == "arn:aws:ssm:us-east-2:767397897469:association/${aws_ssm_association.repair["nhp_cell0"].association_id}"
    )
    error_message = "Each fleet may only read its own repair association's executions."
  }

  # ---------------------------------------------------------------------------
  # Repair document + associations: the exact shape the producer verifies.
  # ---------------------------------------------------------------------------

  assert {
    condition = (
      aws_ssm_document.repair.name == "layerv-nhp-sandbox-runtime-attestation-repair" &&
      aws_ssm_document.repair.document_type == "Command" &&
      aws_ssm_document.repair.document_format == "JSON" &&
      jsondecode(aws_ssm_document.repair.content).schemaVersion == "2.2" &&
      length(jsondecode(aws_ssm_document.repair.content).mainSteps) == 1
    )
    error_message = "The repair document must be one exact single-step JSON Command document."
  }

  assert {
    condition = alltrue([
      for key, association in aws_ssm_association.repair : (
        association.name == aws_ssm_document.repair.name &&
        association.document_version == aws_ssm_document.repair.document_version &&
        length(association.targets) == 1 &&
        association.targets[0].key == "tag:aws:autoscaling:groupName" &&
        length(association.targets[0].values) > 0 &&
        length(association.targets[0].values) == length(distinct(association.targets[0].values)) &&
        association.targets[0].values == sort(association.targets[0].values) &&
        association.max_errors == "0" &&
        association.schedule_expression == "rate(30 minutes)"
      )
    ])
    error_message = "Each repair association must target its ASGs by tag as one sorted distinct selector, pin the exact document version, and fail closed."
  }

  # Both cells are blue/green, so both colours must be targeted. Targeting only
  # the colour-blind asg-name (which equals blue-asg-name) left cell0's ACTIVE
  # green fleet with no collector installed and no attestations at all, so the
  # producer could never assemble evidence for the fleet actually serving UDP.
  assert {
    condition = (
      aws_ssm_association.repair["nhp_cell0"].targets[0].values == tolist([
        "layerv-nhp-sandbox-server",
        "layerv-nhp-sandbox-server-green",
      ]) &&
      aws_ssm_association.repair["nhp_cell1"].targets[0].values == tolist([
        "layerv-nhp-sandbox-cell1-server",
        "layerv-nhp-sandbox-cell1-server-green",
      ]) &&
      aws_ssm_association.repair["qurl_reverse_tunnel_server"].targets[0].values == tolist([
        "layerv-nhp-sandbox-frps",
      ])
    )
    error_message = "Every colour of each attested fleet must be targeted, so the active colour is always covered."
  }

  # ---------------------------------------------------------------------------
  # The collector contract schema.
  #
  # This used to be asserted through the two SSM parameters the UDP-proof
  # deployment-manifest producer read. That producer was deleted in #3799 and
  # the parameters retired, so these now assert the `collector_contract` output
  # directly — the contract is still the binding between the repair document and
  # the exact committed bytes it installs, which is worth keeping regardless of
  # who reads it.
  #
  # The producer's canonical-JSON and 4096-byte encoding assertions are gone with
  # it: they constrained a wire format nothing consumes now. A future consumer
  # should re-derive its own bounds rather than reinstating these.
  # ---------------------------------------------------------------------------

  assert {
    condition = (
      keys(output.collector_contract) == [
        "bucket_policy_sha256",
        "collector_sha256",
        "repair_document_name",
        "repair_document_sha256",
        "repair_document_version",
        "schema_version",
        "service_unit_sha256",
        "timer_unit_sha256",
      ] &&
      output.collector_contract.schema_version == 1 &&
      output.collector_contract.repair_document_name == "layerv-nhp-sandbox-runtime-attestation-repair" &&
      output.collector_contract.repair_document_version == aws_ssm_document.repair.document_version
    )
    error_message = "The collector contract must carry exactly its eight declared fields."
  }

  assert {
    condition = (
      output.collector_contract.collector_sha256 == filesha256("${path.module}/assets/collect-runtime-attestation.py") &&
      output.collector_contract.service_unit_sha256 == filesha256("${path.module}/assets/layerv-runtime-attestation.service") &&
      output.collector_contract.timer_unit_sha256 == filesha256("${path.module}/assets/layerv-runtime-attestation.timer") &&
      output.collector_contract.repair_document_sha256 == sha256(aws_ssm_document.repair.content) &&
      output.collector_contract.bucket_policy_sha256 == sha256(aws_s3_bucket_policy.attestations.policy)
    )
    error_message = "Every contract digest must bind the exact committed bytes it claims to describe."
  }

  # The installer must refuse to write anything whose digest differs from the
  # published contract — the association is the only path that installs bytes.
  assert {
    condition = alltrue([
      for digest in [
        filesha256("${path.module}/assets/collect-runtime-attestation.py"),
        filesha256("${path.module}/assets/layerv-runtime-attestation.service"),
        filesha256("${path.module}/assets/layerv-runtime-attestation.timer"),
      ] : strcontains(jsondecode(aws_ssm_document.repair.content).mainSteps[0].inputs.runCommand[0], digest)
    ])
    error_message = "The repair document must pin every installed file to its published SHA-256."
  }
}

run "rejects_a_non_sandbox_bucket_name" {
  command = plan

  variables {
    bucket_name = "layerv-nhp-prod-runtime-attestations"
  }

  expect_failures = [var.bucket_name]
}

run "rejects_a_node_role_outside_the_sandbox_prefix" {
  command = plan

  variables {
    attested_node_roles = {
      nhp_cell0 = "OrganizationAccountAccessRole"
    }
  }

  expect_failures = [var.attested_node_roles]
}

run "rejects_a_duplicated_node_role" {
  command = plan

  variables {
    attested_node_roles = {
      nhp_cell0 = "layerv-nhp-sandbox-server"
      nhp_cell1 = "layerv-nhp-sandbox-server"
    }
  }

  expect_failures = [var.attested_node_roles]
}
