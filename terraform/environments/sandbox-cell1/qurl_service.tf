# =============================================================================
# Cell1 private qurl-service data plane
# =============================================================================
#
# This is intentionally NOT the Connector Authority. It is the cell-local
# qurl-service consumer/data plane used by the NHP server and, later, the
# cell-local qurl-reverse-tunnel-server. It owns only cell1-prefixed qURL tables
# and has no Control-VPC route, Authority table ARN, ticket-signing key, or
# catalog activation authority.
#
# Ordered dark rollout:
#   1. Apply with deploy_qurl_service=false. This creates only the exact
#      publisher role and the UNPUBLISHED runtime-contract parameter.
#   2. A qurl-service main-only publisher promotes one reviewed image as the
#      atomic {exact repository@sha256 URI, full source revision} contract. It
#      must also bind the source revision inside the image; Terraform never
#      infers it from cell0.
#   3. Set deploy_qurl_service=true and apply a reviewed saved plan. The module
#      creates cell1 tables/secrets/ECS/internal ALB/private DNS and pins the
#      task image as repo@sha256. Cell1 remains absent from the active catalog.

locals {
  qurl_service_repository_name       = "layerv/nhp-qurl"
  qurl_service_source_repository     = "layervai/qurl-service"
  qurl_service_runtime_contract_path = "/${var.environment}/nhp/qurl-service/runtime-contract"
  qurl_service_live_env_lock_path    = "/layerv-nhp-sandbox/qurl-live-env-lock"
  qurl_service_live_env_lock_arn     = "arn:aws:ssm:${data.aws_region.current.region}:${var.aws_account_id}:parameter${local.qurl_service_live_env_lock_path}"
  qurl_service_private_dns_name      = "qurl-api.${aws_service_discovery_private_dns_namespace.cell1.name}"
  qurl_service_private_origin        = "http://${local.qurl_service_private_dns_name}"
  # The environment root's name_prefix already contains "cell1" because it
  # namespaces stateful singleton resources and SSM paths. qurl-service itself
  # appends cell_id, so use the protocol-environment prefix for physical names
  # and keep the infrastructure prefix separately for collision-free SSM.
  qurl_service_resource_name_prefix = "layerv-nhp-${var.protocol_environment}"

  qurl_service_runtime_contract_raw = var.deploy_qurl_service ? data.aws_ssm_parameter.qurl_service_runtime_contract[0].insecure_value : ""
  # The fallback and the false-branch are `null`, NOT `{}`. Both arms of a
  # conditional (and of try()) are type-unified, and unifying the decoded
  # contract object -- whose schema_version is a JSON NUMBER -- with the empty
  # object `{}` collapses the whole value to map(string). That silently rewrote
  # schema_version to the STRING "1", which made two of the three fail-closed
  # preconditions below unsatisfiable by construction:
  #   * identity: `"1" == 1` is false in Terraform, so schema_version could
  #     never validate;
  #   * canonical: jsonencode() re-emitted `"schema_version":"1"` (230 bytes)
  #     while the publisher writes `"schema_version":1` (228 bytes), so the
  #     round-trip could never equal the raw parameter.
  # `null` carries no type, so unification preserves the decoded object exactly
  # and a correctly-published contract validates. Every consumer of this local
  # is either try()-guarded or count-gated behind qurl_service_deployable, so
  # the null path stays fail-closed when deploy_qurl_service = false.
  qurl_service_runtime_contract = var.deploy_qurl_service ? try(
    jsondecode(data.aws_ssm_parameter.qurl_service_runtime_contract[0].insecure_value),
    null,
  ) : null
  qurl_service_runtime_image_uri    = try(local.qurl_service_runtime_contract.image_uri, "")
  qurl_service_runtime_image_digest = try(split("@", local.qurl_service_runtime_image_uri)[1], "")
  # Contract-shape validation split into named sub-checks so the deployable
  # gate below AND the three fail-closed preconditions in
  # terraform_data.qurl_service_runtime_contract reference the same expressions
  # rather than re-authoring them (a silent-drift hazard). Each is individually
  # try()-guarded so it is safe to evaluate on the UNPUBLISHED sentinel or when
  # deploy_qurl_service = false (the contract is null).
  qurl_service_runtime_contract_keys_valid = try(
    toset(keys(local.qurl_service_runtime_contract)) == toset([
      "schema_version",
      "image_uri",
      "source_revision",
    ]),
    false,
  )
  # tostring() rather than a bare `== 1`, so this check cannot silently break
  # again if the fallbacks above ever stop being `null`. The exact numeric form
  # is not left to this check anyway: it is pinned, more strictly, by
  # qurl_service_runtime_contract_canonical_json below, which rebuilds the
  # document with a literal number and compares it to the raw parameter bytes.
  # A string-typed schema_version therefore still fails closed there.
  qurl_service_runtime_contract_identity_valid = try(
    tostring(local.qurl_service_runtime_contract.schema_version) == "1"
    && startswith(
      local.qurl_service_runtime_contract.image_uri,
      "${data.aws_ecr_repository.qurl_service.repository_url}@sha256:",
    )
    && can(regex("^sha256:[0-9a-f]{64}$", local.qurl_service_runtime_image_digest))
    && can(regex("^[0-9a-f]{40}$", local.qurl_service_runtime_contract.source_revision)),
    false,
  )
  # Rebuild the document from its parts rather than re-encoding the decoded
  # value. Re-encoding is what made this unsatisfiable before the `null`
  # fallbacks above: any type collapse rewrote schema_version to "1", so
  # jsonencode(<decoded>) emitted 230 bytes against the publisher's 228 and
  # could never equal the raw parameter for ANY valid contract.
  #
  # Reconstructing with a literal 1 removes that coupling entirely -- this
  # comparison no longer depends on how the decode happened to be typed -- and
  # is STRICTER than the original intent. It pins numeric form, key set, key
  # order (jsonencode sorts) and compact separators in one comparison against
  # the raw bytes, so a contract whose schema_version were 2, or string-typed,
  # or reordered, or whitespace-padded, still fails closed here.
  qurl_service_runtime_contract_canonical_json = try(
    local.qurl_service_runtime_contract_raw == jsonencode({
      schema_version  = 1
      image_uri       = local.qurl_service_runtime_contract.image_uri
      source_revision = local.qurl_service_runtime_contract.source_revision
    }),
    false,
  )
  qurl_service_deployable = (
    var.deploy_qurl_service
    && local.qurl_service_runtime_contract_keys_valid
    && local.qurl_service_runtime_contract_identity_valid
    && local.qurl_service_runtime_contract_canonical_json
  )

  qurl_service_name        = "${local.qurl_service_resource_name_prefix}-${var.cell_id}-qurl-api"
  qurl_service_cluster_arn = "arn:aws:ecs:${data.aws_region.current.region}:${var.aws_account_id}:cluster/${local.qurl_service_name}"
  qurl_service_service_arn = "arn:aws:ecs:${data.aws_region.current.region}:${var.aws_account_id}:service/${local.qurl_service_name}/${local.qurl_service_name}"
  qurl_service_task_arn    = "arn:aws:ecs:${data.aws_region.current.region}:${var.aws_account_id}:task/${local.qurl_service_name}/*"
  qurl_service_taskdef_arn = "arn:aws:ecs:${data.aws_region.current.region}:${var.aws_account_id}:task-definition/${local.qurl_service_name}:*"
  qurl_service_role_arns = [
    "arn:aws:iam::${var.aws_account_id}:role/${local.qurl_service_name}-execution",
    "arn:aws:iam::${var.aws_account_id}:role/${local.qurl_service_name}-task",
  ]
  # Publisher-created revisions retain the infrastructure's standard ownership
  # tags rather than silently dropping them on the first CI deployment. Every
  # value here is fixed in IAM; SourceRevision is the sole dynamic value.
  qurl_service_publisher_task_definition_tags = merge(local.common_tags, {
    Name             = local.qurl_service_name
    Component        = "qurl-service"
    Service          = "qurl"
    Cell             = var.cell_id
    LayerVCell       = var.cell_id
    ManagedBy        = "qurl-service-publisher"
    SourceRepository = local.qurl_service_source_repository
  })
  qurl_service_publisher_task_definition_tag_keys = sort(concat(
    keys(local.qurl_service_publisher_task_definition_tags),
    ["SourceRevision"],
  ))
  # aws:RequestTag/<key> = <value> condition map, shared by the publisher's
  # RegisterTaskDefinition and TagResource statements so both pin the exact same
  # required-tag set from one source.
  qurl_service_publisher_request_tag_conditions = {
    for tag_key, tag_value in local.qurl_service_publisher_task_definition_tags :
    "aws:RequestTag/${tag_key}" => tag_value
  }

  # Container reservation for the single qurl-api container. cell1 runs no ADOT
  # sidecar, so var.grafana_cloud_enabled stays at its module default of false.
  qurl_service_container_cpu    = 256
  qurl_service_container_memory = 512

  # The task-level shape the module actually registers, which is NOT the
  # container reservation above. Fargate accepts only a fixed set of
  # CPU/memory combinations, so the module rounds memory up to a whole GB:
  # ceil(512 / 1024) * 1024 = 1024. Task CPU is unchanged at 256 because
  # nothing raises it without the sidecar.
  #
  # The publisher's ecs:task-cpu / ecs:task-memory IAM conditions below pin
  # this shape, so they MUST use these values and not the container
  # reservation. A stale pin is invisible at plan time and surfaces only as
  # AccessDenied on ecs:RegisterTaskDefinition during a deploy —
  # qurl_service_publisher_task_shape_lockstep fences that against the
  # module's own output.
  qurl_service_runtime_task_cpu    = local.qurl_service_container_cpu
  qurl_service_runtime_task_memory = ceil(local.qurl_service_container_memory / 1024) * 1024
}

data "aws_ecr_repository" "qurl_service" {
  name = local.qurl_service_repository_name
}

# One parameter makes exact-image/source promotion atomic. Separate
# independently writable parameters could briefly pair a new digest with an
# old commit (or vice versa), which is unusable evidence and can deploy the
# wrong source.
resource "aws_ssm_parameter" "qurl_service_runtime_contract" {
  name        = local.qurl_service_runtime_contract_path
  description = "Atomic immutable runtime contract for the private cell1 qurl-service"
  type        = "String"
  value = jsonencode({
    schema_version = 1
    status         = "UNPUBLISHED"
  })

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-qurl-service-runtime-contract"
    Component = "qurl-service"
    Purpose   = "Immutable cell runtime promotion"
  })

  lifecycle {
    # The dedicated qurl-service publisher owns the live value after this
    # foundation exists. Runtime Terraform reads it through the data source
    # below and fails closed on the sentinel or any non-canonical shape.
    ignore_changes = [value]
  }
}

data "aws_ssm_parameter" "qurl_service_runtime_contract" {
  count = var.deploy_qurl_service ? 1 : 0

  name            = aws_ssm_parameter.qurl_service_runtime_contract.name
  with_decryption = false
}

data "aws_ecr_image" "qurl_service_runtime" {
  count = local.qurl_service_deployable ? 1 : 0

  repository_name = data.aws_ecr_repository.qurl_service.name
  image_digest    = local.qurl_service_runtime_image_digest
}

resource "terraform_data" "qurl_service_runtime_contract" {
  count = var.deploy_qurl_service ? 1 : 0

  input = local.qurl_service_runtime_contract

  lifecycle {
    precondition {
      condition     = local.qurl_service_runtime_contract_keys_valid
      error_message = "Cell1 qurl-service runtime contract must contain exactly schema_version, image_uri, and source_revision. Run the governed qurl-service publisher; do not hand-edit or copy cell0 runtime state."
    }
    precondition {
      condition     = local.qurl_service_runtime_contract_identity_valid
      error_message = "Cell1 qurl-service runtime contract identity/digest/source revision is malformed or unproven."
    }
    precondition {
      condition     = local.qurl_service_runtime_contract_canonical_json
      error_message = "Cell1 qurl-service runtime contract must be canonical compact JSON. The governed publisher must write jsonencode({schema_version,image_uri,source_revision}) as one SSM PutParameter operation."
    }
  }
}

resource "terraform_data" "qurl_service_runtime_image" {
  count = local.qurl_service_deployable ? 1 : 0

  input = {
    image_uri       = local.qurl_service_runtime_image_uri
    source_revision = local.qurl_service_runtime_contract.source_revision
  }

  lifecycle {
    precondition {
      condition = try(
        data.aws_ecr_image.qurl_service_runtime[0].image_digest == local.qurl_service_runtime_image_digest
        && contains(
          try(tolist(data.aws_ecr_image.qurl_service_runtime[0].image_tags), []),
          local.qurl_service_runtime_contract.source_revision,
        ),
        false,
      )
      error_message = "Cell1 qurl-service digest must exist in layerv/nhp-qurl and retain the full 40-hex source_revision tag. The publisher must bind and promote that exact pair; a short tag is insufficient."
    }
  }
}

# Main-ref-only qurl-service publication/deployment capability for this cell
# only. AWS IAM cannot evaluate GitHub's workflow_ref custom claim, so the role
# binds the exact repository + main ref. The producer workflow must fail before
# credential assumption unless github.workflow_ref equals its reviewed,
# main-branch workflow path; the rollout runbook records that unavoidable
# workflow-level half of the boundary.
# It can read the shared image, atomically update the one promotion parameter,
# and roll only the deterministic cell1 ECS service. It cannot push/delete ECR
# images, read secrets, mutate DynamoDB, call Authority, or touch cell0.
resource "aws_iam_role" "qurl_service_publisher" {
  name                 = "${local.name_prefix}-qurl-service-publisher"
  description          = "Promote and deploy the private cell1 qurl-service runtime"
  max_session_duration = 10800

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "QurlServiceMainRef"
      Effect = "Allow"
      Principal = {
        Federated = "arn:aws:iam::${var.aws_account_id}:oidc-provider/token.actions.githubusercontent.com"
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:${local.qurl_service_source_repository}:ref:refs/heads/main"
        }
      }
    }]
  })

  tags = merge(local.common_tags, {
    Name       = "${local.name_prefix}-qurl-service-publisher"
    Component  = "qurl-service"
    Purpose    = "Cell1 immutable image promotion"
    SourceRepo = local.qurl_service_source_repository
  })
}

resource "aws_iam_role_policy" "qurl_service_publisher" {
  name = "promote-and-deploy-cell1-qurl-service"
  role = aws_iam_role.qurl_service_publisher.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AuthorizeECRRead"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Sid    = "ReadPublishedImage"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:BatchGetImage",
          "ecr:DescribeImages",
          "ecr:GetDownloadUrlForLayer",
        ]
        Resource = data.aws_ecr_repository.qurl_service.arn
      },
      {
        Sid      = "PublishAtomicRuntimeContract"
        Effect   = "Allow"
        Action   = ["ssm:GetParameter", "ssm:PutParameter"]
        Resource = aws_ssm_parameter.qurl_service_runtime_contract.arn
      },
      {
        Sid      = "CoordinateSharedSandboxMutation"
        Effect   = "Allow"
        Action   = ["ssm:DeleteParameter", "ssm:GetParameter", "ssm:PutParameter"]
        Resource = local.qurl_service_live_env_lock_arn
      },
      {
        Sid      = "EmitSandboxLockFailureMetric"
        Effect   = "Allow"
        Action   = ["cloudwatch:PutMetricData"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "LayerV/QURLServiceCI"
          }
        }
      },
      {
        Sid      = "ReadCell1ECS"
        Effect   = "Allow"
        Action   = ["ecs:DescribeServices"]
        Resource = local.qurl_service_service_arn
      },
      {
        Sid      = "DeployOnlyCell1Service"
        Effect   = "Allow"
        Action   = ["ecs:UpdateService"]
        Resource = local.qurl_service_service_arn
        Condition = {
          ArnEquals = {
            "ecs:cluster" = local.qurl_service_cluster_arn
          }
          ArnLike = {
            "ecs:task-definition" = local.qurl_service_taskdef_arn
          }
        }
      },
      {
        Sid      = "ListOnlyCell1Tasks"
        Effect   = "Allow"
        Action   = ["ecs:ListTasks"]
        Resource = "*"
        Condition = {
          ArnEquals = {
            "ecs:cluster" = local.qurl_service_cluster_arn
          }
        }
      },
      {
        Sid      = "ReadCell1Tasks"
        Effect   = "Allow"
        Action   = ["ecs:DescribeTasks"]
        Resource = local.qurl_service_task_arn
      },
      {
        Sid      = "DescribeTaskDefinition"
        Effect   = "Allow"
        Action   = ["ecs:DescribeTaskDefinition"]
        Resource = "*"
      },
      {
        Sid    = "RegisterOnlyCell1TaskDefinition"
        Effect = "Allow"
        Action = ["ecs:RegisterTaskDefinition"]
        # The current ECS Service Authorization Reference supports the
        # task-definition resource type for RegisterTaskDefinition. Scope the
        # create to this exact family and constrain the complete request shape.
        Resource = local.qurl_service_taskdef_arn
        Condition = {
          StringEquals = local.qurl_service_publisher_request_tag_conditions
          Null = {
            "aws:RequestTag/SourceRevision" = "false"
            "ecs:compute-compatibility"     = "false"
          }
          Bool = {
            "ecs:privileged" = "false"
          }
          NumericEquals = {
            "ecs:task-cpu"    = local.qurl_service_runtime_task_cpu
            "ecs:task-memory" = local.qurl_service_runtime_task_memory
          }
          "ForAllValues:StringEquals" = {
            "aws:TagKeys"               = local.qurl_service_publisher_task_definition_tag_keys
            "ecs:compute-compatibility" = ["FARGATE"]
          }
        }
      },
      {
        Sid      = "TagRegisteredTaskDefinition"
        Effect   = "Allow"
        Action   = ["ecs:TagResource"]
        Resource = local.qurl_service_taskdef_arn
        Condition = {
          StringEquals = merge(
            local.qurl_service_publisher_request_tag_conditions,
            {
              "ecs:CreateAction" = "RegisterTaskDefinition"
            },
          )
          Null = {
            "aws:RequestTag/SourceRevision" = "false"
          }
          "ForAllValues:StringEquals" = {
            "aws:TagKeys" = local.qurl_service_publisher_task_definition_tag_keys
          }
        }
      },
      {
        Sid      = "PassOnlyCell1TaskRoles"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = local.qurl_service_role_arns
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "ecs-tasks.amazonaws.com"
          }
        }
      },
    ]
  })
}

# Lockstep guard: every publisher IAM ARN above (cluster, service, task,
# task-definition, and the passed task/execution roles) is derived from
# local.qurl_service_name, which independently reconstructs the qurl-service
# module's naming convention. If the module ever computes a different physical
# name, those narrowly-scoped grants would silently point at nonexistent ARNs
# and the publisher would fail at deploy time with opaque AccessDenied. Prove
# the reconstruction matches the live cluster/service whenever the module is
# actually deployed (the only point the real resources exist to compare).
resource "terraform_data" "qurl_service_publisher_name_lockstep" {
  count = local.qurl_service_deployable ? 1 : 0

  lifecycle {
    precondition {
      condition = (
        module.qurl_service[0].cluster_name == local.qurl_service_name
        && module.qurl_service[0].service_name == local.qurl_service_name
      )
      error_message = "Publisher IAM ARNs derive from local.qurl_service_name, but the qurl-service module produced a different cluster/service name. Re-align local.qurl_service_resource_name_prefix with the module's naming before deploying; otherwise the scoped publisher grants reference the wrong ARNs."
    }
  }
}

# The publisher's RegisterTaskDefinition grant pins ecs:task-cpu/ecs:task-memory
# with NumericEquals, so those numbers must equal the task shape the module
# actually registers. They are easy to get wrong because the task shape is not
# the container reservation: Fargate accepts only a fixed set of CPU/memory
# combinations, so the module rounds memory up to a whole GB. A stale pin is
# completely invisible at plan time — the policy applies cleanly and then denies
# the publisher's ecs:RegisterTaskDefinition at deploy time with an opaque
# AccessDenied. Prove the pin against the module's own effective shape whenever
# the module is actually deployed.
resource "terraform_data" "qurl_service_publisher_task_shape_lockstep" {
  count = local.qurl_service_deployable ? 1 : 0

  lifecycle {
    precondition {
      condition = (
        tostring(module.qurl_service[0].task_cpu) == tostring(local.qurl_service_runtime_task_cpu)
        && tostring(module.qurl_service[0].task_memory) == tostring(local.qurl_service_runtime_task_memory)
      )
      error_message = "The cell1 publisher's ecs:task-cpu/ecs:task-memory IAM conditions must equal the qurl-service module's effective Fargate task shape. The module rounds container_memory up to a whole GB for CPU/memory-combination validity, so the pin is not the container reservation. Re-align local.qurl_service_runtime_task_cpu/local.qurl_service_runtime_task_memory with the module's task_cpu/task_memory outputs before deploying; otherwise the publisher is denied ecs:RegisterTaskDefinition at deploy time."
    }
  }
}

# qurl-service runtime secrets are independent of cell0 and Control. Values are
# generated out of band from Terraform state, then read only by the exact ECS
# execution role (and the NHP server for the internal token).
resource "aws_secretsmanager_secret" "qurl_service" {
  for_each = local.qurl_service_deployable ? toset(["jwt", "internal-token"]) : toset([])

  name                    = "${local.name_prefix}-qurl-${each.key}"
  description             = "Private cell1 qurl-service ${each.key}"
  recovery_window_in_days = 0
  kms_key_id              = module.kms.secrets_key_arn

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-qurl-${each.key}"
    Component = "qurl-service"
    Purpose   = "Cell-local runtime secret"
  })
}

resource "terraform_data" "qurl_service_secret_seed" {
  for_each = aws_secretsmanager_secret.qurl_service

  triggers_replace = [each.value.arn]

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -euo pipefail
      value=$(aws secretsmanager get-random-password \
        --region "${data.aws_region.current.region}" \
        --password-length 48 \
        --exclude-punctuation \
        --query RandomPassword \
        --output text)
      if [ -z "$value" ]; then
        echo "ERROR: get-random-password returned empty for ${each.key}" >&2
        exit 1
      fi
      printf '%s' "$value" |
        aws secretsmanager put-secret-value \
          --region "${data.aws_region.current.region}" \
          --secret-id "${each.value.id}" \
          --secret-string file:///dev/stdin >/dev/null
    EOT
  }
}

# Keep feedback delivery dark until an operator installs the dedicated Slack
# incoming webhook directly in Secrets Manager. Terraform owns only the
# sentinel value used on first creation, never the production credential.
resource "aws_secretsmanager_secret" "qurl_feedback_slack_webhook" {
  count = local.qurl_service_deployable ? 1 : 0

  name                    = "${local.name_prefix}-qurl-feedback-slack-webhook"
  description             = "Slack incoming webhook for authenticated qURL Desktop feedback"
  recovery_window_in_days = 0
  kms_key_id              = module.kms.secrets_key_arn

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-qurl-feedback-slack-webhook"
    Component = "qurl-service"
    Purpose   = "Desktop feedback delivery"
  })
}

resource "terraform_data" "qurl_feedback_slack_webhook_seed" {
  count            = local.qurl_service_deployable ? 1 : 0
  triggers_replace = [aws_secretsmanager_secret.qurl_feedback_slack_webhook[0].arn]

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -euo pipefail
      printf '%s' 'DISABLED' |
        aws secretsmanager put-secret-value \
          --region "${data.aws_region.current.region}" \
          --secret-id "${aws_secretsmanager_secret.qurl_feedback_slack_webhook[0].id}" \
          --secret-string file:///dev/stdin >/dev/null
    EOT
  }
}

# Deliberately omit a secret-version data source/check: once an operator
# installs the webhook, reading secret_string would copy the credential into
# Terraform state. A failed local-exec instead taints this seed for retry.

module "qurl_service" {
  count  = local.qurl_service_deployable ? 1 : 0
  source = "../../modules/qurl-service"

  environment = var.environment
  name_prefix = local.name_prefix
  cell_id     = var.cell_id
  tags        = merge(local.common_tags, { Service = "qurl" })

  # Required by the image itself, not optional hardening -- see the comment on
  # module.kms in main.tf. The module's own precondition also refuses the flag
  # without a non-empty envelope CMK, which module.kms only creates when its
  # matching flag is true, so these two move together by construction.
  qurl_v2_resource_keys_enabled         = true
  qurl_v2_resource_key_envelope_key_arn = module.kms.qurl_v2_resource_key_envelope_key_arn

  resource_name_prefix = local.qurl_service_resource_name_prefix

  vpc_id             = module.networking.vpc_id
  vpc_cidr           = module.networking.vpc_cidr
  private_subnet_ids = module.networking.private_subnet_ids
  # The primary ALB is private in this mode, so its subnets are also private.
  public_subnet_ids          = module.networking.private_subnet_ids
  public_ingress_enabled     = false
  ingress_security_group_ids = [module.compute.security_group_id]
  api_base_url               = local.qurl_service_private_origin
  enforce_internal_alb_only  = true

  # Deny list of this cell's root-delegating CMKs, mirroring
  # local.qurl_v2_resource_key_protected_kms_arns in terraform/main.tf. Without
  # it a compromised task could TagResource one of these with
  # purpose=qurl-v2-resource-key and reach it through the tag-scoped grant --
  # including ScheduleKeyDeletion on the envelope CMK every wrapped software
  # resource key depends on. The module refuses the feature with an empty list
  # rather than silently granting the tag-scoped policy with no Deny.
  #
  # compact() drops qurl_v2_issuer_key_arn, which is null here because cell1
  # deliberately keeps issuance dark (module.kms in main.tf).
  qurl_v2_resource_key_protected_kms_arns = compact([
    module.kms.ebs_key_arn,
    module.kms.efs_key_arn,
    module.kms.secrets_key_arn,
    module.kms.logs_key_arn,
    module.kms.rds_key_arn,
    module.kms.qurl_v2_issuer_key_arn,
    module.kms.qurl_v2_resource_key_envelope_key_arn,
  ])

  ecr_repo_url        = data.aws_ecr_repository.qurl_service.repository_url
  image_tag_ssm_param = "/${local.name_prefix}/qurl-api-image-tag"
  image_uri           = local.qurl_service_runtime_contract.image_uri
  source_revision     = local.qurl_service_runtime_contract.source_revision
  container_cpu       = local.qurl_service_container_cpu
  container_memory    = local.qurl_service_container_memory
  desired_count       = 1

  dynamodb_table_arns      = module.dynamodb.qurl_table_arns
  qurl_resources_table_arn = module.dynamodb.qurl_resources_table_arn
  # These pre-existing cell1 tables were created by module.dynamodb with the
  # infrastructure namespace plus cell_id. Keep the runtime prefix byte-exact;
  # renaming applied stateful tables is unrelated to canonicalizing the new,
  # not-yet-created qurl-service resource family.
  dynamodb_table_prefix            = "${local.name_prefix}-${var.cell_id}"
  nhp_resources_table_name         = module.dynamodb.resources_table_name
  nhp_resources_table_arn          = module.dynamodb.resources_table_arn
  nhp_resources_customer_id_prefix = "00000000000000000000000001"

  auth0_domain                     = var.qurl_auth0_domain
  auth0_jwks_cache_ttl_seconds     = 3600
  auth0_jwks_fetch_timeout_seconds = 10

  secrets_kms_key_arn               = module.kms.secrets_key_arn
  logs_kms_key_arn                  = module.kms.logs_key_arn
  jwt_secret_arn                    = aws_secretsmanager_secret.qurl_service["jwt"].arn
  internal_service_token_arn        = aws_secretsmanager_secret.qurl_service["internal-token"].arn
  nhp_internal_auth_secret_arn      = aws_secretsmanager_secret.nhp_internal_auth.arn
  feedback_slack_webhook_secret_arn = aws_secretsmanager_secret.qurl_feedback_slack_webhook[0].arn

  nhp_server_internal_url      = "http://${module.compute.cloudmap_service_dns}:8888"
  nhp_server_security_group_id = module.compute.security_group_id

  cookie_domain        = var.qurl_cookie_domain
  qurl_link_domain     = var.qurl_link_domain
  qurl_site_domain     = var.qurl_site_domain
  default_token_expire = 3600
  default_open_time    = 300
  default_ac_id        = "cell1-dark"

  ip_rate_limit            = 300
  ip_rate_burst            = 100
  audit_retention_days     = 90
  cors_allowed_origins     = ""
  additional_allowed_hosts = [local.qurl_service_private_dns_name]

  idempotency_table_name               = module.dynamodb.qurl_idempotency_table_name
  idempotency_table_arn                = module.dynamodb.qurl_idempotency_table_arn
  idempotency_cache_ttl_seconds        = 300
  idempotency_cache_max_size           = 1000
  idempotency_cleanup_interval_seconds = 60
  apikey_idempotency_table_name        = module.dynamodb.qurl_apikey_idempotency_table_name
  apikey_idempotency_table_arn         = module.dynamodb.qurl_apikey_idempotency_table_arn

  health_check_timeout_seconds   = 10
  health_startup_timeout_seconds = 30

  webhooks_enabled                       = false
  webhooks_worker_count                  = 4
  webhooks_max_webhooks_per_owner        = 10
  webhooks_delivery_timeout_seconds      = 30
  webhooks_max_retries                   = 5
  webhooks_event_channel_size            = 1000
  webhooks_retry_worker_interval_seconds = 30
  webhooks_drain_timeout_seconds         = 30
  webhooks_response_body_limit           = 8192
  webhooks_api_version                   = "2024-01-01"

  otel_enabled           = false
  otel_service_name      = "qurl-api"
  otel_service_version   = "dark"
  otel_environment       = var.environment
  otel_exporter_endpoint = "http://localhost:4317"
  otel_exporter_protocol = "grpc"
  otel_exporter_insecure = true
  otel_trace_sample_rate = 0
  otel_metrics_interval  = 60
  otel_metrics_enabled   = false
  otel_tracing_enabled   = false
  otel_log_correlation   = false

  connector_auth_enabled      = false
  target_health_alarm_enabled = true

  depends_on = [
    terraform_data.qurl_service_runtime_contract,
    terraform_data.qurl_service_runtime_image,
    terraform_data.qurl_service_secret_seed,
    terraform_data.nhp_internal_auth_seed,
    terraform_data.qurl_feedback_slack_webhook_seed,
  ]
}

# Private cell1 name for the internal qurl ALB. Resolves only from the cell1
# VPC and targets an internal ALB whose SG admits only the NHP server SG. There
# is no public record and no 0.0.0.0/0 listener rule.
#
# This MUST go through Cloud Map, not aws_route53_record. The zone behind
# aws_service_discovery_private_dns_namespace is owned by Cloud Map, and Route53
# refuses direct writes to it:
#
#   AccessDenied: The resource hostedzone/Z10224932OY0NJE0XW9SV can only be
#   managed through AWS Cloud Map (arn:aws:servicediscovery:...:namespace/...)
#
# so the previous aws_route53_record alias could never apply. It had never run
# before because this is the first apply with deploy_qurl_service = true.
#
# Cloud Map cannot express a Route53 *alias* to an ALB, so this registers a
# CNAME instance instead. The resolved name is byte-identical
# (qurl-api.<namespace>), which is what keeps qurl_service_private_origin and
# every consumer of it unchanged. CNAME records in Cloud Map require the
# WEIGHTED routing policy.
#
# The one behavioural difference from the unusable alias is that an alias would
# have carried evaluate_target_health. Target health is still enforced where it
# matters -- the ALB health-checks its own targets and fails requests to
# unhealthy ones -- this only means DNS itself does not withdraw the name.
resource "aws_service_discovery_service" "qurl_service_private" {
  count = local.qurl_service_deployable ? 1 : 0

  name = "qurl-api"

  dns_config {
    namespace_id   = aws_service_discovery_private_dns_namespace.cell1.id
    routing_policy = "WEIGHTED"

    dns_records {
      ttl  = 60
      type = "CNAME"
    }
  }

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-qurl-api"
    Component = "qurl-service"
  })
}

resource "aws_service_discovery_instance" "qurl_service_private" {
  count = local.qurl_service_deployable ? 1 : 0

  instance_id = "qurl-api-alb"
  service_id  = aws_service_discovery_service.qurl_service_private[0].id

  attributes = {
    AWS_INSTANCE_CNAME = module.qurl_service[0].alb_dns_name
  }
}
