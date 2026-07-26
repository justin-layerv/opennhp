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
  qurl_service_private_dns_name      = "qurl-api.${aws_service_discovery_private_dns_namespace.cell1.name}"
  qurl_service_private_origin        = "http://${local.qurl_service_private_dns_name}"
  # The environment root's name_prefix already contains "cell1" because it
  # namespaces stateful singleton resources and SSM paths. qurl-service itself
  # appends cell_id, so use the protocol-environment prefix for physical names
  # and keep the infrastructure prefix separately for collision-free SSM.
  qurl_service_resource_name_prefix = "layerv-nhp-${var.protocol_environment}"

  qurl_service_runtime_contract_raw = var.deploy_qurl_service ? data.aws_ssm_parameter.qurl_service_runtime_contract[0].insecure_value : ""
  qurl_service_runtime_contract = var.deploy_qurl_service ? try(
    jsondecode(data.aws_ssm_parameter.qurl_service_runtime_contract[0].insecure_value),
    {},
  ) : {}
  qurl_service_runtime_image_uri    = try(local.qurl_service_runtime_contract.image_uri, "")
  qurl_service_runtime_image_digest = try(split("@", local.qurl_service_runtime_image_uri)[1], "")
  # Contract-shape validation split into named sub-checks so the deployable
  # gate below AND the three fail-closed preconditions in
  # terraform_data.qurl_service_runtime_contract reference the same expressions
  # rather than re-authoring them (a silent-drift hazard). Each is individually
  # try()-guarded so it is safe to evaluate on the UNPUBLISHED sentinel or when
  # deploy_qurl_service = false (the contract decodes to {}).
  qurl_service_runtime_contract_keys_valid = try(
    toset(keys(local.qurl_service_runtime_contract)) == toset([
      "schema_version",
      "image_uri",
      "source_revision",
    ]),
    false,
  )
  qurl_service_runtime_contract_identity_valid = try(
    local.qurl_service_runtime_contract.schema_version == 1
    && startswith(
      local.qurl_service_runtime_contract.image_uri,
      "${data.aws_ecr_repository.qurl_service.repository_url}@sha256:",
    )
    && can(regex("^sha256:[0-9a-f]{64}$", local.qurl_service_runtime_image_digest))
    && can(regex("^[0-9a-f]{40}$", local.qurl_service_runtime_contract.source_revision)),
    false,
  )
  qurl_service_runtime_contract_canonical_json = try(
    local.qurl_service_runtime_contract_raw == jsonencode(local.qurl_service_runtime_contract),
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
  max_session_duration = 3600

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
            "ecs:task-cpu"    = 256
            "ecs:task-memory" = 512
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

module "qurl_service" {
  count  = local.qurl_service_deployable ? 1 : 0
  source = "../../modules/qurl-service"

  environment = var.environment
  name_prefix = local.name_prefix
  cell_id     = var.cell_id
  tags        = merge(local.common_tags, { Service = "qurl" })

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

  ecr_repo_url        = data.aws_ecr_repository.qurl_service.repository_url
  image_tag_ssm_param = "/${local.name_prefix}/qurl-api-image-tag"
  image_uri           = local.qurl_service_runtime_contract.image_uri
  source_revision     = local.qurl_service_runtime_contract.source_revision
  container_cpu       = 256
  container_memory    = 512
  desired_count       = 1

  dynamodb_table_arns = module.dynamodb.qurl_table_arns
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

  secrets_kms_key_arn          = module.kms.secrets_key_arn
  logs_kms_key_arn             = module.kms.logs_key_arn
  jwt_secret_arn               = aws_secretsmanager_secret.qurl_service["jwt"].arn
  internal_service_token_arn   = aws_secretsmanager_secret.qurl_service["internal-token"].arn
  nhp_internal_auth_secret_arn = aws_secretsmanager_secret.nhp_internal_auth.arn

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

  connector_auth_enabled                 = false
  connector_active_registrations_enabled = false
  target_health_alarm_enabled            = true

  depends_on = [
    terraform_data.qurl_service_runtime_contract,
    terraform_data.qurl_service_runtime_image,
    terraform_data.qurl_service_secret_seed,
    terraform_data.nhp_internal_auth_seed,
  ]
}

# Private Route53 alias inside the cell1 Cloud Map namespace. It resolves only
# from the cell1 VPC and targets an internal ALB whose SG admits only the NHP
# server SG. There is no public record and no 0.0.0.0/0 listener rule.
resource "aws_route53_record" "qurl_service_private" {
  count = local.qurl_service_deployable ? 1 : 0

  zone_id = aws_service_discovery_private_dns_namespace.cell1.hosted_zone
  name    = local.qurl_service_private_dns_name
  type    = "A"

  alias {
    name                   = module.qurl_service[0].alb_dns_name
    zone_id                = module.qurl_service[0].alb_zone_id
    evaluate_target_health = true
  }
}
