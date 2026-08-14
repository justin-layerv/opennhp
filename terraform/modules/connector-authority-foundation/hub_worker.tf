# Connector Hub Fargate worker (Step 5, slice 5b). DARK-FIRST: every resource
# here is gated on local.hub_worker_deploy and count=0 until this slice's apply
# flips var.hub_worker_enabled true. The worker is the compute that sits BEHIND
# the 5a public UDP edge (hub_edge.tf) -- Fargate tasks register their awsvpc IPs
# into the 5a NLB target group and speak native UDP/62206 to callers, terminating
# the knock and invoking the three live Authority aliases over the (now-opened)
# Lambda interface endpoint.
#
# The worker requires BOTH dependencies live, enforced by the fail-closed
# precondition in main.tf: the 5a public edge (hub_edge_enabled -- so the NLB
# target group + listener exist to register into) AND the Authority Lambda
# runtime (authority_runtime_functions_deploy -- so the 3 :color alias targets
# the worker invokes exist). Constructed role ARNs (below) keep the opened
# endpoint policies plan-known and break the endpoint<->role dependency cycle,
# exactly like the authority runtime's exec-role ARNs.

locals {
  # Single dark-first gate for the whole Hub worker. Kept separate from the 5a
  # edge gate and the authority runtime gate: all three flip in independent
  # applies, and the worker's precondition requires the other two already live.
  hub_worker_enabled = var.hub_worker_enabled
  hub_worker_deploy  = var.hub_worker_enabled
  hub_worker_count   = var.hub_worker_enabled ? 1 : 0

  # Task/execution identity is constructed (account + deterministic name) so the
  # Lambda/ECR/S3 endpoint policies that name these principals are fully known at
  # plan time and independently checkable, and so no dependency cycle forms
  # between an endpoint, its policy, and the role. The IAM role `name`
  # attributes below MUST equal these suffixes or the constructed ARN drifts.
  hub_task_role_arn      = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/${local.name_prefix}-hub-task"
  hub_execution_role_arn = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/${local.name_prefix}-hub-exec"

  # The 3 Hub-facing Authority functions' closed blue AND green alias ARNs,
  # sorted for the task IAM policy and Lambda endpoint policy. ECS deployment
  # overlap intentionally keeps the previous Hub task revision serving while
  # replacements start. The old revision still invokes the previously selected
  # alias, so narrowing these policies to only the new selector causes transient
  # authenticated assignment failures until the old targets drain.
  #
  # Both aliases remain closed qualified targets and neither is reachable by a
  # Hub task unless that task's immutable runtime config names it. The selector
  # therefore continues to own traffic while the policy merely makes rolling
  # replacement safe. The guard keeps this empty while the worker is dark.
  hub_authority_alias_arns = local.hub_worker_deploy ? sort(flatten([
    for selected_alias_arn in values(local.authority_selected_alias_targets.hub) : [
      for color in local.authority_runtime_alias_colors :
      "${trimsuffix(trimsuffix(selected_alias_arn, ":blue"), ":green")}:${color}"
    ]
  ])) : []

  # The publisher-owned digest pin resolves the immutable image the worker runs.
  # UNPUBLISHED (or any non-sha256 value) is rejected by the task-definition
  # precondition below, mirroring the authority runtime's digest gate.
  hub_image_digest = local.hub_worker_deploy ? data.aws_ssm_parameter.hub_image_digest[0].value : ""
  hub_image_uri    = "${aws_ecr_repository.hub.repository_url}@${local.hub_image_digest}"

  # The Hub log group name is referenced both by the log-group resource and by
  # each container's awslogs driver, so it lives in one place.
  hub_log_group_name     = "/layerv/nhp/${var.environment}/control/hub"
  hub_log_retention_days = local.is_prod ? 365 : 30

  # Immutable public runtime config handed to the init container as one JSON
  # blob (NHP_HUB_PUBLIC_CONFIG_JSON). Every field is non-secret; the private
  # key and cookie keys arrive separately via the Secrets Manager `secrets`
  # wiring so no key byte is ever an environment literal. The three alias ARNs
  # are guarded so the blob resolves to empty strings while the worker is dark
  # (it is only consumed inside the count-gated task definition).
  #
  # FLAG: the staged latency ladder below is a structural placeholder to be
  # reconciled against the handler's measurement basis before enable
  # (ladder holds: 3<=9<15<25<30; 0<3<=8<=25-15=10).
  hub_public_config_json = jsonencode({
    environment                         = var.environment
    udp_listen_addr                     = "0.0.0.0:62206"
    health_listen_addr                  = "0.0.0.0:62207"
    aws_region                          = data.aws_region.current.region
    aws_account_id                      = data.aws_caller_identity.current.account_id
    issue_assignment_alias_arn          = local.hub_worker_deploy ? local.authority_selected_alias_targets.hub["issue_assignment"] : ""
    refresh_assignment_alias_arn        = local.hub_worker_deploy ? local.authority_selected_alias_targets.hub["refresh_assignment"] : ""
    issue_credential_recovery_alias_arn = local.hub_worker_deploy ? local.authority_selected_alias_targets.hub["issue_credential_recovery"] : ""
    authority_lambda_timeout            = "9s"
    handler_budget                      = "15s"
    packet_budget                       = "25s"
    response_reserve                    = "8s"
    write_budget                        = "3s"
    max_concurrent_packets              = 64
    packets_per_second                  = 128
    packet_burst                        = 256
    max_concurrent_per_peer             = 4
    response_queue_capacity             = 64
  })
}

# Publisher-owned digest pin. Read live (not the managed UNPUBLISHED default) so
# the worker resolves the exact immutable image; disappears while the worker is
# dark. The task-definition precondition rejects a non-sha256 value.
data "aws_ssm_parameter" "hub_image_digest" {
  count = local.hub_worker_count

  name = local.hub_image_digest_parameter_name
}

# --------------------------------------------------------------------------
# Seeded key material secret.
# --------------------------------------------------------------------------
# The Hub's long-lived private key plus the active/previous cookie keys. Created
# empty here, then seeded or retry-repaired by the CREATE_ONLY keygen Lambda
# (hub_keygen.tf) so no private or cookie key byte ever transits Terraform
# state; the execution role reads it and the init container maps its JSON
# fields into the worker's env. Encrypted with the shared Control data CMK like
# every other Authority secret.
resource "aws_secretsmanager_secret" "hub_key_material" {
  count = local.hub_worker_count

  name                    = "${local.name_prefix}-hub-key-material"
  description             = "Connector Hub private key and cookie keys; seeded once by the keygen Lambda, never via Terraform state"
  kms_key_id              = aws_kms_key.authority_data.arn
  recovery_window_in_days = local.is_prod ? 30 : 7

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-hub-key-material"
    Component = "connector-hub"
    Purpose   = "Connector Hub key material"
  })
}

# --------------------------------------------------------------------------
# ECS task execution role (Fargate agent identity).
# --------------------------------------------------------------------------
# Used by the Fargate agent (NOT the container) to pull the image, decrypt the
# seeded secret, and ship container logs. Named exactly ${name_prefix}-hub-exec
# so local.hub_execution_role_arn (used in the ECR/S3 endpoint policies) is
# exact.
resource "aws_iam_role" "hub_execution" {
  count = local.hub_worker_count

  name                 = "${local.name_prefix}-hub-exec"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "EcsTasksAssume"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.${data.aws_partition.current.dns_suffix}"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-hub-exec"
    Component = "connector-hub"
  })
}

# The AWS-managed execution baseline grants ECR pull + the CloudWatch Logs
# create/put the awslogs driver needs. The secret decrypt/read is added by the
# scoped inline policy below (the managed policy alone cannot read this secret).
resource "aws_iam_role_policy_attachment" "hub_execution" {
  count = local.hub_worker_count

  role       = aws_iam_role.hub_execution[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Scoped secret access for the Fargate agent: GetSecretValue on ONLY the Hub key
# material secret, and kms:Decrypt on ONLY the Control data CMK that encrypts it.
# The `secrets` block in the task definition resolves the secret at task start
# using exactly these two grants.
resource "aws_iam_role_policy" "hub_execution" {
  count = local.hub_worker_count

  name = "hub-execution"
  role = aws_iam_role.hub_execution[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadHubKeyMaterial"
        Effect   = "Allow"
        Action   = "secretsmanager:GetSecretValue"
        Resource = aws_secretsmanager_secret.hub_key_material[0].arn
      },
      {
        Sid      = "DecryptHubKeyMaterial"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = aws_kms_key.authority_data.arn
        Condition = {
          StringEquals = {
            "kms:ViaService"                  = "secretsmanager.${data.aws_region.current.region}.${data.aws_partition.current.dns_suffix}"
            "kms:EncryptionContext:SecretARN" = aws_secretsmanager_secret.hub_key_material[0].arn
          }
        }
      },
    ]
  })
}

# --------------------------------------------------------------------------
# ECS task role (container identity).
# --------------------------------------------------------------------------
# The identity the worker process runs as. It invokes ONLY the three Authority
# aliases and publishes its own operational metrics -- nothing else. Named
# exactly ${name_prefix}-hub-task so local.hub_task_role_arn (used in the Lambda
# endpoint policy) is exact.
resource "aws_iam_role" "hub_task" {
  count = local.hub_worker_count

  name                 = "${local.name_prefix}-hub-task"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "EcsTasksAssume"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.${data.aws_partition.current.dns_suffix}"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-hub-task"
    Component = "connector-hub"
  })
}

# Least-privilege runtime identity: InvokeFunction on ONLY the six closed
# blue/green alias ARNs for the three Hub-facing operations (the network path is
# separately gated by the Lambda endpoint policy, scoped to this same role), and
# PutMetricData constrained to the LayerV/NHP namespace. A task still invokes
# only the alias named in its immutable runtime config; keeping both qualifiers
# authorized lets ECS drain the previous task revision safely. No secret/KMS/data
# grants: the container never reads the secret directly (the execution
# role/agent does) and holds no data-plane reach.
resource "aws_iam_role_policy" "hub_task" {
  count = local.hub_worker_count

  name = "hub-task"
  role = aws_iam_role.hub_task[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AuthorityInvoke"
        Effect   = "Allow"
        Action   = "lambda:InvokeFunction"
        Resource = local.hub_authority_alias_arns
      },
      {
        Sid      = "PublishHubMetrics"
        Effect   = "Allow"
        Action   = "cloudwatch:PutMetricData"
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "LayerV/NHP"
          }
        }
      },
    ]
  })
}

# --------------------------------------------------------------------------
# Worker ENI security group (inline rules; no separate rule resources).
# --------------------------------------------------------------------------
# Ingress is exactly the two Hub ports and trusts only the NLB security-group
# identity. AWS applies that identity to NLB-to-target traffic even with client
# IP preservation, so worker ENIs never need a public-CIDR rule. Egress is HTTPS:
# in-VPC to reach the lambda/logs/secrets/kms/ecr interface endpoints (via CIDR,
# not an SG ref, to avoid an inline-rule cycle with the endpoint SG), plus the
# S3 gateway prefix list for the ECR layer blobs.
resource "aws_security_group" "hub_worker" {
  count = local.hub_worker_count

  name_prefix = "${local.name_prefix}-hub-"
  description = "Connector Hub worker ENIs; UDP/62206 knock + NLB TCP/62207 health in, HTTPS out to Control endpoints"
  vpc_id      = aws_vpc.control.id

  ingress = [
    {
      description      = "NHP UDP knock data from the Hub NLB security group"
      from_port        = 62206
      to_port          = 62206
      protocol         = "udp"
      cidr_blocks      = []
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = local.hub_edge_enabled ? [aws_security_group.hub_nlb[0].id] : []
      self             = false
    },
    {
      description      = "NLB TCP health probe on 62207"
      from_port        = 62207
      to_port          = 62207
      protocol         = "tcp"
      cidr_blocks      = []
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = local.hub_edge_enabled ? [aws_security_group.hub_nlb[0].id] : []
      self             = false
    },
  ]

  egress = [
    {
      description      = "HTTPS to Control interface endpoints (lambda/logs/secrets/kms/ecr) in-VPC"
      from_port        = 443
      to_port          = 443
      protocol         = "tcp"
      cidr_blocks      = [var.vpc_cidr]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      description      = "HTTPS to the S3 gateway endpoint prefix list (ECR layer blobs)"
      from_port        = 443
      to_port          = 443
      protocol         = "tcp"
      prefix_list_ids  = [aws_vpc_endpoint.hub_s3[0].prefix_list_id]
      cidr_blocks      = []
      ipv6_cidr_blocks = []
      security_groups  = []
      self             = false
    },
  ]

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-hub"
    Component = "connector-hub"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# --------------------------------------------------------------------------
# Worker log group.
# --------------------------------------------------------------------------
# Both containers ship here via the awslogs driver. Default (AWS-managed)
# encryption, matching the authority Lambda log groups: CMK-encrypting would
# require extending the data key's byte-reviewed policy to the CloudWatch Logs
# service for this group's ARN, deferred to a follow-up. Payloads are already
# forbidden from Hub logs.
resource "aws_cloudwatch_log_group" "hub" {
  count = local.hub_worker_count

  name              = local.hub_log_group_name
  retention_in_days = local.hub_log_retention_days

  tags = merge(local.common_tags, {
    Name      = local.hub_log_group_name
    Component = "connector-hub"
  })
}

# --------------------------------------------------------------------------
# ECS cluster + task definition + service.
# --------------------------------------------------------------------------
resource "aws_ecs_cluster" "hub" {
  count = local.hub_worker_count

  name = "${local.name_prefix}-hub"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-hub"
    Component = "connector-hub"
  })
}

# Two containers sharing an empty ephemeral hub-etc volume. The init container
# runs as root ONLY to materialize the rendered config into hub-etc, then exits;
# the worker container mounts hub-etc read-only, runs as an unprivileged fixed
# UID with a read-only root filesystem, and is the sole essential task member.
# Key material is injected via `secrets` (Secrets Manager JSON-key selectors),
# never as plaintext env, and the public config travels as one non-secret JSON
# env var built above.
resource "aws_ecs_task_definition" "hub" {
  count = local.hub_worker_count

  family                   = "${local.name_prefix}-hub"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.hub_execution[0].arn
  task_role_arn            = aws_iam_role.hub_task[0].arn

  # Blue/green flip ordering: this task definition's container env carries the
  # Authority alias ARNs by colour, so its replacement IS the traffic switch.
  # Depending on the provisioned-concurrency resource (create-before-destroy)
  # sequences a selector flip as: new colour's pool READY -> task definition
  # replaced -> service rolls -> old colour's pool destroyed. The switch never
  # runs ahead of warm capacity, and a failed provisioning (init runs during
  # the allocation) halts the apply with traffic untouched on the old colour.
  depends_on = [aws_lambda_provisioned_concurrency_config.authority]

  runtime_platform {
    cpu_architecture        = "X86_64"
    operating_system_family = "LINUX"
  }

  # Ephemeral, empty scratch for the rendered config; not persisted across tasks.
  volume {
    name = "hub-etc"
  }

  container_definitions = jsonencode([
    {
      name       = "hub-init"
      image      = local.hub_image_uri
      essential  = false
      user       = "0"
      entryPoint = ["/nhp-hub/nhp-hubd"]
      command    = ["materialize-config"]
      mountPoints = [{
        sourceVolume  = "hub-etc"
        containerPath = "/nhp-hub/etc"
        readOnly      = false
      }]
      environment = [{
        name  = "NHP_HUB_PUBLIC_CONFIG_JSON"
        value = local.hub_public_config_json
      }]
      secrets = [
        {
          name      = "NHP_HUB_PRIVATE_KEY_B64"
          valueFrom = "${aws_secretsmanager_secret.hub_key_material[0].arn}:private_key::"
        },
        {
          name      = "NHP_HUB_ACTIVE_COOKIE_KEY_B64"
          valueFrom = "${aws_secretsmanager_secret.hub_key_material[0].arn}:active_cookie_key::"
        },
        {
          name      = "NHP_HUB_PREVIOUS_COOKIE_KEY_B64"
          valueFrom = "${aws_secretsmanager_secret.hub_key_material[0].arn}:previous_cookie_key::"
        },
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = local.hub_log_group_name
          "awslogs-region"        = data.aws_region.current.region
          "awslogs-stream-prefix" = "init"
        }
      }
    },
    {
      name                   = "hub"
      image                  = local.hub_image_uri
      essential              = true
      user                   = "65532:65532"
      readonlyRootFilesystem = true
      entryPoint             = ["/nhp-hub/nhp-hubd"]
      command                = ["run"]
      dependsOn = [{
        containerName = "hub-init"
        condition     = "SUCCESS"
      }]
      mountPoints = [{
        sourceVolume  = "hub-etc"
        containerPath = "/nhp-hub/etc"
        readOnly      = true
      }]
      portMappings = [
        {
          containerPort = 62206
          protocol      = "udp"
        },
        {
          containerPort = 62207
          protocol      = "tcp"
        },
      ]
      healthCheck = {
        command     = ["CMD", "/nhp-hub/nhp-hubd", "healthcheck"]
        interval    = 30
        timeout     = 3
        retries     = 3
        startPeriod = 10
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = local.hub_log_group_name
          "awslogs-region"        = data.aws_region.current.region
          "awslogs-stream-prefix" = "hub"
        }
      }
    },
  ])

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-hub"
    Component = "connector-hub"
  })

  lifecycle {
    precondition {
      # The publisher-owned pin must resolve to an immutable sha256 digest before
      # any task can start; UNPUBLISHED (or any malformed value) fails closed.
      condition     = !local.hub_worker_deploy || can(regex("^sha256:[0-9a-f]{64}$", local.hub_image_digest))
      error_message = "Hub image digest must be a published sha256 (not UNPUBLISHED)."
    }
  }
}

# Fargate service fronting the 5a NLB target group. desired_count remains
# deploy-pipeline-owned, while Terraform owns task_definition so an attended
# proof-policy selector change actually rolls the live Hub tasks to the selected
# revision. The circuit breaker rolls back a failed deployment automatically.
# It waits on the retry-safe keygen transaction (the secret must hold real key
# material and its exact public identity must be published before a task starts)
# and on the 5a listener (the target group must be wired to a listener before
# registration).
resource "aws_ecs_service" "hub" {
  count = local.hub_worker_count

  name            = "${local.name_prefix}-hub"
  cluster         = aws_ecs_cluster.hub[0].id
  task_definition = aws_ecs_task_definition.hub[0].arn
  launch_type     = "FARGATE"

  # FLAG: desired_count pinned to the measurement basis max_replicas=2; reconcile
  # against the capacity contract before enable.
  desired_count = 2

  network_configuration {
    subnets          = aws_subnet.isolated[*].id
    security_groups  = [aws_security_group.hub_worker[0].id]
    assign_public_ip = false
  }

  load_balancer {
    # one(...[*]) rather than [0] so a misconfiguration (worker enabled while the
    # 5a edge is dark) surfaces as the fail-closed precondition in main.tf with
    # its actionable message, not a bare "Invalid index" during graph eval. In
    # every valid configuration the precondition guarantees the edge is live, so
    # this resolves to the single target group's ARN (module idiom; see the
    # one(aws_lb.hub[*]...) outputs).
    target_group_arn = one(aws_lb_target_group.hub[*].arn)
    container_name   = "hub"
    container_port   = 62206
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  # Blue/green flip ordering, second half. The task-definition dependency on
  # the provisioned-concurrency resource makes the switch wait for the new
  # colour's warm pool; this makes the OLD pool's destroy wait for the drain.
  # Without it, Terraform proceeds as soon as ECS accepts the update, and
  # still-draining Hub tasks hold the old colour's alias ARNs -- whose invokes
  # would fail closed once that pool is destroyed, because the handler rejects
  # non-provisioned initialization by design. Steady-state means the new tasks
  # are serving and the old ones are gone before the deposed pool is released;
  # paired with the circuit breaker above, a failed rollout surfaces as an
  # apply error after ECS rolls back rather than as a silent half-switch.
  # Operationally: every service-touching apply now blocks on the ECS rollout,
  # bounded by the provider's default 20m update timeout (no timeouts block on
  # purpose); a stuck-but-not-failing deployment holds the Control apply until
  # that fires, well inside the deploy job's own limit.
  wait_for_steady_state = true

  lifecycle {
    ignore_changes = [desired_count]
  }

  depends_on = [
    aws_lambda_invocation.hub_keygen,
    aws_lambda_invocation.hub_identity_publication,
    aws_lb_listener.hub,
  ]

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-hub"
    Component = "connector-hub"
  })
}

# --------------------------------------------------------------------------
# Pull-path VPC endpoints (NEW). Fargate in the isolated subnets has no NAT, so
# the image pull must ride private endpoints. ecr.api + ecr.dkr are interface
# endpoints on the shared interface-endpoint SG; S3 is a gateway endpoint on the
# isolated route tables for the ECR layer blobs. All three carry principal- and
# resource-scoped policies (endpoints.tf) admitting ONLY the execution role.
# --------------------------------------------------------------------------
resource "aws_vpc_endpoint" "hub_ecr_api" {
  count = local.hub_worker_count

  vpc_id              = aws_vpc.control.id
  service_name        = "com.amazonaws.${data.aws_region.current.region}.ecr.api"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = aws_subnet.isolated[*].id
  security_group_ids  = [aws_security_group.interface_endpoints.id]
  policy              = local.hub_ecr_endpoint_policy

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-vpce-ecr-api"
    Component = "connector-hub"
    Service   = "ecr.api"
  })
}

resource "aws_vpc_endpoint" "hub_ecr_dkr" {
  count = local.hub_worker_count

  vpc_id              = aws_vpc.control.id
  service_name        = "com.amazonaws.${data.aws_region.current.region}.ecr.dkr"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = aws_subnet.isolated[*].id
  security_group_ids  = [aws_security_group.interface_endpoints.id]
  policy              = local.hub_ecr_endpoint_policy

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-vpce-ecr-dkr"
    Component = "connector-hub"
    Service   = "ecr.dkr"
  })
}

resource "aws_vpc_endpoint" "hub_s3" {
  count = local.hub_worker_count

  vpc_id            = aws_vpc.control.id
  service_name      = "com.amazonaws.${data.aws_region.current.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = aws_route_table.isolated[*].id
  policy            = local.hub_s3_endpoint_policy

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-vpce-s3"
    Component = "connector-hub"
    Service   = "s3"
  })
}
