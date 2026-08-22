mock_provider "aws" {
  mock_data "aws_region" {
    defaults = {
      id     = "us-east-2"
      region = "us-east-2"
    }
  }

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "767397897469"
    }
  }

  mock_data "aws_subnet" {
    defaults = {
      cidr_block = "10.102.10.0/24"
    }
  }

  mock_resource "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws:logs:us-east-2:767397897469:log-group:/layerv/mock"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::767397897469:role/mock"
    }
  }

  mock_resource "aws_iam_policy" {
    defaults = {
      arn = "arn:aws:iam::767397897469:policy/mock"
    }
  }

  mock_resource "aws_lb" {
    defaults = {
      arn        = "arn:aws:elasticloadbalancing:us-east-2:767397897469:loadbalancer/app/mock/1111111111111111"
      arn_suffix = "app/mock/1111111111111111"
      dns_name   = "internal-mock.us-east-2.elb.amazonaws.com"
      zone_id    = "Z0123456789"
    }
  }

  mock_resource "aws_lb_target_group" {
    defaults = {
      arn        = "arn:aws:elasticloadbalancing:us-east-2:767397897469:targetgroup/mock/1111111111111111"
      arn_suffix = "targetgroup/mock/1111111111111111"
    }
  }

  mock_resource "aws_security_group" {
    defaults = {
      id = "sg-0123456789abcdef0"
    }
  }
}

variables {
  environment                            = "sandbox"
  name_prefix                            = "layerv-nhp-sandbox"
  cell_id                                = "cell0"
  vpc_id                                 = "vpc-0123456789abcdef0"
  vpc_cidr                               = "10.100.0.0/16"
  private_subnet_ids                     = ["subnet-11111111", "subnet-22222222"]
  public_subnet_ids                      = ["subnet-33333333", "subnet-44444444"]
  ecr_repo_url                           = "767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/nhp-qurl"
  image_tag_ssm_param                    = "/layerv-nhp-sandbox/qurl-api-image-tag"
  dynamodb_table_arns                    = ["arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-cell0-qurl-resources"]
  auth0_domain                           = "auth.layerv.ai"
  jwt_secret_arn                         = "arn:aws:secretsmanager:us-east-2:767397897469:secret:qurl-jwt-AbCdEf"
  internal_service_token_arn             = "arn:aws:secretsmanager:us-east-2:767397897469:secret:qurl-internal-AbCdEf"
  nhp_internal_auth_secret_arn           = "arn:aws:secretsmanager:us-east-2:767397897469:secret:nhp-internal-AbCdEf"
  feedback_slack_webhook_secret_arn      = "arn:aws:secretsmanager:us-east-2:767397897469:secret:qurl-feedback-AbCdEf"
  secrets_kms_key_arn                    = "arn:aws:kms:us-east-2:767397897469:key/11111111-1111-1111-1111-111111111111"
  logs_kms_key_arn                       = "arn:aws:kms:us-east-2:767397897469:key/22222222-2222-2222-2222-222222222222"
  cookie_domain                          = ".qurl.site.layerv.xyz"
  qurl_link_domain                       = "qurl.link.layerv.xyz"
  qurl_site_domain                       = "qurl.site.layerv.xyz"
  default_token_expire                   = 3600
  default_open_time                      = 300
  ip_rate_limit                          = 300
  ip_rate_burst                          = 100
  audit_retention_days                   = 90
  cors_allowed_origins                   = ""
  default_ac_id                          = "cell0"
  idempotency_cache_ttl_seconds          = 300
  idempotency_cache_max_size             = 1000
  idempotency_cleanup_interval_seconds   = 60
  health_check_timeout_seconds           = 10
  health_startup_timeout_seconds         = 30
  auth0_jwks_cache_ttl_seconds           = 3600
  auth0_jwks_fetch_timeout_seconds       = 10
  webhooks_worker_count                  = 4
  webhooks_max_webhooks_per_owner        = 10
  webhooks_delivery_timeout_seconds      = 30
  webhooks_max_retries                   = 5
  webhooks_event_channel_size            = 1000
  webhooks_retry_worker_interval_seconds = 30
  webhooks_drain_timeout_seconds         = 30
  webhooks_response_body_limit           = 8192
  webhooks_api_version                   = "2024-01-01"
  otel_service_name                      = "qurl-api"
  otel_service_version                   = "test"
  otel_environment                       = "sandbox"
  otel_exporter_endpoint                 = "http://localhost:4317"
  otel_exporter_protocol                 = "grpc"
  otel_exporter_insecure                 = true
  otel_trace_sample_rate                 = 0
  otel_metrics_interval                  = 60
  otel_metrics_enabled                   = false
  otel_tracing_enabled                   = false
  otel_log_correlation                   = false
}

run "legacy_public_primary_stays_unchanged" {
  command = plan

  variables {
    domain_name     = "api.layerv.xyz"
    hosted_zone_id  = "Z0123456789"
    certificate_arn = "arn:aws:acm:us-east-2:767397897469:certificate/11111111-1111-1111-1111-111111111111"
  }

  assert {
    condition = (
      aws_lb.qurl.name == "layerv-nhp-sandbox-cell0-qurl"
      # cell0 leaves resource_name_prefix unset, so the physical and data
      # prefixes coincide and this name must stay byte-identical. Pinned here so
      # any future change to the owned-table prefix proves it is a no-op for the
      # applied cell0 table before it can reach a plan.
      && aws_dynamodb_table.qurl_external_identities.name == "layerv-nhp-sandbox-cell0-qurl-external-identities"
      && aws_lb.qurl.internal == false
      && aws_security_group.alb.description == "Security group for QURL API ALB"
      && length(aws_lb_listener.https) == 1
      && aws_lb_listener.https[0].port == 443
      && aws_lb_listener.https[0].protocol == "HTTPS"
      && aws_lb_listener.http.port == 80
      && aws_lb_listener.http.protocol == "HTTP"
      && length(aws_lb.qurl.subnets) == 2
      && length(aws_security_group.alb.egress) == 1
      && one(aws_security_group.alb.egress).protocol == "-1"
      && toset(one(aws_security_group.alb.egress).cidr_blocks) == toset(["10.100.0.0/16"])
      && length(aws_vpc_security_group_egress_rule.alb_to_ecs_private) == 0
      && length(aws_security_group.ecs.egress) == 1
      && one(aws_security_group.ecs.egress).protocol == "-1"
      && toset(one(aws_security_group.ecs.egress).cidr_blocks) == toset(["0.0.0.0/0"])
      && length(aws_iam_policy.execution_private_boundary) == 0
      && aws_iam_role.execution.permissions_boundary == null
    )
    error_message = "Legacy public mode must preserve the existing cell0 ALB name, scheme, listeners, broad legacy ALB/task egress, and execution-role attachment shape."
  }

  assert {
    condition = alltrue([
      for rule in aws_security_group.alb.ingress :
      length(rule.cidr_blocks) == 1
      && rule.cidr_blocks[0] == "0.0.0.0/0"
      && length(coalesce(rule.security_groups, [])) == 0
    ])
    error_message = "Legacy public mode must retain only the established 0.0.0.0/0 HTTP/HTTPS ingress rules."
  }
}

run "private_primary_is_internal_and_digest_pinned" {
  command = apply

  variables {
    environment                      = "sandbox-cell1"
    name_prefix                      = "layerv-nhp-sandbox-cell1"
    resource_name_prefix             = "layerv-nhp-sandbox"
    cell_id                          = "cell1"
    vpc_cidr                         = "10.102.0.0/16"
    public_subnet_ids                = ["subnet-11111111", "subnet-22222222"]
    public_ingress_enabled           = false
    ingress_security_group_ids       = ["sg-0123456789abcdef0"]
    enforce_internal_alb_only        = true
    image_uri                        = "767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/nhp-qurl@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    source_revision                  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    dynamodb_table_prefix            = "layerv-nhp-sandbox-cell1-cell1"
    nhp_resources_table_name         = "layerv-nhp-sandbox-cell1-cell1-resources"
    nhp_resources_table_arn          = "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-cell1-cell1-resources"
    nhp_resources_customer_id_prefix = "00000000000000000000000001"
    nhp_server_internal_url          = "http://server.nhp.sandbox-cell1.internal:8888"
    nhp_server_security_group_id     = "sg-11111111111111111"
    desired_count                    = 1
    target_health_alarm_enabled      = true
  }

  assert {
    condition = (
      aws_ecs_cluster.qurl.name == "layerv-nhp-sandbox-cell1-qurl-api"
      && aws_lb.qurl.name == "layerv-nhp-sandbox-cell1-qurl"
      # Module-OWNED tables follow the DATA prefix (var.dynamodb_table_prefix,
      # the same value the container gets as DYNAMODB_TABLE_PREFIX), never the
      # physical ECS/ALB prefix. In this private shape the two intentionally
      # differ, so this is the assertion that pins the app's lookup name to the
      # table Terraform actually creates.
      && aws_dynamodb_table.qurl_external_identities.name == "layerv-nhp-sandbox-cell1-cell1-qurl-external-identities"
      && aws_ssm_parameter.ecs_cluster.name == "/layerv-nhp-sandbox-cell1/qurl-ecs-cluster"
      && aws_lb.qurl.internal
      && aws_lb.qurl.drop_invalid_header_fields
      && length(aws_lb_listener.https) == 0
      && aws_lb_listener.http.port == 80
      && aws_lb_listener.http.protocol == "HTTP"
      && length(aws_iam_policy.execution_private_boundary) == 1
      && aws_iam_role.execution.permissions_boundary == aws_iam_policy.execution_private_boundary[0].arn
      && aws_ecs_service.qurl.desired_count == 1
      && aws_ecs_service.qurl.network_configuration[0].assign_public_ip == false
    )
    error_message = "Private mode must use canonical one-cell physical names, retain its isolated SSM namespace, and run one healthy private task behind an internal HTTP:80 ALB with no public task IP."
  }

  assert {
    condition = (
      length(aws_security_group.alb.ingress) == 1
      && length(aws_security_group.alb.egress) == 0
      && alltrue([
        for rule in aws_security_group.alb.ingress :
        rule.from_port == 80
        && rule.to_port == 80
        && length(coalesce(rule.cidr_blocks, [])) == 0
        && toset(rule.security_groups) == toset(["sg-0123456789abcdef0"])
      ])
    )
    error_message = "Private ALB ingress must be TCP/80 from the exact caller SG with no CIDR rule."
  }

  assert {
    condition = (
      length(aws_vpc_security_group_egress_rule.alb_to_ecs_private) == 1
      && aws_vpc_security_group_egress_rule.alb_to_ecs_private[0].security_group_id == aws_security_group.alb.id
      && aws_vpc_security_group_egress_rule.alb_to_ecs_private[0].from_port == 8080
      && aws_vpc_security_group_egress_rule.alb_to_ecs_private[0].to_port == 8080
      && aws_vpc_security_group_egress_rule.alb_to_ecs_private[0].ip_protocol == "tcp"
      && aws_vpc_security_group_egress_rule.alb_to_ecs_private[0].referenced_security_group_id == aws_security_group.ecs.id
    )
    error_message = "Private ALB egress must be TCP/container_port to the exact ECS task SG, never an all-protocol VPC CIDR."
  }

  assert {
    condition = (
      length(aws_security_group.ecs.egress) == 4
      && alltrue([
        for rule in aws_security_group.ecs.egress :
        rule.protocol != "-1"
      ])
      && toset(compact([
        for rule in aws_security_group.ecs.egress :
        rule.cidr_blocks != null
        ? "${rule.protocol}:${rule.from_port}:${rule.to_port}:${join(",", rule.cidr_blocks)}"
        : ""
        ])) == toset([
        "tcp:443:443:0.0.0.0/0",
        "tcp:53:53:10.102.0.2/32",
        "udp:53:53:10.102.0.2/32",
      ])
      && length([
        for rule in aws_security_group.ecs.egress : rule
        if rule.protocol == "tcp"
        && rule.from_port == 8888
        && rule.to_port == 8888
        && rule.cidr_blocks == null
        && toset(rule.security_groups) == toset(["sg-11111111111111111"])
      ]) == 1
    )
    error_message = "Private task egress must exclude all-protocol internet access, use only the VPC resolver /32 for DNS, and target NHP:8888 by exact server SG."
  }

  assert {
    condition = (
      jsondecode(aws_ecs_task_definition.qurl.container_definitions)[0].image
      == "767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/nhp-qurl@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      && contains(
        jsondecode(aws_ecs_task_definition.qurl.container_definitions)[0].environment,
        {
          name  = "QURL_RUNTIME_SOURCE_REVISION"
          value = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        },
      )
      && contains(
        jsondecode(aws_ecs_task_definition.qurl.container_definitions)[0].environment,
        {
          name  = "DYNAMODB_TABLE_PREFIX"
          value = "layerv-nhp-sandbox-cell1-cell1"
        },
      )
    )
    error_message = "Private task definition must consume the exact immutable URI, carry the paired full source revision, and retain the applied cell1 DynamoDB prefix."
  }

  assert {
    condition = (
      { for statement in jsondecode(aws_iam_policy.execution_private_boundary[0].policy).Statement : statement.Sid => statement }["PullExactRepository"].Resource
      == "arn:aws:ecr:us-east-2:767397897469:repository/layerv/nhp-qurl"
      && { for statement in jsondecode(aws_iam_policy.execution_private_boundary[0].policy).Statement : statement.Sid => statement }["DecryptExactRuntimeKey"].Condition.StringEquals["kms:ViaService"]
      == "secretsmanager.us-east-2.amazonaws.com"
      && toset({ for statement in jsondecode(aws_iam_policy.execution_private_boundary[0].policy).Statement : statement.Sid => statement }["DecryptExactRuntimeKey"].Condition.StringEquals["kms:EncryptionContext:SecretARN"])
      == toset([
        "arn:aws:secretsmanager:us-east-2:767397897469:secret:qurl-jwt-AbCdEf",
        "arn:aws:secretsmanager:us-east-2:767397897469:secret:qurl-internal-AbCdEf",
        "arn:aws:secretsmanager:us-east-2:767397897469:secret:nhp-internal-AbCdEf",
        "arn:aws:secretsmanager:us-east-2:767397897469:secret:qurl-feedback-AbCdEf",
      ])
    )
    error_message = "Private execution boundary must pin the exact ECR repository and permit KMS decrypt only through Secrets Manager for the exact runtime secret ARNs."
  }

  assert {
    condition = (
      length([
        for item in jsondecode(aws_ecs_task_definition.qurl.container_definitions)[0].secrets : item
        if item.name == "QURL_FEEDBACK_SLACK_WEBHOOK_URL"
        && item.valueFrom == var.feedback_slack_webhook_secret_arn
      ]) == 1
      && contains(
        { for statement in jsondecode(aws_iam_policy.execution_private_boundary[0].policy).Statement : statement.Sid => statement }["ReadExactRuntimeSecrets"].Resource,
        var.feedback_slack_webhook_secret_arn,
      )
      && length([
        for statement in jsondecode(aws_iam_role_policy.execution_secrets.policy).Statement : statement
        if contains(statement.Action, "secretsmanager:GetSecretValue")
        && contains(statement.Resource, var.feedback_slack_webhook_secret_arn)
      ]) == 1
    )
    error_message = "The task must resolve the dedicated feedback webhook exactly once, and both execution-role policies must grant its launch-time secret read."
  }
}

run "private_primary_requires_nhp_url_and_security_group_pair" {
  command = plan

  variables {
    public_ingress_enabled           = false
    ingress_security_group_ids       = ["sg-0123456789abcdef0"]
    nhp_resources_table_name         = "layerv-nhp-sandbox-cell1-cell1-resources"
    nhp_resources_table_arn          = "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-cell1-cell1-resources"
    nhp_resources_customer_id_prefix = "00000000000000000000000001"
    nhp_server_internal_url          = "http://server.nhp.sandbox.internal:8888"
  }

  expect_failures = [
    aws_security_group.ecs,
  ]
}

run "private_primary_rejects_stale_nhp_security_group" {
  command = plan

  variables {
    public_ingress_enabled       = false
    ingress_security_group_ids   = ["sg-0123456789abcdef0"]
    nhp_server_security_group_id = "sg-11111111111111111"
  }

  expect_failures = [
    aws_security_group.ecs,
  ]
}

run "private_primary_rejects_https_nhp_origin" {
  command = plan

  variables {
    public_ingress_enabled           = false
    ingress_security_group_ids       = ["sg-0123456789abcdef0"]
    nhp_resources_table_name         = "layerv-nhp-sandbox-cell1-cell1-resources"
    nhp_resources_table_arn          = "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-cell1-cell1-resources"
    nhp_resources_customer_id_prefix = "00000000000000000000000001"
    nhp_server_internal_url          = "https://server.nhp.sandbox.internal"
    nhp_server_security_group_id     = "sg-11111111111111111"
  }

  expect_failures = [
    aws_security_group.ecs,
  ]
}

run "legacy_public_accepts_https_nhp_origin" {
  command = plan

  variables {
    nhp_resources_table_name         = "layerv-nhp-sandbox-cell0-qurl-resources"
    nhp_resources_table_arn          = "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-cell0-qurl-resources"
    nhp_resources_customer_id_prefix = "00000000000000000000000001"
    nhp_server_internal_url          = "https://nhp.example.com"
  }

  assert {
    condition = contains(
      jsondecode(aws_ecs_task_definition.qurl.container_definitions)[0].environment,
      {
        name  = "NHP_SERVER_INTERNAL_URL"
        value = "https://nhp.example.com"
      },
    )
    error_message = "Legacy public mode must continue accepting its existing HTTPS NHP origin."
  }
}

run "private_primary_without_nhp_omits_internal_api_egress" {
  command = plan

  variables {
    public_ingress_enabled     = false
    ingress_security_group_ids = ["sg-0123456789abcdef0"]
  }

  assert {
    condition = (
      length(aws_security_group.ecs.egress) == 3
      && length([
        for rule in aws_security_group.ecs.egress : rule
        if rule.from_port == 8888 || rule.to_port == 8888
      ]) == 0
    )
    error_message = "A private-primary service with no NHP origin must not retain stale TCP/8888 egress authority."
  }
}

run "private_prod_primary_accepts_cell_local_http" {
  command = plan

  variables {
    environment                      = "prod"
    name_prefix                      = "layerv-nhp-prod-cell1"
    resource_name_prefix             = "layerv-nhp-prod"
    cell_id                          = "cell1"
    public_ingress_enabled           = false
    ingress_security_group_ids       = ["sg-0123456789abcdef0"]
    enforce_internal_alb_only        = true
    api_base_url                     = "http://qurl-api.prod-cell1.nhp.internal"
    cors_allowed_origins             = "http://qurl-api.prod-cell1.nhp.internal"
    alb_access_logs_bucket           = "layerv-prod-cell1-alb-logs"
    image_uri                        = "767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/nhp-qurl@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    source_revision                  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    nhp_resources_table_name         = "layerv-nhp-prod-cell1-cell1-resources"
    nhp_resources_table_arn          = "arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-prod-cell1-cell1-resources"
    nhp_resources_customer_id_prefix = "00000000000000000000000001"
    nhp_server_internal_url          = "http://server.nhp.prod-cell1.internal:8888"
    nhp_server_security_group_id     = "sg-11111111111111111"
    connector_auth_enabled           = true
    qurl_resources_table_arn         = "arn:aws:dynamodb:us-east-2:235500187906:table/layerv-nhp-prod-cell1-cell1-qurl-resources"
  }

  assert {
    condition = (
      aws_lb.qurl.internal
      && length(aws_lb_listener.https) == 0
      && aws_lb_listener.http.protocol == "HTTP"
      && contains(
        jsondecode(aws_ecs_task_definition.qurl.container_definitions)[0].environment,
        {
          name  = "API_BASE_URL"
          value = "http://qurl-api.prod-cell1.nhp.internal"
        },
      )
      && contains(
        jsondecode(aws_ecs_task_definition.qurl.container_definitions)[0].environment,
        {
          name  = "CORS_ALLOWED_ORIGINS"
          value = "http://qurl-api.prod-cell1.nhp.internal"
        },
      )
    )
    error_message = "A provisioned private production cell must accept its SG-fenced internal HTTP origin without public domain or HTTPS requirements while retaining the exact non-wildcard CORS origin required by qurl-service startup validation."
  }

  assert {
    condition = alltrue([
      for statement in jsondecode(aws_iam_role_policy.task_tunnel_session_fence[0].policy).Statement :
      statement.Action == ["dynamodb:ConditionCheckItem"] &&
      statement.Resource == ["arn:aws:dynamodb:us-east-2:235500187906:table/layerv-nhp-prod-cell1-cell1-qurl-resources"] &&
      !can(statement.Condition)
      if statement.Sid == "TunnelSessionFenceAccess"
      ]) && length([
      for statement in jsondecode(aws_iam_role_policy.task_tunnel_session_fence[0].policy).Statement :
      statement if statement.Sid == "TunnelSessionFenceAccess"
    ]) == 1
    error_message = "production Connector session fencing must grant only ConditionCheckItem on the exact production qurl-resources table"
  }
}

run "private_prod_primary_rejects_empty_cors" {
  command = plan

  variables {
    environment                = "prod"
    name_prefix                = "layerv-nhp-prod-cell1"
    resource_name_prefix       = "layerv-nhp-prod"
    cell_id                    = "cell1"
    public_ingress_enabled     = false
    ingress_security_group_ids = ["sg-0123456789abcdef0"]
    enforce_internal_alb_only  = true
    api_base_url               = "http://qurl-api.prod-cell1.nhp.internal"
    cors_allowed_origins       = ""
    alb_access_logs_bucket     = "layerv-prod-cell1-alb-logs"
  }

  expect_failures = [
    aws_ecs_task_definition.qurl,
  ]
}

run "public_prod_still_requires_public_https_and_cors" {
  command = plan

  variables {
    environment            = "prod"
    name_prefix            = "layerv-nhp-prod"
    api_base_url           = "http://api.example.internal"
    cors_allowed_origins   = ""
    alb_access_logs_bucket = "layerv-prod-alb-logs"
  }

  expect_failures = [
    aws_ecs_task_definition.qurl,
    aws_lb_listener.http,
  ]
}

run "private_primary_rejects_wrong_repository" {
  command = plan

  variables {
    public_ingress_enabled     = false
    ingress_security_group_ids = ["sg-0123456789abcdef0"]
    image_uri                  = "767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/other@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    source_revision            = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }

  expect_failures = [
    var.image_uri,
  ]
}

run "retired_http_agent_runtime_is_detached" {
  command = apply

  variables {
    deploy_qurl_bootstrap_chain = true
    enable_qurl_agent_bootstrap = true
    retire_http_agent_lifecycle = true
    nhp_server_public_key_b64   = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    nhp_server_host             = "cell0.nhp.layerv.xyz"
    qurl_browser_relay_base_url = "https://relay.layerv.xyz"
    agent_registration_enabled  = true
    agent_otp_enabled           = true
    agent_otp_email_from        = "noreply@notify.layerv.xyz"
    agent_otp_relay_base_url    = "https://relay.layerv.xyz"
    agent_otp_pepper_secret_arn = "arn:aws:secretsmanager:us-east-2:767397897469:secret:agent-otp-pepper-AbCdEf"
    agent_otp_config_set_name   = "layerv-nhp-sandbox-agent-otp"
  }

  assert {
    condition = length(setintersection(
      toset([
        for item in jsondecode(aws_ecs_task_definition.qurl.container_definitions)[0].environment :
        item.name
      ]),
      toset([
        "NHP_SERVER_HOST",
        "NHP_SERVER_PORT",
        "QURL_AGENT_BOOTSTRAP_ENABLED",
        "QURL_AGENT_REGISTRATION_ENABLED",
        "QURL_NHP_RELAY_BASE_URL",
        "QURL_AGENT_OTP_ENABLED",
        "QURL_AGENT_OTP_EMAIL_FROM",
      ]),
    )) == 0
    error_message = "The qurl-service task definition must not render retired HTTP bootstrap, registration, relay, or OTP environment variables."
  }

  assert {
    condition = alltrue([
      for item in jsondecode(aws_ecs_task_definition.qurl.container_definitions)[0].secrets :
      item.name != "QURL_AGENT_OTP_PEPPER"
    ])
    error_message = "The qurl-service task definition must not resolve the retired HTTP OTP pepper."
  }

  assert {
    condition = !strcontains(
      aws_iam_role_policy.execution_secrets.policy,
      var.agent_otp_pepper_secret_arn,
    )
    error_message = "The qurl-service execution role must not retain read access to the retired HTTP OTP pepper."
  }

  assert {
    condition = (
      contains(
        jsondecode(aws_ecs_task_definition.qurl.container_definitions)[0].environment,
        {
          name  = "NHP_SERVER_PUBLIC_KEY_B64"
          value = var.nhp_server_public_key_b64
        },
      )
      && contains(
        jsondecode(aws_ecs_task_definition.qurl.container_definitions)[0].environment,
        {
          name  = "QURL_BROWSER_RELAY_BASE_URL"
          value = var.qurl_browser_relay_base_url
        },
      )
    )
    error_message = "HTTP lifecycle retirement must retain the browser relay URL and its pinned NHP server identity."
  }

  assert {
    condition = (
      length(terraform_data.qurl_bootstrap_chain_inputs) == 0
      && length(aws_iam_role_policy.task_agent_otp_ses) == 0
    )
    error_message = "The HTTP lifecycle retirement must delete the qurl-service bootstrap sentinel and legacy SES send grant."
  }
}
