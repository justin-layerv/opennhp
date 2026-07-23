mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = {
      names = ["us-east-2a", "us-east-2b", "us-east-2c"]
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

  mock_data "aws_region" {
    defaults = {
      region = "us-east-2"
    }
  }
}

run "sandbox_foundation_is_global_dark_and_isolated" {
  command = plan

  variables {
    environment                = "sandbox"
    aws_account_id             = "767397897469"
    vpc_cidr                   = "10.102.0.0/16"
    otp_email_from             = "noreply@notify.layerv.xyz"
    ses_configuration_set_name = "layerv-nhp-sandbox-agent-otp"
  }

  assert {
    condition     = output.control_table_prefix == "layerv-nhp-sandbox-control"
    error_message = "The sandbox control prefix drifted or became cell-scoped."
  }

  assert {
    condition = output.control_table_names == {
      api_keys            = "layerv-nhp-sandbox-control-qurl-api-keys"
      agent_keys          = "layerv-nhp-sandbox-control-qurl-agent-keys"
      customers           = "layerv-nhp-sandbox-control-qurl-customers"
      api_key_idempotency = "layerv-nhp-sandbox-control-qurl-apikey-idempotency"
      connector_authority = "layerv-nhp-sandbox-control-connector-authority"
    }
    error_message = "The five global control-table names must remain exact."
  }

  assert {
    condition     = length(aws_subnet.isolated) == 3 && alltrue([for subnet in aws_subnet.isolated : !subnet.map_public_ip_on_launch])
    error_message = "The foundation requires exactly three isolated subnets with public-IP mapping disabled."
  }

  assert {
    condition     = length(aws_default_security_group.control.ingress) == 0 && length(aws_default_security_group.control.egress) == 0
    error_message = "The Control VPC default security group must remain deny-all."
  }

  assert {
    # These assertions are the load-bearing dark-runtime boundary. A future
    # runtime slice must replace them with equally exact caller grants, not
    # delete the endpoint-policy and security-group contract wholesale.
    condition = (
      length(aws_security_group.interface_endpoints.ingress) == 0 &&
      length(aws_security_group.interface_endpoints.egress) == 0 &&
      length(aws_security_group.otp_redis.ingress) == 0 &&
      length(aws_security_group.otp_redis.egress) == 0
    )
    error_message = "The foundation endpoint and Redis security groups must remain deny-all."
  }

  assert {
    condition     = length(aws_route_table.isolated) == 3
    error_message = "The foundation requires one isolated route table per availability zone."
  }

  assert {
    condition     = toset(keys(aws_vpc_endpoint.interface)) == toset(["email", "kms", "lambda", "logs", "monitoring", "secretsmanager"])
    error_message = "The private interface endpoint set drifted."
  }

  assert {
    condition = alltrue([
      for endpoint in values(aws_vpc_endpoint.interface) :
      jsondecode(endpoint.policy).Statement[0].Effect == "Deny" &&
      jsondecode(endpoint.policy).Statement[0].Action == "*" &&
      jsondecode(endpoint.policy).Statement[0].Resource == "*"
    ])
    error_message = "Every interface endpoint must remain deny-all until the authority runtime exists."
  }

  assert {
    condition     = jsondecode(aws_vpc_endpoint.dynamodb.policy).Statement[0].Effect == "Deny"
    error_message = "The DynamoDB gateway endpoint must remain deny-all until the authority runtime exists."
  }

  assert {
    condition     = aws_kms_key.qat1_signing.key_usage == "SIGN_VERIFY" && aws_kms_key.qat1_signing.customer_master_key_spec == "ECC_NIST_P256"
    error_message = "qat1 tickets require a dedicated asymmetric P-256 signing key."
  }

  assert {
    condition     = jsondecode(aws_kms_key.authority_data.policy).Statement[1].Principal.Service == "logs.us-east-2.amazonaws.com"
    error_message = "The Flow Logs KMS principal must follow the active partition DNS suffix."
  }

  assert {
    condition     = aws_ecr_repository.authority.image_tag_mutability == "IMMUTABLE" && aws_ssm_parameter.authority_image_digest.value == "UNPUBLISHED"
    error_message = "The authority image repository must be immutable and runtime must remain unpublished."
  }

  assert {
    condition = (
      aws_ecr_repository.hub.name == "layerv/nhp-hub" &&
      aws_ecr_repository.hub.image_tag_mutability == "IMMUTABLE" &&
      aws_ecr_repository.hub.image_scanning_configuration[0].scan_on_push &&
      aws_ecr_repository.hub.encryption_configuration[0].encryption_type == "KMS" &&
      aws_ssm_parameter.hub_image_digest.name == "/sandbox/nhp/control/hub/image-digest" &&
      aws_ssm_parameter.hub_image_digest.value == "UNPUBLISHED"
    )
    error_message = "The Hub repository must remain immutable, scanned, Control-KMS encrypted, and unpublished."
  }

  assert {
    condition = jsondecode(aws_ecr_lifecycle_policy.hub.policy) == {
      rules = [{
        rulePriority = 1
        description  = "Expire untagged Hub images after 7 days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 7
        }
        action = {
          type = "expire"
        }
      }]
    }
    error_message = "The Hub lifecycle may expire only untagged images after seven days."
  }

  assert {
    condition = (
      output.authority_publisher_role_name == "layerv-nhp-sandbox-control-connector-authority-publisher" &&
      output.authority_publisher_github_environment == "sandbox" &&
      aws_iam_role.authority_publisher.max_session_duration == 3600 &&
      jsondecode(aws_iam_role.authority_publisher.assume_role_policy) == {
        Version = "2012-10-17"
        Statement = [{
          Sid    = "GitHubEnvironmentPublisher"
          Effect = "Allow"
          Principal = {
            Federated = "arn:aws:iam::767397897469:oidc-provider/token.actions.githubusercontent.com"
          }
          Action = "sts:AssumeRoleWithWebIdentity"
          Condition = {
            StringEquals = {
              "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
              "token.actions.githubusercontent.com:sub" = "repo:layervai/qurl-service:environment:sandbox"
            }
          }
        }]
      }
    )
    error_message = "The sandbox publisher must trust only qurl-service's sandbox GitHub Environment."
  }

  assert {
    condition = (
      length(jsondecode(aws_iam_role_policy.authority_publisher.policy).Statement) == 3 &&
      jsondecode(aws_iam_role_policy.authority_publisher.policy).Statement[0] == {
        Sid      = "ECRAuthorization"
        Effect   = "Allow"
        Action   = "ecr:GetAuthorizationToken"
        Resource = "*"
      } &&
      jsondecode(aws_iam_role_policy.authority_publisher.policy).Statement[1].Sid == "AuthorityRepository" &&
      toset(jsondecode(aws_iam_role_policy.authority_publisher.policy).Statement[1].Action) == toset([
        "ecr:BatchCheckLayerAvailability",
        "ecr:BatchGetImage",
        "ecr:CompleteLayerUpload",
        "ecr:DescribeImages",
        "ecr:GetDownloadUrlForLayer",
        "ecr:InitiateLayerUpload",
        "ecr:PutImage",
        "ecr:UploadLayerPart",
      ]) &&
      jsondecode(aws_iam_role_policy.authority_publisher.policy).Statement[1].Resource == "arn:aws:ecr:us-east-2:767397897469:repository/layerv/qurl-connector-authority" &&
      jsondecode(aws_iam_role_policy.authority_publisher.policy).Statement[2].Sid == "AuthorityDigestPin" &&
      toset(jsondecode(aws_iam_role_policy.authority_publisher.policy).Statement[2].Action) == toset([
        "ssm:GetParameter",
        "ssm:PutParameter",
      ]) &&
      jsondecode(aws_iam_role_policy.authority_publisher.policy).Statement[2].Resource == "arn:aws:ssm:us-east-2:767397897469:parameter/sandbox/nhp/control/connector-authority/image-digest"
    )
    error_message = "The publisher policy must remain exact-repository ECR plus exact-parameter SSM, with only ECR authorization on wildcard resource."
  }

  assert {
    condition = (
      output.hub_publisher_role_name == "layerv-nhp-sandbox-control-hub-publisher" &&
      output.hub_publisher_github_environment == "hub-publish-sandbox" &&
      output.hub_publisher_github_subject == "repo:layervai/nhp:environment:hub-publish-sandbox" &&
      aws_iam_role.hub_publisher.max_session_duration == 3600 &&
      jsondecode(aws_iam_role.hub_publisher.assume_role_policy) == {
        Version = "2012-10-17"
        Statement = [{
          Sid    = "GitHubEnvironmentPublisher"
          Effect = "Allow"
          Principal = {
            Federated = "arn:aws:iam::767397897469:oidc-provider/token.actions.githubusercontent.com"
          }
          Action = "sts:AssumeRoleWithWebIdentity"
          Condition = {
            StringEquals = {
              "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
              "token.actions.githubusercontent.com:sub" = "repo:layervai/nhp:environment:hub-publish-sandbox"
            }
          }
        }]
      }
    )
    error_message = "The sandbox Hub publisher must trust only NHP's dedicated Hub publication Environment."
  }

  assert {
    condition = (
      length(jsondecode(aws_iam_role_policy.hub_publisher.policy).Statement) == 3 &&
      jsondecode(aws_iam_role_policy.hub_publisher.policy).Statement[0] == {
        Sid      = "ECRAuthorization"
        Effect   = "Allow"
        Action   = "ecr:GetAuthorizationToken"
        Resource = "*"
      } &&
      jsondecode(aws_iam_role_policy.hub_publisher.policy).Statement[1].Sid == "HubRepository" &&
      toset(jsondecode(aws_iam_role_policy.hub_publisher.policy).Statement[1].Action) == toset([
        "ecr:BatchCheckLayerAvailability",
        "ecr:BatchGetImage",
        "ecr:CompleteLayerUpload",
        "ecr:DescribeImages",
        "ecr:DescribeImageScanFindings",
        "ecr:GetDownloadUrlForLayer",
        "ecr:InitiateLayerUpload",
        "ecr:PutImage",
        "ecr:UploadLayerPart",
      ]) &&
      jsondecode(aws_iam_role_policy.hub_publisher.policy).Statement[1].Resource == "arn:aws:ecr:us-east-2:767397897469:repository/layerv/nhp-hub" &&
      jsondecode(aws_iam_role_policy.hub_publisher.policy).Statement[2].Sid == "HubDigestPin" &&
      toset(jsondecode(aws_iam_role_policy.hub_publisher.policy).Statement[2].Action) == toset([
        "ssm:GetParameter",
        "ssm:PutParameter",
      ]) &&
      jsondecode(aws_iam_role_policy.hub_publisher.policy).Statement[2].Resource == "arn:aws:ssm:us-east-2:767397897469:parameter/sandbox/nhp/control/hub/image-digest"
    )
    error_message = "The Hub publisher policy must remain limited to exact-repository ECR and exact-parameter SSM."
  }

  assert {
    condition = (
      aws_elasticache_user.otp_disabled_default.access_string == "off ~* -@all" &&
      aws_elasticache_user.otp_authority.authentication_mode[0].type == "iam" &&
      aws_elasticache_user.otp_authority.access_string == "on ~connector:* -@all +@connection +@read +@write +@scripting" &&
      aws_elasticache_user.otp_authority.user_name == aws_elasticache_user.otp_authority.user_id &&
      !contains(aws_elasticache_user_group.otp.user_ids, aws_elasticache_user.otp_authority.user_id) &&
      aws_elasticache_user.otp_issuer.authentication_mode[0].type == "iam" &&
      aws_elasticache_user.otp_issuer.access_string == "on %W~connector:registration-otp:v2:{*}:challenge %W~connector:registration-otp:v2:{*}:state ~connector:ratelimit:registration-otp:credential:* ~connector:ratelimit:registration-otp:owner:* ~connector:ratelimit:registration-otp:peer:* ~connector:ratelimit:registration-otp:source:* resetchannels -@all +hello +auth +ping +command +cluster|slots +multi +exec +discard +del +hset +expire +eval +evalsha +zremrangebyscore +zcard +zrange +zadd" &&
      aws_elasticache_user.otp_issuer.user_name == aws_elasticache_user.otp_issuer.user_id &&
      aws_elasticache_user.otp_activator.authentication_mode[0].type == "iam" &&
      aws_elasticache_user.otp_activator.access_string == "on %R~connector:registration-otp:v2:{*}:challenge ~connector:registration-otp:v2:{*}:state resetchannels -@all +hello +auth +ping +command +cluster|slots +watch +unwatch +multi +exec +discard +hmget +hlen +pttl +hset +pexpire" &&
      aws_elasticache_user.otp_activator.user_name == aws_elasticache_user.otp_activator.user_id &&
      toset(aws_elasticache_user_group.otp.user_ids) == toset([
        aws_elasticache_user.otp_disabled_default.user_id,
        aws_elasticache_user.otp_issuer.user_id,
        aws_elasticache_user.otp_activator.user_id,
      ]) &&
      length(aws_elasticache_user.otp_disabled_default.user_id) <= 40 &&
      length(aws_elasticache_user.otp_authority.user_id) <= 40 &&
      length(aws_elasticache_user.otp_issuer.user_id) <= 40 &&
      length(aws_elasticache_user.otp_activator.user_id) == 40 &&
      aws_elasticache_serverless_cache.otp.major_engine_version == "7" &&
      aws_elasticache_serverless_cache.otp.user_group_id == aws_elasticache_user_group.otp.user_group_id &&
      aws_elasticache_serverless_cache.otp.snapshot_retention_limit == 0
    )
    error_message = "OTP Redis must use Redis OSS 7 read/write key ACLs, detach the legacy authority, split issuer and activator permissions, and never snapshot ephemeral state."
  }

  assert {
    condition = (
      !strcontains(aws_elasticache_user.otp_issuer.access_string, "%R~connector:registration-otp:v2:{*}:challenge") &&
      !strcontains(aws_elasticache_user.otp_issuer.access_string, "+@read") &&
      !strcontains(aws_elasticache_user.otp_issuer.access_string, "+@write") &&
      !strcontains(aws_elasticache_user.otp_issuer.access_string, "+@scripting") &&
      !strcontains(aws_elasticache_user.otp_activator.access_string, "%W~connector:registration-otp:v2:{*}:challenge") &&
      !strcontains(aws_elasticache_user.otp_activator.access_string, "%RW~connector:registration-otp:v2:{*}:challenge") &&
      !strcontains(aws_elasticache_user.otp_activator.access_string, "+eval") &&
      !strcontains(aws_elasticache_user.otp_activator.access_string, "+evalsha") &&
      !strcontains(aws_elasticache_user.otp_activator.access_string, "+del") &&
      !strcontains(aws_elasticache_user.otp_activator.access_string, "+hincrby") &&
      !strcontains(aws_elasticache_user.otp_activator.access_string, "+hget") &&
      !strcontains(aws_elasticache_user.otp_issuer.access_string, "+@connection") &&
      !strcontains(aws_elasticache_user.otp_activator.access_string, "+@connection") &&
      !strcontains(aws_elasticache_user.otp_issuer.access_string, "+client") &&
      !strcontains(aws_elasticache_user.otp_activator.access_string, "+client")
    )
    error_message = "Issuer challenge reads and activator challenge writes, deletes, scripts, HINCRBY, unused HGET, or broad connection/client permissions must remain denied."
  }

  assert {
    condition = (
      jsondecode(aws_iam_role.flow_logs.assume_role_policy).Statement[0].Condition.StringEquals["aws:SourceAccount"] == "767397897469" &&
      jsondecode(aws_iam_role.flow_logs.assume_role_policy).Statement[0].Condition.ArnLike["aws:SourceArn"] == "arn:aws:ec2:us-east-2:767397897469:vpc-flow-log/*"
    )
    error_message = "Flow Logs role trust must be limited to this account's regional flow-log resources."
  }

  assert {
    condition = (
      jsondecode(aws_iam_role_policy.flow_logs.policy).Statement[0].Sid == "DiscoverFlowLogGroups" &&
      jsondecode(aws_iam_role_policy.flow_logs.policy).Statement[0].Action == "logs:DescribeLogGroups" &&
      jsondecode(aws_iam_role_policy.flow_logs.policy).Statement[0].Resource == "*" &&
      jsondecode(aws_iam_role_policy.flow_logs.policy).Statement[1].Resource == "arn:aws:logs:us-east-2:767397897469:log-group:/layerv/nhp/sandbox/control/vpc-flow-logs:*" &&
      toset(jsondecode(aws_iam_role_policy.flow_logs.policy).Statement[2].Action) == toset(["logs:CreateLogStream", "logs:PutLogEvents"]) &&
      jsondecode(aws_iam_role_policy.flow_logs.policy).Statement[2].Resource == "arn:aws:logs:us-east-2:767397897469:log-group:/layerv/nhp/sandbox/control/vpc-flow-logs:*"
    )
    error_message = "Flow Logs group discovery must be global while stream discovery and writes use the dedicated group's stream ARN."
  }

  assert {
    condition     = !aws_dynamodb_table.api_keys.deletion_protection_enabled && !aws_dynamodb_table.connector_authority.deletion_protection_enabled
    error_message = "Sandbox tables intentionally omit deletion protection for teardown economics."
  }
}

run "production_tables_are_deletion_protected" {
  command = plan

  override_data {
    target = data.aws_caller_identity.current
    values = {
      account_id = "235500187906"
    }
  }

  variables {
    environment                = "prod"
    aws_account_id             = "235500187906"
    vpc_cidr                   = "10.202.0.0/16"
    otp_email_from             = "noreply@notify.layerv.ai"
    ses_configuration_set_name = "layerv-nhp-prod-agent-otp"
  }

  assert {
    condition = alltrue([
      aws_dynamodb_table.api_keys.deletion_protection_enabled,
      aws_dynamodb_table.agent_keys.deletion_protection_enabled,
      aws_dynamodb_table.customers.deletion_protection_enabled,
      aws_dynamodb_table.api_key_idempotency.deletion_protection_enabled,
      aws_dynamodb_table.connector_authority.deletion_protection_enabled,
    ])
    error_message = "Every production control table must have deletion protection."
  }

  assert {
    condition = (
      output.authority_publisher_role_name == "layerv-nhp-prod-control-connector-authority-publisher" &&
      output.authority_publisher_github_environment == "production" &&
      jsondecode(aws_iam_role.authority_publisher.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] == "repo:layervai/qurl-service:environment:production" &&
      jsondecode(aws_iam_role_policy.authority_publisher.policy).Statement[1].Resource == "arn:aws:ecr:us-east-2:235500187906:repository/layerv/qurl-connector-authority" &&
      jsondecode(aws_iam_role_policy.authority_publisher.policy).Statement[2].Resource == "arn:aws:ssm:us-east-2:235500187906:parameter/prod/nhp/control/connector-authority/image-digest"
    )
    error_message = "Production publication must use qurl-service's production Environment and only production authority targets."
  }

  assert {
    condition = (
      output.hub_publisher_role_name == "layerv-nhp-prod-control-hub-publisher" &&
      output.hub_publisher_github_environment == "hub-publish-production" &&
      output.hub_publisher_github_subject == "repo:layervai/nhp:environment:hub-publish-production" &&
      jsondecode(aws_iam_role.hub_publisher.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] == "repo:layervai/nhp:environment:hub-publish-production" &&
      jsondecode(aws_iam_role_policy.hub_publisher.policy).Statement[1].Resource == "arn:aws:ecr:us-east-2:235500187906:repository/layerv/nhp-hub" &&
      jsondecode(aws_iam_role_policy.hub_publisher.policy).Statement[2].Resource == "arn:aws:ssm:us-east-2:235500187906:parameter/prod/nhp/control/hub/image-digest"
    )
    error_message = "Production Hub publication must use NHP's dedicated Hub publication Environment and only production Hub targets."
  }
}

run "vpc_prefix_must_leave_aws_valid_subnets" {
  command = plan

  variables {
    environment                = "sandbox"
    aws_account_id             = "767397897469"
    vpc_cidr                   = "10.102.0.0/24"
    otp_email_from             = "noreply@notify.layerv.xyz"
    ses_configuration_set_name = "layerv-nhp-sandbox-agent-otp"
  }

  expect_failures = [var.vpc_cidr]
}

run "malformed_otp_sender_reports_variable_error" {
  command = plan

  variables {
    environment                = "sandbox"
    aws_account_id             = "767397897469"
    vpc_cidr                   = "10.102.0.0/16"
    otp_email_from             = "not-an-email-address"
    ses_configuration_set_name = "layerv-nhp-sandbox-agent-otp"
  }

  expect_failures = [var.otp_email_from]
}

run "uppercase_single_character_domain_label_is_valid" {
  command = plan

  variables {
    environment                = "sandbox"
    aws_account_id             = "767397897469"
    vpc_cidr                   = "10.102.0.0/16"
    otp_email_from             = "x@A.IO"
    ses_configuration_set_name = "layerv-nhp-sandbox-agent-otp"
  }

  assert {
    condition     = output.otp_email_from == "x@A.IO"
    error_message = "A valid uppercase one-character DNS label must be accepted in the OTP sender domain."
  }

  assert {
    condition     = output.ses_identity_arn == "arn:aws:ses:us-east-2:767397897469:identity/a.io"
    error_message = "The case-insensitive SES identity domain must normalize to lowercase."
  }
}
