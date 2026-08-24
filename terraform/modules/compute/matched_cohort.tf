# Dormant matched-cohort canary edges.
#
# These resources never select production traffic. They give each AC color a
# stable registration-only endpoint, give the relay candidate a green-only
# internal server endpoint, and give the protected customer smoke a restricted
# green-only public endpoint. The normal promotion workflow owns maintenance,
# selector changes, and rollback; Terraform only creates the addressable slots.

locals {
  matched_cohort_count = var.enable_matched_cohort_canary ? 1 : 0

  matched_cohort_server_user_data = var.enable_matched_cohort_canary ? templatefile(
    "${path.module}/user_data.sh.tpl",
    merge(local.server_user_data_inputs, {
      cloudmap_service_id                    = aws_service_discovery_service.server_candidate[0].id
      cloudmap_service_name                  = "${var.cloudmap_service_name}-candidate"
      dynamodb_ac_assignments_table          = var.matched_cohort_ac_assignments_table
      dynamodb_ac_assignment_authority_table = var.dynamodb_ac_assignments_table
      ssm_image_tag_parameter                = aws_ssm_parameter.matched_cohort_server_image_tag[0].name
    }),
  ) : ""

  matched_cohort_server_bootstrap = var.enable_matched_cohort_canary ? base64encode(<<-BOOTSTRAP
#!/bin/bash
set -euo pipefail
exec > >(tee /var/log/user-data.log | logger -t user-data) 2>&1
for binary in aws curl md5sum; do command -v "$binary" >/dev/null 2>&1 || exit 1; done
TOKEN=$(curl -fsS -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
REGION=$(curl -fsS -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)

# Terraform IAM attachment completion is not a data-plane readiness signal.
# Probe the independent permissions in parallel and continue immediately on a
# healthy first wave. A propagation miss retries every 250 ms for at most 30s;
# there is no unconditional rollout sleep.
candidate_iam_ready() {
  rm -f /tmp/server-init.sh.pending
  local pids=()
  aws s3 cp "s3://${var.plugin_bucket_name}/scripts/server-init-matched-green.sh" /tmp/server-init.sh.pending --region "$REGION" >/dev/null 2>&1 & pids+=("$!")
  aws dynamodb get-item --table-name "${var.dynamodb_ac_assignments_table}" --key '{"ac_id":{"S":"__matched_cohort_iam_probe__"}}' --consistent-read --region "$REGION" >/dev/null 2>&1 & pids+=("$!")
  aws dynamodb get-item --table-name "${var.matched_cohort_ac_assignments_table}" --key '{"ac_id":{"S":"__matched_cohort_iam_probe__"}}' --consistent-read --region "$REGION" >/dev/null 2>&1 & pids+=("$!")
  aws ssm get-parameter --name "/nhp/pool/registration-key" --with-decryption --region "$REGION" >/dev/null 2>&1 & pids+=("$!")
  aws secretsmanager get-secret-value --secret-id "${aws_secretsmanager_secret.server.arn}" --query ARN --output text --region "$REGION" >/dev/null 2>&1 & pids+=("$!")
  aws ecr get-authorization-token --query 'authorizationData[0].proxyEndpoint' --output text --region "$REGION" >/dev/null 2>&1 & pids+=("$!")
  aws servicediscovery get-service --id "${aws_service_discovery_service.server_candidate[0].id}" --region "$REGION" >/dev/null 2>&1 & pids+=("$!")
  local failed=0
  for pid in "$${pids[@]}"; do wait "$pid" || failed=1; done
  if [ "$failed" -ne 0 ]; then
    rm -f /tmp/server-init.sh.pending
    return 1
  fi
  mv /tmp/server-init.sh.pending /tmp/server-init.sh
}

for attempt in $(seq 1 45); do
  candidate_iam_ready && break
  if [ "$attempt" -eq 45 ]; then
    echo "FATAL: candidate IAM data plane was not ready within 30 seconds"
    exit 1
  fi
  if [ "$attempt" -le 10 ]; then
    sleep 0.25
  elif [ "$attempt" -le 25 ]; then
    sleep 0.5
  else
    sleep 1
  fi
done
test "$(md5sum /tmp/server-init.sh | awk '{print $1}')" = "${md5(local.matched_cohort_server_user_data)}"
chmod +x /tmp/server-init.sh
exec /tmp/server-init.sh
BOOTSTRAP
  ) : ""
}

# The candidate uses the established green image path, but owns it only while
# the ordinary blue/green regime is disabled. This keeps the runtime bootstrap
# byte-compatible while the two Terraform deployment regimes remain exclusive.
resource "aws_ssm_parameter" "matched_cohort_server_image_tag" {
  count = local.matched_cohort_count

  name        = "/${var.environment}/nhp/server/green-image-tag"
  description = "Candidate NHP Server image tag for the coordinated matched-cohort canary"
  type        = "String"
  value       = var.image_tag

  tags = merge(var.tags, {
    Name        = "${var.name_prefix}-matched-server-image"
    Component   = "compute"
    Cell        = var.cell_id
    DeployColor = "green"
    Purpose     = "matched-cohort-candidate"
  })

  lifecycle {
    ignore_changes = [value]
  }
}

# Capture both rollout image slots in the immutable contract created by this
# additive plan. The attended selector re-reads each slot before and after its
# writes, so ignore_changes never turns Terraform state into runtime authority.
data "aws_ssm_parameter" "matched_cohort_blue_image_tag" {
  count = local.matched_cohort_count

  name = aws_ssm_parameter.image_tag.name
}

data "aws_ssm_parameter" "matched_cohort_candidate_image_tag" {
  count = local.matched_cohort_count

  name = aws_ssm_parameter.matched_cohort_server_image_tag[0].name
}

# Candidate instances register and discover only this service. A separate
# assignments table without a separate discovery namespace would still allow
# auto-assignment to select blue instances from the shared service.
resource "aws_service_discovery_service" "server_candidate" {
  count = local.matched_cohort_count

  name        = "server-candidate"
  description = "Matched-cohort candidate NHP Server instances"

  dns_config {
    namespace_id = var.namespace_id

    dns_records {
      ttl  = 30
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  tags = merge(var.tags, {
    Name        = "${var.name_prefix}-cloudmap-server-candidate"
    Component   = "compute"
    Cell        = var.cell_id
    DeployColor = "green"
  })
}

resource "aws_iam_role" "server_candidate" {
  count = local.matched_cohort_count

  name = "${var.name_prefix}-server-candidate"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(var.tags, { DeployColor = "green", Purpose = "matched-cohort-candidate" })
}

resource "aws_iam_instance_profile" "server_candidate" {
  count = local.matched_cohort_count

  name = "${var.name_prefix}-server-candidate"
  role = aws_iam_role.server_candidate[0].name
  tags = merge(var.tags, { DeployColor = "green", Purpose = "matched-cohort-candidate" })
}

resource "aws_iam_role_policy_attachment" "server_candidate_ssm" {
  count = local.matched_cohort_count

  role       = aws_iam_role.server_candidate[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "server_candidate_dynamodb" {
  count = local.matched_cohort_count

  role       = aws_iam_role.server_candidate[0].name
  policy_arn = var.matched_cohort_server_policy_arn

  lifecycle {
    precondition {
      condition     = var.matched_cohort_server_policy_arn != "" && var.matched_cohort_server_policy_doc_hash != ""
      error_message = "Matched-cohort candidate server requires its distinct least-privilege DynamoDB policy and digest."
    }
  }
}

resource "aws_iam_role_policy_attachment" "server_candidate_keypair" {
  count = local.matched_cohort_count

  role       = aws_iam_role.server_candidate[0].name
  policy_arn = var.keypair_policy_arn

  lifecycle {
    precondition {
      condition     = var.keypair_policy_arn != null
      error_message = "Matched-cohort candidate server requires the established server keypair policy."
    }
  }
}

resource "aws_iam_role_policy_attachment" "server_candidate_plugins" {
  count = local.matched_cohort_count

  role       = aws_iam_role.server_candidate[0].name
  policy_arn = var.plugin_download_policy_arn

  lifecycle {
    precondition {
      condition     = var.plugin_download_policy_arn != null
      error_message = "Matched-cohort candidate server requires the established plugin/bootstrap download policy."
    }
  }
}

resource "aws_iam_role_policy" "server_candidate_base" {
  count = local.matched_cohort_count

  name = "server-candidate-permissions"
  role = aws_iam_role.server_candidate[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CandidateSecrets"
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = compact([
          aws_secretsmanager_secret.server.arn,
          aws_secretsmanager_secret.cookie_secret.arn,
          aws_secretsmanager_secret.overload_cookie_secret.arn,
          var.etcd_secret_arn,
          var.etcd_tls_secret_arn,
          var.qurl_service_token_secret_arn,
          var.nhp_internal_auth_secret_arn,
        ])
      },
      {
        Sid      = "CandidateECRToken"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Sid    = "CandidateECRImage"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:BatchGetImage",
          "ecr:GetDownloadUrlForLayer",
        ]
        Resource = var.server_repo_arn
      },
      {
        Sid    = "CandidateServiceRegistration"
        Effect = "Allow"
        Action = [
          "servicediscovery:RegisterInstance",
          "servicediscovery:DeregisterInstance",
          "servicediscovery:UpdateInstanceCustomHealthStatus",
          "servicediscovery:GetInstance",
        ]
        Resource = aws_service_discovery_service.server_candidate[0].arn
      },
      {
        Sid    = "CandidateServiceDiscovery"
        Effect = "Allow"
        Action = [
          "servicediscovery:DiscoverInstances",
          "servicediscovery:GetNamespace",
          "servicediscovery:GetService",
        ]
        Resource = "*"
      },
      {
        Sid    = "CandidateLogs"
        Effect = "Allow"
        Action = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = [
          "${aws_cloudwatch_log_group.server.arn}:*",
          "${aws_cloudwatch_log_group.server_stderr.arn}:*",
        ]
      },
      {
        Sid      = "CandidateSecretsKMS"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = var.secrets_kms_key_arn != null ? [var.secrets_kms_key_arn] : []
      },
      {
        Sid      = "CandidateSelfHealth"
        Effect   = "Allow"
        Action   = ["autoscaling:SetInstanceHealth"]
        Resource = "arn:aws:autoscaling:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:autoScalingGroup:*:autoScalingGroupName/${var.name_prefix}-server-candidate"
      },
      {
        Sid      = "CandidateImageSlotRead"
        Effect   = "Allow"
        Action   = ["ssm:GetParameter", "ssm:GetParameters"]
        Resource = "arn:aws:ssm:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:parameter/${var.environment}/nhp/server/*"
      },
      {
        Sid      = "CandidateInstanceTags"
        Effect   = "Allow"
        Action   = ["ec2:DescribeTags"]
        Resource = "*"
      },
      {
        Sid      = "DenyCandidateDeploymentWindowNamespace"
        Effect   = "Deny"
        Action   = ["cloudwatch:PutMetricData"]
        Resource = "*"
        Condition = {
          StringEquals = { "cloudwatch:namespace" = "LayerV/NHP/Deploy" }
        }
      },
      {
        Sid      = "CandidateMetrics"
        Effect   = "Allow"
        Action   = ["cloudwatch:PutMetricData"]
        Resource = "*"
        Condition = {
          StringEquals = { "cloudwatch:namespace" = "LayerV/NHP" }
        }
      },
    ]
  })

  lifecycle {
    precondition {
      condition = (
        var.matched_cohort_ac_assignments_table != "" &&
        var.matched_cohort_ac_assignments_arn != "" &&
        var.matched_cohort_server_policy_arn != ""
      )
      error_message = "Matched-cohort server authority requires its isolated candidate table and distinct DynamoDB policy."
    }
  }
}

resource "aws_iam_role_policy" "server_candidate_control_identity_agent_keys" {
  count = var.enable_matched_cohort_canary && var.control_identity_agent_keys_table_arn != "" ? 1 : 0

  name = "server-candidate-control-identity-agent-keys"
  role = aws_iam_role.server_candidate[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid      = "CandidateControlIdentityAgentKeysGetItem"
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem"]
        Resource = var.control_identity_agent_keys_table_arn
      },
      {
        Sid      = "CandidateControlIdentityAgentKeysIndexQuery"
        Effect   = "Allow"
        Action   = ["dynamodb:Query"]
        Resource = "${var.control_identity_agent_keys_table_arn}/index/*"
      },
      {
        Sid      = "CandidateControlIdentityAgentKeysKMSDecrypt"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [var.control_identity_kms_key_arn]
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id
            "kms:ViaService"    = "dynamodb.${var.control_identity_home_region}.amazonaws.com"
          }
        }
      },
      ], var.enable_native_session_operations ? [{
        Sid      = "CandidateControlIdentityAgentKeysTransactionCondition"
        Effect   = "Allow"
        Action   = ["dynamodb:ConditionCheckItem"]
        Resource = var.control_identity_agent_keys_table_arn
        Condition = {
          StringEquals = {
            "dynamodb:EnclosingOperation" = "TransactWriteItems"
          }
        }
    }] : [])
  })
}

resource "aws_s3_object" "matched_cohort_server_init_script" {
  count = local.matched_cohort_count

  bucket       = var.plugin_bucket_name
  key          = "scripts/server-init-matched-green.sh"
  content      = local.matched_cohort_server_user_data
  content_type = "text/x-shellscript"

  lifecycle {
    precondition {
      condition     = var.plugin_bucket_name != null && var.plugin_download_policy_arn != null
      error_message = "Matched-cohort server bootstrap requires the plugin bucket and its download policy."
    }
  }
}

resource "aws_launch_template" "server_candidate" {
  count = local.matched_cohort_count

  name_prefix   = "${var.name_prefix}-server-candidate-"
  image_id      = local.server_ami_id
  instance_type = local.is_prod ? "c6i.xlarge" : "t3.medium"

  iam_instance_profile { arn = aws_iam_instance_profile.server_candidate[0].arn }

  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.server.id]
  }

  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      volume_size           = 50
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = var.ebs_kms_key_arn
      delete_on_termination = true
    }
  }

  user_data = local.matched_cohort_server_bootstrap

  monitoring { enabled = true }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  tag_specifications {
    resource_type = "instance"
    tags = merge(var.tags, {
      Name        = "${var.name_prefix}-server-candidate"
      Component   = "compute"
      Cell        = var.cell_id
      DeployColor = "green"
    })
  }

  lifecycle {
    create_before_destroy = true
    precondition {
      condition     = length(base64decode(local.matched_cohort_server_bootstrap)) <= 16384
      error_message = "Matched-cohort server bootstrap exceeds EC2's 16384-byte user_data limit."
    }
  }

  depends_on = [
    aws_s3_object.matched_cohort_server_init_script,
    aws_iam_role_policy.server_candidate_base,
    aws_iam_role_policy.server_candidate_control_identity_agent_keys,
    aws_iam_role_policy.server_candidate_connector_authority,
    aws_iam_role_policy_attachment.server_candidate_dynamodb,
    aws_iam_role_policy_attachment.server_candidate_keypair,
    aws_iam_role_policy_attachment.server_candidate_plugins,
    aws_iam_role_policy_attachment.server_candidate_ssm,
  ]
}

resource "aws_lb" "server_registration_blue" {
  count                            = local.matched_cohort_count
  name                             = replace("${var.name_prefix}-reg-blue", "_", "-")
  internal                         = true
  load_balancer_type               = "network"
  subnets                          = var.private_subnet_ids
  enable_cross_zone_load_balancing = true
  enable_deletion_protection       = local.is_prod

  tags = merge(var.tags, {
    Name        = "${var.name_prefix}-registration-blue"
    Component   = "compute"
    Cell        = var.cell_id
    DeployColor = "blue"
    Purpose     = "ac-registration"
  })
}

resource "aws_lb" "server_registration_green" {
  count                            = local.matched_cohort_count
  name                             = replace("${var.name_prefix}-reg-green", "_", "-")
  internal                         = true
  load_balancer_type               = "network"
  subnets                          = var.private_subnet_ids
  enable_cross_zone_load_balancing = true
  enable_deletion_protection       = local.is_prod

  tags = merge(var.tags, {
    Name        = "${var.name_prefix}-registration-green"
    Component   = "compute"
    Cell        = var.cell_id
    DeployColor = "green"
    Purpose     = "ac-registration"
  })
}

resource "aws_lb_target_group" "server_registration_blue" {
  count       = local.matched_cohort_count
  name        = replace("${var.name_prefix}-reg-b", "_", "-")
  port        = 62206
  protocol    = "UDP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  preserve_client_ip   = true
  deregistration_delay = 30

  health_check {
    enabled             = true
    protocol            = "HTTP"
    port                = "8888"
    path                = "/health/live"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 5
    matcher             = "200"
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-registration-blue", DeployColor = "blue" })
}

resource "aws_lb_target_group" "server_registration_green" {
  count       = local.matched_cohort_count
  name        = replace("${var.name_prefix}-reg-g", "_", "-")
  port        = 62206
  protocol    = "UDP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  preserve_client_ip   = true
  deregistration_delay = 30

  health_check {
    enabled             = true
    protocol            = "HTTP"
    port                = "8888"
    path                = "/health/live"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 5
    matcher             = "200"
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-registration-green", DeployColor = "green" })
}

resource "aws_lb_listener" "server_registration_blue" {
  count             = local.matched_cohort_count
  load_balancer_arn = aws_lb.server_registration_blue[0].arn
  port              = 443
  protocol          = "UDP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.server_registration_blue[0].arn
  }
}

resource "aws_lb_listener" "server_registration_green" {
  count             = local.matched_cohort_count
  load_balancer_arn = aws_lb.server_registration_green[0].arn
  port              = 443
  protocol          = "UDP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.server_registration_green[0].arn
  }
}

resource "aws_autoscaling_attachment" "server_registration_blue" {
  count                  = local.matched_cohort_count
  autoscaling_group_name = aws_autoscaling_group.server.name
  lb_target_group_arn    = aws_lb_target_group.server_registration_blue[0].arn
}

# Green relay instances resolve this endpoint once at boot. It is never switched
# and can therefore never send a new-protocol packet to the blue server fleet.
resource "aws_lb" "server_relay_green" {
  count                            = local.matched_cohort_count
  name                             = replace("${var.name_prefix}-rly-green", "_", "-")
  internal                         = true
  load_balancer_type               = "network"
  subnets                          = var.private_subnet_ids
  enable_cross_zone_load_balancing = true
  enable_deletion_protection       = local.is_prod

  tags = merge(var.tags, { Name = "${var.name_prefix}-relay-green", DeployColor = "green" })
}

resource "aws_lb_target_group" "server_relay_green" {
  count       = local.matched_cohort_count
  name        = replace("${var.name_prefix}-rly-g", "_", "-")
  port        = 62206
  protocol    = "UDP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  preserve_client_ip   = true
  deregistration_delay = 30

  health_check {
    enabled             = true
    protocol            = "HTTP"
    port                = "8888"
    path                = "/health/live"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 5
    matcher             = "200"
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-relay-green", DeployColor = "green" })
}

resource "aws_lb_listener" "server_relay_green" {
  count             = local.matched_cohort_count
  load_balancer_arn = aws_lb.server_relay_green[0].arn
  port              = 62206
  protocol          = "UDP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.server_relay_green[0].arn
  }
}

# Candidate-only direct customer edge. The normal server NLB remains unchanged;
# only the protected runner CIDRs can reach this green-only NLB.
resource "aws_security_group" "server_candidate_nlb" {
  count                  = local.matched_cohort_count
  name_prefix            = "${var.name_prefix}-cand-nlb-"
  description            = "Restricted matched-cohort candidate server NLB"
  vpc_id                 = var.vpc_id
  revoke_rules_on_delete = true

  tags = merge(var.tags, { Name = "${var.name_prefix}-candidate-nlb", Purpose = "protected-smoke" })

  lifecycle { create_before_destroy = true }
}

resource "aws_vpc_security_group_ingress_rule" "server_candidate_nlb" {
  for_each = var.enable_matched_cohort_canary ? toset(var.matched_cohort_smoke_ingress_cidrs) : toset([])

  security_group_id = aws_security_group.server_candidate_nlb[0].id
  description       = "Protected matched-cohort smoke ${each.value}"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "udp"
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_egress_rule" "server_candidate_nlb_udp" {
  count                        = local.matched_cohort_count
  security_group_id            = aws_security_group.server_candidate_nlb[0].id
  from_port                    = 62206
  to_port                      = 62206
  ip_protocol                  = "udp"
  referenced_security_group_id = aws_security_group.server.id
}

resource "aws_vpc_security_group_egress_rule" "server_candidate_nlb_health" {
  count                        = local.matched_cohort_count
  security_group_id            = aws_security_group.server_candidate_nlb[0].id
  from_port                    = 8888
  to_port                      = 8888
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.server.id
}

resource "aws_vpc_security_group_ingress_rule" "server_candidate_target" {
  count                        = local.matched_cohort_count
  security_group_id            = aws_security_group.server.id
  description                  = "NHP candidate packets from restricted smoke NLB"
  from_port                    = 62206
  to_port                      = 62206
  ip_protocol                  = "udp"
  referenced_security_group_id = aws_security_group.server_candidate_nlb[0].id
}

resource "aws_vpc_security_group_ingress_rule" "server_candidate_health" {
  count                        = local.matched_cohort_count
  security_group_id            = aws_security_group.server.id
  description                  = "Candidate NLB health checks"
  from_port                    = 8888
  to_port                      = 8888
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.server_candidate_nlb[0].id
}

resource "aws_lb" "server_candidate" {
  count                                                        = local.matched_cohort_count
  name                                                         = replace("${var.name_prefix}-candidate", "_", "-")
  internal                                                     = false
  load_balancer_type                                           = "network"
  subnets                                                      = var.public_subnet_ids
  security_groups                                              = [aws_security_group.server_candidate_nlb[0].id]
  enforce_security_group_inbound_rules_on_private_link_traffic = "on"
  enable_cross_zone_load_balancing                             = true
  enable_deletion_protection                                   = local.is_prod

  tags = merge(var.tags, { Name = "${var.name_prefix}-candidate", Purpose = "protected-smoke" })
}

resource "aws_lb_target_group" "server_candidate" {
  count       = local.matched_cohort_count
  name        = replace("${var.name_prefix}-candidate", "_", "-")
  port        = 62206
  protocol    = "UDP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  preserve_client_ip   = true
  deregistration_delay = 30

  health_check {
    enabled             = true
    protocol            = "HTTP"
    port                = "8888"
    path                = "/health/knock-ready"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 5
    matcher             = "200"
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-candidate", DeployColor = "green" })
}

# Separate from server_candidate because one target group cannot be attached to
# both the restricted smoke NLB and the canonical public NLB. The promotion
# helper selects only this target group while admission is closed.
resource "aws_lb_target_group" "server_candidate_promotion" {
  count       = local.matched_cohort_count
  name        = replace("${var.name_prefix}-cand-prom", "_", "-")
  port        = 62206
  protocol    = "UDP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  preserve_client_ip   = true
  deregistration_delay = 30

  health_check {
    enabled             = true
    protocol            = "HTTP"
    port                = "8888"
    path                = "/health/knock-ready"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 5
    matcher             = "200"
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-candidate-promotion", DeployColor = "green" })
}

resource "aws_lb_listener" "server_candidate" {
  count             = local.matched_cohort_count
  load_balancer_arn = aws_lb.server_candidate[0].arn
  port              = 443
  protocol          = "UDP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.server_candidate[0].arn
  }
}

# Full-size, isolated candidate server fleet. Its launch template binds the
# candidate assignment table, candidate Cloud Map service, and green image
# slot. Terraform never attaches it to the canonical public listener.
resource "aws_autoscaling_group" "server_candidate" {
  count = local.matched_cohort_count

  name                = "${var.name_prefix}-server-candidate"
  vpc_zone_identifier = var.private_subnet_ids
  min_size            = var.min_capacity
  max_size            = var.max_capacity
  desired_capacity    = var.min_capacity

  launch_template {
    id      = aws_launch_template.server_candidate[0].id
    version = aws_launch_template.server_candidate[0].latest_version
  }

  health_check_type         = "EC2"
  health_check_grace_period = 90

  enabled_metrics = [
    "GroupInServiceInstances",
    "GroupDesiredCapacity",
    "GroupMinSize",
    "GroupMaxSize",
    "GroupPendingInstances",
    "GroupTerminatingInstances",
    "GroupTotalInstances",
  ]

  target_group_arns = [
    aws_lb_target_group.server_registration_green[0].arn,
    aws_lb_target_group.server_relay_green[0].arn,
    aws_lb_target_group.server_candidate[0].arn,
    aws_lb_target_group.server_candidate_promotion[0].arn,
  ]

  tag {
    key                 = "Name"
    value               = "${var.name_prefix}-server-candidate"
    propagate_at_launch = true
  }

  tag {
    key                 = "Component"
    value               = "compute"
    propagate_at_launch = true
  }

  tag {
    key                 = "Cell"
    value               = var.cell_id
    propagate_at_launch = true
  }

  tag {
    key                 = "DeployColor"
    value               = "green"
    propagate_at_launch = true
  }

  tag {
    key                 = "ImageTagSSMParam"
    value               = aws_ssm_parameter.matched_cohort_server_image_tag[0].name
    propagate_at_launch = true
  }

  dynamic "tag" {
    for_each = var.tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }

  lifecycle {
    create_before_destroy = true
    ignore_changes        = [desired_capacity, min_size, max_size, suspended_processes]
  }
}

# Candidate termination cleanup scans only the isolated table. The active
# server-ac index is intentionally not reused: sharing it would let candidate
# lifecycle writes and rollback lifecycle writes collide by server ID.
resource "aws_iam_role" "server_candidate_termination_hook" {
  count = local.matched_cohort_count

  name = "${var.name_prefix}-candidate-termination-hook"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "autoscaling.amazonaws.com" }
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "server_candidate_termination_hook" {
  count = local.matched_cohort_count

  name = "candidate-termination-notification"
  role = aws_iam_role.server_candidate_termination_hook[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "PublishExactCandidateTermination"
      Effect   = "Allow"
      Action   = ["sqs:SendMessage", "sqs:GetQueueUrl"]
      Resource = aws_sqs_queue.server_candidate_termination_cleanup_dlq[0].arn
    }]
  })
}

resource "aws_autoscaling_lifecycle_hook" "server_candidate_termination" {
  count = local.matched_cohort_count

  name                    = "${var.name_prefix}-candidate-termination"
  autoscaling_group_name  = aws_autoscaling_group.server_candidate[0].name
  lifecycle_transition    = "autoscaling:EC2_INSTANCE_TERMINATING"
  default_result          = "CONTINUE"
  heartbeat_timeout       = 7200
  notification_target_arn = aws_sqs_queue.server_candidate_termination_cleanup_dlq[0].arn
  role_arn                = aws_iam_role.server_candidate_termination_hook[0].arn
}

resource "aws_cloudwatch_event_rule" "server_candidate_termination" {
  count = local.matched_cohort_count

  name        = "${var.name_prefix}-candidate-termination"
  description = "Capture matched-cohort candidate server termination"
  event_pattern = jsonencode({
    source      = ["aws.autoscaling"]
    detail-type = ["EC2 Instance-terminate Lifecycle Action"]
    detail = {
      AutoScalingGroupName = [aws_autoscaling_group.server_candidate[0].name]
    }
  })
  tags = var.tags
}

# One queue is the direct lifecycle notification path and also receives
# EventBridge delivery and Lambda async handler failures. The two-hour hook
# ceiling retains the physical server while ordinary delivery recovers. If the
# AWS lifecycle global timeout later forces CONTINUE, the permanent DynamoDB
# fence still denies every new route write containing that server and the
# retained queue event completes removal. A stale pre-fence route can therefore
# fail closed against an absent server, but cannot be resurrected.
resource "aws_sqs_queue" "server_candidate_termination_cleanup_dlq" {
  count = local.matched_cohort_count

  name                       = "${var.name_prefix}-candidate-termination-cleanup-dlq"
  message_retention_seconds  = 1209600
  visibility_timeout_seconds = 720
  sqs_managed_sse_enabled    = true

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-candidate-termination-cleanup-dlq"
    Component = "compute"
  })

  lifecycle {
    precondition {
      condition     = var.enable_sns_alerts && local.sns_destination_present
      error_message = "Matched-cohort candidate cleanup requires the shared SNS alarm destination."
    }
  }
}

resource "aws_sqs_queue_policy" "server_candidate_termination_cleanup_dlq" {
  count = local.matched_cohort_count

  queue_url = aws_sqs_queue.server_candidate_termination_cleanup_dlq[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowExactCandidateTerminationEventDLQ"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.server_candidate_termination_cleanup_dlq[0].arn
      Condition = {
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.server_candidate_termination[0].arn
        }
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_cloudwatch_event_target" "server_candidate_termination" {
  count = local.matched_cohort_count

  rule      = aws_cloudwatch_event_rule.server_candidate_termination[0].name
  target_id = "candidate-server-assignment-cleanup"
  arn       = aws_lambda_function.server_candidate_termination_cleanup[0].arn

  retry_policy {
    maximum_event_age_in_seconds = 240
    maximum_retry_attempts       = 2
  }

  dead_letter_config {
    arn = aws_sqs_queue.server_candidate_termination_cleanup_dlq[0].arn
  }

  depends_on = [aws_sqs_queue_policy.server_candidate_termination_cleanup_dlq]
}

resource "aws_lambda_permission" "server_candidate_termination" {
  count = local.matched_cohort_count

  statement_id  = "AllowCandidateTerminationEvent"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.server_candidate_termination_cleanup[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.server_candidate_termination[0].arn
}

data "archive_file" "server_candidate_termination_cleanup" {
  count = local.matched_cohort_count

  type        = "zip"
  source_file = "${path.module}/lambda/server_candidate_termination_cleanup.py"
  output_path = "${path.module}/lambda/server_candidate_termination_cleanup.zip"
}

resource "aws_cloudwatch_log_group" "server_candidate_termination_cleanup" {
  count = local.matched_cohort_count

  name              = "/aws/lambda/${var.name_prefix}-candidate-termination-cleanup"
  retention_in_days = local.is_prod ? 90 : 14
  kms_key_id        = var.logs_kms_key_arn
  tags              = var.tags
}

resource "aws_iam_role" "server_candidate_termination_cleanup" {
  count = local.matched_cohort_count

  name = "${var.name_prefix}-candidate-termination"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy" "server_candidate_termination_cleanup" {
  count = local.matched_cohort_count

  name = "candidate-assignment-cleanup"
  role = aws_iam_role.server_candidate_termination_cleanup[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CandidateAssignmentCleanup"
        Effect = "Allow"
        Action = [
          "dynamodb:DeleteItem",
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:Scan",
          "dynamodb:UpdateItem",
        ]
        Resource = var.matched_cohort_ac_assignments_arn
      },
      {
        Sid      = "CompleteCandidateLifecycle"
        Effect   = "Allow"
        Action   = ["autoscaling:CompleteLifecycleAction"]
        Resource = aws_autoscaling_group.server_candidate[0].arn
      },
      {
        Sid    = "DeregisterCandidateServer"
        Effect = "Allow"
        Action = [
          "servicediscovery:DeregisterInstance",
          "servicediscovery:GetInstance",
        ]
        Resource = aws_service_discovery_service.server_candidate[0].arn
      },
      {
        Sid      = "ObserveCandidateDeregistration"
        Effect   = "Allow"
        Action   = ["servicediscovery:GetOperation"]
        Resource = "*"
      },
      {
        Sid      = "ObserveCandidateTermination"
        Effect   = "Allow"
        Action   = ["ec2:DescribeInstances"]
        Resource = "*"
      },
      {
        Sid      = "PublishCandidateCleanupFailure"
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = aws_sqs_queue.server_candidate_termination_cleanup_dlq[0].arn
      },
      {
        Sid    = "ConsumeCandidateCleanupFailure"
        Effect = "Allow"
        Action = [
          "sqs:ChangeMessageVisibility",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:ReceiveMessage",
        ]
        Resource = aws_sqs_queue.server_candidate_termination_cleanup_dlq[0].arn
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "server_candidate_termination_logs" {
  count = local.matched_cohort_count

  role       = aws_iam_role.server_candidate_termination_cleanup[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "server_candidate_termination_cleanup" {
  count = local.matched_cohort_count

  depends_on = [aws_cloudwatch_log_group.server_candidate_termination_cleanup]

  filename         = data.archive_file.server_candidate_termination_cleanup[0].output_path
  function_name    = "${var.name_prefix}-candidate-termination-cleanup"
  role             = aws_iam_role.server_candidate_termination_cleanup[0].arn
  handler          = "server_candidate_termination_cleanup.handler"
  source_code_hash = data.archive_file.server_candidate_termination_cleanup[0].output_base64sha256
  runtime          = "python3.11"
  timeout          = 120
  memory_size      = 256

  environment {
    variables = {
      AC_ASSIGNMENTS_TABLE = var.matched_cohort_ac_assignments_table
      CLOUDMAP_SERVICE_ID  = aws_service_discovery_service.server_candidate[0].id
    }
  }

  tags = var.tags
}

resource "aws_lambda_event_source_mapping" "server_candidate_termination_cleanup" {
  count = local.matched_cohort_count

  event_source_arn = aws_sqs_queue.server_candidate_termination_cleanup_dlq[0].arn
  function_name    = aws_lambda_function.server_candidate_termination_cleanup[0].arn
  batch_size       = 1
  enabled          = true

  depends_on = [aws_iam_role_policy.server_candidate_termination_cleanup]
}

resource "aws_lambda_function_event_invoke_config" "server_candidate_termination_cleanup" {
  count = local.matched_cohort_count

  function_name                = aws_lambda_function.server_candidate_termination_cleanup[0].function_name
  maximum_event_age_in_seconds = 240
  maximum_retry_attempts       = 1

  destination_config {
    on_failure {
      destination = aws_sqs_queue.server_candidate_termination_cleanup_dlq[0].arn
    }
  }

  depends_on = [aws_iam_role_policy.server_candidate_termination_cleanup]
}

resource "aws_cloudwatch_metric_alarm" "server_candidate_termination_cleanup_dlq" {
  count = local.matched_cohort_count

  alarm_name          = "${var.name_prefix}-candidate-termination-cleanup-dlq"
  alarm_description   = "Candidate server assignment cleanup exhausted async delivery or execution retries; investigate the retained event before its lifecycle hook expires."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.server_candidate_termination_cleanup_dlq[0].name }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.alerts_sns_topic_arn]
  ok_actions          = [var.alerts_sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-candidate-termination-cleanup-dlq"
    Component = "compute"
    Severity  = "critical"
  })
}

resource "aws_cloudwatch_metric_alarm" "server_candidate_termination_event_failures" {
  count = local.matched_cohort_count

  alarm_name          = "${var.name_prefix}-candidate-termination-event-failures"
  alarm_description   = "Candidate server termination EventBridge rule failed to deliver its cleanup event."
  namespace           = "AWS/Events"
  metric_name         = "FailedInvocations"
  dimensions          = { RuleName = aws_cloudwatch_event_rule.server_candidate_termination[0].name }
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.alerts_sns_topic_arn]
  ok_actions          = [var.alerts_sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-candidate-termination-event-failures"
    Component = "compute"
    Severity  = "critical"
  })
}
