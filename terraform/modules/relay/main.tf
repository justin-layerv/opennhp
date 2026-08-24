# NHP-Relay module (#2208 Phase-2 #5).
#
# Stands up the internet-facing relay: an autoscaling fleet (one instance per AZ
# baseline) behind an ALB that forwards a browser's opaque NHP knock to the
# cell's internal server endpoint. The shared-keypair fleet authenticates by
# Noise pubkey + relay.toml registration, not source IP (server
# DisableRelayPeerValidation).
# PR0 publishes public-only relay trust to the server. Native UDP SDKs bypass
# this browser relay and connect directly to their assigned cell's public NLB.
# See docs/design/NHP_RELAY_TOPOLOGY.md.

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {} # used by access_logs.tf (ELB delivery policy ARNs)
data "aws_prefix_list" "s3" {
  name = "com.amazonaws.${data.aws_region.current.id}.s3"
}

resource "terraform_data" "network_ready" {
  input = var.network_ready_token
}

# The relay and load-balancer SGs intentionally have no inline/default rules.
# Collapse every mandatory standalone data/control-plane rule into one barrier
# so the ASG cannot launch a one-shot bootstrap before its ECR, SSM, Secrets,
# S3, health-check, or server-return paths exist.
resource "terraform_data" "fleet_security_ready" {
  input = aws_security_group.relay.id

  depends_on = [
    aws_vpc_security_group_ingress_rule.alb_https,
    aws_vpc_security_group_egress_rule.alb_to_relay,
    aws_vpc_security_group_ingress_rule.relay_http_from_alb,
    aws_vpc_security_group_ingress_rule.relay_udp_ack_return,
    aws_vpc_security_group_egress_rule.relay_to_nhp_udp,
    aws_vpc_security_group_egress_rule.relay_to_vpc_endpoints_https,
    aws_vpc_security_group_ingress_rule.vpc_endpoints_from_relay,
    aws_vpc_security_group_egress_rule.relay_to_s3_https,
  ]
}

# AMI: default to the SSM-published server AMI (Docker + awscli + the
# systemd-resolved stub-disable fix used for the relay's internal-NLB lookup).
# A stock Ubuntu AMI would crash-loop on `net.ResolveUDPAddr` against the
# systemd-resolved stub — see variable.server_ami_id.
data "aws_ssm_parameter" "server_ami" {
  count = var.server_ami_id == null ? 1 : 0
  name  = "/${var.environment}/nhp/server/ami-id"
}

locals {
  is_prod = var.environment == "prod"

  ami_id = var.server_ami_id != null ? var.server_ami_id : data.aws_ssm_parameter.server_ami[0].value

  nhp_server_udp_port = 62206

  nhp_server_cidr_blocks = toset(var.nhp_server_cidr_blocks)

  tags = merge(var.tags, {
    Environment = var.environment
    Component   = "relay"
  })

  user_data = templatefile("${path.module}/user_data.sh.tpl", {
    region                  = data.aws_region.current.id
    environment             = var.environment
    relay_repo_url          = var.relay_repo_url
    secret_arn              = var.relay_secret_arn
    ssm_image_tag_parameter = var.ssm_image_tag_parameter
    log_group               = aws_cloudwatch_log_group.relay.name
    # relay.toml render inputs
    listen_port          = var.listen_port
    udp_listen_port      = var.udp_listen_port
    cell_servers         = var.cell_servers
    cors_allowed_origins = var.cors_allowed_origins
  })

  matched_cohort_user_data = var.enable_matched_cohort_canary ? templatefile("${path.module}/user_data.sh.tpl", {
    region                  = data.aws_region.current.id
    environment             = var.environment
    relay_repo_url          = var.relay_repo_url
    secret_arn              = var.relay_secret_arn
    ssm_image_tag_parameter = var.matched_cohort_image_tag_parameter
    log_group               = aws_cloudwatch_log_group.relay.name
    listen_port             = var.listen_port
    udp_listen_port         = var.udp_listen_port
    cell_servers            = var.matched_cohort_cell_servers
    cors_allowed_origins    = var.cors_allowed_origins
  }) : ""
}
