# NHP-Relay module (#2208 Phase-2 #5).
#
# Stands up the internet-facing relay: an autoscaling fleet (one instance per AZ
# baseline) behind an ALB that forwards a browser's opaque NHP knock to the
# (private) cell server. The shared-keypair fleet authenticates by Noise pubkey +
# relay.toml registration, not source IP (server DisableRelayPeerValidation; 5c).
# Ships DARK — until 5c registers the relay's pubkey in the server's relay.toml,
# every NHP_RLY is rejected at the server's Noise layer (the relay is not yet a
# registered peer), so `POST /relay/{id}` returns 504. The relay boots,
# `/health/live` is 200, and the ALB is internet-reachable, but it can't pivot
# into the private network until 5c lights it up. See
# docs/design/NHP_RELAY_TOPOLOGY.md.

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {} # used by access_logs.tf (ELB delivery policy ARNs)
data "aws_prefix_list" "s3" {
  name = "com.amazonaws.${data.aws_region.current.id}.s3"
}

# AMI: default to the SSM-published server AMI (Docker + awscli + the
# systemd-resolved stub-disable fix the relay's startup CloudMap resolve needs).
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

  private_subnet_cidr_blocks = toset(var.private_subnet_cidr_blocks)

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
}
