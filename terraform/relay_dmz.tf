# Dedicated relay DMZ. This is count-gated by deploy_relay, so production stays
# relay-dark with no network or IAM-policy delta. PR 0's root-owned identity,
# image pin, certificate, DNS alias, and canonical ASG parameter remain outside
# this disposable network/fleet boundary.

resource "time_sleep" "relay_dmz_iam_propagation" {
  count = var.deploy_relay ? 1 : 0

  triggers = {
    policy_doc_hash = module.ecr.terraform_apply_relay_dmz_policy_doc_hash
    policy_arn      = module.ecr.terraform_apply_relay_dmz_policy_arn
    attachment_id   = module.ecr.terraform_apply_relay_dmz_attachment_id
  }

  # Action-list expansion on an already-scoped apply role. This mirrors the
  # repository's 60-second IAM propagation pattern; the relay-network module
  # depends on the wait before exercising Flow Logs, peering, Resolver, or the
  # first-use Resolver service-linked-role grant.
  create_duration = local.iam_propagation_duration

  # Keep the CIDR-overlap proof in every targeted path that reaches the DMZ
  # apply barrier without reintroducing a broad module dependency.
  depends_on = [terraform_data.relay_dmz_preconditions]
}

resource "terraform_data" "relay_dmz_preconditions" {
  count = var.deploy_relay ? 1 : 0

  lifecycle {
    precondition {
      condition     = can(cidrnetmask(var.vpc_cidr)) && cidrnetmask(var.vpc_cidr) == "255.255.0.0"
      error_message = "The relay DMZ overlap proof requires the main vpc_cidr to be an IPv4 /16."
    }

    precondition {
      # Both inputs are constrained to /16. Comparing their canonical network
      # addresses therefore proves the two VPC ranges cannot overlap.
      condition     = cidrhost(var.relay_vpc_cidr, 0) != cidrhost(var.vpc_cidr, 0)
      error_message = "relay_vpc_cidr must not overlap the main VPC CIDR."
    }
  }
}

# Materialize the exact cell-routing input as a plan-visible contract. The saved
# plan gate compares this authoritative value with the rendered relay.toml, so a
# template regression cannot substitute a merely well-shaped but incorrect NHP
# server key. The public key and internal NLB hostname are non-secret values.
resource "terraform_data" "relay_cell_routing" {
  count = var.deploy_relay ? 1 : 0

  input = [{
    name       = "${var.environment}-${var.cell_id}"
    public_key = module.compute.server_public_key_b64
    host       = module.compute.internal_nlb_dns_name
    port       = 62206
  }]
}

module "relay_network" {
  count  = var.deploy_relay ? 1 : 0
  source = "./modules/relay-network"

  environment                     = var.environment
  name_prefix                     = local.name_prefix
  vpc_cidr                        = var.relay_vpc_cidr
  main_vpc_id                     = module.networking.vpc_id
  main_private_subnet_cidr_blocks = module.networking.private_subnet_cidr_blocks
  main_private_route_table_ids    = module.networking.private_route_table_ids
  relay_secret_arn                = module.relay_identity[0].secret_arn
  relay_repo_arn                  = module.ecr.relay_repo_arn
  relay_image_tag_parameter_name  = "/${var.environment}/nhp/relay/image-tag"
  apply_role_ready_token          = time_sleep.relay_dmz_iam_propagation[0].id
  tags                            = merge(local.common_tags, { Service = "nhp-relay" })
}

# Collapse the complete relay-network module into one opaque apply-time token.
# The relay child consumes only this value, so its provider data and security
# policies remain plan-known while its public edges and ASG wait for every DMZ
# route, endpoint, DNS Firewall rule, and forensic logging resource.
resource "terraform_data" "relay_network_ready" {
  count = var.deploy_relay ? 1 : 0

  input      = module.relay_network[0].vpc_id
  depends_on = [module.relay_network]
}

resource "aws_cloudwatch_metric_alarm" "relay_dmz_dns_blocked" {
  count = var.deploy_relay ? 1 : 0

  alarm_name          = "${local.name_prefix}-relay-dmz-dns-blocked"
  alarm_description   = "Relay DMZ DNS Firewall blocked a query; investigate tunneling, DGA, or unexpected runtime dependencies."
  namespace           = module.relay_network[0].dns_blocked_metric_namespace
  metric_name         = module.relay_network[0].dns_blocked_metric_name
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [module.monitoring.sns_topic_arn]
  ok_actions    = [module.monitoring.sns_topic_arn]

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-relay-dmz-dns-blocked"
    Component = "relay-network"
    Service   = "nhp-relay"
  })
}
