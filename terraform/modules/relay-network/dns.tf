resource "aws_cloudwatch_log_group" "resolver" {
  name              = "/layerv/nhp/${var.environment}/relay-dmz/resolver"
  retention_in_days = var.environment == "prod" ? 365 : 30
  kms_key_id        = aws_kms_key.logs.arn

  tags = merge(local.tags, { Name = "${var.name_prefix}-relay-dmz-resolver" })
}

resource "aws_route53_resolver_query_log_config" "relay" {
  name            = "${var.name_prefix}-relay-dmz"
  destination_arn = aws_cloudwatch_log_group.resolver.arn
  tags            = local.tags

  depends_on = [aws_kms_key.logs]
}

resource "aws_route53_resolver_query_log_config_association" "relay" {
  resolver_query_log_config_id = aws_route53_resolver_query_log_config.relay.id
  resource_id                  = aws_vpc.relay.id
}

resource "aws_route53_resolver_firewall_domain_list" "allow" {
  name = "${var.name_prefix}-relay-dmz-allow"
  # Route 53 Resolver persists fully-qualified domain-list entries with a
  # trailing dot. Declare that canonical form so provider refresh cannot turn
  # this fenced security boundary into a perpetual in-place update.
  domains = [
    "api.ecr.${data.aws_region.current.region}.amazonaws.com.",
    "*.dkr.ecr.${data.aws_region.current.region}.amazonaws.com.",
    "secretsmanager.${data.aws_region.current.region}.amazonaws.com.",
    "ssm.${data.aws_region.current.region}.amazonaws.com.",
    "ssmmessages.${data.aws_region.current.region}.amazonaws.com.",
    "logs.${data.aws_region.current.region}.amazonaws.com.",
    "monitoring.${data.aws_region.current.region}.amazonaws.com.",
    "guardduty-data.${data.aws_region.current.region}.amazonaws.com.",
    "s3.${data.aws_region.current.region}.amazonaws.com.",
    "*.s3.${data.aws_region.current.region}.amazonaws.com.",
    "*.elb.${data.aws_region.current.region}.amazonaws.com.",
  ]
  tags = local.tags

  depends_on = [terraform_data.apply_role_ready]
}

resource "aws_route53_resolver_firewall_domain_list" "all" {
  name    = "${var.name_prefix}-relay-dmz-all"
  domains = ["*."]
  tags    = local.tags

  depends_on = [terraform_data.apply_role_ready]
}

resource "aws_route53_resolver_firewall_rule_group" "relay" {
  name = "${var.name_prefix}-relay-dmz"
  tags = local.tags

  depends_on = [terraform_data.apply_role_ready]
}

resource "aws_route53_resolver_firewall_rule" "allow" {
  name                    = "allow-required-domains"
  action                  = "ALLOW"
  priority                = 200
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.relay.id
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.allow.id
  # Trust only CNAME/redirection targets reached from an allowlisted AWS name.
  # A directly queried target is still evaluated independently.
  firewall_domain_redirection_action = "TRUST_REDIRECTION_DOMAIN"
}

locals {
  advanced_dns_protections = {
    DGA            = 100
    DICTIONARY_DGA = 110
    DNS_TUNNELING  = 120
  }
}

resource "aws_route53_resolver_firewall_rule" "advanced" {
  for_each = local.advanced_dns_protections

  name                   = "block-${lower(replace(each.key, "_", "-"))}"
  action                 = "BLOCK"
  block_response         = "NODATA"
  priority               = each.value
  firewall_rule_group_id = aws_route53_resolver_firewall_rule_group.relay.id
  dns_threat_protection  = each.key
  confidence_threshold   = "HIGH"
}

resource "aws_route53_resolver_firewall_rule" "block_all" {
  name                    = "block-all-other-domains"
  action                  = "BLOCK"
  block_response          = "NODATA"
  priority                = 900
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.relay.id
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.all.id
}

resource "aws_route53_resolver_firewall_rule_group_association" "relay" {
  name                   = "${var.name_prefix}-relay-dmz"
  firewall_rule_group_id = aws_route53_resolver_firewall_rule_group.relay.id
  # AWS reserves the boundary value 100 even though its validation error says
  # the accepted range begins at 100. Use the first non-reserved value.
  priority = 101
  vpc_id   = aws_vpc.relay.id
  # Keep this Terraform-owned association rollback-safe. The AWS provider's
  # destroy path does not disable mutation protection before disassociating, so
  # ENABLED would make a reviewed revert/apply fail. CI plan checks plus the
  # post-apply live detector are the drift controls for this boundary.
  mutation_protection = "DISABLED"
  tags                = local.tags
}

resource "aws_route53_resolver_firewall_config" "relay" {
  resource_id        = aws_vpc.relay.id
  firewall_fail_open = "DISABLED"
}

resource "aws_cloudwatch_log_metric_filter" "dns_blocked" {
  name           = "${var.name_prefix}-relay-dmz-dns-blocked"
  log_group_name = aws_cloudwatch_log_group.resolver.name
  # Functional validation deliberately resolves example.com to prove the
  # catch-all rule. Keep that controlled probe in Resolver logs, but exclude it
  # from the paging metric so every routine relay refresh does not create an
  # expected ALARM/OK notification pair.
  pattern = "{ $.firewall_rule_action = \"BLOCK\" && $.query_name != %^example\\.com\\.*$% }"

  metric_transformation {
    name      = "RelayDmzDnsBlocked"
    namespace = "LayerV/NHP"
    value     = "1"
  }
}
