mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = {
      names = ["us-east-2a", "us-east-2b", "us-east-2c"]
    }
  }

  mock_data "aws_region" {
    defaults = {
      region = "us-east-2"
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
}

variables {
  environment                     = "sandbox"
  name_prefix                     = "layerv-nhp-sandbox"
  vpc_cidr                        = "10.101.0.0/16"
  main_vpc_id                     = "vpc-0123456789abcdef0"
  main_private_subnet_cidr_blocks = ["10.100.10.0/24", "10.100.11.0/24", "10.100.12.0/24"]
  main_private_route_table_ids    = ["rtb-0123456789abcdef0"]
  relay_secret_arn                = "arn:aws:secretsmanager:us-east-2:767397897469:secret:layerv-nhp-sandbox-relay-identity-abc123"
  relay_repo_arn                  = "arn:aws:ecr:us-east-2:767397897469:repository/layerv-nhp-sandbox-relay"
  relay_image_tag_parameter_name  = "/sandbox/nhp/relay/image-tag"
  apply_role_ready_token          = "iam-propagation-ready"
}

run "dmz_contract" {
  command = plan

  assert {
    condition = (
      aws_vpc.relay.cidr_block == "10.101.0.0/16" &&
      aws_vpc.relay.enable_dns_hostnames &&
      aws_vpc.relay.enable_dns_support &&
      aws_vpc.relay.enable_network_address_usage_metrics
    )
    error_message = "The relay VPC must retain the dedicated /16 and DNS/address-usage controls."
  }

  assert {
    condition = (
      toset(keys(jsondecode(aws_kms_key.logs.policy).Statement[1].Condition)) == toset(["ArnEquals"]) &&
      toset(jsondecode(aws_kms_key.logs.policy).Statement[1].Condition.ArnEquals["kms:EncryptionContext:aws:logs:arn"]) == toset([
        "arn:aws:logs:us-east-2:767397897469:log-group:/layerv/nhp/sandbox/relay-dmz/flow",
        "arn:aws:logs:us-east-2:767397897469:log-group:/layerv/nhp/sandbox/relay-dmz/resolver",
      ])
    )
    error_message = "The dedicated DMZ logs key must be account-, service-, and exact-log-group scoped."
  }

  assert {
    condition = (
      length(aws_subnet.public) == 3 &&
      length(aws_subnet.relay) == 3 &&
      length(aws_subnet.endpoint) == 3 &&
      alltrue([for subnet in aws_subnet.public : !subnet.map_public_ip_on_launch]) &&
      alltrue([for subnet in aws_subnet.relay : !subnet.map_public_ip_on_launch]) &&
      alltrue([for subnet in aws_subnet.endpoint : !subnet.map_public_ip_on_launch])
    )
    error_message = "All three subnet tiers must span three AZs and disable automatic public IP assignment."
  }

  assert {
    condition = (
      [for subnet in aws_subnet.public : subnet.cidr_block] == ["10.101.0.0/24", "10.101.1.0/24", "10.101.2.0/24"] &&
      [for subnet in aws_subnet.relay : subnet.cidr_block] == ["10.101.10.0/24", "10.101.11.0/24", "10.101.12.0/24"] &&
      [for subnet in aws_subnet.endpoint : subnet.cidr_block] == ["10.101.20.0/24", "10.101.21.0/24", "10.101.22.0/24"]
    )
    error_message = "The public, relay, and endpoint tiers must retain their non-overlapping /24 allocations."
  }

  assert {
    condition = (
      aws_route.public_default.destination_cidr_block == "0.0.0.0/0" &&
      length(aws_route_table.relay) == 3 &&
      length(aws_route_table.endpoint) == 3 &&
      length(aws_route.relay_to_main_private) == 9 &&
      toset([for route in aws_route.relay_to_main_private : route.destination_cidr_block]) == toset(var.main_private_subnet_cidr_blocks) &&
      length(aws_route.main_private_to_relay) == 3 &&
      toset([for route in aws_route.main_private_to_relay : route.destination_cidr_block]) == toset(["10.101.10.0/24", "10.101.11.0/24", "10.101.12.0/24"])
    )
    error_message = "Only the public tier may have a default route; peering routes must use exact /24s in both directions."
  }

  assert {
    condition = toset(keys(local.interface_endpoint_services)) == toset([
      "ecr-api", "ecr-dkr", "guardduty-data", "logs", "monitoring", "secretsmanager", "ssm", "ssmmessages",
    ])
    error_message = "The DMZ must retain exactly eight private-DNS interface endpoints and one relay-route-table-only S3 gateway endpoint."
  }

  assert {
    condition     = length(aws_vpc_endpoint.interface) == 8
    error_message = "The DMZ must create each of the eight approved interface endpoints."
  }

  assert {
    condition = alltrue([
      for policy in values(local.endpoint_policies) :
      length([for statement in jsondecode(policy).Statement : statement if try(statement.Sid, "") == "DenyCrossAccountPrincipals"]) == 1
    ])
    error_message = "Every interface endpoint policy must retain the explicit cross-account deny."
  }

  assert {
    condition = (
      jsondecode(aws_vpc_endpoint.s3.policy).Statement[0].Action == "s3:GetObject" &&
      toset(jsondecode(aws_vpc_endpoint.s3.policy).Statement[0].Resource) == toset([
        "arn:aws:s3:::prod-us-east-2-starport-layer-bucket/*",
        "arn:aws:s3:::amazon-ssm-us-east-2/*",
        "arn:aws:s3:::aws-ssm-us-east-2/*",
        "arn:aws:s3:::us-east-2-birdwatcher-prod/*",
        "arn:aws:s3:::aws-ssm-document-attachments-us-east-2/*",
      ])
    )
    error_message = "The S3 endpoint must allow GetObject only from the five approved regional buckets."
  }

  assert {
    condition = (
      aws_route53_resolver_firewall_config.relay.firewall_fail_open == "DISABLED" &&
      toset(aws_route53_resolver_firewall_domain_list.allow.domains) == toset([
        "api.ecr.us-east-2.amazonaws.com.",
        "*.dkr.ecr.us-east-2.amazonaws.com.",
        "secretsmanager.us-east-2.amazonaws.com.",
        "ssm.us-east-2.amazonaws.com.",
        "ssmmessages.us-east-2.amazonaws.com.",
        "logs.us-east-2.amazonaws.com.",
        "monitoring.us-east-2.amazonaws.com.",
        "guardduty-data.us-east-2.amazonaws.com.",
        "s3.us-east-2.amazonaws.com.",
        "*.s3.us-east-2.amazonaws.com.",
        "*.elb.us-east-2.amazonaws.com.",
      ]) &&
      toset(aws_route53_resolver_firewall_domain_list.all.domains) == toset(["*."]) &&
      aws_route53_resolver_firewall_rule_group_association.relay.mutation_protection == "DISABLED" &&
      aws_route53_resolver_firewall_rule_group_association.relay.priority == 101 &&
      aws_route53_resolver_firewall_rule.allow.priority == 200 &&
      aws_route53_resolver_firewall_rule.block_all.priority == 900 &&
      aws_route53_resolver_firewall_rule.block_all.action == "BLOCK" &&
      toset(keys(aws_route53_resolver_firewall_rule.advanced)) == toset(["DGA", "DICTIONARY_DGA", "DNS_TUNNELING"]) &&
      alltrue([for rule in aws_route53_resolver_firewall_rule.advanced : rule.priority < aws_route53_resolver_firewall_rule.allow.priority])
    )
    error_message = "DNS Firewall must use AWS-canonical domain entries, fail closed, stay Terraform-rollback-safe, and evaluate advanced threat blocks before the allowlist and catch-all block."
  }

  assert {
    condition = (
      aws_flow_log.relay.traffic_type == "ALL" &&
      aws_flow_log.relay.max_aggregation_interval == 60 &&
      aws_route53_resolver_query_log_config.relay.name == "layerv-nhp-sandbox-relay-dmz" &&
      aws_cloudwatch_log_group.resolver.name == "/layerv/nhp/sandbox/relay-dmz/resolver" &&
      aws_cloudwatch_log_metric_filter.dns_blocked.pattern == "{ $.firewall_rule_action = \"BLOCK\" && $.query_name != %^example\\.com\\.*$% }"
    )
    error_message = "VPC Flow Logs and VPC Resolver query logging must remain enabled for the DMZ."
  }

  assert {
    condition = (
      jsondecode(aws_iam_role_policy.flow.policy).Statement[0].Sid == "DiscoverFlowLogGroup" &&
      jsondecode(aws_iam_role_policy.flow.policy).Statement[0].Action == "logs:DescribeLogGroups" &&
      jsondecode(aws_iam_role_policy.flow.policy).Statement[0].Resource == "*" &&
      jsondecode(aws_iam_role_policy.flow.policy).Statement[1].Sid == "DescribeFlowLogStreams" &&
      jsondecode(aws_iam_role_policy.flow.policy).Statement[1].Action == "logs:DescribeLogStreams" &&
      jsondecode(aws_iam_role_policy.flow.policy).Statement[1].Resource == "arn:aws:logs:us-east-2:767397897469:log-group:/layerv/nhp/sandbox/relay-dmz/flow" &&
      jsondecode(aws_iam_role_policy.flow.policy).Statement[2].Sid == "WriteFlowLogStreams" &&
      toset(jsondecode(aws_iam_role_policy.flow.policy).Statement[2].Action) == toset([
        "logs:CreateLogStream",
        "logs:PutLogEvents",
      ]) &&
      jsondecode(aws_iam_role_policy.flow.policy).Statement[2].Resource == "arn:aws:logs:us-east-2:767397897469:log-group:/layerv/nhp/sandbox/relay-dmz/flow:*"
    )
    error_message = "Flow Logs must discover groups globally while stream writes remain scoped to the dedicated DMZ group."
  }

  assert {
    condition = (
      jsondecode(aws_iam_role.flow.assume_role_policy).Statement[0].Principal.Service == "vpc-flow-logs.amazonaws.com" &&
      jsondecode(aws_iam_role.flow.assume_role_policy).Statement[0].Condition.StringEquals["aws:SourceAccount"] == "767397897469" &&
      jsondecode(aws_iam_role.flow.assume_role_policy).Statement[0].Condition.ArnLike["aws:SourceArn"] == "arn:aws:ec2:us-east-2:767397897469:vpc-flow-log/*"
    )
    error_message = "Flow Logs role trust must be limited to this account's regional flow-log resources."
  }
}
