# One plan-visible and runtime-readable inventory for the attended selector.
# It contains addresses and reviewed boot-slot labels only. PR2 must build a
# separate immutable release manifest that binds the exact signed source and
# digest-qualified server, AC, and relay images; the SHA-256 of that canonical
# manifest is the selector/maintenance --release-id. A mutable source tag or
# this address inventory is never final fleet authority. No workflow or
# instance can edit this parameter.

locals {
  matched_cohort_contract = var.enable_matched_cohort_canary ? {
    schema      = 2
    environment = var.environment
    server = {
      canonical_endpoint               = module.compute.nlb_dns_name
      canonical_listener_arn           = module.compute.nlb_udp_listener_arn
      blue_target_group_arn            = module.compute.target_group_arn
      candidate_target_group_arn       = module.compute.matched_cohort_candidate_promotion_target_group_arn
      candidate_endpoint               = module.compute.matched_cohort_candidate_server_dns_name
      candidate_listener_arn           = module.compute.matched_cohort_candidate_listener_arn
      candidate_smoke_target_group_arn = module.compute.matched_cohort_candidate_smoke_target_group_arn
      blue_rollback                    = module.compute.matched_cohort_blue_rollback_authority
      candidate_authority              = module.compute.matched_cohort_candidate_authority
      active_assignment_table          = module.dynamodb.ac_assignments_table_name
      candidate_assignment_table       = module.dynamodb.matched_cohort_ac_assignments_table_name
      candidate_cloudmap_service_arn   = module.compute.matched_cohort_candidate_cloudmap_service_arn
      blue_registration_endpoint       = module.compute.matched_cohort_registration_blue_dns_name
      green_registration_endpoint      = module.compute.matched_cohort_registration_green_dns_name
    }
    ac = {
      canonical_endpoint               = module.ac.nlb_dns_name
      canonical_listener_arn           = module.ac.canonical_listener_arn
      blue_target_group_arn            = module.ac.tcp_target_group_blue_arn
      candidate_target_group_arn       = module.ac.matched_cohort_candidate_target_group_arn
      candidate_endpoint               = module.ac.matched_cohort_candidate_nlb_dns_name
      candidate_listener_arn           = module.ac.matched_cohort_candidate_listener_arn
      candidate_smoke_target_group_arn = module.ac.matched_cohort_candidate_smoke_target_group_arn
      active_asg                       = module.ac.asg_name
      blue_rollback                    = module.ac.matched_cohort_blue_rollback_authority
      candidate_authority              = module.ac.matched_cohort_candidate_authority
      frps_selectors                   = module.ac.matched_cohort_frps_selectors
    }
    relay = {
      canonical_rule_arn         = module.relay[0].canonical_rule_arn
      blue_target_group_arn      = module.relay[0].blue_target_group_arn
      candidate_target_group_arn = module.relay[0].matched_cohort_candidate_target_group_arn
      candidate_listener_arn     = module.relay[0].matched_cohort_candidate_listener_arn
      candidate_rule_arn         = module.relay[0].matched_cohort_candidate_rule_arn
      candidate_endpoint         = module.relay[0].matched_cohort_candidate_dns_name
      public_hostname            = var.relay_dns_name
      blue_rollback              = module.relay[0].matched_cohort_blue_rollback_authority
      candidate_authority        = module.relay[0].matched_cohort_candidate_authority
      blue_server_endpoint       = module.compute.internal_nlb_dns_name
      green_server_endpoint      = module.compute.matched_cohort_relay_green_dns_name
    }
    maintenance = {
      closed_cidr_ipv4    = "192.0.2.255/32"
      operator_lock_table = module.dynamodb.matched_cohort_operator_lock_table_name
      server_ingress_rules = {
        nhp = module.compute.matched_cohort_public_ingress_rule
      }
      ac_ingress_rules = module.ac.matched_cohort_public_ingress_rules
      relay_rule       = module.relay[0].matched_cohort_maintenance_rule
    }
  } : null
}

resource "aws_ssm_parameter" "matched_cohort_contract" {
  count = var.enable_matched_cohort_canary ? 1 : 0

  name        = "/${var.environment}/nhp/matched-cohort/contract-v2"
  description = "Exact immutable-address inventory for the attended matched-cohort selector"
  type        = "String"
  value       = jsonencode(local.matched_cohort_contract)

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-matched-cohort-contract"
    Component = "deployment"
  })
}

check "matched_cohort_canary_preconditions" {
  assert {
    condition = !var.enable_matched_cohort_canary || (
      var.environment == "prod" &&
      var.enable_canary_deployment &&
      !var.enable_blue_green &&
      !var.enable_ac_blue_green &&
      var.public_nhp_udp_ingress_cidrs == null &&
      var.deploy_ac &&
      var.deploy_relay
    )
    error_message = "The matched-cohort canary is prod-only, preserves the current normal-canary regime and legacy public server rule, and requires both AC and relay fleets."
  }
}

output "matched_cohort_contract_parameter" {
  description = "SSM parameter containing the exact selector inventory; null while the dormant primitive is disabled."
  value       = var.enable_matched_cohort_canary ? aws_ssm_parameter.matched_cohort_contract[0].name : null
}
