# AC Module Outputs

output "nlb_dns_name" {
  description = "AC NLB DNS name"
  value       = aws_lb.ac.dns_name
}

output "nlb_arn" {
  description = "AC NLB ARN"
  value       = aws_lb.ac.arn
}

output "nlb_arn_suffix" {
  description = "AC NLB ARN suffix for CloudWatch"
  value       = aws_lb.ac.arn_suffix
}

output "nlb_zone_id" {
  description = "AC NLB zone ID for Route 53"
  value       = aws_lb.ac.zone_id
}

output "canonical_listener_arn" {
  description = "Canonical AC TCP listener changed only by the attended matched-cohort selector."
  value       = aws_lb_listener.https.arn
}

output "fqdn" {
  description = "AC fully qualified domain name"
  value       = var.skip_dns_records ? var.domain_name : (var.enable_cloudfront ? aws_route53_record.ac_cloudfront[0].fqdn : aws_route53_record.ac[0].fqdn)
}

output "asg_name" {
  description = "Auto Scaling Group name"
  value       = aws_autoscaling_group.ac.name
}

output "asg_arn" {
  description = "Auto Scaling Group ARN"
  value       = aws_autoscaling_group.ac.arn
}

output "launch_template_arn" {
  description = "AC launch template ARN (for canary deployment IAM)"
  value       = aws_launch_template.ac.arn
}

output "target_group_arn_suffix" {
  description = "TCP target group ARN suffix for CloudWatch alarm dimensions"
  value       = aws_lb_target_group.ac_tcp.arn_suffix
}

output "security_group_id" {
  description = "AC security group ID"
  value       = aws_security_group.ac.id
}

output "matched_cohort_public_ingress_rules" {
  description = "Exact canonical AC target rules changed only by the attended maintenance gate."
  value = var.enable_matched_cohort_canary ? merge(
    {
      https = {
        security_group_id      = aws_security_group.ac.id
        security_group_rule_id = aws_vpc_security_group_ingress_rule.ac_https.security_group_rule_id
        description            = aws_vpc_security_group_ingress_rule.ac_https.description
        ip_protocol            = "tcp"
        from_port              = 443
        to_port                = 443
        open_cidr_ipv4         = "0.0.0.0/0"
      }
      http = {
        security_group_id      = aws_security_group.ac.id
        security_group_rule_id = aws_vpc_security_group_ingress_rule.ac_http.security_group_rule_id
        description            = aws_vpc_security_group_ingress_rule.ac_http.description
        ip_protocol            = "tcp"
        from_port              = 80
        to_port                = 80
        open_cidr_ipv4         = "0.0.0.0/0"
      }
      portal = {
        security_group_id      = aws_security_group.ac.id
        security_group_rule_id = aws_vpc_security_group_ingress_rule.ac_portal.security_group_rule_id
        description            = aws_vpc_security_group_ingress_rule.ac_portal.description
        ip_protocol            = "tcp"
        from_port              = 8888
        to_port                = 8888
        open_cidr_ipv4         = "0.0.0.0/0"
      }
      nhp_connector = {
        security_group_id      = aws_security_group.ac.id
        security_group_rule_id = aws_vpc_security_group_ingress_rule.ac_nhp_connector.security_group_rule_id
        description            = aws_vpc_security_group_ingress_rule.ac_nhp_connector.description
        ip_protocol            = "tcp"
        from_port              = 4732
        to_port                = 4732
        open_cidr_ipv4         = "0.0.0.0/0"
      }
      nhp_knock = {
        security_group_id      = aws_security_group.ac.id
        security_group_rule_id = aws_vpc_security_group_ingress_rule.ac_nhp_knock.security_group_rule_id
        description            = aws_vpc_security_group_ingress_rule.ac_nhp_knock.description
        ip_protocol            = "udp"
        from_port              = 62206
        to_port                = 62206
        open_cidr_ipv4         = "0.0.0.0/0"
      }
    },
    var.frp_control_upstream_host != "" ? {
      frps_primary = {
        security_group_id      = aws_security_group.ac.id
        security_group_rule_id = aws_vpc_security_group_ingress_rule.ac_frps_control[0].security_group_rule_id
        description            = aws_vpc_security_group_ingress_rule.ac_frps_control[0].description
        ip_protocol            = "tcp"
        from_port              = var.frp_control_port
        to_port                = var.frp_control_port
        open_cidr_ipv4         = "0.0.0.0/0"
      }
    } : {},
    {
      for name, upstream in var.frp_control_additional_upstreams : "frps_${name}" => {
        security_group_id      = aws_security_group.ac.id
        security_group_rule_id = aws_vpc_security_group_ingress_rule.ac_frps_control_additional[name].security_group_rule_id
        description            = aws_vpc_security_group_ingress_rule.ac_frps_control_additional[name].description
        ip_protocol            = "tcp"
        from_port              = upstream.listen_port
        to_port                = upstream.listen_port
        open_cidr_ipv4         = "0.0.0.0/0"
      }
    },
  ) : {}
}

output "cloudmap_service_arn" {
  description = "Cloud Map service ARN"
  value       = aws_service_discovery_service.ac.arn
}

output "cloudmap_service_dns" {
  description = "Cloud Map DNS name for AC discovery"
  value       = "ac.${var.namespace_name}"
}

output "log_group_name" {
  description = "CloudWatch log group name"
  value       = aws_cloudwatch_log_group.ac.name
}

output "instance_role_arn" {
  description = "AC instance IAM role ARN"
  value       = aws_iam_role.ac.arn
}

# Note: plugin_bucket outputs removed - plugins now managed by unified plugins module

output "ac_secret_arn" {
  description = "ARN of the AC secret containing the private key"
  value       = aws_secretsmanager_secret.ac.arn
}

# =============================================================================
# SSM Parameter Outputs for CI/CD
# =============================================================================

output "ssm_image_tag_parameter" {
  description = "SSM parameter name for the deployed image tag"
  value       = aws_ssm_parameter.image_tag.name
}

output "ssm_asg_name_parameter" {
  description = "SSM parameter name for the ASG name"
  value       = aws_ssm_parameter.asg_name.name
}

# =============================================================================
# Egress EIP Outputs
# =============================================================================

output "egress_eip_addresses" {
  description = "Stable public IPs for customer origin firewall whitelisting"
  value       = var.enable_egress_eips ? aws_eip.ac[*].public_ip : []
}

output "egress_eip_allocation_ids" {
  description = "EIP allocation IDs for AC instances"
  value       = var.enable_egress_eips ? aws_eip.ac[*].id : []
}

# =============================================================================
# Blue/Green Deployment Outputs
# =============================================================================

output "blue_green_enabled" {
  description = "Whether blue/green deployment is enabled for AC"
  value       = var.enable_blue_green
}

output "green_asg_name" {
  description = "AC Green ASG name for CI/CD scripts (null if blue/green not enabled)"
  value       = var.enable_blue_green ? aws_autoscaling_group.ac_green[0].name : null
}

output "green_asg_arn" {
  description = "AC Green ASG ARN (null if blue/green not enabled)"
  value       = var.enable_blue_green ? aws_autoscaling_group.ac_green[0].arn : null
}

output "tcp_target_group_blue_arn" {
  description = "Blue TCP target group ARN (existing)"
  value       = aws_lb_target_group.ac_tcp.arn
}

output "tcp_target_group_green_arn" {
  description = "Green TCP target group ARN (null if blue/green not enabled)"
  value       = var.enable_blue_green ? aws_lb_target_group.ac_tcp_green[0].arn : null
}

output "ssm_active_color_parameter" {
  description = "SSM parameter name for AC active deployment color"
  value       = var.enable_blue_green ? aws_ssm_parameter.active_color[0].name : null
}

output "ssm_green_image_tag_parameter" {
  description = "SSM parameter name for AC green ASG image tag"
  value       = var.enable_blue_green ? aws_ssm_parameter.green_image_tag[0].name : null
}

output "ssm_green_asg_name_parameter" {
  description = "SSM parameter name for AC green ASG name"
  value       = var.enable_blue_green ? aws_ssm_parameter.green_asg_name[0].name : null
}

output "matched_cohort_candidate_nlb_dns_name" {
  description = "Restricted candidate-only AC hostname used by the protected lifecycle smoke."
  value       = var.enable_matched_cohort_canary ? aws_lb.ac_candidate[0].dns_name : null
}

output "matched_cohort_candidate_listener_arn" {
  description = "Source-fenced candidate AC HTTPS listener."
  value       = var.enable_matched_cohort_canary ? aws_lb_listener.ac_candidate[0].arn : null
}

output "matched_cohort_candidate_smoke_target_group_arn" {
  description = "Candidate AC target group used only by the source-fenced smoke listener."
  value       = var.enable_matched_cohort_canary ? aws_lb_target_group.ac_candidate_smoke[0].arn : null
}

output "matched_cohort_candidate_asg_name" {
  description = "Full-size isolated candidate AC ASG."
  value       = var.enable_matched_cohort_canary ? aws_autoscaling_group.ac_candidate[0].name : null
}

output "matched_cohort_blue_rollback_authority" {
  description = "Exact capacity, launch-template, and old-image authority required before the canonical-endpoint AC ASG may stop."
  value = var.enable_matched_cohort_canary ? {
    asg_name                = aws_autoscaling_group.ac_matched_blue[0].name
    min_size                = coalesce(var.ac_min_capacity, local.is_prod ? 2 : 1)
    max_size                = local.resolved_max_capacity
    desired_capacity        = coalesce(var.ac_min_capacity, local.is_prod ? 2 : 1)
    launch_template_id      = aws_launch_template.ac_matched_blue[0].id
    launch_template_version = tostring(aws_launch_template.ac_matched_blue[0].latest_version)
    image_parameter         = aws_ssm_parameter.image_tag.name
    image_tag               = nonsensitive(data.aws_ssm_parameter.matched_cohort_blue_image_tag[0].value)
    target_group_arns = sort(concat(
      [aws_lb_target_group.ac_tcp.arn],
      var.frp_control_upstream_host != "" ? [aws_lb_target_group.ac_frps_control[0].arn] : [],
      [for name in sort(keys(var.frp_control_additional_upstreams)) : aws_lb_target_group.ac_frps_control_additional[name].arn],
    ))
  } : null
}

output "matched_cohort_candidate_authority" {
  description = "Exact isolated AC candidate fleet authority."
  value = var.enable_matched_cohort_canary ? {
    asg_name                = aws_autoscaling_group.ac_candidate[0].name
    min_size                = coalesce(var.ac_min_capacity, local.is_prod ? 2 : 1)
    max_size                = local.resolved_max_capacity
    desired_capacity        = coalesce(var.ac_min_capacity, local.is_prod ? 2 : 1)
    launch_template_id      = aws_launch_template.ac_matched_green[0].id
    launch_template_version = tostring(aws_launch_template.ac_matched_green[0].latest_version)
    image_parameter         = aws_ssm_parameter.matched_cohort_ac_image_tag[0].name
    image_tag               = nonsensitive(data.aws_ssm_parameter.matched_cohort_candidate_image_tag[0].value)
    target_group_arns = sort(concat(
      [
        aws_lb_target_group.ac_candidate[0].arn,
        aws_lb_target_group.ac_candidate_smoke[0].arn,
      ],
      [for name in sort(keys(local.matched_cohort_frps_controls)) : aws_lb_target_group.ac_candidate_frps[name].arn],
    ))
  } : null
}

output "matched_cohort_candidate_target_group_arn" {
  description = "Candidate AC target group reserved for the canonical listener selector."
  value       = var.enable_matched_cohort_canary ? aws_lb_target_group.ac_candidate[0].arn : null
}

output "matched_cohort_candidate_image_parameter" {
  description = "SSM image slot consumed only by the candidate AC ASG."
  value       = var.enable_matched_cohort_canary ? aws_ssm_parameter.matched_cohort_ac_image_tag[0].name : null
}

output "matched_cohort_frps_selectors" {
  description = "Exact canonical/candidate/closed FRPS listener vector switched with the AC HTTPS listener."
  value = var.enable_matched_cohort_canary ? merge(
    var.frp_control_upstream_host != "" ? {
      primary = {
        canonical_listener_arn     = aws_lb_listener.frps_control[0].arn
        blue_target_group_arn      = aws_lb_target_group.ac_frps_control[0].arn
        candidate_target_group_arn = aws_lb_target_group.ac_candidate_frps["primary"].arn
        candidate_listener_arn     = aws_lb_listener.ac_candidate_frps["primary"].arn
        listen_port                = var.frp_control_port
      }
    } : {},
    {
      for name, upstream in var.frp_control_additional_upstreams : name => {
        canonical_listener_arn     = aws_lb_listener.frps_control_additional[name].arn
        blue_target_group_arn      = aws_lb_target_group.ac_frps_control_additional[name].arn
        candidate_target_group_arn = aws_lb_target_group.ac_candidate_frps[name].arn
        candidate_listener_arn     = aws_lb_listener.ac_candidate_frps[name].arn
        listen_port                = upstream.listen_port
      }
    },
  ) : {}
}
