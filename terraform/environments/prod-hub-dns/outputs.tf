output "hub_fqdn" {
  description = "The production Connector Hub public A-alias name."
  value       = var.hub_dns_name
}

output "hub_nlb_dns_name" {
  description = "The Hub NLB DNS name when this source-locked root is enabled."
  value       = try(data.aws_lb.hub[0].dns_name, null)
}

output "hub_nlb_zone_id" {
  description = "The Hub NLB canonical hosted zone ID when enabled."
  value       = try(data.aws_lb.hub[0].zone_id, null)
}
