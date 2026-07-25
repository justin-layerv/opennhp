output "hub_fqdn" {
  description = "The Connector Hub public A-alias record name."
  value       = var.hub_dns_name
}

output "hub_nlb_dns_name" {
  description = "The Hub NLB DNS name the record aliases to."
  value       = data.aws_lb.hub.dns_name
}

output "hub_nlb_zone_id" {
  description = "The Hub NLB canonical hosted zone ID."
  value       = data.aws_lb.hub.zone_id
}
