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

output "cell0_fqdn" {
  description = "The cell0 server public A-alias record name."
  value       = var.cell0_dns_name
}

output "cell0_nlb_dns_name" {
  description = "The cell0 server NLB DNS name the record aliases to."
  value       = data.aws_lb.cell0.dns_name
}
