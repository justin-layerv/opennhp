# DNS Module Outputs

output "fqdn" {
  description = "Fully qualified domain name for NHP"
  value       = var.hosted_zone_name != null && !var.skip_main_record ? aws_route53_record.nhp[0].fqdn : var.domain_name
}

output "zone_id" {
  description = "Route 53 hosted zone ID"
  value       = var.hosted_zone_name != null ? data.aws_route53_zone.main[0].zone_id : null
}

output "name_servers" {
  description = "Name servers for the hosted zone"
  value       = var.hosted_zone_name != null ? data.aws_route53_zone.main[0].name_servers : null
}
