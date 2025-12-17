output "fqdn" {
  description = "Fully qualified domain name"
  value       = var.hosted_zone_name != null ? aws_route53_record.nhp[0].fqdn : null
}
