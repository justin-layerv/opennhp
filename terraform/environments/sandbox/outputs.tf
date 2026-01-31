# Sandbox environment outputs

# QURL Link DNS records (for manual creation in layerv-mgmt)
output "qurl_link_acm_validation_records" {
  description = "ACM certificate validation DNS records - create these in qurl.link zone (layerv-mgmt)"
  value       = module.nhp.qurl_link_acm_validation_records
}

output "qurl_link_cloudfront_domain" {
  description = "CloudFront domain name for qurl.link A record alias"
  value       = module.nhp.qurl_link_cloudfront_domain
}

output "qurl_link_cloudfront_zone_id" {
  description = "CloudFront zone ID for qurl.link A record alias"
  value       = module.nhp.qurl_link_cloudfront_zone_id
}
