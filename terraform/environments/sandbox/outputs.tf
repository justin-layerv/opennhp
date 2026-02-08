# Sandbox environment outputs

# QURL Link DNS records
output "qurl_link_acm_validation_records" {
  description = "ACM certificate validation DNS records for QURL link frontend"
  value       = module.nhp.qurl_link_acm_validation_records
}

output "qurl_link_cloudfront_domain" {
  description = "CloudFront domain name for QURL link A record alias"
  value       = module.nhp.qurl_link_cloudfront_domain
}

output "qurl_link_cloudfront_zone_id" {
  description = "CloudFront zone ID for QURL link A record alias"
  value       = module.nhp.qurl_link_cloudfront_zone_id
}
