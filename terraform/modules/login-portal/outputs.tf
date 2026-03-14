output "cloudfront_domain_name" {
  description = "CloudFront distribution domain name"
  value       = aws_cloudfront_distribution.login_portal.domain_name
}

output "cloudfront_hosted_zone_id" {
  description = "CloudFront distribution Route53 hosted zone ID (for alias records)"
  value       = aws_cloudfront_distribution.login_portal.hosted_zone_id
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID"
  value       = aws_cloudfront_distribution.login_portal.id
}

output "s3_bucket_name" {
  description = "S3 bucket name"
  value       = aws_s3_bucket.login_portal.id
}

output "domain_name" {
  description = "Domain name for the login portal"
  value       = var.domain_name
}
