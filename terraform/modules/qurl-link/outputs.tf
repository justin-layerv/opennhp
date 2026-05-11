output "cloudfront_domain_name" {
  description = "CloudFront distribution domain name"
  value       = aws_cloudfront_distribution.qurl_link.domain_name
}

output "cloudfront_hosted_zone_id" {
  description = "CloudFront distribution Route53 hosted zone ID (for alias records)"
  value       = aws_cloudfront_distribution.qurl_link.hosted_zone_id
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID"
  value       = aws_cloudfront_distribution.qurl_link.id
}

output "s3_bucket_name" {
  description = "S3 bucket name"
  value       = aws_s3_bucket.qurl_link.id
}

output "domain_name" {
  description = "Domain name for the QURL link redirect page"
  value       = var.domain_name
}

output "index_html_content_hash" {
  description = "md5 of the deployed index.html. Private API of the root-module composition: consumed only by terraform_data.qurl_link_invalidation as its triggers_replace key and caller-reference. Not intended for external consumers."
  value       = md5(local.index_html)
}
