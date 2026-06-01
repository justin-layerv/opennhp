output "waf_web_acl_arn" {
  description = "WAF Web ACL ARN for association with CloudFront or regional resources"
  value       = aws_wafv2_web_acl.main.arn
}

output "waf_web_acl_id" {
  description = "WAF Web ACL ID"
  value       = aws_wafv2_web_acl.main.id
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = var.enable_guardduty ? aws_guardduty_detector.main[0].id : null
}

output "permission_boundary_arn" {
  description = "IAM permission boundary policy ARN. Route53 writes are ACME TXT-only; revalidate real DNS-01 issuance before first attaching this boundary to a role."
  value       = aws_iam_policy.permission_boundary.arn
}

output "cloudtrail_arn" {
  description = "CloudTrail ARN"
  value       = var.enable_cloudtrail ? aws_cloudtrail.main[0].arn : null
}

output "cloudtrail_s3_bucket_name" {
  description = "CloudTrail S3 bucket name"
  value       = var.enable_cloudtrail ? aws_s3_bucket.cloudtrail[0].id : null
}
