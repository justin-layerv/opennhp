terraform {
  # The alerts_sns_topic_arn variable uses a cross-variable validation (its
  # condition references var.enable_guardduty / var.enable_guardduty_alerts),
  # which Terraform supports only from 1.9+. The root module pins ~> 1.14 and CI
  # runs 1.14.3, so this is satisfied today; declaring the floor here
  # self-documents the constraint so a future consumer pinned <1.9 fails at init
  # with a clear message rather than a confusing validation error. Provider
  # requirements are intentionally inherited from the root module.
  required_version = ">= 1.9"
}
