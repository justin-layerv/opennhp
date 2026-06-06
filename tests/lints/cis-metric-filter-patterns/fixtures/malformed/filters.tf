locals {
  cloudtrail_filters = {
    alpha = {
      metric_name = "AlphaCount"
      pattern     = "{ ($.eventName = CreateTrail) }"
    }
  }
}
