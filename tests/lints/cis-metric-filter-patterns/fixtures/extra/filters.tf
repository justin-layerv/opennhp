locals {
  cloudtrail_filters = {
    alpha = {
      metric_name = "AlphaCount"
      pattern     = "{ ($.eventName = CreateTrail) || ($.eventName = DeleteTrail) }"
    }

    beta = {
      metric_name = "BetaCount"
      pattern     = "{ $.userIdentity.type = \"Root\" }"
    }
  }
}
