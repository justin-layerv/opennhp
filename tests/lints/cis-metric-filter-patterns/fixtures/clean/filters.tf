locals {
  cloudtrail_filters = {
    # regression: a comment with an unbalanced brace } inside the map must
    # not skew brace-depth / map-bounds detection. Also a // style one {
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
