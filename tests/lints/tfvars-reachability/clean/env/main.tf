variable "feature_enabled" {
  type    = bool
  default = false
}

module "nhp" {
  source          = "../.."
  feature_enabled = var.feature_enabled
}
