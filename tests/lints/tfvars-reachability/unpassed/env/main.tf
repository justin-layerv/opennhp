variable "feature_enabled" {
  type    = bool
  default = false
}

module "nhp" {
  source = "../.."
}
