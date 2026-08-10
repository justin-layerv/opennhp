variable "feature_enabled" {
  type    = bool
  default = false
}

variable "plugin_map" {
  type    = any
  default = {}
}

module "nhp" {
  source          = "../.."
  feature_enabled = var.feature_enabled
  plugin_map      = var.plugin_map
}
