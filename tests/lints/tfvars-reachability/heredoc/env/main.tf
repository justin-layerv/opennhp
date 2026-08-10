variable "feature_enabled" {
  type    = bool
  default = false
}

variable "policy_body" {
  type    = string
  default = ""
}

variable "comparison_note" {
  type    = string
  default = ""
}

module "nhp" {
  source          = "../.."
  feature_enabled = var.feature_enabled
  policy_body     = var.policy_body
  comparison_note = var.comparison_note
}
