variable "environment" {
  description = "Environment name"
  type        = string
}

variable "name_prefix" {
  description = "Name prefix for resources"
  type        = string
}

variable "tags" {
  description = "Tags for resources"
  type        = map(string)
  default     = {}
}

variable "qurl_v2_issuer_key_enabled" {
  description = "Provision the qURL v2 issuer signing key (ECDSA P-256 SIGN_VERIFY). Default false so envs not in the v2 rollout create no key. Set true (per-env tfvars) to stage the key; issuance/admission remain separately gated."
  type        = bool
  default     = false
}

variable "qurl_v2_resource_keys_enabled" {
  description = "Provision the single shared symmetric envelope CMK that qurl-service uses to wrap SOFTWARE-custody qURL v2 resource private keys (grants live in modules/qurl-service task_qurl_v2_resource_key_envelope). One shared key replaces the per-resource CMKs of hardware custody. Default false so envs not in the v2 rollout create no key."
  type        = bool
  default     = false
}
