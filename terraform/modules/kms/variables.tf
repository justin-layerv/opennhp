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

# Opaque ordering token (a `time_sleep` id from the root module's
# IAM-propagation shim) that must settle before the envelope CMK is created,
# so the CI apply role's freshly granted kms:EnableKeyRotation has propagated
# through the IAM auth evaluator before EnableKeyRotation runs at create time.
# See terraform/CLAUDE.md → "IAM eventual-consistency shim pattern". Null when
# qurl_v2_resource_keys_enabled is false (no key, so nothing to gate).
variable "resource_key_envelope_create_after" {
  description = "Opaque dependency token (root-module time_sleep id) gating envelope-CMK creation until the CI role's kms:EnableKeyRotation grant has propagated. Null when qurl_v2_resource_keys_enabled is false."
  type        = string
  default     = null
}
