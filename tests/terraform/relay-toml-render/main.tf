terraform {
  required_version = ">= 1.8.0"
}

locals {
  old_key = base64encode("00000000000000000000000000000000")
  new_key = base64encode("11111111111111111111111111111111")

  old_current = templatefile("${path.module}/../../../terraform/modules/compute/relay.toml.tpl", {
    relay_trusted_public_keys_b64 = sort([local.old_key, local.new_key])
  })
  new_current = templatefile("${path.module}/../../../terraform/modules/compute/relay.toml.tpl", {
    relay_trusted_public_keys_b64 = sort([local.new_key, local.old_key])
  })
}

output "old_current" {
  value = local.old_current
}

output "new_current" {
  value = local.new_current
}
