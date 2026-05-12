# Bootstrap NHP Resources for the FRPS reverse-tunnel cold-start path.
# Seeded into the `nhp_resources` table; nhp-server reads them on knock
# receipt (`storage.go::Resource`). See PR description for the
# QURL→reverse-tunnel plan and the network-surface trace.
locals {
  # Singular today. A second region requires reviewing the env-canonical
  # alias below — the precondition fences a silent multi-region collision.
  frps_resource_regions = {
    (var.aws_region) = {
      enabled   = var.deploy_frps && var.deploy_qurl_service
      dest_host = "frps-${sort(var.frps_az_suffixes)[0]}.${module.data.namespace_name}"
    }
  }

  # Emit both `frps-{region}` and `frps-{environment}` rows pointing at the
  # same target. The env-canonical alias is what the agent's hard-coded
  # `EnvKnockResourceID = "frps-prod"` default resolves on cold start
  # (qurl-reverse-tunnel-client `cmd/frpc/knock.go:50`); without it an
  # unconfigured agent gets ErrResourceNotFound and crash-loops after 5
  # failures (no lex-smallest fallback in `pkg/tunnel/knock.go:174-183`).
  frps_resource_ids = merge(
    {
      for region, cfg in local.frps_resource_regions :
      "frps-${region}" => cfg if cfg.enabled
    },
    {
      for region, cfg in local.frps_resource_regions :
      "frps-${var.environment}" => cfg if cfg.enabled
    },
  )

  # LayerV system customer (nil ULID) per dynamodb module convention.
  nhp_system_customer_id = "00000000000000000000000000"

  # Non-empty sentinel for `ac_id` / `auth_service_id` on this seed row.
  # An empty string would project these rows into `ac_id-index` under the
  # empty-string GSI key, where a default-valued `GetResourceByACID("")`
  # caller would pull them back (doubly so since the env-canonical alias
  # adds a second row under the same key). The reserved-name shape
  # (`__…__`) is structurally outside both real AC IDs (`<vendor>-<role>`
  # lowercase-dashed) and `auth_service_id` (bare lowercase), so a literal
  # `frps-system` typo can't collide. It does not defend against a caller
  # that passes the sentinel string explicitly.
  nhp_system_seed_sentinel = "__nhp_frps_seed_row__"
}

resource "aws_dynamodb_table_item" "frps_nhp_resource" {
  for_each = local.frps_resource_ids

  table_name = module.dynamodb.resources_table_name
  hash_key   = "customer_id"
  range_key  = "resource_id"

  item = jsonencode({
    customer_id = { S = local.nhp_system_customer_id }
    resource_id = { S = each.key }
    # For FRPS the consumer-facing FQDN and dial target collapse to the
    # same Cloud Map name — the agent dials FRPS directly.
    resource_fqdn = { S = each.value.dest_host }
    ac_id         = { S = local.nhp_system_seed_sentinel }
    dest_host     = { S = each.value.dest_host }
    dest_port     = { N = tostring(var.frps_bind_port) }
    # Mirrors the AC's `DefaultIpOpenTime = 120` (constants.go); shorter
    # than the QURL default (300s) since the agent dials immediately on
    # knock-receipt. Hard-coded — drift from the AC constant is silent.
    open_time       = { N = "120" }
    auth_service_id = { S = local.nhp_system_seed_sentinel }
  })

  lifecycle {
    # Mirrors `aws_dynamodb_table_item.ac_license`: Console / qurl-service
    # update Resource fields out-of-band; TF must not fight them. Does NOT
    # defend row destruction on `deploy_frps = false` or a `var.aws_region`
    # rename (the for_each key flips). #1909 tracks `prevent_destroy = true`
    # once qurl-service starts persisting non-trivial state here.
    ignore_changes = [item]

    # Fail loud if a second region lands. The inner-for in
    # `frps_resource_ids` produces duplicate `frps-${var.environment}` keys
    # — Terraform's last-wins picks whichever region sorts last by map-key,
    # silently flipping the env-canonical alias the agent's hard-coded
    # default resolves to. Counts DECLARED entries (not enabled), so a
    # disabled second region trips this BEFORE the collision can land.
    # Edge case: all-disabled regions produce zero instances and this
    # precondition never evaluates (#1913 tracks a module-scope `check`).
    precondition {
      condition     = length(local.frps_resource_regions) == 1
      error_message = "local.frps_resource_regions has ${length(local.frps_resource_regions)} entries but the `frps-${var.environment}` env-canonical alias in `local.frps_resource_ids` assumes exactly one region. Adding a second region without picking an explicit primary owner would silently flip `frps-${var.environment}` (e.g., `frps-prod`) to whichever region sorts last by map-key. Introduce an explicit primary-region variable that owns the env-canonical alias (or retire the alias entirely once the agent learns per-region lookup) before adding a second entry."
    }
  }
}
