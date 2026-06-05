# Bootstrap NHP Resources for the qURL reverse-tunnel cold-start path.
# Seeded into the `nhp_resources` table; nhp-server reads them on knock
# receipt via the DDB-backed ResourceLookup bridge
# (`endpoints/server/resource_lookup.go`, landed in #2107). The bridge
# returns the same `AuthServiceProviderData` shape the static-TOML
# loader produced historically, but reads from DDB on cache miss so a
# row update takes effect within the 60s cache TTL — no instance
# refresh required.
#
# Historical note: prior to #1976's cutover (this PR) the catalog was
# ALSO baked into `/opt/layerv/nhp-server/etc/resource.toml` via a
# user_data overlay rendered from `local.tunnel_server_resource_toml_overlay`.
# That dual-write path was removed once the bridge proved out — the
# DDB row is now the single source of truth.
locals {
  # Placement-neutral NHP resId for the reverse-tunnel control channel. Clients
  # knock this ID; nhp-server chooses an AZ-specific row internally and returns
  # the chosen public FRP host:port in the ACK under this same key.
  tunnel_server_res_id = "qurl-tunnel-server"

  tunnel_server_resources_enabled = var.deploy_frps && var.deploy_qurl_service

  # Deterministic AZ ordering is load-bearing for the public port map:
  # suffix resources map to frps_bind_port + index.
  #
  # The port map is the only practical way to expose per-AZ public
  # control ingress on one DNS name: FRP control is raw TCP/yamux, so an
  # NLB/Traefik listener cannot route by HTTP Host or TLS SNI.
  tunnel_server_az_suffixes     = var.deploy_frps ? sort(var.frps_az_suffixes) : []
  tunnel_server_primary_az      = length(local.tunnel_server_az_suffixes) > 0 ? local.tunnel_server_az_suffixes[0] : ""
  tunnel_server_primary_host    = local.tunnel_server_primary_az != "" ? "frps-${local.tunnel_server_primary_az}.${module.data.namespace_name}" : ""
  tunnel_server_az_control_port = { for idx, suffix in local.tunnel_server_az_suffixes : suffix => var.frps_bind_port + idx }

  # Resource row shape:
  #
  # Rollout order is load-bearing: deploy an nhp-server image that knows how
  # to resolve the placement-neutral qurl-tunnel-server ID into these per-AZ
  # rows BEFORE applying Terraform that removes the old placement-neutral row.
  # A stale server fleet would otherwise see only qurl-tunnel-server-{suffix}
  # rows and reject every standard qURL tunnel knock as RESOURCE_INFO_NOT_FOUND.
  # The converse is safe: a new server can run while the direct row still
  # exists because authenticated agent knocks carry PublicKey and prefer the
  # per-AZ rows; the direct-row fallback is only for empty-identity transition
  # probes. Rollback has the inverse order: recreate the direct row before
  # rolling back to an older server image. Any transition/debug direct row must
  # include an explicit port; the placement-neutral alias now forces port_suffix
  # so clients receive a complete ACK host:port and never rely on YAML fallback.
  #
  # Today placement is catalog-driven, not live-health-aware. If an AZ endpoint
  # is unavailable, remove its suffix row from this catalog (or roll out the
  # health-aware resolver tracked in #2191) before expecting identities pinned
  # to that AZ to re-place elsewhere.
  #
  #   - dest_host: internal per-AZ Cloud Map name. Informational for the
  #     NHP ack today, but useful for forensics and for the AC module's
  #     public-listener -> private-FRPS forwarding contract.
  #
  #   - customer_facing_host/customer_facing_port: public connect.layerv.*
  #     endpoint the agent dials after a successful knock. Non-primary
  #     rows set port_suffix=true so ResourceInfo.DestHost() always returns
  #     "connect.layerv.*:<port>" and the ipset-opened tuple matches the
  #     per-AZ public listener. Even the primary port is explicit: standard
  #     clients do not carry a fallback FRP port in YAML.

  tunnel_server_az_resources = {
    for suffix in local.tunnel_server_az_suffixes :
    "${local.tunnel_server_res_id}-${suffix}" => {
      dest_host            = "frps-${suffix}.${module.data.namespace_name}"
      customer_facing_host = var.connect_layerv_host
      customer_facing_port = local.tunnel_server_az_control_port[suffix]
      port_suffix          = true
    }
  }

  tunnel_server_resource_ids = (
    local.tunnel_server_resources_enabled
    ? local.tunnel_server_az_resources
    : {}
  )

  # LayerV system customer (nil ULID) per dynamodb module convention.
  # Matches `nhpSystemCustomerID` in resource_lookup.go — the bridge
  # queries this partition for agent-aspId catalog lookup and static qURL
  # tunnel-server placement rows.
  nhp_system_customer_id = "00000000000000000000000000"

  # Reserved dynamic qURL customer_id prefix. Matches
  # `nhpQURLDynamicCustomerIDPrefix` in resource_lookup.go and qurl-service's
  # NHPQurlDynamicCustomerIDPrefix. qurl-service writes dynamic per-token
  # `q_...` rows under shard keys "<prefix>-00" through "<prefix>-ff", so
  # DynamoDB hot traffic spreads across 256 partition keys while IAM
  # LeadingKeys still excludes Terraform-owned static rows.
  nhp_qurl_dynamic_customer_id_prefix = "00000000000000000000000001"

  # OpenTime in seconds. Mirrors the server's `DefaultIpOpenTime = 120`
  # constant (`endpoints/server/constants.go`); shorter than the QURL
  # default (300s) since the agent dials the tunnel server immediately
  # on knock-receipt. Hard-coded here — drift from the Go constant
  # would be silent, but the bridge clamps non-positive values to
  # DefaultIpOpenTime and any plausible operational change wants to
  # move both in lockstep.
  tunnel_server_open_time = 120
}

# RFC-1035 shape fence on the per-row `dest_host` (the internal Cloud
# Map dial target written into the DDB seed row's `dest_host` field).
# Today's values come from `module.data.namespace_name` +
# `var.frps_az_suffixes[0]` which already conform; this is a tripwire
# for a future loosening of either upstream rather than the primary
# fence on the inputs. Soft `check` rather than hard precondition
# because input regression is vanishingly unlikely; a warning is
# enough.
check "tunnel_server_dest_host_shape" {
  assert {
    condition = alltrue([
      for _, cfg in local.tunnel_server_resource_ids :
      can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$", cfg.dest_host))
    ])
    error_message = "Every `local.tunnel_server_resource_ids[*].dest_host` is the internal tunnel-server dial target written into the DDB seed row's `dest_host` field; each must be a per-label RFC 1035 DNS name. Today's values derive from `module.data.namespace_name` + `var.frps_az_suffixes` which already conform; a future change to either input must preserve that."
  }
}

check "tunnel_server_resource_id_static_prefix" {
  assert {
    condition = alltrue([
      for resource_id, _ in local.tunnel_server_resource_ids :
      startswith(resource_id, "qurl-")
    ])
    error_message = "Every static qURL tunnel-server resource_id must keep the `qurl-` prefix because resource_lookup.go key-bounds the qURL ASP cache to static `qurl-` rows; dynamic qurl-service rows live under resource_id-derived shard keys and resolve through exact GetItem."
  }
}

resource "aws_dynamodb_table_item" "tunnel_server_nhp_resource" {
  for_each = local.tunnel_server_resource_ids

  table_name = module.dynamodb.resources_table_name
  hash_key   = "customer_id"
  range_key  = "resource_id"

  # The bridge (endpoints/server/resource_lookup.go) reads this row on
  # cache miss for any aspId knock. Field mapping (DDB → in-memory
  # AuthServiceProviderData):
  #
  #   auth_service_id → row included when FilterExpression matches the
  #                     requested aspId; populates ResourceGroup.AuthServiceId
  #   resource_id     → ResourceGroup.ResourceId + inner Resources map key
  #                     (inner-equals-outer is load-bearing — see
  #                     resource_lookup.go::queryAndCache)
  #   ac_id           → ResourceInfo.ACId (which AC issues the ipset-open
  #                     token; the server uses this to route the AC op)
  #   resource_fqdn   → ResourceInfo.Hostname (what the agent dials)
  #   dest_port       → ResourceInfo.Addr.Port
  #   port_suffix     → ResourceInfo.PortSuffix. When true, the ack
  #                     ResourceHost is "resource_fqdn:dest_port".
  #   open_time       → ResourceGroup.OpenTime (clamped if ≤0 or
  #                     exceeds uint32 by the bridge)
  #
  # NOT propagated by the bridge today (informational only):
  #   dest_host       — internal Cloud Map name; retained for forensics
  #                     and for future use if dial target diverges from
  #                     ingress hostname.
  #
  # Synthesized by the bridge (hardcoded, not stored in DDB):
  #   Addr.Protocol = "tcp" — every NHP-gated resource is TCP today.
  #   Addr.Ip = ""          — load-bearing empty sentinel; AC's
  #                           applyDefaultIpSubstitution writes LOCAL_IP
  #                           at ipset-time.
  #   SkipAuth = true       — pre-authenticated; X25519+DDB pubkey
  #                           lookup IS the auth gate (the agent plugin
  #                           fences on this).
  #
  # Do NOT add `ttl` to these static rows. qurl-service-owned dynamic `q_...`
  # rows live under local.nhp_qurl_dynamic_customer_id_prefix shard keys, carry
  # ttl, and the exact lookup rejects expired rows before DynamoDB's lazy TTL
  # sweeper eventually removes them; a ttl attribute here can silently expire
  # the static tunnel placement catalog.
  item = jsonencode({
    customer_id     = { S = local.nhp_system_customer_id }
    resource_id     = { S = each.key }
    auth_service_id = { S = var.ac_auth_service_id }
    ac_id           = { S = var.qurl_default_ac_id }
    resource_fqdn   = { S = each.value.customer_facing_host }
    dest_host       = { S = each.value.dest_host }
    dest_port       = { N = tostring(each.value.customer_facing_port) }
    port_suffix     = { BOOL = each.value.port_suffix }
    open_time       = { N = tostring(local.tunnel_server_open_time) }
  })

  # Lifecycle NOTE: unlike `aws_dynamodb_table_item.ac_license` (which
  # carries `ignore_changes = [item]` because Console/qurl-service write
  # to those rows out-of-band), these static qurl-tunnel-server rows are
  # TF-exclusively owned. qurl-service writes dynamic per-token `q_...`
  # rows under the reserved dynamic shard-key prefix, so IAM prevents it from
  # mutating the static `qurl-tunnel-server*` resource IDs seeded here. Apply MUST
  # reconcile these rows so a TF-side `item` change (e.g. the #1976
  # cutover flipping auth_service_id and ac_id off their sentinels and
  # resource_fqdn to the customer-facing host) actually propagates to
  # DDB. Without that reconciliation the bridge's FilterExpression
  # matches no rows and every knock returns ErrResourceUnknownASP — the
  # failure mode this PR explicitly exists to fix. If a future
  # out-of-band writer mutates these static resource IDs, revisit
  # field-level `ignore_changes = [item["<field>"]]` rather than the
  # whole `item`. #1909 tracks `prevent_destroy = true` for row-deletion
  # safety once that out-of-band-write surface exists.
}

locals {
  # Central fence for Terraform-owned static rows in nhp_resources. Dynamic
  # qurl-service-owned `q_...` rows intentionally carry ttl under the reserved
  # shard prefix; any future Terraform-owned static table item resource must be
  # added here so table-wide DynamoDB TTL cannot silently reap it.
  static_nhp_resources_table_items = values(aws_dynamodb_table_item.tunnel_server_nhp_resource)
}

check "static_resource_rows_omit_ttl" {
  assert {
    condition = alltrue([
      for row in local.static_nhp_resources_table_items :
      !contains(keys(jsondecode(row.item)), "ttl")
    ])
    error_message = "Terraform-owned static nhp_resources rows must not carry ttl; DynamoDB TTL is table-wide and would eventually delete them."
  }
}

# State address rename — `frps_nhp_resource` → `tunnel_server_nhp_resource`.
# The underlying DDB row's hash/range key is unchanged, so a moved block
# preserves state without a destroy/recreate cycle. The prior name was
# load-bearing FRPS-implementation-detail naming; the new name matches
# `local.tunnel_server_*` and the `staticplugins/agent/` package.
# Removal tracked in #2144 — retire after both sandbox + prod apply on
# a post-#2141 commit so the moved-from address has cleared from every
# env's state file.
moved {
  from = aws_dynamodb_table_item.frps_nhp_resource
  to   = aws_dynamodb_table_item.tunnel_server_nhp_resource
}
