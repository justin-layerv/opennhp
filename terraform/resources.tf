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
  # Single NHP resId for the reverse-tunnel control channel — the
  # protected resource the agent knocks for. Per the NHP spec (CSA
  # "Stealth Mode SDP for Zero Trust Network Infrastructure" Appendix 2,
  # NHP-KNK Message Fields): Resource ID identifies "the protected
  # resource being accessed" — the identity of WHAT is protected, not
  # where it's deployed (region, environment) or which underlying tunnel
  # tech happens to fronts it (FRPS today, possibly different later).
  # Routing concerns belong in the AC-returned Hostname/Port, not the
  # resId. The same name is used in every environment.
  tunnel_server_res_id = "qurl-tunnel-server"

  tunnel_server_resource = {
    enabled = var.deploy_frps && var.deploy_qurl_service
    # Two distinct hostnames — do not conflate.
    #
    #   - `dest_host`: INTERNAL per-AZ Cloud Map name (private,
    #     AC-SG-only). Retained on the seed row for forensics and for
    #     a future case where the dial target genuinely diverges from
    #     the ingress hostname (proxy/gateway in front). The bridge
    #     does NOT propagate this field into the agent's ack today
    #     (see resource_lookup.go::queryAndCache — `Hostname` carries
    #     the dial target, `Addr.Ip` is the load-bearing empty
    #     sentinel). Still carries the `frps-` prefix because it
    #     names the Cloud Map service, which lives in a separate
    #     naming axis from the NHP resId.
    #
    #   - `customer_facing_host`: PUBLIC DNS name the agent dials.
    #     Written into the DDB seed row's `resource_fqdn` field; the
    #     bridge materializes that as `ResourceInfo.Hostname` and the
    #     agent's `DestHost()` prefers Hostname over the empty
    #     `Addr.Ip` sentinel.
    dest_host            = "frps-${sort(var.frps_az_suffixes)[0]}.${module.data.namespace_name}"
    customer_facing_host = var.connect_layerv_host
  }

  # Single-entry map keyed on the spec-aligned resId. Retains the map
  # shape so the downstream `for_each` loop over `seed-rows` doesn't
  # need restructuring when a second LayerV-platform agent resource
  # eventually lands — adding a new row is one more entry in this
  # local + one more DDB write, no bridge or plugin change needed.
  tunnel_server_resource_ids = (
    local.tunnel_server_resource.enabled
    ? { (local.tunnel_server_res_id) = local.tunnel_server_resource }
    : {}
  )

  # LayerV system customer (nil ULID) per dynamodb module convention.
  # Matches `nhpSystemCustomerID` in resource_lookup.go — the bridge
  # queries this partition for any agent-aspId catalog lookup.
  nhp_system_customer_id = "00000000000000000000000000"

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
    error_message = "Every `local.tunnel_server_resource_ids[*].dest_host` is the internal tunnel-server dial target written into the DDB seed row's `dest_host` field; each must be a per-label RFC 1035 DNS name. Today's values derive from `module.data.namespace_name` + `var.frps_az_suffixes[0]` which already conform; a future change to either input must preserve that."
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
  item = jsonencode({
    customer_id     = { S = local.nhp_system_customer_id }
    resource_id     = { S = each.key }
    auth_service_id = { S = var.ac_auth_service_id }
    ac_id           = { S = var.qurl_default_ac_id }
    resource_fqdn   = { S = each.value.customer_facing_host }
    dest_host       = { S = each.value.dest_host }
    dest_port       = { N = tostring(var.frps_bind_port) }
    open_time       = { N = tostring(local.tunnel_server_open_time) }
  })

  # Lifecycle NOTE: unlike `aws_dynamodb_table_item.ac_license` (which
  # carries `ignore_changes = [item]` because Console/qurl-service write
  # to those rows out-of-band), the LayerV-system tunnel-server row is
  # TF-exclusively owned. qurl-service does NOT write to `nhp_resources`
  # for the system tenant (audited 2026-05-23 — no `nhp_resources` /
  # `NhpResourcesTable` consumer in qurl-service; the table is read-only
  # for non-TF writers via the bridge). Apply MUST reconcile this row
  # so a TF-side `item` change (e.g. the #1976 cutover flipping
  # auth_service_id and ac_id off their sentinels and resource_fqdn to
  # the customer-facing host) actually propagates to DDB. Without that
  # reconciliation the bridge's FilterExpression matches no rows and
  # every knock returns ErrResourceUnknownASP — the failure mode this
  # PR explicitly exists to fix. If a future system-tenant out-of-band
  # writer lands (qurl-service growing system-row persistence), revisit
  # field-level `ignore_changes = [item["<field>"]]` rather than the
  # whole `item`. #1909 tracks `prevent_destroy = true` for row-deletion
  # safety once that out-of-band-write surface exists.
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
