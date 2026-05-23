# Bootstrap NHP Resources for the qURL reverse-tunnel cold-start path.
# Seeded into the `nhp_resources` table; nhp-server reads them on knock
# receipt (`storage.go::Resource`). See PR description for the
# QURL→reverse-tunnel plan and the network-surface trace.
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
    # Two distinct hostnames — do not conflate. The split is the
    # core of the SLACK_QURL_ROLLOUT.md §6 redesign.
    #
    #   - `dest_host`: INTERNAL per-AZ Cloud Map name (private,
    #     AC-SG-only). Feeds the DDB seed row + the AC Traefik TCP
    #     entrypoint's upstream service (AC userspace → private tunnel
    #     server). Still carries the `frps-` prefix because it names the
    #     Cloud Map service, which lives in a separate naming axis from
    #     the NHP resId and has its own consumer contract with
    #     qurl-service URL construction. Renaming that is a separate
    #     change.
    #   - `customer_facing_host`: PUBLIC DNS name the agent dials.
    #     Threaded into the TOML overlay's `Hostname` field; rendered
    #     alongside the load-bearing `Addr.Ip = ""` sentinel that the
    #     AC substitutes to LOCAL_IP at ipset-write time (see
    #     `applyDefaultIpSubstitution` in endpoints/ac/msghandler.go).
    dest_host            = "frps-${sort(var.frps_az_suffixes)[0]}.${module.data.namespace_name}"
    customer_facing_host = var.connect_layerv_host
  }

  # Single-entry map keyed on the spec-aligned resId. Retains the map
  # shape so the downstream `for_each`/`for` loops over `seed-rows` and
  # `overlay-entries` don't need restructuring — they iterate over what
  # is now a 1-element map.
  tunnel_server_resource_ids = (
    local.tunnel_server_resource.enabled
    ? { (local.tunnel_server_res_id) = local.tunnel_server_resource }
    : {}
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

  # OpenTime in seconds. Single source of truth shared by the DDB seed
  # row (rendered via `tostring(local.tunnel_server_open_time)` below)
  # and the TOML overlay's `OpenTime = ${local.tunnel_server_open_time}`
  # interpolation. Mirrors the server's `DefaultIpOpenTime = 120`
  # constant (`endpoints/server/constants.go:67`); shorter than the QURL
  # default (300s) since the agent dials the tunnel server immediately
  # on knock-receipt. Hard-coded here — drift from the Go constant
  # would be silent. The Go regression test
  # (`TestFRPSResourceTOMLOverlay_…`) asserts that the rendered
  # `OpenTime` equals `server.DefaultIpOpenTime`, so a bump on either
  # side surfaces as a CI failure that forces the other side to follow.
  tunnel_server_open_time = 120

  # Sentinel comment for the overlay block written into
  # `/opt/layerv/nhp-server/etc/resource.toml` by `user_data.sh.tpl`.
  # The user_data overlay step is SELF-HEALING across sentinel version
  # bumps: before each append it runs
  #   sed -i "/^${frps_overlay_sentinel_prefix}/,/^${frps_overlay_end_sentinel}/d"
  # to strip any prior block (any version), then appends the current
  # rendered overlay. Bumping v1 → v2 → … therefore needs NO operator
  # intervention; user_data re-exec on a host carrying v1 strips v1
  # and lays down v2 in the same run. The end-sentinel
  # (`local.frps_overlay_end_sentinel`) is necessary because
  # `Addr.Protocol` repeats per resource group and a sed range
  # terminated by it would leave subsequent groups behind on
  # multi-group overlays. The start-anchor matches the literal prefix
  # only (no `[0-9]\+` digit-suffix requirement) so it stays equivalent
  # to the grep existence check — a version-less sentinel that passes
  # grep would otherwise fail the sed range and silently produce
  # duplicate tables. See the equivalent grep pattern in
  # `user_data.sh.tpl`.
  #
  # The sentinel is still version-stamped so operators inspecting a
  # running host can `grep` for the literal `# FRPS bootstrap overlay vN`
  # line and know which generation is present. Bump the version on a
  # rendered-shape change that callers must distinguish (e.g. for
  # a fleet-wide rollout audit).
  #
  # Bumped v1 → v2 on 2026-05-18 with the FRPS-behind-AC redesign
  # (SLACK_QURL_ROLLOUT.md §6): Hostname now points at the
  # customer-facing AC ingress (`var.connect_layerv_host`) instead of
  # the internal FRPS host.
  frps_overlay_sentinel_prefix = "# FRPS bootstrap overlay v"
  frps_overlay_sentinel        = "${local.frps_overlay_sentinel_prefix}2"

  # Runtime overlay block appended to /opt/layerv/nhp-server/etc/resource.toml
  # by `terraform/modules/compute/user_data.sh.tpl` at boot. Until the
  # DDB→authServiceMap bridge lands (#1976), the baked TOML is the only
  # path nhp-server reads at runtime — `endpoints/server/config.go::loadResources`
  # never consults the `nhp_resources` table the rows above seed.
  #
  # ⚠ LOAD-BEARING — read this first: `pelletier/go-toml/v2` maps TOML
  # keys to Go FIELD NAMES, NOT to `json:` tag values. Every key below
  # spells out the Go field name (`ResourceGroups`, `Resources`, `ACId`,
  # `Hostname`, `Addr`) rather than the lowercase shape the `json:` tags
  # suggest. A "fix" that renames keys to match `json:` tags silently
  # parses into empty structs and `updateResources` drops the rows.
  # Fenced by `TestFRPSResourceTOMLOverlay_SchemaMatchesAuthSvcProviderMap`
  # in endpoints/server/config_test.go.
  #
  # Schema MUST match `common.AuthSvcProviderMap` in `nhp/common/types.go`,
  # NOT the shallower `common.ResourceGroupMap` shape used by
  # `examples/server_plugin/etc/resource.toml`. The nesting has to spell
  # out the Go field names:
  #
  #     ["aspId".ResourceGroups."<resourceId>"]
  #     OpenTime = 120
  #
  #     ["aspId".ResourceGroups."<resourceId>".Resources."<resourceName>"]
  #     ACId = "..."  Hostname = "..."  Addr.{Ip,Port,Protocol} = ...
  #
  # The inner `Resources."<resourceName>"` key is the load-bearing one:
  # `handleNhpOpenResource` populates `ackMsg.ResourceHost[resourceName]`
  # and `ackMsg.ACTokens[resourceName]` keyed by the inner key, and
  # tunnel-client #142's `pickResourceHost(resourceID, ackMsg.ResourceHost)`
  # does `resourceHost[resourceID]`. So the inner resourceName has to
  # MATCH the outer resourceId — `qurl-tunnel-server` maps to
  # `qurl-tunnel-server`. The collapse looks redundant but it's the
  # only way the agent's lookup resolves to a non-empty value. The
  # rendered TOML carries this invariant as an inline comment so a
  # post-deploy editor doesn't silently break it.
  #
  # Diverges from the DDB rows on `aspId` / `ACId` because those fields
  # carry different concerns at each layer:
  #   - DDB rows use `__nhp_frps_seed_row__` for both fields (GSI-collision
  #     defense; see `nhp_system_seed_sentinel` doc above). The bridge will
  #     read DDB and rewrite these to live values when it lands.
  #   - The TOML overlay carries the values the agent actually knocks with
  #     today: `aspId = var.ac_auth_service_id` (matches tunnel-client #142's
  #     `LAYERV_KNOCK_ASP_ID` default), `ACId = var.qurl_default_ac_id`
  #     (the same AC that handles QURL knocks — `handleNhpOpenResource` in
  #     `endpoints/server/udpserver.go:2973` requires a live AC connection
  #     keyed by `ACId`, and the AC issues the `qurl_knock_token` the
  #     tunnel-server validates via `POST /nhp/internal/token/validate`).
  #
  # Hostnames mirror `aws_dynamodb_table_item.frps_nhp_resource` above so
  # the DDB and TOML paths converge on the same dial target.
  #
  # `AuthSvcId` (the Go field on `AuthServiceProviderData`) is deliberately
  # NOT emitted as a TOML key — `updateResources` in
  # `endpoints/server/config.go:780` sets it from the map key
  # (`aspData.AuthSvcId = aspId`) on every load, so an in-file value would
  # be overwritten anyway. The map-key spelling is what matters and is
  # already validated.
  #
  # Quote-injection safety: every value interpolated into a `"..."`
  # literal is hard-fenced upstream by per-variable `validation {}`
  # blocks (`var.ac_auth_service_id`, `var.qurl_default_ac_id`,
  # `var.connect_layerv_host` in `terraform/variables.tf`) plus the
  # `check` block below on `dest_host` (whose source values are
  # already-fenced upstreams). `res_id` is a constant string literal
  # (`local.tunnel_server_res_id`) — no interpolation at all, so quote-
  # injection is structurally impossible there.
  # End-sentinel marker, paired with `frps_overlay_sentinel`. The
  # sed-strip in `user_data.sh.tpl`'s overlay step deletes the range
  # `[start_sentinel..end_sentinel]` on user_data re-exec, so the
  # closing anchor must be a unique line that appears exactly ONCE
  # per overlay (regardless of how many resource groups are in it).
  # `Addr.Protocol` repeats per group, so it can't serve as a range
  # terminator for multi-group overlays.
  #
  # FROZEN literal — must not change across overlay versions. The
  # "v1 → v2 → … needs NO operator intervention" property of the
  # sed-strip in user_data depends on the END sentinel being a
  # version-INDEPENDENT line that every overlay generation shares.
  # The START sentinel carries the version (`# FRPS bootstrap
  # overlay v2`) so operators inspecting a host can identify the
  # generation; the END sentinel must stay generic so a vN+1
  # user_data running on a vN host can still find the terminator
  # of the existing block and strip it before laying down vN+1.
  # If a future change ever genuinely requires a new end-sentinel
  # string, it must ship in TWO PRs: the first generalizes the
  # user_data sed to match BOTH the old and the new terminators;
  # the second updates this literal in lockstep. A one-step rename
  # produces duplicate tables → server log-and-skips the malformed
  # `resource.toml` → fleet-wide resource-map loss. Fenced below
  # by `terraform_data.frps_overlay_end_sentinel_frozen`.
  frps_overlay_end_sentinel = "# FRPS bootstrap overlay end"

  tunnel_server_resource_toml_overlay = (
    length(local.tunnel_server_resource_ids) == 0
    ? ""
    : join("\n", concat(
      [
        "",
        local.frps_overlay_sentinel,
        "# Wave 5 prep — SLACK_QURL_ROLLOUT.md §6.",
        "# Mirrors the DDB rows in terraform/resources.tf for the runtime path.",
        "# TODO(#1976): retire when DDB→authServiceMap bridge lands.",
        "# INVARIANT: inner `Resources.\"<resName>\"` key MUST equal outer",
        "# `ResourceGroups.\"<resId>\"` key — see resources.tf for rationale.",
      ],
      flatten([
        for res_id in sort(keys(local.tunnel_server_resource_ids)) : [
          "",
          "[\"${var.ac_auth_service_id}\".ResourceGroups.\"${res_id}\"]",
          "OpenTime = ${local.tunnel_server_open_time}",
          # SkipAuth = true is load-bearing: the layerv static plugin
          # (endpoints/server/staticplugins/layerv/main.go) fences on
          # `res.SkipAuth` and refuses with ErrBackendAuthRequired
          # (52007) if it's false. The agent-bootstrap flow has no
          # backend-auth path — the X25519+DDB pubkey resolution in
          # `nhpauth.go::resolveAgentPeerForKnock` IS the access
          # control — so flagging SkipAuth here is the matching
          # contract from terraform's side. Same shape as
          # passcode/oidc resources. TF↔Go drift on this is fenced
          # by TestFRPSResourceTOMLOverlay_SkipAuthTrue in
          # endpoints/server/config_test.go.
          "SkipAuth = true",
          "",
          # Inner resourceName matches outer resourceId — see schema doc above.
          "[\"${var.ac_auth_service_id}\".ResourceGroups.\"${res_id}\".Resources.\"${res_id}\"]",
          "ACId = \"${var.qurl_default_ac_id}\"",
          # Hostname is the customer-facing dial target (the public AC
          # ingress fronting the tunnel server). `Hostname` wins over
          # `Addr.Ip` in `ResourceInfo.DestHost()` for the agent's dial
          # target.
          "Hostname = \"${local.tunnel_server_resource_ids[res_id].customer_facing_host}\"",
          # Addr.Ip = "" is the load-bearing sentinel:
          # `applyDefaultIpSubstitution` in
          # `endpoints/ac/msghandler.go` substitutes `a.config.DefaultIp`
          # (= AC's `LOCAL_IP`) when writing the ipset entry. Net entry:
          # `(agent_ip, frps_bind_port, ac_local_ip)` — the triple a
          # real customer SYN actually has at AC INPUT. Unit-fenced by
          # `TestApplyDefaultIpSubstitution` in endpoints/ac.
          "# Addr.Ip intentionally empty — AC substitutes DefaultIp at ipset-write time.",
          "# Hostname above is what the agent dials (DestHost() prefers Hostname over Ip).",
          "Addr.Ip = \"\"",
          "Addr.Port = ${var.frps_bind_port}",
          "Addr.Protocol = \"tcp\"",
        ]
      ]),
      [
        "",
        local.frps_overlay_end_sentinel,
      ],
    ))
  )
}

# Defense-in-depth fence on the `dest_host` interpolation written
# into the DDB seed row. The customer-facing Hostname interpolation
# (`local.tunnel_server_resource_ids[*].customer_facing_host` → overlay) and
# the empty-string + quote-injection checks on the two AC IDs are
# now hard-fenced upstream:
#   - `var.ac_auth_service_id`, `var.qurl_default_ac_id`,
#     `var.connect_layerv_host` carry `validation {}` regex blocks
#     in `terraform/variables.tf` (apply refuses on bad input).
#   - The empty-string requirement for both AC IDs (when
#     `deploy_frps = true`) is hard-fenced in
#     `terraform_data.frps_preconditions` in `terraform/main.tf`.
# The DDB `dest_host` field stays here as a `check` block because
# its source values (`module.data.namespace_name` joined to
# `var.frps_az_suffixes[0]`) come from upstreams that already
# exclude `"` and `\`; this is a tripwire for a future loosening
# of either upstream, not the primary fence. `check` was promoted
# to `validation` for the load-bearing interpolations; this one
# stays soft because the upstream constraints make a failure
# vanishingly unlikely and a soft warning surfaces the input
# regression without blocking a plan.
# Hard fence on the end-sentinel FROZEN invariant. Promoted from a soft
# `check` block to a `terraform_data` precondition by the same severity-
# asymmetry argument used for the heredoc-delimiter fence and the Traefik
# render check: cost of a stale assert at deliberate rename time is one
# PR; cost of silent corruption (duplicate `[…]` tables → server log-and-
# skips → fleet-wide resource-map loss) is hours of fleet diagnosis. A
# soft `check` would only surface as a plan-time warning the operator
# could hurry past; apply must REFUSE.
resource "terraform_data" "frps_overlay_end_sentinel_frozen" {
  # Re-evaluate when the local literal changes.
  input = local.frps_overlay_end_sentinel

  lifecycle {
    precondition {
      # The end-sentinel literal is consumed by user_data's sed-strip
      # via `templatefile` interpolation. Today's plan-time consumers
      # all see the same value, but the user_data sed-strip is
      # `[start..end]`-range-based against the literal that user_data
      # was rendered with; the in-place overlay block on a running EC2
      # host carries the literal from whichever PR shipped that
      # user_data. Bumping this string in a single PR strips against
      # the new terminator while the on-disk block ends with the old
      # one — the range fails to terminate, the strip leaves the old
      # block behind, and the appended new block produces duplicate
      # `[…]` tables that `pelletier/go-toml/v2` rejects fleet-wide.
      #
      # This precondition exists so a contributor changing the literal
      # also has to update the precondition in the same edit and stops
      # to read the FROZEN doc fence above. The comparison is
      # self-referential by design — it's a tripwire, not a runtime
      # check — but because it lives on `terraform_data`, apply
      # REFUSES (not warns) when the two halves disagree.
      condition     = local.frps_overlay_end_sentinel == "# FRPS bootstrap overlay end"
      error_message = "local.frps_overlay_end_sentinel has been changed away from its FROZEN literal `# FRPS bootstrap overlay end`. Read the FROZEN doc fence on the local above before proceeding — a one-step rename across overlay generations produces duplicate-table corruption in /opt/layerv/nhp-server/etc/resource.toml fleet-wide. Required two-PR rollout: (1) generalize the sed-strip in terraform/modules/compute/user_data.sh.tpl to match BOTH the old and new terminators; (2) update this literal + the precondition in lockstep."
    }
  }
}

# NOTE: a prior `check "frps_resource_ids_no_alias_collision"` block
# fenced the silent shadow risk between `frps-${region}` and
# `frps-${environment}` rows in a pre-spec-rename `merge()`. With the
# single fixed `qurl-tunnel-server` resId (one entry, no merge), the
# collision shape is structurally impossible. Removed in the rename
# rather than left as defensive dead code — the comment above on
# `local.tunnel_server_resource_ids` documents the single-entry shape.

check "tunnel_server_overlay_dest_host_shape" {
  assert {
    # `dest_host` is composed from `module.data.namespace_name`
    # (= `nhp.{var.environment}.internal`, `environment` ∈
    # {sandbox, prod}) joined to `var.frps_az_suffixes[0]` (each
    # entry fenced to `^[a-z]$`). Per-label RFC 1035 form below
    # matches `connect_layerv_host`'s validation for consistency.
    # The regex is intentionally TLD-agnostic — `.internal` is not
    # a public-DNS-valid TLD but Route 53 / Cloud Map accept it for
    # private zones, and this fence is about per-label shape (alpha-
    # numeric, hyphens internal only), not TLD validity. A future
    # tightening to require an ICANN-registered TLD would break the
    # private Cloud Map name today.
    condition = alltrue([
      for _, cfg in local.tunnel_server_resource_ids :
      can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$", cfg.dest_host))
    ])
    error_message = "Every `local.tunnel_server_resource_ids[*].dest_host` is the internal tunnel-server dial target written into the DDB seed row's `dest_host` field; each must be a per-label RFC 1035 DNS name. Today's values derive from `module.data.namespace_name` + `var.frps_az_suffixes[0]` which already conform; a future change to either input must preserve that."
  }
}

# Hard fence on the heredoc-delimiter-not-in-body invariant. Promoted
# from a soft `check` block to a `terraform_data` precondition by the
# same severity-asymmetry argument used for the Traefik render check:
# cost of a stale assert at delimiter-rename time is one PR; cost of
# silent truncation (bash heredoc terminates at the first occurrence
# of the delimiter in the body → server log-and-skips the malformed
# file → fleet-wide resource-map loss) is hours of fleet diagnosis.
# Apply refuses if the rendered overlay contains the delimiter literal.
resource "terraform_data" "frps_overlay_heredoc_delimiter_fence" {
  count = length(local.tunnel_server_resource_ids) == 0 ? 0 : 1

  # Re-evaluate when the rendered overlay changes.
  input = sha256(local.tunnel_server_resource_toml_overlay)

  lifecycle {
    precondition {
      condition     = !strcontains(local.tunnel_server_resource_toml_overlay, "OVERLAYEOF_FRPS_V2_DO_NOT_EDIT")
      error_message = "local.tunnel_server_resource_toml_overlay contains the literal string `OVERLAYEOF_FRPS_V2_DO_NOT_EDIT`, which is the heredoc delimiter in user_data.sh.tpl. The rendered overlay would silently truncate at that line, the server would log-and-skip the malformed resource.toml, and the tunnel-server resource map would vanish fleet-wide. Rename the delimiter in user_data.sh.tpl AND this precondition, or trace the tfvar that injected the literal."
    }
  }
}

resource "aws_dynamodb_table_item" "frps_nhp_resource" {
  for_each = local.tunnel_server_resource_ids

  table_name = module.dynamodb.resources_table_name
  hash_key   = "customer_id"
  range_key  = "resource_id"

  item = jsonencode({
    customer_id = { S = local.nhp_system_customer_id }
    resource_id = { S = each.key }
    # The consumer-facing FQDN and dial target collapse to the
    # same Cloud Map name — the agent dials the tunnel server directly.
    resource_fqdn = { S = each.value.dest_host }
    ac_id         = { S = local.nhp_system_seed_sentinel }
    dest_host     = { S = each.value.dest_host }
    dest_port     = { N = tostring(var.frps_bind_port) }
    # OpenTime: shared with TOML overlay via `local.tunnel_server_open_time`.
    # See the local's doc for the AC-constant rationale.
    open_time       = { N = tostring(local.tunnel_server_open_time) }
    auth_service_id = { S = local.nhp_system_seed_sentinel }
  })

  lifecycle {
    # Mirrors `aws_dynamodb_table_item.ac_license`: Console / qurl-service
    # update Resource fields out-of-band; TF must not fight them. Does NOT
    # defend row destruction on `deploy_frps = false`. #1909 tracks
    # `prevent_destroy = true` once qurl-service starts persisting non-
    # trivial state here.
    ignore_changes = [item]
  }
}
