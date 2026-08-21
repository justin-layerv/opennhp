variable "authority_runtime_contract" {
  description = <<-EOT
    Nullable versioned Connector Authority deployment contract. Null keeps the
    foundation dark. A non-null value freezes one environment/account/region,
    one blue-or-green selector, the provisioned-cell caller catalog plus its
    immutable evidence identity, the exact 3 + 5N Authority operation graph,
    and its evidence-backed concurrency and request-rate envelopes.
    Caller max_replicas includes every simultaneously live old/new or surge
    replica, not only the converged desired count.

    The type is deliberately any: Terraform object conversion discards unknown
    attributes before validation. The recursive exact-key checks below reject
    missing, extra, malformed, partial, or mixed deployment graphs at plan time.
  EOT
  type        = any
  default     = null
}

variable "authority_runtime_contract_evidence_verified" {
  description = "Internal dark-launch latch. It may become true only in the later exact-main evidence-generator composition that verifies the referenced blobs before Terraform runs; Control roots intentionally leave it false in this contract-only slice."
  type        = bool
  default     = false
}

locals {
  authority_contract_schema_version = 1

  authority_contract_top_keys = toset([
    "schema_version",
    "phase",
    "selected_authority_color",
    "provisioned_cells",
    "provisioned_cells_evidence",
    "qat1_kid",
    "global",
    "functions",
  ])
  authority_contract_cell_keys = toset([
    "caller_role_arn",
    "cell_table_prefix",
    "qurl_resources_table_arn",
    "qurl_resource_key_material_table_arn",
    "cell_data_kms_key_arn",
    "resource_key_envelope_kms_key_arn",
    "resource_key_software_custody_enabled",
  ])
  authority_contract_global_base_keys = toset([
    "environment",
    "aws_partition",
    "aws_account_id",
    "aws_region",
    "authority_repository_url",
    "authority_digest_parameter_name",
    "authority_image_source",
    "qat1_raw_key_arn",
    "qat1_alias_arn",
    "otp_redis_cache_name",
    "otp_redis_endpoint",
    "regional_lambda_concurrency_quota",
    "non_authority_reserved_concurrency",
    "retained_unreserved_concurrency",
    "dependency_headroom",
    "caller_capacity",
    "basis_evidence",
    "result_evidence",
  ])
  # authority_image_digest is present for exactly one source. Making the closed
  # key set mode-dependent is what makes "tracks published images AND names a
  # digest" unrepresentable, rather than something the identity check has to
  # catch after the fact. An absent or unrecognized source falls to the pinned
  # shape, so a contract that omits the field cannot silently start tracking
  # whatever qurl-service published last.
  authority_contract_global_keys = (
    local.authority_image_tracks_publish
    ? local.authority_contract_global_base_keys
    : setunion(local.authority_contract_global_base_keys, ["authority_image_digest"])
  )
  authority_contract_dependency_headroom_keys = toset([
    "dynamodb_max_in_flight",
    "kms_max_in_flight",
    "redis_max_connections",
    "ses_max_in_flight",
  ])
  # proof_controller is present if and only if the sandbox-only proof gate is
  # on. With the gate off this set is byte-identical to the historical closure,
  # so an existing contract that carries a proof_controller block is rejected as
  # an unknown key rather than silently accepted.
  authority_contract_caller_capacity_keys = toset(concat(
    ["hub_workers", "cell_workers"],
    var.authority_proof_mutation_controls_enabled ? ["proof_controller"] : [],
  ))
  authority_contract_worker_keys = toset([
    "max_replicas",
    "preinvoke_limits",
    "preinvoke_rate_limits",
  ])
  authority_contract_rate_limit_keys = toset([
    "burst",
    "refill_per_second",
  ])
  authority_contract_hub_operation_suffixes = {
    issue_assignment          = "ia"
    refresh_assignment        = "ra"
    issue_credential_recovery = "icr"
  }
  authority_contract_cell_operation_suffixes = {
    issue_registration_otp       = "iro"
    activate_registration        = "ar"
    complete_registration        = "cr"
    complete_credential_recovery = "ccr"
    resolve_connector_resource   = "creso"
  }
  # Attended-proof mutation controls are a THIRD operation family, deliberately
  # not merged into the hub or cell maps above. Keeping them separate is the
  # structural fence: the hub/cell caller-capacity closures below are keyed on
  # those two maps, so a proof operation can never acquire a hub or cell
  # preinvoke budget, and authority_selected_alias_targets never offers a proof
  # alias to the Hub task role or a cell server role. The family is empty unless
  # the sandbox-only gate is on, so the committed default reproduces the exact
  # historical 3 + 5N graph byte for byte.
  authority_contract_proof_operation_suffixes = var.authority_proof_mutation_controls_enabled ? {
    mutate_proof_agent                = "pm"
    prepare_proof_credential_recovery = "pcr"
  } : {}
  # The handler (layervai/qurl-service internal/connectorauthorityruntime,
  # parseOperation) matches CONNECTOR_AUTHORITY_OPERATION EXACTLY against the
  # PascalCase operation constants exported by layervai/qurl-conformance. The
  # snake_case operation keys above are this module's internal identity (exec
  # role policy names, tags, log/description labels) and are NOT the wire value
  # -- feeding them verbatim fails the function closed at init with
  # configuration_invalid. Map each operation to its conformance constant for
  # the function environment. A missing key fails at plan time, which is the
  # intended signal to extend this map when an operation is added above. Note
  # OTP capitalization rules out deriving these from the snake_case keys.
  authority_operation_conformance_name = {
    issue_assignment                  = "IssueAssignment"
    refresh_assignment                = "RefreshAssignment"
    issue_credential_recovery         = "IssueCredentialRecovery"
    issue_registration_otp            = "IssueRegistrationOTP"
    activate_registration             = "ActivateRegistration"
    complete_registration             = "CompleteRegistration"
    complete_credential_recovery      = "CompleteCredentialRecovery"
    resolve_connector_resource        = "ResolveConnectorResource"
    mutate_proof_agent                = "MutateProofAgent"
    prepare_proof_credential_recovery = "PrepareProofCredentialRecovery"
  }
  authority_contract_function_keys = toset([
    "steady_provisioned_concurrency",
    "steady_reserved_concurrency",
    "rollout_active_provisioned_concurrency",
    "rollout_standby_provisioned_concurrency",
    "rollout_reserved_concurrency",
    "max_caller_in_flight",
    "max_caller_requests_per_second",
    "rollback_retention_seconds",
    "basis_evidence",
    "result_evidence",
  ])
  authority_contract_evidence_keys = toset([
    "repository",
    "source_commit",
    "path",
    "sha256",
    "schema_version",
  ])

  authority_runtime_contract_enabled = var.authority_runtime_contract != null
  authority_contract_global          = try(var.authority_runtime_contract.global, {})
  authority_contract_cells = try({
    for cell_id, cell in var.authority_runtime_contract.provisioned_cells :
    cell_id => cell
  }, {})
  authority_contract_functions = try({
    for function_name, function in var.authority_runtime_contract.functions :
    function_name => function
  }, {})
  authority_contract_caller_capacity = try(var.authority_runtime_contract.global.caller_capacity, {})
  authority_contract_hub_workers     = try(var.authority_runtime_contract.global.caller_capacity.hub_workers, {})
  # Projected unconditionally, exactly like hub_workers. The gate is enforced by
  # authority_contract_caller_capacity_keys instead: with the gate off that
  # closed key set omits proof_controller, so a contract carrying one is
  # rejected as an unknown key rather than silently projected here.
  authority_contract_proof_controller = try(var.authority_runtime_contract.global.caller_capacity.proof_controller, {})
  authority_contract_cell_workers = try({
    for cell_id, worker in var.authority_runtime_contract.global.caller_capacity.cell_workers :
    cell_id => worker
  }, {})

  authority_function_prefix = "layerv-nhp-${var.environment}-ca"
  authority_expected_hub_functions = {
    for operation, suffix in local.authority_contract_hub_operation_suffixes :
    "${local.authority_function_prefix}-${suffix}" => {
      operation = operation
      cell_id   = ""
    }
  }
  authority_expected_cell_functions = merge(concat(
    [{}],
    [
      for cell_id in keys(local.authority_contract_cells) : {
        for operation, suffix in local.authority_contract_cell_operation_suffixes :
        "${local.authority_function_prefix}-${suffix}-${cell_id}" => {
          operation = operation
          cell_id   = cell_id
        }
      }
    ],
  )...)
  # Proof functions are environment-scoped like the hub group (no cell suffix):
  # the control addresses an agent, not a cell, and one function performs the
  # cell0-to-cell1 move across both.
  authority_expected_proof_functions = {
    for operation, suffix in local.authority_contract_proof_operation_suffixes :
    "${local.authority_function_prefix}-${suffix}" => {
      operation = operation
      cell_id   = ""
    }
  }
  authority_expected_functions = merge(
    local.authority_expected_hub_functions,
    local.authority_expected_cell_functions,
    local.authority_expected_proof_functions,
  )
  authority_actual_function_names   = toset(keys(local.authority_contract_functions))
  authority_expected_hub_names      = toset(keys(local.authority_expected_hub_functions))
  authority_expected_proof_names    = toset(keys(local.authority_expected_proof_functions))
  authority_expected_function_names = toset(keys(local.authority_expected_functions))
  authority_expected_cell_names = {
    for cell_id in keys(local.authority_contract_cells) :
    cell_id => toset([
      for operation, suffix in local.authority_contract_cell_operation_suffixes :
      "${local.authority_function_prefix}-${suffix}-${cell_id}"
    ])
  }

  authority_expected_caller_in_flight = {
    for function_name, spec in local.authority_expected_functions :
    function_name => (
      contains(local.authority_expected_proof_names, function_name)
      ? try(
        local.authority_contract_proof_controller.max_replicas *
        local.authority_contract_proof_controller.preinvoke_limits[spec.operation],
        -1,
      )
      : spec.cell_id == ""
      ? try(
        local.authority_contract_hub_workers.max_replicas *
        local.authority_contract_hub_workers.preinvoke_limits[spec.operation],
        -1,
      )
      : try(
        local.authority_contract_cell_workers[spec.cell_id].max_replicas *
        local.authority_contract_cell_workers[spec.cell_id].preinvoke_limits[spec.operation],
        -1,
      )
    )
  }

  # Lambda's provisioned-concurrency request-rate ceiling is evaluated over a
  # one-second interval. A full caller token bucket can spend its complete
  # burst and every token refilled during that interval, on every replica.
  authority_expected_caller_requests_per_second = {
    for function_name, spec in local.authority_expected_functions :
    function_name => (
      contains(local.authority_expected_proof_names, function_name)
      ? try(
        local.authority_contract_proof_controller.max_replicas * (
          local.authority_contract_proof_controller.preinvoke_rate_limits[spec.operation].burst +
          local.authority_contract_proof_controller.preinvoke_rate_limits[spec.operation].refill_per_second
        ),
        -1,
      )
      : spec.cell_id == ""
      ? try(
        local.authority_contract_hub_workers.max_replicas * (
          local.authority_contract_hub_workers.preinvoke_rate_limits[spec.operation].burst +
          local.authority_contract_hub_workers.preinvoke_rate_limits[spec.operation].refill_per_second
        ),
        -1,
      )
      : try(
        local.authority_contract_cell_workers[spec.cell_id].max_replicas * (
          local.authority_contract_cell_workers[spec.cell_id].preinvoke_rate_limits[spec.operation].burst +
          local.authority_contract_cell_workers[spec.cell_id].preinvoke_rate_limits[spec.operation].refill_per_second
        ),
        -1,
      )
    )
  }

  authority_available_lambda_concurrency = try(
    local.authority_contract_global.regional_lambda_concurrency_quota -
    local.authority_contract_global.non_authority_reserved_concurrency -
    local.authority_contract_global.retained_unreserved_concurrency,
    -1,
  )

  authority_contract_evidence_objects = concat(
    [
      try(var.authority_runtime_contract.provisioned_cells_evidence, null),
      try(local.authority_contract_global.basis_evidence, null),
    ],
    try(local.authority_contract_global.result_evidence, null) == null
    ? []
    : [try(local.authority_contract_global.result_evidence, null)],
    flatten([
      for function in values(local.authority_contract_functions) : concat(
        [try(function.basis_evidence, null)],
        try(function.result_evidence, null) == null
        ? []
        : [try(function.result_evidence, null)],
      )
    ]),
  )

  # Recursive schema closure. Every exact-key comparison is protected by try so
  # a wrong Terraform type is a deterministic false result, never an evaluator
  # error that bypasses the contract with a partially converted object.
  authority_contract_shape_valid = !local.authority_runtime_contract_enabled || try(
    toset(keys(var.authority_runtime_contract)) == local.authority_contract_top_keys &&
    toset(keys(local.authority_contract_global)) == local.authority_contract_global_keys &&
    alltrue([
      for cell in values(local.authority_contract_cells) :
      toset(keys(cell)) == local.authority_contract_cell_keys
    ]) &&
    toset(keys(local.authority_contract_global.dependency_headroom)) == local.authority_contract_dependency_headroom_keys &&
    toset(keys(local.authority_contract_caller_capacity)) == local.authority_contract_caller_capacity_keys &&
    toset(keys(local.authority_contract_hub_workers)) == local.authority_contract_worker_keys &&
    toset(keys(local.authority_contract_hub_workers.preinvoke_limits)) == toset(keys(local.authority_contract_hub_operation_suffixes)) &&
    toset(keys(local.authority_contract_hub_workers.preinvoke_rate_limits)) == toset(keys(local.authority_contract_hub_operation_suffixes)) &&
    alltrue([
      for rate_limit in values(local.authority_contract_hub_workers.preinvoke_rate_limits) :
      toset(keys(rate_limit)) == local.authority_contract_rate_limit_keys
    ]) &&
    (
      !var.authority_proof_mutation_controls_enabled ||
      (
        toset(keys(local.authority_contract_proof_controller)) == local.authority_contract_worker_keys &&
        toset(keys(local.authority_contract_proof_controller.preinvoke_limits)) == toset(keys(local.authority_contract_proof_operation_suffixes)) &&
        toset(keys(local.authority_contract_proof_controller.preinvoke_rate_limits)) == toset(keys(local.authority_contract_proof_operation_suffixes)) &&
        alltrue([
          for rate_limit in values(local.authority_contract_proof_controller.preinvoke_rate_limits) :
          toset(keys(rate_limit)) == local.authority_contract_rate_limit_keys
        ])
      )
    ) &&
    toset(keys(local.authority_contract_cell_workers)) == toset(keys(local.authority_contract_cells)) &&
    alltrue([
      for worker in values(local.authority_contract_cell_workers) :
      toset(keys(worker)) == local.authority_contract_worker_keys &&
      toset(keys(worker.preinvoke_limits)) == toset(keys(local.authority_contract_cell_operation_suffixes)) &&
      toset(keys(worker.preinvoke_rate_limits)) == toset(keys(local.authority_contract_cell_operation_suffixes)) &&
      alltrue([
        for rate_limit in values(worker.preinvoke_rate_limits) :
        toset(keys(rate_limit)) == local.authority_contract_rate_limit_keys
      ])
    ]) &&
    alltrue([
      for function in values(local.authority_contract_functions) :
      toset(keys(function)) == local.authority_contract_function_keys
    ]),
    false,
  )

  authority_contract_identity_valid = !local.authority_runtime_contract_enabled || try(
    var.authority_runtime_contract.schema_version == local.authority_contract_schema_version &&
    jsonencode(var.authority_runtime_contract.schema_version) == jsonencode(tonumber(var.authority_runtime_contract.schema_version)) &&
    contains(["measurement", "ready"], var.authority_runtime_contract.phase) &&
    contains(["blue", "green"], var.authority_runtime_contract.selected_authority_color) &&
    length(local.authority_contract_cells) > 0 &&
    contains(keys(local.authority_contract_cells), "cell0") &&
    local.authority_contract_global.environment == var.environment &&
    local.authority_contract_global.aws_account_id == var.aws_account_id &&
    local.authority_contract_global.aws_partition == data.aws_partition.current.partition &&
    local.authority_contract_global.aws_region == data.aws_region.current.region &&
    local.authority_contract_global.authority_repository_url == aws_ecr_repository.authority.repository_url &&
    local.authority_contract_global.authority_digest_parameter_name == local.authority_image_digest_parameter_name &&
    # The contract must state which image source applies, and carry a basis
    # digest under exactly one of them. A contract that tracks published images
    # while also naming a digest is ambiguous about which one governs, so it is
    # rejected rather than resolved by precedence.
    contains(["pinned_digest", "publish_parameter"], local.authority_image_source) &&
    # publish_parameter is not a trade prod may make; see the local.
    local.authority_image_source_permitted &&
    (local.authority_image_tracks_publish
      ? local.authority_image_basis_digest == null
    : local.authority_image_basis_digest != null) &&
    # Shape is checked on the RESOLVED digest, so it covers a published value
    # just as strictly as a pinned one -- including the seeded UNPUBLISHED
    # placeholder, which fails here on a fresh environment.
    #
    # Note what is deliberately absent: no comparison of the basis against the
    # live publish parameter. That comparison is what let qurl-service CI
    # invalidate every open Control plan, and it was never an independent
    # attestation anyway -- the same CI both builds the image and writes the
    # parameter. The binding that matters is below and still fails closed: the
    # resolved digest must be a real image in the Authority ECR repository.
    can(regex("^sha256:[0-9a-f]{64}$", local.authority_runtime_image_digest)) &&
    data.aws_ecr_image.authority_runtime[0].image_digest == local.authority_runtime_image_digest &&
    data.aws_ecr_image.authority_runtime[0].image_uri == "${aws_ecr_repository.authority.repository_url}@${local.authority_runtime_image_digest}" &&
    local.authority_contract_global.qat1_raw_key_arn == aws_kms_key.qat1_signing.arn &&
    local.authority_contract_global.qat1_alias_arn == aws_kms_alias.qat1_signing.arn &&
    jsonencode(var.authority_runtime_contract.qat1_kid) == jsonencode(tostring(var.authority_runtime_contract.qat1_kid)) &&
    can(regex("^[A-Za-z0-9._-]{1,128}$", var.authority_runtime_contract.qat1_kid)) &&
    local.authority_contract_global.otp_redis_cache_name == aws_elasticache_serverless_cache.otp.name &&
    local.authority_contract_global.otp_redis_endpoint == "${aws_elasticache_serverless_cache.otp.endpoint[0].address}:6379" &&
    aws_elasticache_serverless_cache.otp.endpoint[0].port == 6379 &&
    alltrue([
      for cell_id, cell in local.authority_contract_cells :
      length(cell_id) <= 32 &&
      can(regex("^[a-z0-9]+(-[a-z0-9]+)*$", cell_id)) &&
      cell.caller_role_arn == "arn:${local.authority_contract_global.aws_partition}:iam::${local.authority_contract_global.aws_account_id}:role/${cell_id == "cell0" ? "layerv-nhp-${var.environment}-server" : "layerv-nhp-${var.environment}-${cell_id}-server"}" &&
      contains([
        "layerv-nhp-${var.environment}-${cell_id}",
        "layerv-nhp-${var.environment}-${cell_id}-${cell_id}",
      ], cell.cell_table_prefix) &&
      cell.qurl_resources_table_arn == "arn:${local.authority_contract_global.aws_partition}:dynamodb:${local.authority_contract_global.aws_region}:${local.authority_contract_global.aws_account_id}:table/${cell.cell_table_prefix}-qurl-resources" &&
      cell.qurl_resource_key_material_table_arn == "arn:${local.authority_contract_global.aws_partition}:dynamodb:${local.authority_contract_global.aws_region}:${local.authority_contract_global.aws_account_id}:table/${cell.cell_table_prefix}-qurl-resource-key-material" &&
      can(regex(
        "^arn:${local.authority_contract_global.aws_partition}:kms:${local.authority_contract_global.aws_region}:${local.authority_contract_global.aws_account_id}:key/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        cell.cell_data_kms_key_arn,
      )) &&
      can(regex(
        "^arn:${local.authority_contract_global.aws_partition}:kms:${local.authority_contract_global.aws_region}:${local.authority_contract_global.aws_account_id}:key/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        cell.resource_key_envelope_kms_key_arn,
      )) &&
      cell.cell_data_kms_key_arn != cell.resource_key_envelope_kms_key_arn &&
      jsonencode(cell.resource_key_software_custody_enabled) == jsonencode(tobool(cell.resource_key_software_custody_enabled))
    ]) &&
    length(toset([for cell in values(local.authority_contract_cells) : cell.caller_role_arn])) == length(local.authority_contract_cells) &&
    length(toset([for cell in values(local.authority_contract_cells) : cell.cell_table_prefix])) == length(local.authority_contract_cells) &&
    length(toset([for cell in values(local.authority_contract_cells) : cell.qurl_resources_table_arn])) == length(local.authority_contract_cells) &&
    length(toset([for cell in values(local.authority_contract_cells) : cell.qurl_resource_key_material_table_arn])) == length(local.authority_contract_cells) &&
    length(toset([for cell in values(local.authority_contract_cells) : cell.cell_data_kms_key_arn])) == length(local.authority_contract_cells) &&
    length(toset([for cell in values(local.authority_contract_cells) : cell.resource_key_envelope_kms_key_arn])) == length(local.authority_contract_cells),
    false,
  )

  authority_contract_graph_valid = !local.authority_runtime_contract_enabled || try(
    length(setsubtract(local.authority_expected_hub_names, local.authority_actual_function_names)) == 0 &&
    length(setsubtract(local.authority_actual_function_names, local.authority_expected_function_names)) == 0 &&
    alltrue([
      for cell_id, expected_names in local.authority_expected_cell_names :
      contains(
        [0, length(expected_names)],
        length(setintersection(local.authority_actual_function_names, expected_names)),
      )
    ]) &&
    (
      var.authority_runtime_contract.phase == "measurement" ||
      local.authority_actual_function_names == local.authority_expected_function_names
    ) &&
    alltrue([
      for function_name in local.authority_actual_function_names :
      local.authority_expected_caller_in_flight[function_name] >= 1 &&
      local.authority_expected_caller_requests_per_second[function_name] >= 1
    ]),
    false,
  )

  authority_contract_integer_capacity_valid = !local.authority_runtime_contract_enabled || try(
    alltrue([
      for value in concat(
        [
          local.authority_contract_global.regional_lambda_concurrency_quota,
          local.authority_contract_global.non_authority_reserved_concurrency,
          local.authority_contract_global.retained_unreserved_concurrency,
          local.authority_contract_hub_workers.max_replicas,
        ],
        values(local.authority_contract_global.dependency_headroom),
        values(local.authority_contract_hub_workers.preinvoke_limits),
        flatten([
          for rate_limit in values(local.authority_contract_hub_workers.preinvoke_rate_limits) :
          values(rate_limit)
        ]),
        var.authority_proof_mutation_controls_enabled ? concat(
          [local.authority_contract_proof_controller.max_replicas],
          values(local.authority_contract_proof_controller.preinvoke_limits),
          flatten([
            for rate_limit in values(local.authority_contract_proof_controller.preinvoke_rate_limits) :
            values(rate_limit)
          ]),
        ) : [],
        flatten([
          for worker in values(local.authority_contract_cell_workers) :
          concat(
            [worker.max_replicas],
            values(worker.preinvoke_limits),
            flatten([
              for rate_limit in values(worker.preinvoke_rate_limits) :
              values(rate_limit)
            ]),
          )
        ]),
        flatten([
          for function in values(local.authority_contract_functions) : [
            function.steady_provisioned_concurrency,
            function.steady_reserved_concurrency,
            function.rollout_active_provisioned_concurrency,
            function.rollout_standby_provisioned_concurrency,
            function.rollout_reserved_concurrency,
            function.max_caller_in_flight,
            function.max_caller_requests_per_second,
            function.rollback_retention_seconds,
          ]
        ]),
      ) :
      jsonencode(value) == jsonencode(tonumber(value)) && floor(value) == value
    ]),
    false,
  )

  authority_contract_capacity_valid = !local.authority_runtime_contract_enabled || try(
    local.authority_contract_global.regional_lambda_concurrency_quota >= 1 &&
    local.authority_contract_global.non_authority_reserved_concurrency >= 0 &&
    local.authority_contract_global.retained_unreserved_concurrency >= 100 &&
    local.authority_available_lambda_concurrency >= 1 &&
    # This precursor freezes positive, evidence-addressable downstream
    # headroom. The exact-main evidence checker owns service-specific demand
    # comparison because each operation has a different measured fan-out; the
    # schema intentionally does not invent those ratios.
    alltrue([
      for value in values(local.authority_contract_global.dependency_headroom) :
      value >= 1
    ]) &&
    local.authority_contract_hub_workers.max_replicas >= 1 &&
    alltrue([
      for value in values(local.authority_contract_hub_workers.preinvoke_limits) :
      value >= 1
    ]) &&
    alltrue([
      for rate_limit in values(local.authority_contract_hub_workers.preinvoke_rate_limits) :
      rate_limit.burst >= 1 &&
      rate_limit.refill_per_second >= 1
    ]) &&
    (
      !var.authority_proof_mutation_controls_enabled ||
      (
        # One attended controller, serialized: a proof mutation is never
        # concurrent with itself, so a replica or budget above one would only
        # widen a control that mutates live authorization state.
        local.authority_contract_proof_controller.max_replicas == 1 &&
        alltrue([
          for value in values(local.authority_contract_proof_controller.preinvoke_limits) :
          value == 1
        ]) &&
        alltrue([
          for rate_limit in values(local.authority_contract_proof_controller.preinvoke_rate_limits) :
          rate_limit.burst == 1 &&
          rate_limit.refill_per_second == 1
        ])
      )
    ) &&
    alltrue([
      for worker in values(local.authority_contract_cell_workers) :
      worker.max_replicas >= 1 &&
      alltrue([for value in values(worker.preinvoke_limits) : value >= 1]) &&
      alltrue([
        for rate_limit in values(worker.preinvoke_rate_limits) :
        rate_limit.burst >= 1 &&
        rate_limit.refill_per_second >= 1
      ])
    ]) &&
    alltrue([
      for function_name, function in local.authority_contract_functions :
      function.steady_provisioned_concurrency >= 1 &&
      # The steady reserved envelope covers BOTH colours' warm pools at once,
      # exactly like the rollout invariant below covers active + standby. A
      # blue/green selector flip provisions the new colour before the old one
      # releases (create-before-destroy on the provisioned-concurrency
      # resource), and Lambda refuses any alias allocation that would exceed
      # the function's reserved concurrency -- measured on the 2026-08-12
      # cutover. reserved == provisioned would make every flip delete-first
      # and serve a cold window mid-switch.
      function.steady_reserved_concurrency == 2 * function.steady_provisioned_concurrency &&
      function.rollout_active_provisioned_concurrency >= 1 &&
      function.rollout_standby_provisioned_concurrency >= 1 &&
      function.rollout_reserved_concurrency == (
        function.rollout_active_provisioned_concurrency +
        function.rollout_standby_provisioned_concurrency
      ) &&
      function.max_caller_in_flight == local.authority_expected_caller_in_flight[function_name] &&
      function.max_caller_requests_per_second == local.authority_expected_caller_requests_per_second[function_name] &&
      function.max_caller_in_flight <= function.steady_provisioned_concurrency &&
      function.max_caller_in_flight <= function.rollout_active_provisioned_concurrency &&
      function.max_caller_in_flight <= function.rollout_standby_provisioned_concurrency &&
      function.max_caller_requests_per_second <= 10 * function.steady_provisioned_concurrency &&
      function.max_caller_requests_per_second <= 10 * function.rollout_active_provisioned_concurrency &&
      function.max_caller_requests_per_second <= 10 * function.rollout_standby_provisioned_concurrency &&
      max(
        function.steady_reserved_concurrency,
        function.rollout_reserved_concurrency,
      ) <= local.authority_available_lambda_concurrency &&
      function.rollback_retention_seconds >= 1 &&
      function.rollback_retention_seconds <= 86400
    ]) &&
    sum([
      for function in values(local.authority_contract_functions) :
      function.steady_reserved_concurrency
    ]) <= local.authority_available_lambda_concurrency &&
    sum([
      for function in values(local.authority_contract_functions) :
      function.rollout_reserved_concurrency
    ]) <= local.authority_available_lambda_concurrency,
    false,
  )

  authority_contract_evidence_valid = !local.authority_runtime_contract_enabled || try(
    alltrue([
      for evidence in local.authority_contract_evidence_objects :
      evidence != null &&
      toset(keys(evidence)) == local.authority_contract_evidence_keys &&
      jsonencode(evidence.repository) == jsonencode(tostring(evidence.repository)) &&
      jsonencode(evidence.source_commit) == jsonencode(tostring(evidence.source_commit)) &&
      jsonencode(evidence.path) == jsonencode(tostring(evidence.path)) &&
      jsonencode(evidence.sha256) == jsonencode(tostring(evidence.sha256)) &&
      evidence.repository == "layervai/nhp" &&
      can(regex("^[0-9a-f]{40}$", evidence.source_commit)) &&
      can(regex("^docs/evidence/connector-authority/v1/[A-Za-z0-9][A-Za-z0-9._/-]*\\.json$", evidence.path)) &&
      !strcontains(evidence.path, "..") &&
      can(regex("^[0-9a-f]{64}$", evidence.sha256)) &&
      evidence.schema_version == local.authority_contract_schema_version &&
      jsonencode(evidence.schema_version) == jsonencode(tonumber(evidence.schema_version))
    ]) &&
    (
      var.authority_runtime_contract.phase == "measurement"
      ? (
        local.authority_contract_global.result_evidence == null &&
        alltrue([
          for function in values(local.authority_contract_functions) :
          function.result_evidence == null
        ])
      )
      : (
        local.authority_contract_global.result_evidence != null &&
        alltrue([
          for function in values(local.authority_contract_functions) :
          function.result_evidence != null
        ])
      )
    ),
    false,
  )

  authority_contract_enablement_valid = (
    !local.authority_runtime_contract_enabled ||
    var.authority_runtime_contract_evidence_verified
  )

  # ---------------------------------------------------------------------------
  # Attended-proof mutation control fences.
  #
  # These are deliberately expressed as plan-time hard failures rather than as
  # conditional resource creation: a mis-set input must stop the apply, not
  # quietly produce a narrower graph. Each clause below is independently
  # sufficient to keep the control out of prod and out of every ordinary caller
  # path; they are ANDed so no single edit can open it.
  # ---------------------------------------------------------------------------

  # qurl-service derives the placement partition as OWNER# followed by the
  # lowercase hex SHA-256 of the authenticated owner identity
  # (internal/repository/dynamodb/agent_placement_repo.go agentPlacementOwnerPK).
  # Reproducing it here lets the execution role be pinned to exactly one tenant
  # partition with dynamodb:LeadingKeys.
  authority_proof_owner_partition_key = (
    var.authority_proof_mutation_owner_id == null
    ? null
    : "OWNER#${sha256(var.authority_proof_mutation_owner_id)}"
  )
  # The directive partition the control arms and reads. It is a single literal
  # partition so the same LeadingKeys fence covers it.
  authority_proof_directive_partition_key = "PROOF"

  # The proof-runner root pre-creates this deterministic protected-environment
  # role. Control owns the role's ca-pm inline policy so selection and grant are
  # one atomic saved plan; no operator-supplied alias crosses state boundaries.
  authority_proof_controller_role_name = "layerv-nhp-${var.environment}-udp-proof-controller"
  authority_proof_controller_role_arn  = "arn:${data.aws_partition.current.partition}:iam::${var.aws_account_id}:role/${local.authority_proof_controller_role_name}"

  authority_proof_mutation_fence_valid = !var.authority_proof_mutation_controls_enabled || try(
    # 1. Sandbox only. prod can never plan this function.
    var.environment == "sandbox" &&
    !local.is_prod &&
    # 2. The dedicated proof tenant must be named, so the data fence is real.
    var.authority_proof_mutation_owner_id != null &&
    local.authority_proof_owner_partition_key != null &&
    # 3. The only admitted controller identity is the deterministic role whose
    #    selected-alias policy Control owns in this same plan.
    length(var.authority_proof_mutation_controller_role_arns) == 1 &&
    one(var.authority_proof_mutation_controller_role_arns) == local.authority_proof_controller_role_arn &&
    # 4. The control may only exist on top of a bound contract that actually
    #    budgets it, so it can never be enabled ahead of reviewed capacity.
    local.authority_runtime_contract_enabled &&
    length(local.authority_expected_proof_names) > 0 &&
    length(setsubtract(local.authority_expected_proof_names, local.authority_actual_function_names)) == 0,
    false,
  )

  authority_proof_policy_consumers_fence_valid = !var.authority_proof_policy_consumers_staged || try(
    var.environment == "sandbox" &&
    !local.is_prod &&
    var.authority_proof_mutation_controls_enabled &&
    local.authority_runtime_contract_enabled &&
    var.authority_runtime_functions_enabled &&
    length(local.authority_expected_proof_names) == 2,
    false,
  )

  authority_proof_policy_rollout_fence_valid = try(
    (
      var.authority_proof_policy_selected_color == null &&
      var.authority_proof_policy_prepared_color == null
      ) || (
      local.authority_proof_policy_rollout_active &&
      var.environment == "sandbox" &&
      !local.is_prod &&
      var.authority_proof_policy_consumers_staged &&
      var.authority_proof_mutation_controls_enabled &&
      var.authority_runtime_functions_enabled &&
      var.hub_worker_enabled &&
      # The EFFECTIVE selector (review #3857): every other colour-bearing
      # rendering derives from it, and a fence reading the committed value
      # here could silently disagree with a live pointer. Identical while the
      # pointer gate is dark.
      local.authority_runtime_effective_selected_color == "blue" &&
      length(local.authority_proof_policy_consumer_functions) == 3 &&
      length(local.authority_proof_policy_rollout_functions) == 4 &&
      alltrue([
        for function_name in local.authority_proof_policy_rollout_function_names :
        local.authority_contract_functions[function_name].rollout_active_provisioned_concurrency ==
        local.authority_contract_functions[function_name].rollout_standby_provisioned_concurrency
      ])
    ),
    false,
  )

  authority_proof_policy_selected_alias_ready = try(
    !local.authority_proof_policy_rollout_active ||
    var.authority_proof_policy_selected_color != var.authority_proof_policy_prepared_color ||
    alltrue([
      for function_name in keys(local.authority_proof_policy_rollout_functions) :
      data.aws_lambda_alias.authority_proof_policy_live[
        "${function_name}:${var.authority_proof_policy_selected_color}"
      ].function_version == aws_lambda_function.authority[function_name].version
    ]),
    false,
  )

  # With the gate off, no proof function may appear in the contract at all. The
  # expected-set subtraction in authority_contract_graph_valid already rejects
  # it; this states the invariant independently so a future refactor of that
  # closure cannot silently admit one.
  authority_proof_absent_when_disabled_valid = (
    var.authority_proof_mutation_controls_enabled ||
    !local.authority_runtime_contract_enabled ||
    length([
      for function_name in local.authority_actual_function_names :
      function_name
      if endswith(function_name, "-pm")
      || endswith(function_name, "-pcr")
    ]) == 0
  )

  authority_selected_alias_targets = !local.authority_runtime_contract_enabled ? null : {
    hub = {
      for function_name, spec in local.authority_expected_hub_functions :
      spec.operation => "arn:${local.authority_contract_global.aws_partition}:lambda:${local.authority_contract_global.aws_region}:${local.authority_contract_global.aws_account_id}:function:${function_name}:${local.authority_proof_policy_effective_color}"
    }
    cells = {
      for cell_id, expected_names in local.authority_expected_cell_names :
      cell_id => {
        for function_name in expected_names :
        local.authority_expected_functions[function_name].operation => "arn:${local.authority_contract_global.aws_partition}:lambda:${local.authority_contract_global.aws_region}:${local.authority_contract_global.aws_account_id}:function:${function_name}:${local.authority_runtime_effective_selected_color}"
        if contains(local.authority_actual_function_names, function_name)
      }
    }
    # Separate key by design. Consumers select .hub or .cells; nothing that
    # builds a runtime caller policy iterates the whole object, so the proof
    # alias is unreachable from the Hub task role and every cell server role
    # even though it lives in the same derivation.
    proof = {
      for function_name, spec in local.authority_expected_proof_functions :
      spec.operation => "arn:${local.authority_contract_global.aws_partition}:lambda:${local.authority_contract_global.aws_region}:${local.authority_contract_global.aws_account_id}:function:${function_name}:${spec.operation == "mutate_proof_agent" ? local.authority_proof_policy_effective_color : local.authority_runtime_effective_selected_color}"
      if contains(local.authority_actual_function_names, function_name)
    }
  }
}
