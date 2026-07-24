variable "authority_runtime_contract" {
  description = <<-EOT
    Nullable versioned Connector Authority deployment contract. Null keeps the
    foundation dark. A non-null value freezes one environment/account/region,
    one blue-or-green selector, the provisioned-cell caller catalog plus its
    immutable evidence identity, the exact 3 + 4N Authority operation graph,
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
  authority_contract_cell_keys = toset(["caller_role_arn"])
  authority_contract_global_keys = toset([
    "environment",
    "aws_partition",
    "aws_account_id",
    "aws_region",
    "authority_repository_url",
    "authority_digest_parameter_name",
    "authority_image_digest",
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
  authority_contract_dependency_headroom_keys = toset([
    "dynamodb_max_in_flight",
    "kms_max_in_flight",
    "redis_max_connections",
    "ses_max_in_flight",
  ])
  authority_contract_caller_capacity_keys = toset([
    "hub_workers",
    "cell_workers",
  ])
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
  authority_expected_functions      = merge(local.authority_expected_hub_functions, local.authority_expected_cell_functions)
  authority_actual_function_names   = toset(keys(local.authority_contract_functions))
  authority_expected_hub_names      = toset(keys(local.authority_expected_hub_functions))
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
      spec.cell_id == ""
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
      spec.cell_id == ""
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
    can(regex("^sha256:[0-9a-f]{64}$", local.authority_contract_global.authority_image_digest)) &&
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
      cell.caller_role_arn == "arn:${local.authority_contract_global.aws_partition}:iam::${local.authority_contract_global.aws_account_id}:role/${cell_id == "cell0" ? "layerv-nhp-${var.environment}-server" : "layerv-nhp-${var.environment}-${cell_id}-server"}"
    ]) &&
    length(toset([for cell in values(local.authority_contract_cells) : cell.caller_role_arn])) == length(local.authority_contract_cells),
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
      function.steady_reserved_concurrency == function.steady_provisioned_concurrency &&
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

  authority_selected_alias_targets = !local.authority_runtime_contract_enabled ? null : {
    hub = {
      for function_name, spec in local.authority_expected_hub_functions :
      spec.operation => "arn:${local.authority_contract_global.aws_partition}:lambda:${local.authority_contract_global.aws_region}:${local.authority_contract_global.aws_account_id}:function:${function_name}:${var.authority_runtime_contract.selected_authority_color}"
    }
    cells = {
      for cell_id, expected_names in local.authority_expected_cell_names :
      cell_id => {
        for function_name in expected_names :
        local.authority_expected_functions[function_name].operation => "arn:${local.authority_contract_global.aws_partition}:lambda:${local.authority_contract_global.aws_region}:${local.authority_contract_global.aws_account_id}:function:${function_name}:${var.authority_runtime_contract.selected_authority_color}"
        if contains(local.authority_actual_function_names, function_name)
      }
    }
  }
}
