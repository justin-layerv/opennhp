#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -gt 1 ]]; then
  echo "usage: $0 [terraform-show-json]" >&2
  exit 2
fi

plan_json="${1:-}"
repo_root="${NHP_REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
checker_repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
control_plan_checker="${checker_repo_root}/.github/scripts/check-control-sandbox-first-apply.py"
module_dir="${repo_root}/terraform/modules/connector-authority-foundation"
control_dir="${repo_root}/terraform/control"
scan_paths=("$module_dir" "$control_dir")

for scan_path in "${scan_paths[@]}"; do
  if [[ ! -d "$scan_path" ]]; then
    echo "ERROR: Connector Authority scan path is missing: ${scan_path}" >&2
    exit 1
  fi
done

scan_tf_regex() {
  local pattern="$1"
  local status=0

  grep -R -nH -E --include='*.tf' -- "$pattern" "${scan_paths[@]}" || status=$?
  case "$status" in
    0 | 1)
      return "$status"
      ;;
    *)
      echo "ERROR: Connector Authority Terraform scan failed with status ${status}" >&2
      return 2
      ;;
  esac
}

forbidden_resource_types=(
  aws_api_gateway_rest_api
  aws_apigatewayv2_api
  aws_ec2_transit_gateway_connect
  aws_ec2_transit_gateway_peering_attachment
  aws_ec2_transit_gateway_peering_attachment_accepter
  aws_ec2_transit_gateway_vpc_attachment
  aws_ec2_transit_gateway_vpc_attachment_accepter
  aws_default_route_table
  aws_eip
  aws_egress_only_internet_gateway
  # aws_internet_gateway, aws_lb, aws_lb_listener, and aws_route are legitimized
  # by the Connector Hub public UDP edge slice (Step 5): one edge IGW, one public
  # route table with a single 0.0.0.0/0 route to it, and the public UDP-443 Hub
  # NLB + listener in the public subnets. Like the authority runtime functions
  # they are NOT free here -- they are gated instead by the exact inventory +
  # transition contract in check-control-sandbox-first-apply.py, which admits
  # them only as the exact Hub-edge set and asserts the internet route lives ONLY
  # on the public edge route table (the isolated workload tables stay local-only).
  # aws_lambda_function and aws_lambda_alias are similarly legitimized by the
  # Connector Authority runtime slice. aws_lambda_function_url,
  # aws_egress_only_internet_gateway, aws_nat_gateway, and aws_eip stay forbidden:
  # the authority never exposes a public URL/API Gateway/ALB route, the Hub
  # workers hold no public IP, and the edge needs no NAT or elastic IP.
  aws_lambda_function_url
  aws_nat_gateway
  aws_route53_record
  aws_vpc_peering_connection
  aws_vpc_peering_connection_accepter
  aws_vpc_peering_connection_options
)

for resource_type in "${forbidden_resource_types[@]}"; do
  status=0
  scan_tf_regex "resource[[:space:]]+\"${resource_type}\"" || status=$?
  case "$status" in
    0)
      echo "ERROR: dark Connector Authority foundation must not declare ${resource_type}" >&2
      exit 1
      ;;
    1) ;;
    *) exit "$status" ;;
  esac
done

# aws_route_table accepts nested route blocks and a route list attribute. Both
# forms compile into the parent resource and would otherwise bypass the
# forbidden aws_route resource-type fence. Keep this lexical and fail closed
# so compact one-line declarations and either HCL spelling are rejected.
status=0
scan_tf_regex '(^|[[:space:]{])route[[:space:]]*([=]|[{])' || status=$?
case "$status" in
  0)
    echo "ERROR: dark Connector Authority foundation must not declare inline route blocks or route attributes" >&2
    exit 1
    ;;
  1) ;;
  *) exit "$status" ;;
esac

if [[ -n "$plan_json" ]]; then
  if [[ ! -r "$plan_json" ]]; then
    echo "ERROR: Connector Authority plan JSON is not readable: ${plan_json}" >&2
    exit 1
  fi
  if jq -e 'has("resource_changes")' "$plan_json" >/dev/null; then
    if ! jq -e '(.resource_changes | type) == "array"' "$plan_json" >/dev/null; then
      echo "ERROR: Connector Authority plan JSON resource_changes must be an array" >&2
      exit 1
    fi
  elif ! jq -e '(.resource_drift | type) == "array" and (.resource_drift | length) > 0' "$plan_json" >/dev/null; then
    echo "ERROR: Connector Authority plan JSON must contain a resource_changes array or non-empty resource_drift array" >&2
    exit 1
  fi
  if ! jq -e '
    (has("resource_drift") | not)
    or .resource_drift == null
    or (.resource_drift | type) == "array"
  ' "$plan_json" >/dev/null; then
    echo "ERROR: Connector Authority plan JSON resource_drift must be an array when present" >&2
    exit 1
  fi

  # The blue/green selector flip: the contract's selected_authority_color
  # moves between the two valid colours and nothing else in the contract
  # changes shape. The flip re-homes steady provisioned concurrency to the new
  # colour (create-before-destroy -- the reserved envelope is 2x provisioned,
  # so the new colour warms while the old is still live) and replaces
  # the Hub task definition (its container env carries the alias ARNs by
  # colour). Any delete outside those two shapes defeats the flag.
  # Steady-PC completion recovery: a partial cutover left the fleet with the
  # Hub and contract on the new colour but the steady pools stuck on the old.
  # The recovery re-homes exactly those pools (delete,create) and NOTHING else
  # is destructive -- no task-def replacement, no contract change. Admitted only
  # when every destructive action is such a re-home.
  # The 13 runtime-function steady pools (proof pm/pcr excluded -- they are
  # gone after the teardown). The recovery re-homes the COMPLETE set together;
  # a partial set is itself a hazard and a lone re-home (e.g. an unknown
  # function) must still fall through to the refusal.
  authority_steady_pc_completion_allowed=false
  if jq -e --argjson expected '[
      "module.control.aws_lambda_provisioned_concurrency_config.authority[\"layerv-nhp-sandbox-ca-ar-cell0\"]",
      "module.control.aws_lambda_provisioned_concurrency_config.authority[\"layerv-nhp-sandbox-ca-ar-cell1\"]",
      "module.control.aws_lambda_provisioned_concurrency_config.authority[\"layerv-nhp-sandbox-ca-ccr-cell0\"]",
      "module.control.aws_lambda_provisioned_concurrency_config.authority[\"layerv-nhp-sandbox-ca-ccr-cell1\"]",
      "module.control.aws_lambda_provisioned_concurrency_config.authority[\"layerv-nhp-sandbox-ca-cr-cell0\"]",
      "module.control.aws_lambda_provisioned_concurrency_config.authority[\"layerv-nhp-sandbox-ca-cr-cell1\"]",
      "module.control.aws_lambda_provisioned_concurrency_config.authority[\"layerv-nhp-sandbox-ca-creso-cell0\"]",
      "module.control.aws_lambda_provisioned_concurrency_config.authority[\"layerv-nhp-sandbox-ca-creso-cell1\"]",
      "module.control.aws_lambda_provisioned_concurrency_config.authority[\"layerv-nhp-sandbox-ca-ia\"]",
      "module.control.aws_lambda_provisioned_concurrency_config.authority[\"layerv-nhp-sandbox-ca-icr\"]",
      "module.control.aws_lambda_provisioned_concurrency_config.authority[\"layerv-nhp-sandbox-ca-iro-cell0\"]",
      "module.control.aws_lambda_provisioned_concurrency_config.authority[\"layerv-nhp-sandbox-ca-iro-cell1\"]",
      "module.control.aws_lambda_provisioned_concurrency_config.authority[\"layerv-nhp-sandbox-ca-ra\"]"
    ]' '
    ([
      (.resource_changes[]?, .resource_drift[]?)
      | select((.change.actions | index("delete")) and .change.actions != ["no-op"])
      | .address
    ] | sort) as $destroyed
    | $destroyed == ($expected | sort)
    # Delete-first ONLY: a selector flip re-homes the same 13 addresses
    # create-before-destroy, and this flag must stay false there so the two
    # recovery shapes cannot be misread as simultaneously live (review #3855).
    and ([
      (.resource_changes[]?, .resource_drift[]?)
      | select((.address | IN($expected[])) and .change.actions != ["delete", "create"])
    ] | length) == 0
  ' "$plan_json" >/dev/null; then
    authority_steady_pc_completion_allowed=true
  fi

  authority_selector_flip_allowed=false
  if jq -e '
    ([
      .resource_changes[]?
      | select(.address == "module.control.terraform_data.foundation_contract")
      | select((.change.before.input.authority_runtime_contract.selected_authority_color) as $b
          | (.change.after.input.authority_runtime_contract.selected_authority_color) as $a
          | ($b == "blue" or $b == "green") and ($a == "blue" or $a == "green") and $b != $a)
    ] | length == 1)
  ' "$plan_json" >/dev/null; then
    authority_selector_flip_allowed=true
  fi

  # Four exact replacement classes are intentional:
  #
  # * a tainted Connector Authority FUNCTION replan recreates a function left
  #   Failed by an earlier partial apply;
  # * the two attended-proof provisioned-concurrency configs may be tainted by
  #   a failed Lambda initialization. This shell fence admits only their exact
  #   addresses/action class; the Python convergence checker immediately after
  #   this gate proves the complete before/after envelope and image transition;
  # * the one-time Authority function-SG generation change removes the live
  #   predecessor's inline VPC-CIDR rule. Omitting that rule from configuration
  #   would leave it unmanaged, so the clean SG must replace it;
  # * the one-time Hub NLB source-fence migration MUST replace the NLB and its
  #   listener: AWS cannot add a security group to an NLB created without one.
  #   The NLB is create-before-destroy, but the listener must be
  #   destroy-before-create because AWS forbids one target group from serving
  #   listeners on two load balancers, so each address is admitted only in its
  #   exact action order; the Python convergence checker proves the new
  #   NLB/SG/worker graph.
  #
  # The function-SG generation change also has an exact DEPOSED continuation.
  # Its create_before_destroy replacement created the generation-2 group and
  # repointed every function, but the generation-1 delete could not complete
  # while published function versions still pinned that group to live Lambda
  # ENIs, so Terraform left the predecessor object deposed and pending delete.
  # That single reviewed object is admitted below; deposed deletes are NOT
  # admitted generally. Remove this branch once the object is reaped, together
  # with the deposed sites in the first-apply checker; KEEP the shared
  # legacy_authority_sg_before helper, which the replacement above still uses.
  #
  # Keep the SG admissions self-contained and exact here as well as in the
  # first-apply checker. Any retained/substituted CIDR or any other delete stays
  # destructive.
  # The Hub ECS task definition is immutable, so an image-only deploy presents
  # as a destructive replacement. Admit it here only after the authoritative
  # Python plan validator proves it is the sole non-noop change and pins every
  # non-image field plus the exact sandbox account/region/repository/digest.
  # This shell fence deliberately delegates the deep shape instead of growing a
  # second jq implementation that can drift from the complete Control checker.
  # The governed proof-rollout retirement. Dropping the selector colours ends the
  # rollout window, so the four standby warm pools it created are deleted and the
  # Hub's ca-pm alias target moves -- an immutable ECS task definition, hence a
  # replacement. Live state goes dark FIRST, through this gate flip; the code
  # removal follows separately. That ordering is what makes this admissible where
  # a code-first teardown is not (see AUTHORITY_PROOF_MUTATION_CONTROLS.md
  # "Rollback ordering" and PR #3809, closed for inverting it).
  #
  # Bounded two ways so nothing can borrow the lane: the plan's COMPLETE
  # destructive set must equal exactly these five addresses, and the contract
  # must prove the selector colours are going from set to null. A plan that
  # destroys anything else, or that is not the retirement, fails the equality
  # and falls through to the refusal below.
  authority_proof_rollout_retirement_allowed=false
  if jq -e '
    def destructive:
      .change.actions != ["no-op"]
      and .change.actions != ["read"]
      and (.change.actions | index("delete"));
    ([(.resource_changes[]?, .resource_drift[]?) | select(destructive) | .address]
      | unique) as $destroyed
    | (($destroyed == ["module.control.aws_ecs_task_definition.hub[0]"])
    or (
      # The selector flip: the Hub task definition replaces (its container env
      # carries the alias ARNs by colour) and the 13 steady pools re-home. The
      # subtraction still pins the COMPLETE destructive set.
      $authority_selector_flip_allowed
      and (
        ($destroyed - [
          (.resource_changes[]? | select(
            (.address | startswith("module.control.aws_lambda_provisioned_concurrency_config.authority[\""))
            and .change.actions == ["create", "delete"]
          ) | .address)
        ]) == ["module.control.aws_ecs_task_definition.hub[0]"]
      )
    )
    or (
      # The pointer-align + window-close shape: the four standby pools go, and
      # the steady provisioned concurrency re-homes from the old selected
      # colour to the new one (delete+create; qualifier is the identity). The
      # equality below still pins the COMPLETE destructive set, so anything
      # else riding along collapses the allowance.
      ($destroyed - [
        (.resource_changes[]? | select(
          (.address | startswith("module.control.aws_lambda_provisioned_concurrency_config.authority[\""))
          and .change.actions == ["delete", "create"]
        ) | .address)
      ]) == [
        "module.control.aws_lambda_provisioned_concurrency_config.authority_proof_standby[\"layerv-nhp-sandbox-ca-ia\"]",
        "module.control.aws_lambda_provisioned_concurrency_config.authority_proof_standby[\"layerv-nhp-sandbox-ca-icr\"]",
        "module.control.aws_lambda_provisioned_concurrency_config.authority_proof_standby[\"layerv-nhp-sandbox-ca-pm\"]",
        "module.control.aws_lambda_provisioned_concurrency_config.authority_proof_standby[\"layerv-nhp-sandbox-ca-ra\"]"
      ]
    )
    or ($destroyed == [
        "module.control.aws_ecs_task_definition.hub[0]",
        "module.control.aws_lambda_provisioned_concurrency_config.authority_proof_standby[\"layerv-nhp-sandbox-ca-ia\"]",
        "module.control.aws_lambda_provisioned_concurrency_config.authority_proof_standby[\"layerv-nhp-sandbox-ca-icr\"]",
        "module.control.aws_lambda_provisioned_concurrency_config.authority_proof_standby[\"layerv-nhp-sandbox-ca-pm\"]",
        "module.control.aws_lambda_provisioned_concurrency_config.authority_proof_standby[\"layerv-nhp-sandbox-ca-ra\"]"
      ]))
    and (
      [ .resource_changes[]?
        | select(.address == "module.control.terraform_data.foundation_contract")
        | select(.change.before.input.authority_proof_policy_selected_color != null)
        | select(
            .change.before.input.authority_proof_policy_selected_color
            != .change.after.input.authority_proof_policy_selected_color
            or .change.before.input.authority_proof_policy_prepared_color
              != .change.after.input.authority_proof_policy_prepared_color
          )
      ] | length
    ) == 1
  ' --argjson authority_selector_flip_allowed \
    "$authority_selector_flip_allowed" \
    "$plan_json" >/dev/null; then
    authority_proof_rollout_retirement_allowed=true
  fi


  hub_worker_image_update_allowed=false
  if jq -e '
    [
      (.resource_changes[]?, .resource_drift[]?)
      | select(
          .change.actions != ["no-op"]
          and .change.actions != ["read"]
        )
    ] | map(select(.change.actions | index("delete"))) as $destructive
    | ($destructive | length) == 1
      and $destructive[0].address
        == "module.control.aws_ecs_task_definition.hub[0]"
      and $destructive[0].change.actions == ["delete", "create"]
  ' "$plan_json" >/dev/null; then
    # A proof selector transition also replaces the task definition, because the
    # Hub's Authority alias ARNs move by colour. That is not an image update and
    # must not be judged as one; authority-proof-rollout-retirement owns it and
    # proves the container definitions differ only in that colour.
    if [[ "$authority_proof_rollout_retirement_allowed" != true \
       && "$authority_selector_flip_allowed" != true ]] \
      && ! python3 "$control_plan_checker" \
      hub-worker-image-update "$plan_json" >/dev/null; then
      echo "ERROR: Hub worker task-definition replacement failed its exact image-only contract" >&2
      exit 1
    fi
    hub_worker_image_update_allowed=true
  fi

  # A failed proof-policy prepare leaves only the inactive green IA/RA/ICR
  # concurrency allocations tainted. Admit their replacements only when the
  # entire plan is the exact reviewed recovery: four function updates, four
  # green-alias updates, those three 0 -> 2 replacements, and the missing PM
  # green allocation. The Python convergence checker independently proves the
  # full runtime and prior-state contract; this fence prevents any destructive
  # action from borrowing that recovery lane before it gets there.
  authority_proof_prepare_recovery_allowed=false
  if jq -e '
    def meaningful:
      .change.actions != ["no-op"]
      and .change.actions != ["read"];
    def change_key:
      "\(.address)|\(.type)|\(.mode // "null")|\(.deposed // "null")|\(.change.actions | join(","))";
    def exact_replacement($function_name; $before_count):
      .type == "aws_lambda_provisioned_concurrency_config"
      and .mode == "managed"
      and (.deposed // null) == null
      and .action_reason == "replace_because_tainted"
      and .change.actions == ["delete", "create"]
      and .change.before == {
        function_name: $function_name,
        id: ($function_name + ",green"),
        provisioned_concurrent_executions: $before_count,
        qualifier: "green",
        region: "us-east-2",
        skip_destroy: false,
        timeouts: null
      }
      and .change.after == {
        function_name: $function_name,
        provisioned_concurrent_executions: 2,
        qualifier: "green",
        region: "us-east-2",
        skip_destroy: false,
        timeouts: null
      }
      and .change.after_unknown == {id: true};
    def exact_pm_create:
      .type == "aws_lambda_provisioned_concurrency_config"
      and .mode == "managed"
      and (.deposed // null) == null
      and (.action_reason // null) == null
      and .change.actions == ["create"]
      and .change.before == null
      and .change.after == {
        function_name: "layerv-nhp-sandbox-ca-pm",
        provisioned_concurrent_executions: 1,
        qualifier: "green",
        region: "us-east-2",
        skip_destroy: false,
        timeouts: null
      }
      and .change.after_unknown == {id: true};

    (
      [
        .resource_changes[]?
        | select(meaningful)
        | change_key
      ] | sort
    ) == ([
      "module.control.aws_lambda_alias.authority[\"layerv-nhp-sandbox-ca-ia:green\"]|aws_lambda_alias|managed|null|update",
      "module.control.aws_lambda_alias.authority[\"layerv-nhp-sandbox-ca-icr:green\"]|aws_lambda_alias|managed|null|update",
      "module.control.aws_lambda_alias.authority[\"layerv-nhp-sandbox-ca-pm:green\"]|aws_lambda_alias|managed|null|update",
      "module.control.aws_lambda_alias.authority[\"layerv-nhp-sandbox-ca-ra:green\"]|aws_lambda_alias|managed|null|update",
      "module.control.aws_lambda_function.authority[\"layerv-nhp-sandbox-ca-ia\"]|aws_lambda_function|managed|null|update",
      "module.control.aws_lambda_function.authority[\"layerv-nhp-sandbox-ca-icr\"]|aws_lambda_function|managed|null|update",
      "module.control.aws_lambda_function.authority[\"layerv-nhp-sandbox-ca-pm\"]|aws_lambda_function|managed|null|update",
      "module.control.aws_lambda_function.authority[\"layerv-nhp-sandbox-ca-ra\"]|aws_lambda_function|managed|null|update",
      "module.control.aws_lambda_provisioned_concurrency_config.authority_proof_standby[\"layerv-nhp-sandbox-ca-ia\"]|aws_lambda_provisioned_concurrency_config|managed|null|delete,create",
      "module.control.aws_lambda_provisioned_concurrency_config.authority_proof_standby[\"layerv-nhp-sandbox-ca-icr\"]|aws_lambda_provisioned_concurrency_config|managed|null|delete,create",
      "module.control.aws_lambda_provisioned_concurrency_config.authority_proof_standby[\"layerv-nhp-sandbox-ca-pm\"]|aws_lambda_provisioned_concurrency_config|managed|null|create",
      "module.control.aws_lambda_provisioned_concurrency_config.authority_proof_standby[\"layerv-nhp-sandbox-ca-ra\"]|aws_lambda_provisioned_concurrency_config|managed|null|delete,create"
    ] | sort)
    and (
      [
        .resource_drift[]?
        | select(.change.actions | index("delete"))
      ] | length
    ) == 0
    and (
      [
        .resource_changes[]?
        | select(
            (
              .address
                == "module.control.aws_lambda_provisioned_concurrency_config.authority_proof_standby[\"layerv-nhp-sandbox-ca-ia\"]"
              and exact_replacement(
                "layerv-nhp-sandbox-ca-ia";
                .change.before.provisioned_concurrent_executions
              )
            )
            or (
              .address
                == "module.control.aws_lambda_provisioned_concurrency_config.authority_proof_standby[\"layerv-nhp-sandbox-ca-icr\"]"
              and exact_replacement(
                "layerv-nhp-sandbox-ca-icr";
                .change.before.provisioned_concurrent_executions
              )
            )
            or (
              .address
                == "module.control.aws_lambda_provisioned_concurrency_config.authority_proof_standby[\"layerv-nhp-sandbox-ca-ra\"]"
              and exact_replacement(
                "layerv-nhp-sandbox-ca-ra";
                .change.before.provisioned_concurrent_executions
              )
            )
          )
      ] | length
    ) == 3
    and (
      (
        [
          .resource_changes[]?
          | select(
              .address
                | startswith(
                    "module.control.aws_lambda_provisioned_concurrency_config.authority_proof_standby["
                  )
            )
          | select(.change.actions == ["delete", "create"])
          | .change.before.provisioned_concurrent_executions
        ] | unique
      ) as $before_counts
      | (
        ($before_counts == [0] or $before_counts == [2])
        and (
          [
            .resource_changes[]?
            | select(
                .address
                  == "module.control.aws_lambda_provisioned_concurrency_config.authority_proof_standby[\"layerv-nhp-sandbox-ca-pm\"]"
              )
            | select(exact_pm_create)
          ] | length
        ) == 1
      )
    )
  ' "$plan_json" >/dev/null; then
    authority_proof_prepare_recovery_allowed=true
  fi

  # The strict authority-proof-disable teardown: every destructive action must
  # belong to the attended-proof pair (ca-pm / ca-pcr), and the foundation
  # contract must drop the consumer-staging key in the same plan. Any delete
  # outside the pair defeats the flag and falls to the refusal below.
  authority_proof_disable_allowed=false
  if jq -e '
    ([
      (.resource_changes[]?, .resource_drift[]?)
      | select(.change.actions | index("delete"))
      | .address
    ] | length > 0)
    and ([
      (.resource_changes[]?, .resource_drift[]?)
      | select(.change.actions | index("delete"))
      | .address
      | select(test("layerv-nhp-sandbox-ca-(pm|pcr)") | not)
    ] | length == 0)
    and ([
      .resource_changes[]?
      | select(.address == "module.control.terraform_data.foundation_contract")
      # The definitional witness that the attended-proof pair is leaving: both
      # its functions present in the contract graph before, both absent after.
      # (Keying on the staging flag was wrong -- step 1 retires that key, so a
      # sequenced step-2 plan never shows it dropping.)
      | select(.change.before.input.authority_runtime_contract.functions
          | has("layerv-nhp-sandbox-ca-pm") and has("layerv-nhp-sandbox-ca-pcr"))
      | select(.change.after.input.authority_runtime_contract.functions
          | (has("layerv-nhp-sandbox-ca-pm") or has("layerv-nhp-sandbox-ca-pcr")) | not)
    ] | length == 1)
  ' "$plan_json" >/dev/null; then
    authority_proof_disable_allowed=true
  fi

  destructive_resources="$(jq -r \
    --argjson hub_worker_image_update_allowed \
      "$hub_worker_image_update_allowed" \
    --argjson authority_proof_prepare_recovery_allowed \
      "$authority_proof_prepare_recovery_allowed" \
    --argjson authority_proof_rollout_retirement_allowed \
      "$authority_proof_rollout_retirement_allowed" \
    --argjson authority_proof_disable_allowed \
      "$authority_proof_disable_allowed" \
    --argjson authority_selector_flip_allowed \
      "$authority_selector_flip_allowed" \
    --argjson authority_steady_pc_completion_allowed \
      "$authority_steady_pc_completion_allowed" '
    # The exact generation-1 function-SG before-state, shared by the replacement
    # and its deposed continuation so both admissions cannot drift apart. Kept
    # field-for-field in lockstep with _is_exact_legacy_authority_sg_before in
    # the first-apply checker so the two guards agree across languages too.
    def legacy_authority_sg_before:
      .name_prefix == "layerv-nhp-sandbox-control-ca-fn-"
      and .description == (
        "Connector Authority function ENIs; egress to Control dependency "
        + "endpoints only"
      )
      and (.vpc_id | test("^vpc-[0-9a-f]+$"))
      and ((.ingress // []) == [])
      and (
        [.egress[]? | select(
          .description == "HTTPS to Control interface endpoints (KMS) in-VPC"
          and .cidr_blocks == ["10.102.0.0/16"]
          and .ipv6_cidr_blocks == []
          and .prefix_list_ids == []
          and .security_groups == []
          and .self == false
          and .protocol == "tcp"
          and .from_port == 443
          and .to_port == 443
        )] | length
      ) == 1
      and (
        [.egress[]? | select(
          .description == "HTTPS to the DynamoDB gateway endpoint prefix list"
          and .cidr_blocks == []
          and .ipv6_cidr_blocks == []
          and (.prefix_list_ids | length) == 1
          and (.prefix_list_ids[0] | test("^pl-[0-9a-f]+$"))
          and .security_groups == []
          and .self == false
          and .protocol == "tcp"
          and .from_port == 443
          and .to_port == 443
        )] | length
      ) == 1
      and (.egress | length) == 2;

    (.resource_changes[]?, .resource_drift[]?)
    | select(.change.actions | index("delete"))
    | select(
        ((
          $authority_proof_disable_allowed
          and (.address | test("layerv-nhp-sandbox-ca-(pm|pcr)"))
        ) or (
          (.address | startswith("module.control.aws_lambda_function.authority["))
          and (
            (.change.actions == ["delete", "create"])
            or (.change.actions == ["create", "delete"])
          )
        ) or (
          (
            .address
              == "module.control.aws_lambda_provisioned_concurrency_config.authority[\"layerv-nhp-sandbox-ca-pm\"]"
            or .address
              == "module.control.aws_lambda_provisioned_concurrency_config.authority[\"layerv-nhp-sandbox-ca-pcr\"]"
            or (
              $authority_proof_rollout_retirement_allowed
              and (.address | startswith("module.control.aws_lambda_provisioned_concurrency_config.authority[\""))
            )
            or (
              # The selector flip re-homes every steady pool to the new colour.
              $authority_selector_flip_allowed
              and (.address | startswith("module.control.aws_lambda_provisioned_concurrency_config.authority[\""))
            )
            or (
              # The completion recovery re-homes the stuck steady pools.
              $authority_steady_pc_completion_allowed
              and (.address | startswith("module.control.aws_lambda_provisioned_concurrency_config.authority[\""))
            )
          )
          and .type == "aws_lambda_provisioned_concurrency_config"
          and .mode == "managed"
          and (.deposed // null) == null
          and (
            .change.actions == ["delete", "create"]
            or (
              # The selector flip re-homes create-before-destroy: the steady
              # reserved envelope is 2x provisioned, so the new colour warms
              # to READY while the old pool is still live, and the fleet
              # never serves an unwarmed window mid-switch.
              $authority_selector_flip_allowed
              and .change.actions == ["create", "delete"]
            )
            or (
              # The historical completion recovery (#3854) re-homed the stuck
              # pools delete-first, freeing the reserved budget the old colour
              # still held under the reserved == provisioned algebra.
              $authority_steady_pc_completion_allowed
              and .change.actions == ["delete", "create"]
            )
          )
        ) or (
          $authority_proof_prepare_recovery_allowed
          and (
            .address
              == "module.control.aws_lambda_provisioned_concurrency_config.authority_proof_standby[\"layerv-nhp-sandbox-ca-ia\"]"
            or .address
              == "module.control.aws_lambda_provisioned_concurrency_config.authority_proof_standby[\"layerv-nhp-sandbox-ca-icr\"]"
            or .address
              == "module.control.aws_lambda_provisioned_concurrency_config.authority_proof_standby[\"layerv-nhp-sandbox-ca-ra\"]"
          )
          and .type == "aws_lambda_provisioned_concurrency_config"
          and .mode == "managed"
          and (.deposed // null) == null
          and .change.actions == ["delete", "create"]
        ) or (
          $authority_proof_rollout_retirement_allowed
          and (.address | startswith("module.control.aws_lambda_provisioned_concurrency_config.authority_proof_standby["))
          and .type == "aws_lambda_provisioned_concurrency_config"
          and .mode == "managed"
          and (.deposed // null) == null
          and .change.actions == ["delete"]
        ) or (
          ($authority_proof_rollout_retirement_allowed or $authority_selector_flip_allowed)
          and .address == "module.control.aws_ecs_task_definition.hub[0]"
          and .type == "aws_ecs_task_definition"
          and .mode == "managed"
          and (.deposed // null) == null
          and .change.actions == ["delete", "create"]
        ) or (
          .address == "module.control.aws_security_group.authority_lambda[0]"
          and .type == "aws_security_group"
          and (.deposed // null) == null
          and .change.actions == ["create", "delete"]
          and .change.replace_paths == [["name_prefix"]]
          and (.change.before | legacy_authority_sg_before)
          and .change.after.name_prefix == "layerv-nhp-sandbox-control-ca-fn-v2-"
          and .change.before.vpc_id == .change.after.vpc_id
          and ((.change.after.ingress // []) == [])
          and ((.change.after.egress // []) == [])
          and .change.after_unknown.ingress == true
          and .change.after_unknown.egress == true
        ) or (
          .address == "module.control.aws_security_group.authority_lambda[0]"
          and .type == "aws_security_group"
          and .mode == "managed"
          and .deposed == "4a2844f4"
          and .change.actions == ["delete"]
          and .change.after == null
          and .change.before.id == "sg-0584cd75da80a2c7d"
          and (.change.before | legacy_authority_sg_before)
        ) or (
          # The one reviewed removal of the detached legacy Connector OTP Redis
          # user (NHP #3362): a net delete, admitted only at its exact reviewed
          # before-state. Kept field-for-field in lockstep with
          # _is_exact_legacy_otp_user_delete in the first-apply checker, which
          # separately refuses to combine it with any other Control change.
          # Remove this branch once the delete is applied, together with the
          # LEGACY_OTP_REDIS_USER_* sites in that checker.
          .address == "module.control.aws_elasticache_user.otp_authority"
          and .type == "aws_elasticache_user"
          and .mode == "managed"
          and (.deposed // null) == null
          and .change.actions == ["delete"]
          and .change.after == null
          and .change.before.user_id == "layerv-nhp-sandbox-control-otp-auth"
          and .change.before.user_name == "layerv-nhp-sandbox-control-otp-auth"
          and .change.before.access_string == (
            "on ~connector:* -@all +@connection +@read +@write +@scripting"
          )
          and .change.before.engine == "redis"
          and ((.change.before.user_group_ids // []) == [])
          and ((.change.before.authentication_mode | length) == 1)
          and .change.before.authentication_mode[0].type == "iam"
          and .change.before.authentication_mode[0].password_count == 0
          and ((.change.before.authentication_mode[0].passwords // []) == [])
        ) or (
          # The one reviewed removal of the Hub proof-runner source fence
          # (qurl-go ADR 0001, ledger 2026-08-03-open-sandbox-udp-edges): sandbox
          # opens to developers inside and outside the company, so this exact /32
          # ingress rule is replaced by the 0.0.0.0/0 rule, whose create is not
          # destructive and needs no allowance. Admitted only as a net delete of
          # exactly this address on UDP 443. Remove this branch once applied --
          # the rule no longer exists afterwards, so it becomes inert.
          .address
            == "module.control.aws_vpc_security_group_ingress_rule.hub_nlb_udp[\"3.141.109.76/32\"]"
          and .type == "aws_vpc_security_group_ingress_rule"
          and .mode == "managed"
          and (.deposed // null) == null
          and .change.actions == ["delete"]
          and .change.after == null
          and .change.before.cidr_ipv4 == "3.141.109.76/32"
          and .change.before.ip_protocol == "udp"
          and .change.before.from_port == 443
          and .change.before.to_port == 443
        ) or (
          .address == "module.control.aws_lb.hub[0]"
          and .change.actions == ["create", "delete"]
        ) or (
          .address == "module.control.aws_lb_listener.hub[0]"
          and .change.actions == ["delete", "create"]
        ) or (
          $hub_worker_image_update_allowed
          and .address
            == "module.control.aws_ecs_task_definition.hub[0]"
          and .type == "aws_ecs_task_definition"
          and .mode == "managed"
          and (.deposed // null) == null
          and .change.actions == ["delete", "create"]
        )) | not
      )
    | "\(.address) [\(.change.actions | join(","))]"
  ' "$plan_json")"
  if [[ -n "$destructive_resources" ]]; then
    echo "ERROR: dark Connector Authority plan contains destructive actions:" >&2
    echo "$destructive_resources" >&2
    exit 1
  fi

  for resource_type in "${forbidden_resource_types[@]}"; do
    addresses="$(jq -r --arg resource_type "$resource_type" '
      (.resource_changes[]?, .resource_drift[]?)
      | select(.type == $resource_type and .change.after != null)
      | .address
    ' "$plan_json")"
    if [[ -n "$addresses" ]]; then
      echo "ERROR: dark Connector Authority plan contains ${resource_type}:" >&2
      echo "$addresses" >&2
      exit 1
    fi
  done

  # The AWS provider marks after_unknown.route=true for a clean route table at
  # CREATE, so a freshly-created edge table has after.route=null and is not
  # flagged. Once the edge is live, a no-op refresh reports the KNOWN route list
  # populated by the standalone aws_route resource -- that reflection is not an
  # inline declaration, so skip unchanged (no-op/read) tables. A real inline
  # route entering on a create/update/replace still surfaces a known non-empty
  # route list and is rejected; and the unconditional lexical source fence above
  # owns authored inline routes on every run regardless of plan action.
  inline_route_tables="$(jq -r '
    (.resource_changes[]?, .resource_drift[]?)
    | select(.type == "aws_route_table" and .change.after != null)
    | select(.change.actions != ["no-op"] and .change.actions != ["read"])
    | select(((.change.after.route? // []) | length) > 0)
    | .address
  ' "$plan_json")"
  if [[ -n "$inline_route_tables" ]]; then
    echo "ERROR: dark Connector Authority plan contains inline route declarations:" >&2
    echo "$inline_route_tables" >&2
    exit 1
  fi
fi

# Keep this deliberately lexical rather than value-only: URLs hidden in lists,
# maps, templates, or heredocs are still HTTP dependencies. Terraform comments
# under these roots must cite docs without spelling an HTTP URL so the security
# fence cannot gain parser-shaped blind spots.
status=0
scan_tf_regex 'https?://' || status=$?
case "$status" in
  0)
    echo "ERROR: Connector Authority foundation must not contain HTTP URLs; cite a repository issue number or relative documentation path instead" >&2
    exit 1
    ;;
  1) ;;
  *) exit "$status" ;;
esac

for environment in sandbox prod; do
  backend="${repo_root}/terraform/control/environments/${environment}/backend.tf"
  expected="nhp/${environment}/control/terraform.tfstate"
  if [[ ! -r "$backend" ]]; then
    echo "ERROR: ${environment} control backend is not readable: ${backend}" >&2
    exit 1
  fi

  backend_key=""
  backend_key_count=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ ^[[:space:]]*key[[:space:]]*=[[:space:]]*\"([^\"]+)\"[[:space:]]*$ ]]; then
      backend_key="${BASH_REMATCH[1]}"
      backend_key_count=$((backend_key_count + 1))
    fi
  done <"$backend"

  if [[ "$backend_key_count" -ne 1 || "$backend_key" != "$expected" ]]; then
    echo "ERROR: ${environment} control backend must use ${expected}" >&2
    exit 1
  fi
done

sandbox_wrapper="${control_dir}/environments/sandbox/main.tf"
prod_wrapper="${control_dir}/environments/prod/main.tf"
if [[ ! -r "$sandbox_wrapper" || ! -r "$prod_wrapper" ]]; then
  echo "ERROR: Connector Authority environment module wrappers must both be readable" >&2
  exit 1
fi
if ! cmp -s "$sandbox_wrapper" "$prod_wrapper"; then
  echo "ERROR: Connector Authority sandbox and prod module wrappers must remain byte-identical" >&2
  exit 1
fi

# Both roots now hard-lock materialization TRUE: removing a live catalog row is
# a drain/migrate procedure, not an input flip. Production reached that polarity
# once it gained the "separately reviewed production cell inventory" this guard
# previously waited on — the review-pinned cell0 row in
# environments/prod/variables.tf, whose endpoint identity comes from live
# production readback. Either way exactly one default and one condition must be
# present and agree on the environment's pinned polarity; a mismatch fails
# closed.
require_catalog_materialization_latch() {
  local variables_file="$1"
  local environment="$2"
  local expected="$3"
  local variable_block

  if ! variable_block="$(
    awk -v name='provisioned_cell_catalog_materialization_enabled' '
      $0 ~ "^[[:space:]]*variable[[:space:]]+\"" name "\"[[:space:]]*\\{[[:space:]]*$" {
        if (seen != 0 || capture != 0) {
          exit 2
        }
        seen = 1
        capture = 1
      }
      capture != 0 {
        print
      }
      capture != 0 && $0 ~ "^}[[:space:]]*$" {
        capture = 0
      }
      END {
        if (seen != 1 || capture != 0) {
          exit 2
        }
      }
    ' "$variables_file"
  )"; then
    echo "ERROR: ${environment} Control variables must declare exactly one closed provisioned-cell materialization gate" >&2
    exit 1
  fi

  # A true latch asserts the variable directly; a false latch negates it.
  local negation=''
  if [[ "$expected" == 'false' ]]; then
    negation='!'
  fi

  local default_count
  local pinned_default_count
  local condition_count
  local pinned_condition_count
  default_count="$(grep -E -c \
    '^[[:space:]]*default[[:space:]]*=' <<<"$variable_block" || true)"
  pinned_default_count="$(grep -E -c \
    "^[[:space:]]*default[[:space:]]*=[[:space:]]*${expected}[[:space:]]*\$" \
    <<<"$variable_block" || true)"
  condition_count="$(grep -E -c \
    '^[[:space:]]*condition[[:space:]]*=' <<<"$variable_block" || true)"
  pinned_condition_count="$(grep -E -c \
    "^[[:space:]]*condition[[:space:]]*=[[:space:]]*${negation}var\.provisioned_cell_catalog_materialization_enabled[[:space:]]*\$" \
    <<<"$variable_block" || true)"

  if [[ "$default_count" -ne 1 || "$pinned_default_count" -ne 1 ||
        "$condition_count" -ne 1 || "$pinned_condition_count" -ne 1 ]]; then
    echo "ERROR: ${environment} Control variables must hard-lock provisioned-cell catalog materialization ${expected}" >&2
    exit 1
  fi
}

# Both roots compose the same child-module interface. Sandbox may open the
# latch only through the exact-main generated tfvars; production locks both
# inputs dark at the variable boundary.
for environment in sandbox prod; do
  environment_root="${control_dir}/environments/${environment}"
  wrapper_count="$(grep -E -c \
    '^[[:space:]]*authority_runtime_contract_evidence_verified[[:space:]]*=[[:space:]]*var\.authority_runtime_contract_evidence_verified[[:space:]]*$' \
    "${environment_root}/main.tf" || true)"
  if [[ "$wrapper_count" -ne 1 ]]; then
    echo "ERROR: ${environment} Control wrapper must pass the internal evidence latch exactly once from its root variable" >&2
    exit 1
  fi
  catalog_wrapper_count="$(grep -E -c \
    '^[[:space:]]*provisioned_cell_catalog_materialization_enabled[[:space:]]*=[[:space:]]*var\.provisioned_cell_catalog_materialization_enabled[[:space:]]*$' \
    "${environment_root}/main.tf" || true)"
  if [[ "$catalog_wrapper_count" -ne 1 ]]; then
    echo "ERROR: ${environment} Control wrapper must pass the provisioned-cell materialization gate exactly once from its root variable" >&2
    exit 1
  fi
  # Sandbox owns the two reviewed rows after the restoration; production owns
  # the single review-pinned cell0 row. Both catalogs are live, so both latch
  # materialization on.
  expected_catalog_latch='true'
  require_catalog_materialization_latch \
    "${environment_root}/variables.tf" "$environment" "$expected_catalog_latch"
  # Reject any COMMITTED tfvars in the Control root (a committed *.auto.tfvars /
  # *.auto.tfvars.json would be terraform-auto-loaded and could open the latch),
  # but EXCLUDE the sanctioned exact-main runtime output
  # `authority-runtime.generated.tfvars.json`: the workflow's byte-verifying
  # generator writes it into this root at plan time (it is git-ignored and
  # atomically overwritten every run), so its presence on disk here is expected
  # and is the only supported way to open the sandbox latch (see the comment
  # above). Matching it was a regression from adding the `.json` variants.
  if find "$environment_root" -maxdepth 1 -type f \
    \( -name '*.tfvars' -o -name '*.tfvars.json' \
       -o -name '*.auto.tfvars' -o -name '*.auto.tfvars.json' \) \
    ! -name 'authority-runtime.generated.tfvars.json' -print -quit \
    | grep -q .; then
    echo "ERROR: ${environment} Control root must not commit runtime tfvars" >&2
    exit 1
  fi
done

prod_variables="${control_dir}/environments/prod/variables.tf"
# Production Control no longer hard-locks these variables closed — production
# ships the Authority runtime, so the root must be able to accept a real
# contract. The fail-closed property that matters is unchanged and is now
# asserted directly: every gate that would create or arm runtime state must
# DEFAULT closed, so a plan that does not explicitly supply it through the
# reviewed production dispatch can never assert one. Checking the defaults is
# strictly stronger than the error-string grep it replaces, which only proved a
# validation block was present.
for gate in \
  'authority_runtime_contract:null' \
  'authority_runtime_contract_evidence_verified:false' \
  'authority_runtime_functions_enabled:false' \
  'hub_edge_enabled:false' \
  'hub_worker_enabled:false'; do
  gate_name="${gate%%:*}"
  gate_default="${gate#*:}"
  # Match the block whether the variable opens inline (`variable "x" { ... }`)
  # or across lines, and accept any interior whitespace: `terraform fmt` aligns
  # `default` into a column, so a fixed-string compare would bind this contract
  # to one particular alignment.
  block="$(
    awk -v name="$gate_name" '
      $0 ~ "^[[:space:]]*variable[[:space:]]+\"" name "\"[[:space:]]*\\{" { inside = 1 }
      inside { print }
      inside && $0 ~ "^\\}[[:space:]]*$" { exit }
      inside && $0 ~ "\\}[[:space:]]*$" && $0 ~ "\\{" { exit }
    ' "$prod_variables"
  )"
  if [[ -z "$block" ]]; then
    echo "ERROR: production Control variables must declare ${gate_name}" >&2
    exit 1
  fi
  if ! printf '%s\n' "$block" |
    grep -Eq "^[[:space:]]*default[[:space:]]*=[[:space:]]*${gate_default}[[:space:]]*\$|[[:space:]]default[[:space:]]*=[[:space:]]*${gate_default}[[:space:]]*\\}"; then
    echo "ERROR: production Control gate ${gate_name} must fail closed with 'default = ${gate_default}'; a reviewed production dispatch supplies the open value, never the committed default" >&2
    exit 1
  fi
done

# Which image is deployed is chosen by the contract's declared source, and the
# digest is deliberately NOT compared against the reviewed basis inside
# authority_contract_identity_valid. That comparison is what let qurl-service
# CI invalidate every Control plan the moment it published, and pinning the
# digest to escape it stopped sandbox from running new builds at all. These
# checks pin the replacement shape so neither failure can be reintroduced by
# edit.
ssm_publish_read_count="$(
  { grep -R -h -E --include='*.tf' \
      'data[[:space:]]+"aws_ssm_parameter"[[:space:]]+"authority_image_publish"' \
      "$module_dir" || true; } | wc -l | tr -d ' '
)"
ecr_read_count="$(
  { grep -R -h -E --include='*.tf' \
      'data[[:space:]]+"aws_ecr_image"[[:space:]]+"authority_runtime"' \
      "$module_dir" || true; } | wc -l | tr -d ' '
)"
if [[ "$ssm_publish_read_count" -ne 1 ]]; then
  echo "ERROR: Connector Authority runtime must declare exactly one publish-parameter read" >&2
  exit 1
fi
if [[ "$ecr_read_count" -ne 1 ]]; then
  echo "ERROR: Connector Authority runtime must declare exactly one conditional ECR digest read" >&2
  exit 1
fi
# The publish read must be gated on the declared source, so a pinned contract
# performs no publisher-owned read at all.
if ! grep -Fq 'count = local.authority_runtime_contract_enabled && local.authority_image_tracks_publish ? 1 : 0' \
  "${module_dir}/ecr.tf"; then
  echo "ERROR: Connector Authority publish-parameter read must be gated on the contract AND the publish_parameter source" >&2
  exit 1
fi
# It must read the known local, never the managed parameter's attribute. The
# resource reference adds a dependency edge that defers the read to apply, and a
# digest unknown at plan cannot be checked at plan -- the seeded UNPUBLISHED
# value would become an apply failure instead of a refused plan.
if ! grep -Fq 'name = local.authority_image_digest_parameter_name' \
  "${module_dir}/ecr.tf"; then
  echo "ERROR: Connector Authority publish-parameter read must resolve the known parameter-name local so the digest is checkable at plan" >&2
  exit 1
fi
# The ECR read must resolve whatever the declared source produced, which is what
# proves the deployed digest refers to a real published image under either mode.
if ! grep -Fq 'image_digest    = local.authority_runtime_image_digest' \
  "${module_dir}/ecr.tf"; then
  echo "ERROR: Connector Authority ECR read must resolve the source-selected digest" >&2
  exit 1
fi
# publish_parameter hands an environment's deployed image to qurl-service CI
# without review here. Prod may not make that trade. The rule cannot be proved
# by a module test -- a prod-flavoured plan fails identity for a dozen unrelated
# reasons, so an expect_failures case there passes with the rule deleted -- so
# it is pinned statically instead: the local must exist AND be consumed by the
# identity check. Defining it and forgetting to use it would be silent.
if ! grep -REq --include='*.tf' \
  'authority_image_source_permitted[[:space:]]*=[[:space:]]*!local\.authority_image_tracks_publish[[:space:]]*\|\|[[:space:]]*var\.environment[[:space:]]*!=[[:space:]]*"prod"' \
  "$module_dir"; then
  echo "ERROR: Connector Authority must define authority_image_source_permitted as the non-prod publish rule" >&2
  exit 1
fi
if ! grep -REq --include='*.tf' \
  '^[[:space:]]*local\.authority_image_source_permitted[[:space:]]*&&' \
  "$module_dir"; then
  echo "ERROR: authority_image_source_permitted must be consumed by the contract identity check" >&2
  exit 1
fi
# The reviewed basis must never be compared against the live publish parameter
# again; that coupling is the original defect.
# The defect shape is "reviewed basis compared against the published digest",
# and it can now be spelled through the intermediate locals as well as through
# the original names. Match all three spellings; the identity check and the
# Python checker are the real backstop, but a tripwire that only catches the
# historical wording is not a tripwire.
if grep -REq --include='*.tf' \
  'authority_contract_global\.authority_image_digest[[:space:]]*==|==[[:space:]]*.*aws_ssm_parameter\.authority_image_publish|authority_image_basis_digest[[:space:]]*==[[:space:]]*local\.authority_runtime_image_digest|authority_runtime_image_digest[[:space:]]*==[[:space:]]*local\.authority_image_basis_digest' \
  "$module_dir"; then
  echo "ERROR: the reviewed basis digest must not be compared against the publish parameter; that coupling let an unrelated repository invalidate every Control plan" >&2
  exit 1
fi
if ! grep -Fq 'count = local.authority_runtime_contract_enabled ? 1 : 0' \
  "${module_dir}/ecr.tf"; then
  echo "ERROR: Connector Authority runtime ECR read must remain conditional on the verified contract" >&2
  exit 1
fi

sandbox_outputs="${control_dir}/environments/sandbox/outputs.tf"
prod_outputs="${control_dir}/environments/prod/outputs.tf"
if [[ ! -r "$sandbox_outputs" || ! -r "$prod_outputs" ]]; then
  echo "ERROR: Connector Authority environment output wrappers must both be readable" >&2
  exit 1
fi
if ! cmp -s "$sandbox_outputs" "$prod_outputs"; then
  echo "ERROR: Connector Authority sandbox and prod output wrappers must remain byte-identical" >&2
  exit 1
fi

echo "Connector Authority foundation contract is clean"
