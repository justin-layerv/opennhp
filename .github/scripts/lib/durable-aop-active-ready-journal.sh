#!/usr/bin/env bash
# Shared closed-schema validation for the fixed sandbox ACTIVE/READY audit
# subjournal. The caller provides canonical_digest() and target_fence_digest()
# (or aliases fence_digest to it) before invoking these functions.

active_ready_owner_digest() {
	local owner=$1
	{
		for field in cell_id ac_id public_key lifecycle_version work_version task_count pending_count phase boot_id \
			flush_generation target_version target_authority_version target_counted_active_slot activated_control_version \
			ready_control_version target_created_at_ms target_prepared_at_ms target_updated_at_ms aak_enqueued_at_ms \
			aak_transaction_id created_at_ms updated_at_ms retired_at_ms; do
			printf '\0%s' "$(jq -r ".${field}" <<<"$owner")"
		done
	} | sha256sum | awk '{print $1}'
}

active_ready_target_session_pk() {
	local fence=$1 digest
	digest=$(printf 'v1\0%s\0%s\0%s\0%s\0%s' \
		"$(jq -r .control_cell_id <<<"$fence")" "$(jq -r .ac_id <<<"$fence")" \
		"$(jq -r .public_key <<<"$fence")" "$(jq -r .boot_id <<<"$fence")" \
		"$(jq -r .flush_generation <<<"$fence")" | sha256sum | awk '{print $1}')
	printf 'TARGET#%s\n' "$digest"
}

validate_active_ready_plan() {
	local plan=$1 count index target fence owner
	jq -e '
		type == "object" and (keys | sort) == ["ac_id","control_cell_id","region","schema","table","targets"] and
		.schema == "layerv.durable-aop-active-ready-predecessor-plan.v1" and
		.table == "layerv-nhp-sandbox-cell0-nhp-session-control" and .region == "us-east-2" and
		.ac_id == "layerv-ac-tf" and .control_cell_id == "cell0" and
		(.targets | type == "array" and length == 3) and
		[.targets[].id] == ["active-ready-predecessor-1","active-ready-predecessor-2","active-ready-predecessor-3"] and
		([.targets[].fence.public_key] | length == (unique | length)) and
		([.targets[] | (keys | sort) == ["fence","fence_sha256","id","owner","owner_sha256"] and
			(.fence_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
			(.owner_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
			(.fence | type == "object" and (keys | sort) ==
				["aak_enqueued_at_ms","aak_transaction_id","ac_id","activated_control_version","authority_version",
				 "boot_id","control_cell_id","counted_active_slot","created_at_ms","flush_generation","prepared_at_ms",
				 "public_key","ready_control_version","version"] and
				.ac_id == "layerv-ac-tf" and .control_cell_id == "cell0" and .counted_active_slot == true and
				.authority_version == "7" and .activated_control_version == "250" and .ready_control_version == "250" and
				([.flush_generation,.version,.aak_enqueued_at_ms,.aak_transaction_id,.created_at_ms,.prepared_at_ms] |
					all(type == "string" and test("^[1-9][0-9]*$"))) and
				([.public_key,.boot_id] | all(type == "string" and length > 0))) and
			(.owner | type == "object" and (keys | sort) ==
				["aak_enqueued_at_ms","aak_transaction_id","ac_id","activated_control_version","boot_id","cell_id",
				 "created_at_ms","flush_generation","lifecycle_version","pending_count","phase","public_key",
				 "ready_control_version","retired_at_ms","target_authority_version","target_counted_active_slot",
				 "target_created_at_ms","target_prepared_at_ms","target_updated_at_ms","target_version","task_count",
				 "updated_at_ms","work_version"] and
				.cell_id == "cell0" and .ac_id == "layerv-ac-tf" and .phase == "READY" and
				.task_count == "0" and .pending_count == "0" and .retired_at_ms == "0" and
				.target_counted_active_slot == true and .target_authority_version == "7" and
				.activated_control_version == "250" and .ready_control_version == "250" and
				([.lifecycle_version,.work_version,.flush_generation,.target_version,.target_created_at_ms,
				  .target_prepared_at_ms,.target_updated_at_ms,.aak_enqueued_at_ms,.aak_transaction_id,.created_at_ms,
				  .updated_at_ms] | all(type == "string" and test("^[1-9][0-9]*$"))))] | all)
	' >/dev/null <<<"$plan" || return 1
	count=$(jq -r '.targets | length' <<<"$plan")
	for ((index=0; index<count; index++)); do
		target=$(jq -c --argjson i "$index" '.targets[$i]' <<<"$plan")
		fence=$(jq -cS .fence <<<"$target")
		owner=$(jq -cS .owner <<<"$target")
		[[ "$(target_fence_digest "$fence")" == "$(jq -r .fence_sha256 <<<"$target")" &&
		   "$(active_ready_owner_digest "$owner")" == "$(jq -r .owner_sha256 <<<"$target")" ]] || return 1
		jq -e --argjson fence "$fence" '
			.public_key == $fence.public_key and .boot_id == $fence.boot_id and
			.flush_generation == $fence.flush_generation and .target_version == $fence.version and
			.target_authority_version == $fence.authority_version and
			.target_counted_active_slot == $fence.counted_active_slot and
			.activated_control_version == $fence.activated_control_version and
			.ready_control_version == $fence.ready_control_version and
			.target_created_at_ms == $fence.created_at_ms and .target_prepared_at_ms == $fence.prepared_at_ms and
			.aak_enqueued_at_ms == $fence.aak_enqueued_at_ms and .aak_transaction_id == $fence.aak_transaction_id
		' >/dev/null <<<"$owner" || return 1
	done
}

active_ready_decommission_owner() {
	jq -cS '.phase="DECOMMISSIONING" | .lifecycle_version=((.lifecycle_version|tonumber)+1|tostring)' <<<"$1"
}

validate_active_ready_target_receipts() {
	local row=$1 planned=$2 directory_digest=$3 status fence owner decommission latch quiescence receipt
	local expected_version expected_authority expected_session
	status=$(jq -r .status <<<"$row")
	fence=$(jq -cS .fence <<<"$planned")
	owner=$(jq -cS .owner <<<"$planned")
	decommission=$(active_ready_decommission_owner "$owner")
	jq -e --arg id "$(jq -r .id <<<"$planned")" --arg digest "$(jq -r .fence_sha256 <<<"$planned")" '
		.id == $id and .fence_sha256 == $digest
	' >/dev/null <<<"$row" || return 1
	case "$status" in
		pending) [[ "$(jq -c 'keys|sort' <<<"$row")" == '["fence_sha256","id","status"]' ]]; return ;;
		latched) [[ "$(jq -c 'keys|sort' <<<"$row")" == '["fence_sha256","id","latch_receipt","status"]' ]] || return 1 ;;
		quiescent) [[ "$(jq -c 'keys|sort' <<<"$row")" == '["fence_sha256","id","latch_receipt","quiescence_receipt","status"]' ]] || return 1 ;;
		retired) [[ "$(jq -c 'keys|sort' <<<"$row")" == '["fence_sha256","id","latch_receipt","quiescence_receipt","receipt","status"]' ]] || return 1 ;;
		*) return 1 ;;
	esac
	latch=$(jq -cS .latch_receipt <<<"$row")
	jq -e --arg id "$(jq -r .id <<<"$planned")" --arg fence "$(jq -r .fence_sha256 <<<"$planned")" \
		--arg owner_digest "$(active_ready_owner_digest "$decommission")" --arg directory "$directory_digest" \
		--argjson owner "$decommission" '
		type == "object" and (keys | sort) == ["directory_sha256","fence_sha256","owner","owner_sha256","schema","target_id"] and
		.schema == "layerv.durable-aop-active-ready-latch-receipt.v1" and .target_id == $id and
		.fence_sha256 == $fence and .owner == $owner and .owner_sha256 == $owner_digest and
		.directory_sha256 == $directory
	' >/dev/null <<<"$latch" || return 1
	[[ "$status" == latched ]] && return 0
	quiescence=$(jq -cS .quiescence_receipt <<<"$row")
	expected_session=$(active_ready_target_session_pk "$fence")
	jq -e --arg id "$(jq -r .id <<<"$planned")" --arg fence "$(jq -r .fence_sha256 <<<"$planned")" \
		--arg owner_digest "$(active_ready_owner_digest "$decommission")" --arg directory "$directory_digest" \
		--arg session "$expected_session" '
		type == "object" and (keys | sort) == ["directory_sha256","fence_sha256","owner_pending_count","owner_sha256",
		 "owner_task_count","schema","target_id","target_session_count","target_session_pk"] and
		.schema == "layerv.durable-aop-active-ready-quiescence-receipt.v1" and .target_id == $id and
		.fence_sha256 == $fence and .owner_sha256 == $owner_digest and .owner_task_count == "0" and
		.owner_pending_count == "0" and .target_session_pk == $session and .target_session_count == "0" and
		.directory_sha256 == $directory
	' >/dev/null <<<"$quiescence" || return 1
	[[ "$status" == quiescent ]] && return 0
	receipt=$(jq -cS .receipt <<<"$row")
	expected_version=$(( $(jq -r .version <<<"$fence") + 1 ))
	expected_authority=$(( $(jq -r .authority_version <<<"$fence") + 1 ))
	jq -e --arg id "$(jq -r .id <<<"$planned")" --arg key "$(jq -r .public_key <<<"$fence")" \
		--arg version "$expected_version" --arg authority "$expected_authority" '
		type == "object" and (keys | sort) == ["authority_version","counted_active_slot","public_key","retired_at_ms",
		 "retired_target_sha256","schema","target_id","version"] and
		.schema == "layerv.durable-aop-stale-target-retirement-receipt.v1" and .target_id == $id and
		.public_key == $key and .version == $version and .authority_version == $authority and
		.counted_active_slot == false and (.retired_at_ms | type == "string" and test("^[1-9][0-9]*$")) and
		(.retired_target_sha256 | type == "string" and test("^[0-9a-f]{64}$"))
	' >/dev/null <<<"$receipt"
}

validate_active_ready_journal_authority() {
	local journal=$1 orchestrator=$2 state_digest=$3 main_digest=$4 fence_digest=$5
	local plan plan_digest status quiescence_digest count index row planned directory_digest
	jq -e --arg orchestrator "$orchestrator" --arg state_digest "$state_digest" --arg main_digest "$main_digest" \
		--arg fence_digest "$fence_digest" '
		type == "object" and (keys | sort) == ["fence_drain_sha256","orchestrator_sha","plan","plan_sha256",
		 "quiescence_sha256","schema","source_main_journal_parameter","source_main_journal_sha256",
		 "source_main_journal_version","source_state_sha256","source_state_version","status","targets"] and
		.schema == "layerv.durable-aop-active-ready-predecessor-journal.v1" and
		.source_state_version == 30 and .source_state_sha256 == $state_digest and
		.source_main_journal_parameter == "/sandbox/nhp/cutovers/durable-aop-v1/stale-target-retirement" and
		.source_main_journal_version == 8 and .source_main_journal_sha256 == $main_digest and
		.orchestrator_sha == $orchestrator and .fence_drain_sha256 == $fence_digest and
		(.plan_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
		(.quiescence_sha256 | type == "string" and test("^([0-9a-f]{64})?$")) and
		(.status == "latching" or .status == "quiescent" or .status == "retiring" or .status == "complete") and
		(.targets | type == "array" and length == 3)
	' >/dev/null <<<"$journal" || return 1
	plan=$(jq -cS .plan <<<"$journal")
	validate_active_ready_plan "$plan" || return 1
	plan_digest=$(canonical_digest "$plan")
	[[ "$plan_digest" == "$(jq -r .plan_sha256 <<<"$journal")" ]] || return 1
	directory_digest=$(jq -r .fence_drain_sha256 <<<"$journal")
	count=$(jq -r '.targets | length' <<<"$journal")
	for ((index=0; index<count; index++)); do
		row=$(jq -c --argjson i "$index" '.targets[$i]' <<<"$journal")
		planned=$(jq -c --argjson i "$index" '.plan.targets[$i]' <<<"$journal")
		validate_active_ready_target_receipts "$row" "$planned" "$directory_digest" || return 1
	done
	status=$(jq -r .status <<<"$journal")
	case "$status" in
		latching) jq -e '([.targets[].status] == ["pending","pending","pending"] or [.targets[].status] == ["latched","pending","pending"] or [.targets[].status] == ["quiescent","pending","pending"] or [.targets[].status] == ["quiescent","latched","pending"] or [.targets[].status] == ["quiescent","quiescent","pending"] or [.targets[].status] == ["quiescent","quiescent","latched"]) and .quiescence_sha256 == ""' >/dev/null <<<"$journal" || return 1 ;;
		quiescent) jq -e '[.targets[].status] == ["quiescent","quiescent","quiescent"]' >/dev/null <<<"$journal" || return 1 ;;
		retiring) jq -e '([.targets[].status] == ["retired","quiescent","quiescent"] or [.targets[].status] == ["retired","retired","quiescent"])' >/dev/null <<<"$journal" || return 1 ;;
		complete) jq -e '[.targets[].status] == ["retired","retired","retired"]' >/dev/null <<<"$journal" || return 1 ;;
	esac
	if [[ "$status" != latching ]]; then
		quiescence_digest=$(jq -cS '[.targets[] | .status="quiescent" | del(.receipt)]' <<<"$journal" | sha256sum | awk '{print $1}')
		[[ "$quiescence_digest" == "$(jq -r .quiescence_sha256 <<<"$journal")" ]] || return 1
	fi
}
