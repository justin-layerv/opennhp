#!/usr/bin/env bash
# Verify the separate attended qurl-connector UDP lifecycle proof.  The trusted
# workflow owns the sandbox credentials and exact strict inventory; this reader
# additionally opens its immutable artifact so the receipt is cross-bound to
# the repaired NHP source/image, controller run, qurl-connector PR #609 head,
# and released qurl-go v0.8.0 authority.

set -euo pipefail

REPOSITORY=layervai/qurl-connector
WORKFLOW_PATH=.github/workflows/sandbox-smoke.yml
QURL_GO_V080_SHA=d02c25995df085f0437c7a572714c26e907a8a59
APPROVED_CONNECTOR_PR_HEAD_SHA=0000000000000000000000000000000000000000
APPROVED_CONNECTOR_MERGE_SHA=0000000000000000000000000000000000000000
RUN_ID=${CUTOVER_CONNECTOR_LIFECYCLE_RUN_ID:?CUTOVER_CONNECTOR_LIFECYCLE_RUN_ID is required}
RUN_ATTEMPT=${CUTOVER_CONNECTOR_LIFECYCLE_RUN_ATTEMPT:?CUTOVER_CONNECTOR_LIFECYCLE_RUN_ATTEMPT is required}
NHP_SOURCE_SHA=${CUTOVER_EXPECTED_REPAIR_SOURCE_SHA:?CUTOVER_EXPECTED_REPAIR_SOURCE_SHA is required}
NHP_CONTROLLER_SOURCE_SHA=${CUTOVER_EXPECTED_NHP_CONTROLLER_SOURCE_SHA:?CUTOVER_EXPECTED_NHP_CONTROLLER_SOURCE_SHA is required}
NHP_SERVER_DIGEST=${CUTOVER_EXPECTED_NHP_SERVER_DIGEST:?CUTOVER_EXPECTED_NHP_SERVER_DIGEST is required}
: "${GH_TOKEN:?GH_TOKEN is required}"

[[ "$RUN_ID" =~ ^[1-9][0-9]*$ && "$RUN_ATTEMPT" =~ ^[1-9][0-9]*$ ]] || {
  echo "connector lifecycle run id/attempt must be positive integers" >&2
  exit 2
}
[[ "$NHP_SOURCE_SHA" =~ ^[0-9a-f]{40}$ && "$NHP_CONTROLLER_SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]] || {
  echo "NHP repair/controller sources must be exact lowercase 40-hex" >&2
  exit 2
}
[[ "$NHP_SERVER_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || {
  echo "expected NHP server digest is malformed" >&2
  exit 2
}

# This gate is intentionally unreachable before #609 merges.  The protected
# runner executes connector main, so bind both reviewed authorities: the final
# PR head and GitHub's exact merged-main commit.  A later main run is not
# interchangeable with this one-time release proof.
pr=$(gh api "repos/${REPOSITORY}/pulls/609")
CONNECTOR_PR_HEAD_SHA=$(jq -er '
  select(.number == 609 and .head.repo.full_name == "layervai/qurl-connector" and
    .state == "closed" and .merged == true and
    (.head.sha | type == "string" and test("^[0-9a-f]{40}$")) and
    (.merge_commit_sha | type == "string" and test("^[0-9a-f]{40}$"))) | .head.sha
' <<<"$pr") || {
  echo "connector lifecycle source is not the exact merged qurl-connector PR #609 authority" >&2
  exit 1
}
CONNECTOR_SHA=$(jq -r .merge_commit_sha <<<"$pr")
[[ "$CONNECTOR_PR_HEAD_SHA" == "$APPROVED_CONNECTOR_PR_HEAD_SHA" &&
   "$CONNECTOR_SHA" == "$APPROVED_CONNECTOR_MERGE_SHA" ]] || {
  echo "connector lifecycle authority is not the final reviewed/merged #609 source" >&2
  exit 1
}

run=$(gh api "repos/${REPOSITORY}/actions/runs/${RUN_ID}")
jq -e --arg sha "$CONNECTOR_SHA" --arg path "$WORKFLOW_PATH" --argjson attempt "$RUN_ATTEMPT" '
  .head_sha == $sha and .head_branch == "main" and .event == "workflow_dispatch" and .run_attempt == $attempt and
  .status == "completed" and .conclusion == "success" and
  (.path == $path or
   .path == ("layervai/qurl-connector/" + $path + "@refs/heads/" + .head_branch))
' >/dev/null <<<"$run" || {
  echo "connector lifecycle run is not the exact successful attended PR #609 workflow attempt" >&2
  exit 1
}

jobs=$(gh api --paginate "repos/${REPOSITORY}/actions/runs/${RUN_ID}/attempts/${RUN_ATTEMPT}/jobs?per_page=100" --slurp)
jq -e '
  [.[].jobs[] | select(.name == "Attended Connector UDP proof (strict)" and .conclusion == "success")] as $strict |
  ($strict | length == 1) and
  (([$strict[0].steps[]? | select(.conclusion == "success") | .name] | unique) as $steps |
    (["Authenticate exact deployment manifest",
      "Run exact strict proof inventory",
      "Build allowlisted strict proof evidence",
      "Upload non-secret strict proof evidence",
      "Require complete published proof gate"] |
      all(. as $required | ($steps | index($required)) != null)))
' >/dev/null <<<"$jobs" || {
  echo "connector lifecycle run lacks the exact successful attended proof job/steps" >&2
  exit 1
}

artifact_name="strict-sandbox-proof-pre_removal-${CONNECTOR_SHA}-${RUN_ATTEMPT}"
artifacts=$(gh api --paginate "repos/${REPOSITORY}/actions/runs/${RUN_ID}/artifacts?per_page=100" --slurp)
artifact=$(jq -ce --arg name "$artifact_name" '
  [.[].artifacts[] | select(.name == $name and .expired == false)] |
  select(length == 1) | .[0] |
  select((.id | type == "number" and . > 0) and
         (.size_in_bytes | type == "number" and . > 0 and . <= 5242880) and
         (.digest | type == "string" and test("^sha256:[0-9a-f]{64}$")))
' <<<"$artifacts") || {
  echo "connector lifecycle proof artifact is missing, duplicated, expired, oversized, or malformed" >&2
  exit 1
}

artifact_id=$(jq -r .id <<<"$artifact")
artifact_digest=$(jq -r .digest <<<"$artifact")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
gh api "repos/${REPOSITORY}/actions/artifacts/${artifact_id}/zip" >"$tmp/artifact.zip"
[[ "sha256:$(sha256sum "$tmp/artifact.zip" | awk '{print $1}')" == "$artifact_digest" ]] || {
  echo "connector lifecycle artifact bytes do not match GitHub's immutable digest" >&2
  exit 1
}

python3 - "$tmp/artifact.zip" "$tmp" <<'PY'
import os
import stat
import sys
import zipfile

archive, destination = sys.argv[1:]
expected = {
    "deployment-runtime-inputs.json",
    "sandbox-deployment-manifest.json",
    "strict-typed-evidence.json",
    "strict-proof-scenarios.json",
    "strict-sandbox-proof.evidence.json",
    "typed-evidence-contract.json",
}
found = {}
total = 0
with zipfile.ZipFile(archive) as bundle:
    for entry in bundle.infolist():
        if entry.is_dir():
            continue
        mode = entry.external_attr >> 16
        normalized = entry.filename.replace("\\", "/")
        if stat.S_ISLNK(mode) or "/" in normalized or normalized in ("", ".", ".."):
            raise SystemExit(f"unsafe connector proof artifact path: {entry.filename}")
        if normalized not in expected or normalized in found:
            raise SystemExit(f"unexpected or duplicate connector proof file: {entry.filename}")
        if not 1 <= entry.file_size <= 1024 * 1024:
            raise SystemExit(f"connector proof file size is invalid: {entry.filename}")
        total += entry.file_size
        if total > 2 * 1024 * 1024:
            raise SystemExit("connector proof artifact expands beyond 2 MiB")
        found[normalized] = entry
    if set(found) != expected:
        raise SystemExit(f"connector proof file set mismatch: {sorted(found)}")
    for name, entry in found.items():
        target = os.path.join(destination, name)
        descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as output, bundle.open(entry) as source:
            written = 0
            while block := source.read(1024 * 1024):
                written += len(block)
                if written > entry.file_size or written > 1024 * 1024:
                    raise SystemExit(f"connector proof file expanded beyond its bound: {entry.filename}")
                output.write(block)
            if written != entry.file_size:
                raise SystemExit(f"connector proof file size mismatch: {entry.filename}")
PY

evidence="$tmp/strict-sandbox-proof.evidence.json"
manifest="$tmp/sandbox-deployment-manifest.json"
NHP_CONTROLLER_RUN_ID=$(jq -er '.nhp_controller_run_id | select(type == "string" and test("^[1-9][0-9]*$"))' "$evidence") || {
  echo "connector lifecycle evidence lacks a canonical NHP controller run id" >&2; exit 1;
}
NHP_CONTROLLER_RUN_ATTEMPT=$(jq -er '.nhp_controller_run_attempt | select(type == "string" and test("^[1-9][0-9]*$"))' "$evidence") || {
  echo "connector lifecycle evidence lacks a canonical NHP controller run attempt" >&2; exit 1;
}
jq -e --arg connector "$CONNECTOR_SHA" --arg run "$RUN_ID" --arg attempt "$RUN_ATTEMPT" \
  --arg nhp_controller "$NHP_CONTROLLER_SOURCE_SHA" --arg controller_run "$NHP_CONTROLLER_RUN_ID" \
  --arg controller_attempt "$NHP_CONTROLLER_RUN_ATTEMPT" '
  type == "object" and .schema_version == 1 and .phase == "pre_removal" and
  .repository == "layervai/qurl-connector" and .commit_sha == $connector and
  .run_id == $run and .run_attempt == $attempt and
  .nhp_controller_run_id == $controller_run and .nhp_controller_run_attempt == $controller_attempt and
  (.dispatch_correlation_id | test("^nhp-" + $controller_run + "-" + $controller_attempt + "-connector-pre_removal-[0-9a-f]{32}$")) and
  .gate_passed == true and .input_outcome == "success" and .enforcement_outcome == "success" and
  .inputs_unchanged == true and .counts.blocking == 0 and .counts.failures == 0 and
  .counts.skips == 0 and .counts.implemented > 0 and .counts.exact_passes == .counts.implemented and
  .provenance_valid == true and .two_cell_provenance == true and .typed_evidence_complete == true and
  (.deployment_producer | .repository == "layervai/nhp" and
    .workflow_path == ".github/workflows/udp-proof-deployment-manifest.yml" and
    .head_sha == $nhp_controller and (.run_id | test("^[1-9][0-9]*$")) and
    (.run_attempt | test("^[1-9][0-9]*$")) and
    (.artifact_id | test("^[1-9][0-9]*$")) and
    (.artifact_digest | test("^sha256:[0-9a-f]{64}$")))
' >/dev/null "$evidence" || {
  echo "connector lifecycle evidence does not bind the exact strict run and repaired NHP controller" >&2
  exit 1
}

jq -e --arg connector "$CONNECTOR_SHA" --arg qurl_go "$QURL_GO_V080_SHA" \
  --arg nhp "$NHP_SOURCE_SHA" --arg server_digest "$NHP_SERVER_DIGEST" '
  type == "object" and .schema_version == 1 and .phase == "pre_removal" and
  .retirement_state == "http_lifecycle_present" and
  .repositories.qurl_connector == $connector and .repositories.qurl_go == $qurl_go and
  .repositories.nhp == $nhp and .connector_modules.qurl_go == $qurl_go and
  .images.nhp_cell0 == $server_digest and .images.nhp_cell1 == $server_digest
' >/dev/null "$manifest" || {
  echo "connector lifecycle deployment manifest does not bind qurl-go v0.8.0 and the repaired two-cell NHP image" >&2
  exit 1
}

producer_run=$(jq -r .deployment_producer.run_id "$evidence")
producer_attempt=$(jq -r .deployment_producer.run_attempt "$evidence")
printf 'v1|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
  "$REPOSITORY" "$RUN_ID" "$RUN_ATTEMPT" "$CONNECTOR_SHA" "$CONNECTOR_PR_HEAD_SHA" "$QURL_GO_V080_SHA" \
  "$artifact_id" "$artifact_digest" "$NHP_CONTROLLER_RUN_ID" "$NHP_CONTROLLER_RUN_ATTEMPT" \
  "$producer_run" "$producer_attempt" "$NHP_CONTROLLER_SOURCE_SHA" "$NHP_SOURCE_SHA" "$NHP_SERVER_DIGEST"
