#!/usr/bin/env bash
# Asserts the qURL v2 revocation-latency SLO is in lockstep between the Go
# source-of-truth constant and the CloudWatch alarm threshold (#2792).
#
# Sites compared:
#   - endpoints/server/revocation_retry.go::RevocationDeliveryLatencyP99SLO
#       (a time.Duration literal, e.g. `15 * time.Second`)
#   - terraform/modules/monitoring/main.tf
#       aws_cloudwatch_metric_alarm.revocation_delivery_latency_high.threshold
#       (a plain number in MILLISECONDS, e.g. 15000)
#   - terraform/modules/compute/main.tf
#       terraform_data.revocation_retry_config_contract age-out precondition
#       (a plain number in SECONDS, e.g. 15)
#
# The alarm threshold is the millisecond projection of the Go SLO: the metric
# (MetricRevocationDeliveryLatency) is recorded via metrics.RecordLatency, which
# records milliseconds. If the two drift, the p99 alarm fires at a bound that no
# longer matches the documented SLO — a silent observability gap, exactly the
# failure mode the inline lockstep comments warn about. This lint surfaces the
# drift at PR time. The compute precondition is the second projection: it rejects
# retry age-out settings that are not greater than the same SLO, so it must move
# with the Go constant too.
#
# Supported Go SLO shapes (single-line const, value in seconds or milliseconds):
#   RevocationDeliveryLatencyP99SLO = 15 * time.Second
#   RevocationDeliveryLatencyP99SLO = 15000 * time.Millisecond
# A refactor to any other shape fails loud here (the extract returns empty and
# the script exits with a clear error) rather than silently accepting a stale
# value — update this extractor in the same change.
#
# Wired into `make lint-workflows` and `.github/workflows/validate-workflows.yml`
# (the CI step + the &validate_paths trigger on this script and BOTH
# source-of-truth files) — #2817 closed the gap where this ran only locally, so
# a one-sided edit to either site would have passed CI silently.
#
# Testability: REPO_ROOT may be overridden via $REVOCATION_SLO_LOCKSTEP_ROOT so
# the paired fixture test (tests/scripts/check-revocation-slo-lockstep_test.sh)
# can point the extractors at mutated copies in a tempdir. Defaults to the git
# toplevel.

set -euo pipefail

REPO_ROOT="${REVOCATION_SLO_LOCKSTEP_ROOT:-$(git rev-parse --show-toplevel)}"
GO_SRC="${REPO_ROOT}/endpoints/server/revocation_retry.go"
TF_SRC="${REPO_ROOT}/terraform/modules/monitoring/main.tf"
TF_COMPUTE_SRC="${REPO_ROOT}/terraform/modules/compute/main.tf"

if [ ! -f "$GO_SRC" ]; then
  echo "ERROR: $GO_SRC not found" >&2
  exit 1
fi
if [ ! -f "$TF_SRC" ]; then
  echo "ERROR: $TF_SRC not found" >&2
  exit 1
fi
if [ ! -f "$TF_COMPUTE_SRC" ]; then
  echo "ERROR: $TF_COMPUTE_SRC not found" >&2
  exit 1
fi

# Extract the Go SLO constant's numeric scalar and its time unit. Matches a
# single-line `RevocationDeliveryLatencyP99SLO = <int> * time.<Unit>` const,
# tolerating surrounding whitespace and an optional trailing comment.
# `-m1` stops at the first hit; `|| true` is load-bearing — a no-match grep exits
# 1, which under `set -e` would abort the script HERE with no diagnostic and
# defeat the `if [ -z ... ]` clear-error handler just below. Tolerate the
# non-match so that handler runs and emits the actionable "could not extract"
# message (a refactor to an unsupported shape must fail loud, not silently).
go_line=$(grep -m1 -E 'RevocationDeliveryLatencyP99SLO[[:space:]]*=[[:space:]]*[0-9]+[[:space:]]*\*[[:space:]]*time\.(Second|Millisecond)' "$GO_SRC") || true
if [ -z "$go_line" ]; then
  echo "ERROR: could not extract RevocationDeliveryLatencyP99SLO from $GO_SRC" >&2
  echo "       (expected: RevocationDeliveryLatencyP99SLO = <int> * time.Second|Millisecond)" >&2
  exit 1
fi
go_scalar=$(printf '%s\n' "$go_line" | sed -E 's/^.*=[[:space:]]*([0-9]+)[[:space:]]*\*[[:space:]]*time\..*$/\1/')
go_unit=$(printf '%s\n' "$go_line" | sed -E 's/^.*time\.(Second|Millisecond).*$/\1/')

# Normalize the Go SLO to milliseconds (the unit the alarm threshold uses).
case "$go_unit" in
  Second)      go_ms=$(( go_scalar * 1000 )) ;;
  Millisecond) go_ms=$(( go_scalar )) ;;
  *)
    echo "ERROR: unexpected time unit '$go_unit' in $GO_SRC" >&2
    exit 1
    ;;
esac

# Extract the alarm threshold (milliseconds) from the latency alarm block. Scope
# the scan to the lines following the resource declaration so a future second
# `threshold =` elsewhere in the file cannot be picked up by accident.
tf_threshold=$(awk '
  /resource "aws_cloudwatch_metric_alarm" "revocation_delivery_latency_high"/ { inblock = 1 }
  inblock && /^[[:space:]]*threshold[[:space:]]*=/ {
    sub(/^[[:space:]]*threshold[[:space:]]*=[[:space:]]*/, "")
    sub(/[[:space:]]*(#.*)?$/, "")
    print
    exit
  }
  inblock && /^}/ { exit }
' "$TF_SRC")

if [ -z "$tf_threshold" ]; then
  echo "ERROR: could not extract the threshold from aws_cloudwatch_metric_alarm.revocation_delivery_latency_high in $TF_SRC" >&2
  exit 1
fi
if ! printf '%s' "$tf_threshold" | grep -Eq '^[0-9]+$'; then
  echo "ERROR: extracted alarm threshold '$tf_threshold' is not a plain integer (ms) in $TF_SRC" >&2
  exit 1
fi

if [ "$go_ms" != "$tf_threshold" ]; then
  cat <<EOF >&2
ERROR: revocation-latency SLO drift between the Go constant and the CloudWatch alarm.

       $GO_SRC::RevocationDeliveryLatencyP99SLO
         = ${go_scalar} * time.${go_unit}  (= ${go_ms} ms)

       $TF_SRC
         aws_cloudwatch_metric_alarm.revocation_delivery_latency_high.threshold
         = ${tf_threshold} ms

       The alarm threshold must equal the SLO in milliseconds (RecordLatency
       records ms). Update both sites in lockstep (#2792).
EOF
  exit 1
fi

if [ $(( go_ms % 1000 )) -ne 0 ]; then
  echo "ERROR: RevocationDeliveryLatencyP99SLO (${go_ms} ms) is not whole seconds; update the Terraform age-out precondition and this lint together." >&2
  exit 1
fi
go_seconds=$(( go_ms / 1000 ))

# Extract the compute-module age-out precondition SLO mirror (seconds). Scope the
# scan to the revocation retry contract so a future unrelated age-out comparison
# cannot satisfy the check accidentally.
tf_compute_slo_seconds=$(awk '
  /resource "terraform_data" "revocation_retry_config_contract"/ { inblock = 1 }
  inblock && /var\.revocation_retry_age_out_seconds[[:space:]]*>[[:space:]]*[0-9]+/ {
    line = $0
    sub(/^.*var\.revocation_retry_age_out_seconds[[:space:]]*>[[:space:]]*/, "", line)
    sub(/[[:space:])].*$/, "", line)
    print line
    exit
  }
  inblock && /^}/ { exit }
' "$TF_COMPUTE_SRC")

if [ -z "$tf_compute_slo_seconds" ]; then
  echo "ERROR: could not extract the revocation_retry_age_out_seconds SLO precondition from terraform_data.revocation_retry_config_contract in $TF_COMPUTE_SRC" >&2
  exit 1
fi
if ! printf '%s' "$tf_compute_slo_seconds" | grep -Eq '^[0-9]+$'; then
  echo "ERROR: extracted retry age-out SLO precondition '$tf_compute_slo_seconds' is not a plain integer (seconds) in $TF_COMPUTE_SRC" >&2
  exit 1
fi

if [ "$go_seconds" != "$tf_compute_slo_seconds" ]; then
  cat <<EOF >&2
ERROR: revocation-latency SLO drift between the Go constant and the Terraform retry age-out precondition.

       $GO_SRC::RevocationDeliveryLatencyP99SLO
         = ${go_scalar} * time.${go_unit}  (= ${go_seconds} seconds)

       $TF_COMPUTE_SRC
         terraform_data.revocation_retry_config_contract
         revocation_retry_age_out_seconds > ${tf_compute_slo_seconds}

       The retry age-out precondition must compare against the same SLO in
       seconds. Update both sites in lockstep (#2793).
EOF
  exit 1
fi

echo "OK: revocation-latency SLO is lockstep across the Go const, CloudWatch alarm, and retry age-out precondition (${go_ms} ms)"
