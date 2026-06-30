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
#
# The alarm threshold is the millisecond projection of the Go SLO: the metric
# (MetricRevocationDeliveryLatency) is recorded via metrics.RecordLatency, which
# records milliseconds. If the two drift, the p99 alarm fires at a bound that no
# longer matches the documented SLO — a silent observability gap, exactly the
# failure mode the inline lockstep comments warn about. This lint surfaces the
# drift at PR time.
#
# Supported Go SLO shapes (single-line const, value in seconds or milliseconds):
#   RevocationDeliveryLatencyP99SLO = 15 * time.Second
#   RevocationDeliveryLatencyP99SLO = 15000 * time.Millisecond
# A refactor to any other shape fails loud here (the extract returns empty and
# the script exits with a clear error) rather than silently accepting a stale
# value — update this extractor in the same change.
#
# Wired into `make lint-workflows`.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
GO_SRC="${REPO_ROOT}/endpoints/server/revocation_retry.go"
TF_SRC="${REPO_ROOT}/terraform/modules/monitoring/main.tf"

if [ ! -f "$GO_SRC" ]; then
  echo "ERROR: $GO_SRC not found" >&2
  exit 1
fi
if [ ! -f "$TF_SRC" ]; then
  echo "ERROR: $TF_SRC not found" >&2
  exit 1
fi

# Extract the Go SLO constant's numeric scalar and its time unit. Matches a
# single-line `RevocationDeliveryLatencyP99SLO = <int> * time.<Unit>` const,
# tolerating surrounding whitespace and an optional trailing comment.
go_line=$(grep -E 'RevocationDeliveryLatencyP99SLO[[:space:]]*=[[:space:]]*[0-9]+[[:space:]]*\*[[:space:]]*time\.(Second|Millisecond)' "$GO_SRC" | head -n1)
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

echo "OK: revocation-latency SLO is lockstep across the Go const + CloudWatch alarm (${go_ms} ms)"
