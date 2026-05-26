#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPT="${REPO_ROOT}/scripts/check-nhp-server-internal-url-validation-drift.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

write_matching_fixture() {
  local root="$1"
  mkdir -p \
    "$root/terraform/modules/qurl-reverse-tunnel-server" \
    "$root/terraform/modules/qurl-service"

  cat > "$root/terraform/main.tf" <<'EOF'
resource "terraform_data" "nhp_server_internal_url_preconditions" {
  lifecycle {
    precondition {
      condition = (
        local.nhp_server_internal_url == ""
        || can(regex("^https://[^[:space:]/?#]+$", local.nhp_server_internal_url))
        || can(regex("^http://([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+internal:([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$", local.nhp_server_internal_url))
      )
      error_message = "local.nhp_server_internal_url must be empty, an HTTPS origin URL or an HTTP private hosted-zone origin ending in .internal with an explicit valid TCP port (1-65535); either form must have no path, query, fragment, or trailing slash (for example http://server.nhp.sandbox.internal:8888)."
    }
  }
}
EOF

  cat > "$root/terraform/modules/qurl-reverse-tunnel-server/variables.tf" <<'EOF'
variable "nhp_server_internal_url" {
  description = <<-EOT
    Heredoc descriptions may contain { braces } outside the validation block.
  EOT
  type        = string
  default     = ""

  validation {
    condition = (
      var.nhp_server_internal_url == ""
      || can(regex("^https://[^[:space:]/?#]+$", var.nhp_server_internal_url))
      || can(regex("^http://([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+internal:([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$", var.nhp_server_internal_url))
    )
    error_message = "nhp_server_internal_url must be empty, an HTTPS origin URL or an HTTP private hosted-zone origin ending in .internal with an explicit valid TCP port (1-65535); either form must have no path, query, fragment, or trailing slash (for example http://server.nhp.sandbox.internal:8888)."
  }
}
EOF

  cp "$root/terraform/modules/qurl-reverse-tunnel-server/variables.tf" \
    "$root/terraform/modules/qurl-service/variables.tf"
}

replace_once() {
  local file="$1"
  local old="$2"
  local new="$3"
  python3 - "$file" "$old" "$new" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
old = sys.argv[2]
new = sys.argv[3]
text = path.read_text(encoding="utf-8")
if old not in text:
    raise SystemExit(f"fixture mutation target not found in {path}: {old}")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
PY
}

matching="$tmp/matching"
write_matching_fixture "$matching"
"$SCRIPT" "$matching" >/dev/null

unbalanced_heredoc="$tmp/unbalanced-heredoc"
write_matching_fixture "$unbalanced_heredoc"
replace_once \
  "$unbalanced_heredoc/terraform/modules/qurl-reverse-tunnel-server/variables.tf" \
  "Heredoc descriptions may contain { braces } outside the validation block." \
  "Heredoc descriptions may contain JSON-like { braces outside the validation block."
"$SCRIPT" "$unbalanced_heredoc" >/dev/null

root_drift="$tmp/root-drift"
write_matching_fixture "$root_drift"
replace_once \
  "$root_drift/terraform/main.tf" \
  '6553[0-5])$' \
  '6553[0-4])$'
if "$SCRIPT" "$root_drift" >/dev/null 2>&1; then
  echo "ERROR: root regex drift fixture passed unexpectedly" >&2
  exit 1
fi

module_drift="$tmp/module-drift"
write_matching_fixture "$module_drift"
replace_once \
  "$module_drift/terraform/modules/qurl-reverse-tunnel-server/variables.tf" \
  '6553[0-5])$' \
  '6553[0-4])$'
if "$SCRIPT" "$module_drift" >/dev/null 2>&1; then
  echo "ERROR: module regex drift fixture passed unexpectedly" >&2
  exit 1
fi

regex_drift="$tmp/regex-drift"
write_matching_fixture "$regex_drift"
replace_once \
  "$regex_drift/terraform/modules/qurl-service/variables.tf" \
  '6553[0-5])$' \
  '6553[0-4])$'
if "$SCRIPT" "$regex_drift" >/dev/null 2>&1; then
  echo "ERROR: regex drift fixture passed unexpectedly" >&2
  exit 1
fi

message_drift="$tmp/message-drift"
write_matching_fixture "$message_drift"
replace_once \
  "$message_drift/terraform/modules/qurl-service/variables.tf" \
  "with an explicit valid TCP port (1-65535)" \
  "with an explicit valid port"
if "$SCRIPT" "$message_drift" >/dev/null 2>&1; then
  echo "ERROR: error-message drift fixture passed unexpectedly" >&2
  exit 1
fi

module_local_message="$tmp/module-local-message"
write_matching_fixture "$module_local_message"
replace_once \
  "$module_local_message/terraform/modules/qurl-service/variables.tf" \
  "nhp_server_internal_url must be empty" \
  "local.nhp_server_internal_url must be empty"
if "$SCRIPT" "$module_local_message" >/dev/null 2>&1; then
  echo "ERROR: module local-prefixed error-message fixture passed unexpectedly" >&2
  exit 1
fi

echo "nhp_server_internal_url validation drift fixtures passed."
