#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECKER="${ROOT_DIR}/scripts/check-ac-user-data-heredoc-backticks.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass_count=0
fail_count=0

expect_pass() {
  local name="$1"
  local fixture="$2"
  if bash "$CHECKER" "$fixture" >/tmp/check-ac-user-data-heredoc-backticks.out 2>&1; then
    echo "  PASS: ${name}"
    pass_count=$((pass_count + 1))
  else
    echo "  FAIL: ${name} should pass" >&2
    cat /tmp/check-ac-user-data-heredoc-backticks.out >&2
    fail_count=$((fail_count + 1))
  fi
}

expect_fail() {
  local name="$1"
  local fixture="$2"
  if bash "$CHECKER" "$fixture" >/tmp/check-ac-user-data-heredoc-backticks.out 2>&1; then
    echo "  FAIL: ${name} should fail" >&2
    cat /tmp/check-ac-user-data-heredoc-backticks.out >&2
    fail_count=$((fail_count + 1))
  else
    echo "  PASS: ${name}"
    pass_count=$((pass_count + 1))
  fi
}

bad_backtick="$TMP/bad-backtick.sh.tpl"
cat > "$bad_backtick" <<'EOF'
cat > /home/ubuntu/traefik/traefik.toml << TRAEFIKEOF
[api]
  # This would execute `traefik` during boot.
TRAEFIKEOF
EOF

bad_dollar_paren="$TMP/bad-dollar-paren.sh.tpl"
cat > "$bad_dollar_paren" <<'EOF'
cat >> /home/ubuntu/traefik/dynamic.toml << DYNAMICEOF
[http.routers.example]
  # This would execute $(traefik version) during boot.
DYNAMICEOF
EOF

quoted_target="$TMP/quoted-target.sh.tpl"
cat > "$quoted_target" <<'EOF'
cat >> /home/ubuntu/traefik/frps-control.toml << 'FRPSCTRLEOF'
[tcp.routers.frps-control]
  rule = "HostSNI(`*`)"
FRPSCTRLEOF
EOF

escaped_literals="$TMP/escaped-literals.sh.tpl"
cat > "$escaped_literals" <<'EOF'
cat >> /home/ubuntu/traefik/dynamic.toml << QURLDYNAMICEOF
[http.middlewares.qurl-router.plugin.qurl-router]
  # Literal prose \`frpServerUrls\` and \$(not-a-command) are safe.
  serviceToken = "$QURL_SERVICE_TOKEN"
QURLDYNAMICEOF
EOF

bad_even_backslash="$TMP/bad-even-backslash.sh.tpl"
cat > "$bad_even_backslash" <<'EOF'
cat >> /home/ubuntu/traefik/dynamic.toml << QURLDYNAMICEOF
# The first backslash escapes the second, so the backtick still executes.
\\`still-executes`
QURLDYNAMICEOF
EOF

bad_config="$TMP/bad-config.sh.tpl"
cat > "$bad_config" <<'EOF'
cat > /opt/layerv/nhp-ac/etc/config.toml << CONFIGEOF
# This would execute `PrivateKeyBase64` before nhp-acd config lands.
CONFIGEOF
EOF

bad_systemd="$TMP/bad-systemd.sh.tpl"
cat > "$bad_systemd" <<'EOF'
cat > /etc/systemd/system/nhp-acd.service << SVCEOF
[Service]
# This would execute $(systemctl --version) before systemd units land.
SVCEOF
EOF

non_traefik_target="$TMP/non-traefik-target.sh.tpl"
cat > "$non_traefik_target" <<'EOF'
cat > /tmp/not-traefik.toml << EOF_NOT_TRAF
# Outside the AC Traefik config tree, so this checker ignores `literal`.
EOF_NOT_TRAF
EOF

suffix_order="$TMP/suffix-order.sh.tpl"
cat > "$suffix_order" <<'EOF'
cat <<'TRAEFIKEOF' > /home/ubuntu/traefik/traefik.toml
[api]
  # Quoted suffix-order heredoc can contain `literal`.
TRAEFIKEOF
EOF

dash_tabs="$TMP/dash-tabs.sh.tpl"
cat > "$dash_tabs" <<'EOF'
cat > /etc/systemd/system/nhp-health-monitor.service <<-SVCEOF
[Unit]
# The tab-indented terminator below is valid for <<-.
	SVCEOF
EOF

space_before_dash_terminator="$TMP/space-before-dash-terminator.sh.tpl"
cat > "$space_before_dash_terminator" <<'EOF'
cat > /etc/systemd/system/nhp-health-monitor.service <<-SVCEOF
  SVCEOF
# Because spaces do not terminate <<-, this raw backtick is still in body.
`still-executes`
SVCEOF
EOF

real_file="${ROOT_DIR}/terraform/modules/ac/user_data.sh.tpl"

echo "Failure fixtures:"
expect_fail "unquoted Traefik heredoc raw backtick" "$bad_backtick"
expect_fail "unquoted Traefik heredoc raw command substitution" "$bad_dollar_paren"
expect_fail "unquoted AC config heredoc raw backtick" "$bad_config"
expect_fail "unquoted AC systemd heredoc raw command substitution" "$bad_systemd"
expect_fail "space does not terminate dash heredoc" "$space_before_dash_terminator"
expect_fail "even backslash leaves backtick unescaped" "$bad_even_backslash"

echo "Passing fixtures:"
expect_pass "quoted Traefik heredoc raw backtick" "$quoted_target"
expect_pass "unquoted Traefik heredoc escaped literals" "$escaped_literals"
expect_pass "non-Traefik heredoc ignored" "$non_traefik_target"
expect_pass "quoted suffix-order Traefik heredoc" "$suffix_order"
expect_pass "tab terminates dash heredoc" "$dash_tabs"
expect_pass "real AC user_data template" "$real_file"

if [ "$fail_count" -ne 0 ]; then
  echo "check-ac-user-data-heredoc-backticks: ${pass_count} passed, ${fail_count} failed" >&2
  exit 1
fi

echo "check-ac-user-data-heredoc-backticks: ${pass_count} passed, 0 failed"
