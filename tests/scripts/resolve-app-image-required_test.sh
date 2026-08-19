#!/usr/bin/env bash
# Fixture tests for .github/scripts/resolve-app-image-required.sh.

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$HERE/../.." && pwd)
SCRIPT="$REPO_ROOT/.github/scripts/resolve-app-image-required.sh"

pass=0
fail=0
failures=""
report_pass() { pass=$((pass + 1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
report_fail() { fail=$((fail + 1)); failures+="  ✗ $1: $2\n"; printf '  \033[31m✗\033[0m %s\n      %s\n' "$1" "$2"; }
assert_non_empty() {
  local name="$1" value="$2"
  if [[ -n "$value" ]]; then
    report_pass "$name"
  else
    report_fail "$name" "extracted value was empty"
  fi
}

assert_multiline_equals() {
  local name="$1" want="$2" got="$3"
  if [[ "$got" == "$want" ]]; then
    report_pass "$name"
  else
    report_fail "$name" "want '$want' got '$got'"
  fi
}

assert_lines_contain_all() {
  local name="$1" haystack="$2" needles="$3"
  local missing=()
  local needle

  while IFS= read -r needle; do
    [[ -z "$needle" ]] && continue
    if ! grep -Fxq "$needle" <<< "$haystack"; then
      missing+=("$needle")
    fi
  done <<< "$needles"

  if [[ "${#missing[@]}" -eq 0 ]]; then
    report_pass "$name"
  else
    report_fail "$name" "missing lines: ${missing[*]}"
  fi
}

assert_empty() {
  local name="$1" value="$2"
  if [[ -z "$value" ]]; then
    report_pass "$name"
  else
    report_fail "$name" "expected empty output, got: $value"
  fi
}

extract_script_array() {
  local array="$1"
  awk -v array="$array" '
    $0 == array "=(" { in_array = 1; next }
    in_array && $0 == ")" { exit }
    in_array {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "")
      if ($0 != "") print
    }
  ' "$SCRIPT"
}

extract_workflow_app_filter() {
  awk '
    $0 == "            app:" { in_app = 1; next }
    in_app && $0 ~ /^            [A-Za-z0-9_-]+:/ { exit }
    in_app && $0 ~ /^[[:space:]]*-/ {
      line = $0
      sub(/^[[:space:]]*-[[:space:]]*/, "", line)
      gsub(/\047/, "", line)
      sub(/\/\*\*$/, "", line)
      print line
    }
  ' "$REPO_ROOT/.github/workflows/build-and-push.yml"
}

relay_go_dependency_paths() {
  local imports
  if ! imports=$(cd "$REPO_ROOT/endpoints" && go list -deps -f '{{.ImportPath}}' ./relay/main); then
    echo "go list relay dependencies failed" >&2
    return 1
  fi

  awk '
    /^github.com\/OpenNHP\/opennhp\/endpoints\// {
      sub(/^github.com\/OpenNHP\/opennhp\/endpoints\//, "")
      split($0, parts, "/")
      if (parts[1] != "") print "endpoints/" parts[1]
      next
    }
    /^github.com\/OpenNHP\/opennhp\/nhp(\/|$)/ {
      print "nhp"
      next
    }
    /^github.com\/layervai\/nhp\/internalauth(\/|$)/ {
      print "internalauth"
      next
    }
  ' <<< "$imports" | sort -u
}

relay_dockerfile_shared_docker_inputs() {
  {
    awk '
      /^[[:space:]]*COPY[[:space:]]+/ && $0 ~ /(^|[[:space:]])docker\// {
        for (i = 2; i < NF; i++) {
          if ($i ~ /^docker\//) print $i
        }
      }
    ' "$REPO_ROOT/docker/Dockerfile.relay"
    sed -nE 's|.*source=(docker/[^,[:space:]]+).*|\1|p' "$REPO_ROOT/docker/Dockerfile.relay"
  } | sort -u
}

tmpdir=$(mktemp -d)
origin_dir="${tmpdir}-origin.git"
shallow_dir="${tmpdir}-shallow"
trap 'rm -rf "$tmpdir" "$origin_dir" "$shallow_dir"' EXIT

git -C "$tmpdir" init -q
git -C "$tmpdir" config user.email test@example.com
git -C "$tmpdir" config user.name "Test User"

mkdir -p "$tmpdir/endpoints/server" "$tmpdir/endpoints/relay" "$tmpdir/terraform" "$tmpdir/docker"
printf 'old\n' > "$tmpdir/endpoints/server/forward.go"
printf 'old\n' > "$tmpdir/endpoints/relay/relay.go"
printf 'old\n' > "$tmpdir/terraform/main.tf"
printf 'old\n' > "$tmpdir/docker/ubuntu-apt-install-with-fallback.sh"
printf 'old\n' > "$tmpdir/.trivyignore"
git -C "$tmpdir" add .
git -C "$tmpdir" commit -q -m base
base=$(git -C "$tmpdir" rev-parse HEAD)

printf 'infra\n' > "$tmpdir/terraform/main.tf"
git -C "$tmpdir" add .
git -C "$tmpdir" commit -q -m infra-only
infra=$(git -C "$tmpdir" rev-parse HEAD)

printf 'app\n' > "$tmpdir/endpoints/server/forward.go"
git -C "$tmpdir" add .
git -C "$tmpdir" commit -q -m app-change
app=$(git -C "$tmpdir" rev-parse HEAD)

printf 'relay\n' > "$tmpdir/endpoints/relay/relay.go"
git -C "$tmpdir" add .
git -C "$tmpdir" commit -q -m relay-change
relay=$(git -C "$tmpdir" rev-parse HEAD)

printf 'mirror helper\n' > "$tmpdir/docker/ubuntu-apt-install-with-fallback.sh"
git -C "$tmpdir" add .
git -C "$tmpdir" commit -q -m mirror-helper-change
mirror_helper=$(git -C "$tmpdir" rev-parse HEAD)

printf 'ignore\n' > "$tmpdir/.trivyignore"
git -C "$tmpdir" add .
git -C "$tmpdir" commit -q -m trivyignore-change
trivyignore=$(git -C "$tmpdir" rev-parse HEAD)

run_case() {
  local name="$1" want="$2"
  shift 2
  local out rc
  out=$(cd "$tmpdir" && "$SCRIPT" "$@" 2>&1)
  rc=$?
  if [[ "$rc" -eq 0 && "$out" == *"app_image_required=$want"* ]]; then
    report_pass "$name"
  else
    report_fail "$name" "rc=$rc output='$out' want app_image_required=$want"
  fi
}

run_reason_case() {
  local name="$1" want="$2" reason="$3"
  shift 3
  local out rc
  out=$(cd "$tmpdir" && "$SCRIPT" "$@" 2>&1)
  rc=$?
  if [[ "$rc" -eq 0 && "$out" == *"app_image_required=$want"* && "$out" == *"$reason"* ]]; then
    report_pass "$name"
  else
    report_fail "$name" "rc=$rc output='$out' want app_image_required=$want and reason containing '$reason'"
  fi
}

run_error_case() {
  local name="$1" reason="$2"
  shift 2
  local out rc
  out=$(cd "$tmpdir" && "$SCRIPT" "$@" 2>&1)
  rc=$?
  if [[ "$rc" -ne 0 && "$out" == *"$reason"* ]]; then
    report_pass "$name"
  else
    report_fail "$name" "rc=$rc output='$out' want error containing '$reason'"
  fi
}

run_git_diff_failure_case() {
  local name="git diff errors fail loud instead of masquerading as drift"
  local wrapper_dir="$tmpdir/git-wrapper"
  local real_git out rc

  real_git=$(command -v git)
  mkdir -p "$wrapper_dir"
  cat > "$wrapper_dir/git" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [[ "\${1:-}" == "diff" ]]; then
  echo "fatal: simulated diff failure" >&2
  exit 128
fi
exec "$real_git" "\$@"
EOF
  chmod +x "$wrapper_dir/git"

  out=$(cd "$tmpdir" && PATH="$wrapper_dir:$PATH" "$SCRIPT" "$app" "server=$base" 2>&1)
  rc=$?
  if [[ "$rc" -ne 0 && "$out" == *"git diff failed for server active image tag"* && "$out" == *"simulated diff failure"* ]]; then
    report_pass "$name"
  else
    report_fail "$name" "rc=$rc output='$out' want git diff failure to fail loud"
  fi
}

run_subdir_case() {
  local name="subdirectory caller resolves pathspecs from repo root"
  local out rc

  out=$(cd "$tmpdir/endpoints" && "$SCRIPT" "$app" "server=$base" 2>&1)
  rc=$?
  if [[ "$rc" -eq 0 && "$out" == *"app_image_required=true"* ]]; then
    report_pass "$name"
  else
    report_fail "$name" "rc=$rc output='$out' want app_image_required=true"
  fi
}

run_shallow_fetch_case() {
  local name="shallow checkout fetches missing active tag before diffing"
  local out rc

  rm -rf "$origin_dir" "$shallow_dir"
  git clone --bare "$tmpdir" "$origin_dir" >/dev/null 2>&1
  git -C "$origin_dir" config uploadpack.allowReachableSHA1InWant true
  git clone --depth=1 "file://$origin_dir" "$shallow_dir" >/dev/null 2>&1

  out=$(cd "$shallow_dir" && "$SCRIPT" "$trivyignore" "server=$relay" 2>&1)
  rc=$?
  if [[ "$rc" -eq 0 && "$out" == *"app_image_required=true"* ]]; then
    report_pass "$name"
  else
    report_fail "$name" "rc=$rc output='$out' want app_image_required=true"
  fi
}

echo "Running resolve-app-image-required tests..."

workflow_app_filter=$(extract_workflow_app_filter)
server_ac_paths=$(extract_script_array SERVER_AC_IMAGE_PATHS)
relay_paths=$(extract_script_array RELAY_IMAGE_PATHS)
relay_deps=$(relay_go_dependency_paths)
relay_deps_rc=$?
relay_required_inputs=$'endpoints/go.mod\nendpoints/go.sum\ndocker/Dockerfile.relay\ndocker/ubuntu-apt-install-with-fallback.sh\nMakefile\n.trivyignore'
relay_shared_docker_inputs=$(relay_dockerfile_shared_docker_inputs)

assert_non_empty "workflow app filter extraction is non-empty" "$workflow_app_filter"
assert_non_empty "server/ac image path extraction is non-empty" "$server_ac_paths"
assert_multiline_equals "server/ac image paths mirror workflow app filter" \
  "$workflow_app_filter" \
  "$server_ac_paths"
assert_non_empty "relay image path extraction is non-empty" "$relay_paths"
if [[ "$relay_deps_rc" -eq 0 ]]; then
  assert_non_empty "relay go dependency extraction is non-empty" "$relay_deps"
  assert_lines_contain_all "relay image paths cover go dependency surface" "$relay_paths" "$relay_deps"
else
  report_fail "relay go dependency extraction is non-empty" "go list failed"
fi
assert_lines_contain_all "relay image paths include Dockerfile and build inputs" "$relay_paths" "$relay_required_inputs"
assert_non_empty "relay Dockerfile shared docker/ input extraction is non-empty" "$relay_shared_docker_inputs"
assert_lines_contain_all "relay image paths cover shared docker/ inputs" "$relay_paths" "$relay_shared_docker_inputs"

run_case "same app tree after infra-only commit does not require image" \
  false "$infra" "server=$base" "ac=$base"

run_case "tag equal to HEAD does not require image" \
  false "$app" "server=$app" "ac=$app"

run_case "app change since active tag requires image" \
  true "$app" "server=$base" "ac=$base"

run_case "any lagging component requires image" \
  true "$app" "server=$app" "ac=$base"

run_case "unknown active tag requires image" \
  true "$app" "server=unknown" "ac=$app"

run_case "non-sha active tag requires image" \
  true "$app" "server=sandbox" "ac=$app"

run_reason_case "short active tag requires full commit ID" \
  true "not a git SHA" "$app" "server=0123456" "ac=$app"

run_case "missing active commit requires image" \
  true "$app" "server=0123456789abcdef0123456789abcdef01234567" "ac=$app"

run_reason_case "64-character object IDs reach commit availability check" \
  true "not available as a git commit" "$app" \
  "server=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" "ac=$app"

run_case "relay ignores server-only endpoint changes" \
  false "$app" "relay=$base"

run_case "relay source change requires relay image" \
  true "$relay" "relay=$base"

run_case "relay mirror helper change requires relay image" \
  true "$mirror_helper" "relay=$relay"

run_case ".trivyignore change requires image" \
  true "$trivyignore" "server=$relay" "ac=$relay" "relay=$relay"

run_reason_case "target older than active app tag requires target image" \
  true "has app paths that differ from target" "$base" "server=$app"

run_error_case "unknown component fails loud" \
  "unknown app image component 'sever'" "$app" "sever=$base"

run_git_diff_failure_case
run_subdir_case
run_shallow_fetch_case

echo ""
echo "Passed: $pass"
echo "Failed: $fail"
if [[ "$fail" -gt 0 ]]; then
  printf '\nFailures:\n%b' "$failures"
  exit 1
fi
