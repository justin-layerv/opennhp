#!/bin/sh
# Runs on a qurl-reverse-tunnel-server EC2 instance via SSM.
set -eu

DASHBOARD_PORT="${1:-}"
EXPECTED_IMAGE_TAG="${2:-}"
TARGET_ENVIRONMENT="${3:-}"

case "$DASHBOARD_PORT" in
  ''|*[!0-9]*)
    echo "dashboard port must be an integer TCP port from 1024 through 65535; got '$DASHBOARD_PORT'." >&2
    exit 1
    ;;
esac
DASHBOARD_PORT_DECIMAL="$DASHBOARD_PORT"
while [ "${DASHBOARD_PORT_DECIMAL#0}" != "$DASHBOARD_PORT_DECIMAL" ]; do
  DASHBOARD_PORT_DECIMAL="${DASHBOARD_PORT_DECIMAL#0}"
done
if [ -z "$DASHBOARD_PORT_DECIMAL" ]; then
  DASHBOARD_PORT_DECIMAL=0
fi
if [ "$DASHBOARD_PORT_DECIMAL" -lt 1024 ] || [ "$DASHBOARD_PORT_DECIMAL" -gt 65535 ]; then
  echo "dashboard port must be an integer TCP port from 1024 through 65535; got '$DASHBOARD_PORT'." >&2
  exit 1
fi

case "$TARGET_ENVIRONMENT" in
  prod|sandbox)
    ;;
  *)
    echo "target environment must be prod or sandbox; got '$TARGET_ENVIRONMENT'." >&2
    exit 1
    ;;
esac

# The workflow validates before SSM; keep this for ad-hoc SSM use of the script.
if [ -n "$EXPECTED_IMAGE_TAG" ]; then
  if [ "${#EXPECTED_IMAGE_TAG}" -ne 40 ] || printf "%s" "$EXPECTED_IMAGE_TAG" | grep -q "[^0-9a-f]"; then
    echo "expected image tag must be a full 40-character lowercase git SHA; got '$EXPECTED_IMAGE_TAG'." >&2
    exit 1
  fi
fi

# user_data installs jq/curl; Ubuntu coreutils supplies mktemp/timeout. Fail
# closed if the instance image changes and drops one of these probe tools.
for tool in jq curl mktemp timeout; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool is required for qurl-reverse-tunnel-server smoke" >&2
    exit 1
  fi
done

SERVERINFO_JSON="$(mktemp /tmp/qurl-rts-serverinfo.XXXXXX.json)"
VERSION_STDERR="$(mktemp /tmp/qurl-rts-version-stderr.XXXXXX.log)"
trap 'rm -f "$SERVERINFO_JSON" "$VERSION_STDERR"' EXIT

if ! systemctl is-active --quiet qurl-reverse-tunnel-server; then
  echo "qurl-reverse-tunnel-server service is not active" >&2
  systemctl status --no-pager --lines=20 qurl-reverse-tunnel-server >&2 || true
  exit 1
fi

BINARY=/opt/layerv/qurl-reverse-tunnel-server/nhp-frps
if [ ! -x "$BINARY" ]; then
  echo "qurl-reverse-tunnel-server binary not found at $BINARY" >&2
  exit 1
fi
VERSION_STATUS=0
# Version metadata is a stdout contract; stderr stays diagnostic-only so a
# startup warning cannot satisfy the git-commit parser below.
VERSION_OUTPUT="$(timeout 30 "$BINARY" --version 2>"$VERSION_STDERR")" || VERSION_STATUS=$?
if [ "$VERSION_STATUS" -ne 0 ]; then
  if [ "$VERSION_STATUS" -eq 124 ]; then
    echo "qurl-reverse-tunnel-server --version timed out after 30s for $BINARY" >&2
  else
    echo "qurl-reverse-tunnel-server --version failed for $BINARY with status=$VERSION_STATUS" >&2
    printf "%s\n" "$VERSION_OUTPUT" >&2
    cat "$VERSION_STDERR" >&2 || true
  fi
  exit 1
fi
VERSION_OUTPUT="$(printf "%s\n" "$VERSION_OUTPUT" | tr -d '\r')"
printf "%s\n" "$VERSION_OUTPUT"

if [ -n "$EXPECTED_IMAGE_TAG" ]; then
  # Source format: qurl-reverse-tunnel-server/internal/version.Full prints
  # `git commit: <short-or-full-lowercase-sha>`. Fail closed if it drifts.
  # Prod release images must expose a bare clean SHA; suffixes like `-dirty`
  # are rejected so promotion never proves an ambiguous build.
  # This assumes the QRtS image tag is the source commit SHA, matching
  # qurl-reverse-tunnel-server docker-publish.
  # Short version prefixes are accepted intentionally because the
  # promoted image tag is always the full 40-character source SHA.
  # The awk capture intentionally takes the whole field after `git commit: `;
  # any trailing annotation then fails the bare-SHA validation below.
  ACTUAL_COMMIT="$(printf "%s\n" "$VERSION_OUTPUT" | awk -F": " '/^git commit: / {print $2; exit}')"
  if [ -z "$ACTUAL_COMMIT" ]; then
    echo "expected git commit prefix for image tag $EXPECTED_IMAGE_TAG but --version did not print git commit" >&2
    exit 1
  fi
  if [ "${#ACTUAL_COMMIT}" -lt 7 ] || [ "${#ACTUAL_COMMIT}" -gt 40 ] || printf "%s" "$ACTUAL_COMMIT" | grep -q "[^0-9a-f]"; then
    echo "binary git commit '$ACTUAL_COMMIT' is not a bare lowercase SHA prefix" >&2
    exit 1
  fi
  case "$EXPECTED_IMAGE_TAG" in
    "$ACTUAL_COMMIT"*)
      echo "binary git commit $ACTUAL_COMMIT matches image tag $EXPECTED_IMAGE_TAG"
      ;;
    *)
      echo "binary git commit $ACTUAL_COMMIT does not match image tag $EXPECTED_IMAGE_TAG" >&2
      exit 1
      ;;
  esac
fi

echo "dashboard probe requires 200 + .version in prod; sandbox may accept HTTP 401 until dashboard credentials are passed through SSM"
CODE=000
DASHBOARD_MAX_ATTEMPTS=18
DASHBOARD_RETRY_DELAY_SECONDS=5
DASHBOARD_CURL_MAX_SECONDS=10
DASHBOARD_CURL_CONNECT_SECONDS=5
# 18 attempts with bounded curl calls and 5s inter-attempt delay leaves
# generous headroom under the 660s SSM executionTimeout.
ATTEMPT=1
while [ "$ATTEMPT" -le "$DASHBOARD_MAX_ATTEMPTS" ]; do
  : > "$SERVERINFO_JSON"
  CODE="$(curl -sS --max-time "$DASHBOARD_CURL_MAX_SECONDS" --connect-timeout "$DASHBOARD_CURL_CONNECT_SECONDS" -o "$SERVERINFO_JSON" -w "%{http_code}" "http://127.0.0.1:${DASHBOARD_PORT_DECIMAL}/api/serverinfo" || true)"
  case "$CODE" in
    200|401)
      break
      ;;
    000|5??|404)
      # 404 stays in the warmup set because the dashboard socket can bind
      # before `/api/serverinfo` is ready; a wrong route still fails closed
      # after the bounded retry budget.
      echo "dashboard status=$CODE warming attempt=$ATTEMPT/$DASHBOARD_MAX_ATTEMPTS"
      if [ "$ATTEMPT" -lt "$DASHBOARD_MAX_ATTEMPTS" ]; then
        sleep "$DASHBOARD_RETRY_DELAY_SECONDS"
      fi
      ;;
    4??)
      echo "dashboard status=$CODE is a terminal dashboard response"
      break
      ;;
    *)
      break
      ;;
  esac
  ATTEMPT=$((ATTEMPT + 1))
done

case "$CODE" in
  200)
    # The prod dashboard is currently unauthenticated (see user_data.sh.tpl
    # TODO(#1260)), so this is the live path. Keep the `.version` assertion:
    # it is the upstream FRP `/api/serverinfo` contract that proves the
    # dashboard served real server metadata instead of only accepting a socket.
    if ! jq -e \
      'type == "object" and (.version? | type == "string" and length > 0)' \
      "$SERVERINFO_JSON" >/dev/null; then
      echo "dashboard serverinfo JSON missing non-empty .version string" >&2
      cat "$SERVERINFO_JSON" >&2 || true
      exit 1
    fi
    ;;
  401)
    if [ "$TARGET_ENVIRONMENT" = "prod" ]; then
      echo "dashboard returned 401 in prod; expected unauthenticated 200 + .version until dashboard credentials are passed through SSM" >&2
      exit 1
    fi
    # TODO(#1260): when dashboard basic auth lands, pass credentials through
    # SSM and require authenticated 200 + `.version` instead of accepting a
    # generic sandbox 401.
    echo "dashboard API requires basic auth in sandbox - accepting 401 after service and binary checks"
    ;;
  000|5??|404)
    echo "dashboard never left warmup (last status=$CODE)" >&2
    if [ -s "$SERVERINFO_JSON" ]; then
      cat "$SERVERINFO_JSON" >&2 || true
    else
      echo "dashboard response body empty" >&2
    fi
    exit 1
    ;;
  *)
    echo "unexpected dashboard status=$CODE" >&2
    if [ -s "$SERVERINFO_JSON" ]; then
      cat "$SERVERINFO_JSON" >&2 || true
    else
      echo "dashboard response body empty" >&2
    fi
    exit 1
    ;;
esac

echo "qurl-reverse-tunnel-server smoke ok"
