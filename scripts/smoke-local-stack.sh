#!/usr/bin/env bash
# smoke-local-stack.sh up|down
# ----------------------------------------------------------------------------
# Bring up / tear down the self-contained local NHP stack
# (dynamodb-local + nhp-server) that the smoke suite's `local` target runs
# against. Driven by scripts/run-smoke.sh (TARGET=local) and by the
# `test-smoke-local` Makefile target.
#
#   up   - start dynamodb-local, wait for it, create the DynamoDB tables,
#          build+start nhp-server, wait for /health/live to go green.
#   down - stop and remove the stack (and its in-memory DynamoDB volume).
#
# Idempotent: `up` can run over an existing stack; table creation ignores
# "already exists". Requires Docker + the AWS CLI (both present on local dev
# machines and on GitHub's ubuntu-latest runners).
# ----------------------------------------------------------------------------

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STACK_DIR="${REPO_ROOT}/tests/smoke/local-stack"
COMPOSE_FILE="${STACK_DIR}/docker-compose.yaml"

DDB_ENDPOINT="${NHP_SMOKE_DDB_ENDPOINT:-http://localhost:8000}"
SERVER_HEALTH_URL="${NHP_SMOKE_SERVER_HEALTH_URL:-http://localhost:8888/health/live}"
SERVER_KNOCKREADY_URL="${NHP_SMOKE_SERVER_KNOCKREADY_URL:-http://localhost:8888/health/knock-ready}"
AWS_REGION_LOCAL="us-east-2"

# Local AC license. The AC's plaintext LicenseKey is the single source of
# truth in tests/smoke/local-stack/ac/etc/config.toml (the AC sends it in
# NHP_AOL); the server validates it against the row seeded below. These two
# constants are sha256(key) and bcrypt(key) of that plaintext — regenerate
# them if the config's LicenseKey changes (a mismatch fails the AC handshake
# loudly during `up`, so it cannot drift silently):
#   printf %s '<LicenseKey from ac/etc/config.toml>' | shasum -a256   # -> LICENSE_SHA256
#   # bcrypt (Go-compatible $2a$/$2b$), e.g. via golang.org/x/crypto/bcrypt
LICENSE_SHA256="f60002ae94e912e2434647d6fd350bc00bb89ce684b4700ba1cb7bc3bde83b94"
# Single quotes are intentional — the bcrypt hash contains literal $-segments
# ($2a$...) that must NOT undergo shell expansion.
# shellcheck disable=SC2016
LICENSE_BCRYPT='$2a$10$qvvW.q89uZSzqJsNAs.7tOh0fpV1rZrXQ/y.yrG7Df4jATAOAV1fC'

# dynamodb-local ignores credential values but the AWS CLI refuses to sign
# without them. Scope the dummies to this script's AWS CLI calls only.
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-dummy}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-dummy}"
export AWS_REGION="$AWS_REGION_LOCAL"

compose() { docker compose -f "$COMPOSE_FILE" "$@"; }

# Dump the tail of the server+AC container logs. Called when a bring-up
# wait_for times out (key mismatch, AC-registration failure, etc.) so a PR-CI
# failure is debuggable straight from the job log without re-running the stack.
dump_stack_logs() {
  echo "--- smoke-local-stack: nhp-server + nhp-ac logs (last 60 lines) ---" >&2
  compose logs --tail=60 nhp-server nhp-ac >&2 || true
}

ddb() {
  aws dynamodb "$@" --endpoint-url "$DDB_ENDPOINT" --region "$AWS_REGION_LOCAL" --output text
}

# Create one PAY_PER_REQUEST table with a single string hash key. Skips
# creation when the table already exists (describe-table precheck) so `up`
# is idempotent against a still-running dynamodb-local.
create_table() {
  local name="$1" pk="$2"
  if ddb describe-table --table-name "$name" >/dev/null 2>&1; then
    echo "  table $name already exists"
    return 0
  fi
  echo "  creating table $name (pk=$pk)"
  ddb create-table \
    --table-name "$name" \
    --attribute-definitions "AttributeName=${pk},AttributeType=S" \
    --key-schema "AttributeName=${pk},KeyType=HASH" \
    --billing-mode PAY_PER_REQUEST >/dev/null
}

# Create the composite-key durable session-control table plus its KEYS_ONLY
# due-work GSI. Correctness uses strong base-table PK/SK reads; the GSI exists
# only so the bounded recovery worker can discover due rows in the same shape
# as the cloud deployment.
create_session_control_table() {
  local name="nhp-session-control"
  if ddb describe-table --table-name "$name" >/dev/null 2>&1; then
    echo "  table $name already exists"
    return 0
  fi
  echo "  creating table $name (pk=pk, sk=sk, gsi=due-index)"
  ddb create-table \
    --table-name "$name" \
    --attribute-definitions \
      AttributeName=pk,AttributeType=S \
      AttributeName=sk,AttributeType=S \
      AttributeName=due_shard,AttributeType=S \
      AttributeName=due_sort,AttributeType=S \
    --key-schema \
      AttributeName=pk,KeyType=HASH \
      AttributeName=sk,KeyType=RANGE \
    --global-secondary-indexes '[{"IndexName":"due-index","KeySchema":[{"AttributeName":"due_shard","KeyType":"HASH"},{"AttributeName":"due_sort","KeyType":"RANGE"}],"Projection":{"ProjectionType":"KEYS_ONLY"}}]' \
    --billing-mode PAY_PER_REQUEST >/dev/null
}

# Seed an active, never-expiring license so the cloud-mode AC license check
# passes (permit mode accepts an unbound license, so no pubkey allowlist is
# needed). Idempotent: put-item overwrites.
seed_license() {
  echo "  seeding local AC license into nhp-licenses"
  ddb put-item --table-name nhp-licenses --item "{
    \"license_key_sha256\": {\"S\": \"${LICENSE_SHA256}\"},
    \"license_key_hash\": {\"S\": \"${LICENSE_BCRYPT}\"},
    \"active\": {\"BOOL\": true},
    \"expires_at\": {\"N\": \"0\"},
    \"max_acs\": {\"N\": \"10\"},
    \"customer_id\": {\"S\": \"local-smoke\"},
    \"tier\": {\"S\": \"local\"},
    \"created_at\": {\"N\": \"0\"},
    \"updated_at\": {\"N\": \"0\"}
  }" >/dev/null
}

wait_for() {
  local what="$1" tries="$2"; shift 2
  local i
  for ((i = 1; i <= tries; i++)); do
    if "$@" >/dev/null 2>&1; then
      echo "  $what ready (after ${i}s)"
      return 0
    fi
    sleep 1
  done
  echo "ERROR: $what not ready after ${tries}s" >&2
  return 1
}

up() {
  command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found" >&2; exit 2; }
  docker compose version >/dev/null 2>&1 || { echo "ERROR: 'docker compose' (v2) unavailable — this stack uses the v2 subcommand, not the legacy docker-compose v1 shim" >&2; exit 2; }
  command -v aws >/dev/null 2>&1 || { echo "ERROR: aws CLI not found (needed to create dynamodb-local tables)" >&2; exit 2; }

  # Fail fast if a bind-mounted config is missing. docker-compose mounts
  # ./server/etc and ./ac/etc read-only into the containers; if a host dir is
  # absent (e.g. a .gitignore rule silently dropped it from the commit) Docker
  # auto-creates it EMPTY and the daemon boots with no keys — the AC handshake
  # then fails and /health/knock-ready only times out 90s later with no hint
  # why. Surface it now as an immediate, actionable error.
  local cfg
  for cfg in "${STACK_DIR}/server/etc/config.toml" "${STACK_DIR}/ac/etc/config.toml"; do
    [ -f "$cfg" ] || {
      echo "ERROR: missing $cfg — its bind-mount would be empty (daemon starts with no key)." >&2
      echo "       Is it tracked? Check: git ls-files tests/smoke/local-stack/" >&2
      exit 2
    }
  done

  echo "smoke-local-stack: starting dynamodb-local..."
  compose up -d dynamodb-local
  wait_for "dynamodb-local" 60 ddb list-tables

  echo "smoke-local-stack: creating tables + seeding license..."
  # Partition keys must match endpoints/server/dynamodb_storage.go. The
  # startup Ping does a GetItem against ACAssignmentsTable, so it must exist
  # before the server starts or the server falls back to no-storage.
  create_table "nhp-ac-assignments" "ac_id"
  create_table "nhp-licenses" "license_key_sha256"
  create_table "nhp-resources" "resource_id"
  create_session_control_table
  seed_license

  echo "smoke-local-stack: building + starting nhp-server (first build is slow)..."
  compose up -d --build nhp-server
  wait_for "nhp-server /health/live" 120 curl -sf "$SERVER_HEALTH_URL" || { dump_stack_logs; exit 1; }

  echo "smoke-local-stack: building + starting nhp-ac..."
  compose up -d --build nhp-ac
  # knock-ready returns 200 only once the AC has registered (NHP_AOL ->
  # license check -> NHP_AAK) and shows up as a live AC peer.
  wait_for "nhp-server /health/knock-ready (AC registered)" 90 curl -sf "$SERVER_KNOCKREADY_URL" || { dump_stack_logs; exit 1; }

  echo "smoke-local-stack: up."
}

down() {
  echo "smoke-local-stack: tearing down..."
  compose down -v --remove-orphans || true
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *)
    echo "usage: $0 up|down" >&2
    exit 2
    ;;
esac
