#!/usr/bin/env bash
# Compare the one-way NHP application-operation profiles used by the sandbox
# blue/green fleet. This is intentionally a closed list: an unknown profile
# must never be guessed newer at a protocol boundary.

set -euo pipefail

profile_order() {
  case "${1:-}" in
    legacy-aop-v1) printf '10\n' ;;
    durable-aop-v1) printf '20\n' ;;
    *)
      echo "unknown NHP application-operation profile: '${1:-}'" >&2
      return 2
      ;;
  esac
}

if [[ $# -lt 2 ]]; then
  echo "usage: $0 order <profile> | assert-at-least <candidate> <minimum> | record <profile> <image-tag> | assert-record <record> <profile> <image-tag>" >&2
  exit 2
fi

case "$1" in
  order)
    [[ $# -eq 2 ]] || exit 2
    profile_order "$2"
    ;;
  assert-at-least)
    [[ $# -eq 3 ]] || exit 2
    candidate_order=$(profile_order "$2")
    minimum_order=$(profile_order "$3")
    if ((candidate_order < minimum_order)); then
      echo "profile '$2' is below irreversible minimum '$3'" >&2
      exit 1
    fi
    ;;
  record)
    [[ $# -eq 3 && -n "$3" && "$3" != *'|'* ]] || exit 2
    profile_order "$2" >/dev/null
    printf 'v1|%s|%s\n' "$2" "$3"
    ;;
  assert-record)
    [[ $# -eq 4 ]] || exit 2
    expected=$($0 record "$3" "$4")
    if [[ "$2" != "$expected" ]]; then
      echo "slot profile record mismatch: got '$2', want '$expected'" >&2
      exit 1
    fi
    ;;
  *)
    echo "unknown command: '$1'" >&2
    exit 2
    ;;
esac
