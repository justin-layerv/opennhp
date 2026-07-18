#!/usr/bin/env bash

set -euo pipefail

repository="${GITHUB_REPOSITORY:-}"
if [[ ! "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "ERROR: GITHUB_REPOSITORY must be an owner/repository pair" >&2
  exit 2
fi

if [[ -n "${GH_TOKEN:-}" ]] || [[ -n "${GITHUB_TOKEN:-}" ]]; then
  echo "::error::GitHub API token remains in the Terraform step environment"
  exit 1
fi

# Query effective config, not only .git/config. actions/checkout v7 stores its
# extraheader in a runner-temp file referenced through local includeIf entries;
# a --local query misses the live credential that git itself would still use.
if git config --get-regexp '^http\..*\.extraheader$' >/dev/null; then
  echo "::error::checkout HTTP authorization remains in effective git config"
  exit 1
else
  status=$?
  [[ "$status" -eq 1 ]] || exit "$status"
fi

# Reject even a dangling checkout-style include. Its condition may not match the
# current worktree during this check yet become active for a later git process.
if git config --local --name-only \
  --get-regexp '^includeif\.gitdir:.*\.path$' >/dev/null; then
  echo "::error::checkout credential include remains in local git config"
  exit 1
else
  status=$?
  [[ "$status" -eq 1 ]] || exit "$status"
fi

# actions/checkout's expected origin has no userinfo. Fence this separately so
# an embedded token cannot bypass both config checks.
origin_url="$(git remote get-url origin)"
case "$origin_url" in
  "https://github.com/$repository" | "https://github.com/$repository.git") ;;
  *)
    echo "::error::origin URL is not the credential-free GitHub repository URL"
    exit 1
    ;;
esac
