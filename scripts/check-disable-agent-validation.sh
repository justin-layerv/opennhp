#!/usr/bin/env bash
# check-disable-agent-validation.sh
# ----------------------------------------------------------------------------
# Fail if any committed config file in the prod path sets
# `DisableAgentValidation = true` (or its TOML/JSON-shaped variants).
#
# Why this exists (#1157 F9):
#
#   The `DisableAgentValidation` flag tells the NHP server to skip
#   agent static-pubkey validation entirely — the server trusts any
#   peer claiming to be an agent, no key check. It was added for
#   bring-up / dev parity and is set to `false` everywhere in
#   committed configs, but nothing structurally PREVENTS a future PR
#   from quietly flipping a prod config to `true`. If that happened,
#   the server would silently accept impersonated agents in prod —
#   no AAK rejection signal, no metric, no log, just an attacker
#   sending NHP_KNOCK requests as if they were a fleet agent and
#   landing inside the trust boundary.
#
#   This script is the structural fence: a one-sided edit to a prod
#   config that sets the flag true trips the lint at PR time, and
#   reviewers are forced to either revert or add an explicit
#   "this is the dev config and not deployed to prod" exception
#   (path-based, NOT a comment opt-out — opt-outs decay).
#
# Scope:
#
#   "Prod path" is defined as any of:
#     - `terraform/modules/compute/user_data.sh.tpl`        (deployed to prod ASG)
#     - `terraform/environments/prod/**`                    (prod tfvars / overrides)
#     - `terraform/environments/sandbox/**`                 (sandbox is also a deploy target)
#     - `docker/nhp-server/etc/config.toml`                 (image-baked default)
#
#   `endpoints/server/main/etc/config.toml` is the dev/test fixture
#   shipped in the source tree — NOT deployed. It's still in the
#   scan list as a defense-in-depth check (so a copy/paste bug
#   doesn't unset there either, since dev fixtures get copied into
#   deploys).
#
# Detection:
#
#   The check is intentionally string-based, not parser-based:
#     - Targets are TOML, HCL, and a shell heredoc (user_data.sh.tpl).
#     - All three formats use `DisableAgentValidation = <bool>`
#       syntax (TOML uses spaces, HCL uses `= true`, the shell
#       heredoc embeds TOML verbatim).
#     - A parser-based check would need three different parsers and
#       would still need to walk through Go templating in user_data
#       to resolve a value that's a literal here.
#
#   Whitespace-tolerant CASE-INSENSITIVE grep:
#     `DisableAgentValidation\s*=\s*true` (matched with -i; see the
#     long-form rationale on the grep line itself).
#
#   Comments are stripped before matching so a `# DisableAgentValidation
#   = true` doc line doesn't trip the gate.
#
# Usage:
#   ./scripts/check-disable-agent-validation.sh        # exit 0 in sync, 1 on violation
#   make lint                                          # wired into the lint target
#
# Dependencies: bash, grep, find, sed (POSIX baseline). No PyYAML or
# parser dependency — keeps the check runnable in a fresh CI image
# without a virtualenv setup step.
# ============================================================================

set -euo pipefail

# Paths to check. Each entry is either a literal file or a directory
# (recursively scanned for *.toml, *.tf, *.tfvars, *.tpl, *.sh).
#
# JSON is intentionally not in the find filter — the project uses TOML
# / HCL / shell-heredoc-TOML for server config today. If a JSON config
# path is ever added, extend BOTH the -name filter below AND the grep
# regex (the JSON shape is `"DisableAgentValidation"\s*:\s*true`,
# which the current TOML/HCL regex won't match). The Config struct
# already has json:"disableAgentValidation" tags, so a JSON decoder
# would parse the bool — which means the lint must follow.
#
# More generally: this is a hand-curated allowlist, not a deny-by-
# default scan. A future PR that introduces a NEW prod config path
# (a parallel image config, a new tf environment under
# terraform/environments/, etc.) without registering it here would
# silently bypass the lint. The "no candidate files found" guard
# below catches the all-paths-missing misconfiguration but NOT the
# new-path-not-listed case. When adding a new deployable config
# location, register it here in the same PR — and the reverse: a
# PR that retires a prod path from this list must also retire the
# config file (or the lint stops protecting it). Tracked at
# DEFAULT_PROD_PATHS-discipline as part of #1157 F9 acceptance.
#
# An optional override env var (DISABLE_AGENT_VALIDATION_SCAN_PATHS,
# colon-separated) replaces the default list. Used by the fixture
# suite under tests/lints/disable-agent-validation/ to exercise the
# script against synthetic config trees without polluting the real
# repo. NOT a production opt-out: a CI runner that sets this would
# silently bypass the check, so leaving it unset keeps the prod
# default authoritative.
DEFAULT_PROD_PATHS=(
	"terraform/modules/compute/user_data.sh.tpl"
	"terraform/environments/prod"
	"terraform/environments/sandbox"
	"docker/nhp-server/etc/config.toml"
	"endpoints/server/main/etc/config.toml"
)

if [[ -n "${DISABLE_AGENT_VALIDATION_SCAN_PATHS:-}" ]]; then
	IFS=':' read -r -a PROD_PATHS <<< "${DISABLE_AGENT_VALIDATION_SCAN_PATHS}"
	# When the env var is set we trust the caller's cwd — the
	# fixture suite drops the tempdir as cwd and uses relative
	# paths within it. Skip the script-relative cd below.
	REPO_ROOT="$(pwd)"
else
	PROD_PATHS=("${DEFAULT_PROD_PATHS[@]}")
	# Must run from repo root. Without this, a CI runner that
	# invokes the script via an absolute path from /home/runner/...
	# but with cwd elsewhere would silently scan zero files — which
	# would PASS this check and provide no signal. Anchor cwd by
	# resolving the script's location and `cd`'ing to its parent.
	SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
	REPO_ROOT="$(dirname "${SCRIPT_DIR}")"
	cd "${REPO_ROOT}"
fi

# Collect candidate files. Use a temp file to avoid command-line
# length limits on large repos.
CANDIDATES_TMP="$(mktemp)"
trap 'rm -f "${CANDIDATES_TMP}"' EXIT

for p in "${PROD_PATHS[@]}"; do
	if [[ -d "${p}" ]]; then
		find "${p}" -type f \
			\( -name '*.toml' -o -name '*.tf' -o -name '*.tfvars' \
			   -o -name '*.tpl' -o -name '*.sh' \) \
			>> "${CANDIDATES_TMP}"
	elif [[ -f "${p}" ]]; then
		echo "${p}" >> "${CANDIDATES_TMP}"
	fi
done

if [[ ! -s "${CANDIDATES_TMP}" ]]; then
	echo "check-disable-agent-validation: ERROR: no candidate files found." >&2
	echo "  This usually means the script is being run from outside the repo root," >&2
	echo "  or the prod-paths list is stale. Verify cwd is the repo root." >&2
	exit 1
fi

VIOLATIONS=0
while IFS= read -r f; do
	# Strip comments before matching:
	#   - '#' starts a line/inline comment in TOML and shell.
	#   - '//' starts a line/inline comment in HCL.
	# A simple sed pipe handles both.
	#
	# The strip is intentionally naive on '#' inside quoted TOML
	# strings (e.g., `description = "foo # bar"` becomes
	# `description = "foo `). For the current Config struct (no
	# string fields containing '#' in deployable configs) this is
	# moot, and the regex still requires `DisableAgentValidation =
	# true` to match — so the naive strip cannot manufacture a
	# false-positive, only mangle log output if the lint ever prints
	# stripped lines for triage. Don't replace with a TOML/HCL parser
	# unless a real call site emerges; the parser dependency is the
	# anti-pattern this script exists to avoid.
	#
	# Case-insensitive match (-i) is REQUIRED, not belt-and-suspenders:
	# pelletier/go-toml/v2 (this project's TOML decoder) matches keys
	# to Go struct fields case-insensitively when the field has no
	# `toml:` tag. Config.DisableAgentValidation is not toml-tagged,
	# so `disableagentvalidation = true` / `DISABLEAGENTVALIDATION =
	# true` / `disableAgentValidation = true` would all be parsed by
	# the runtime and set the bool — a case-sensitive lint would miss
	# the bypass entirely. Verified empirically with go-toml v2.3.0;
	# rerun the check from #1157 F9 review if the dependency moves.
	if sed -e 's|//.*||' -e 's|#.*||' "${f}" \
		| grep -E -i -q '^[[:space:]]*DisableAgentValidation[[:space:]]*=[[:space:]]*true([[:space:]]|$)'; then
		echo "VIOLATION: ${f} sets DisableAgentValidation=true (see #1157 F9)" >&2
		VIOLATIONS=$((VIOLATIONS + 1))
	fi
done < "${CANDIDATES_TMP}"

if [[ "${VIOLATIONS}" -gt 0 ]]; then
	echo "" >&2
	echo "check-disable-agent-validation: FAILED (${VIOLATIONS} violation(s))" >&2
	echo "" >&2
	echo "DisableAgentValidation=true disables agent static-pubkey validation" >&2
	echo "entirely. Setting it true in any deployable config is a security" >&2
	echo "regression: the server would accept any peer claiming to be an" >&2
	echo "agent, no key check. See #1157 F9 and the gate's docstring in" >&2
	echo "endpoints/server/config.go." >&2
	echo "" >&2
	echo "If you genuinely need this for a non-deploy fixture, the" >&2
	echo "fixture must NOT be in any path scanned by this script — move" >&2
	echo "it under tests/ (which is excluded), add a README explaining" >&2
	echo "why it's not deployed, and remove the offending file from" >&2
	echo "DEFAULT_PROD_PATHS at the top of this script if applicable." >&2
	exit 1
fi

echo "check-disable-agent-validation: OK (scanned $(wc -l < "${CANDIDATES_TMP}" | tr -d ' ') file(s))"
