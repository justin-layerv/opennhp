#!/usr/bin/env bash
#
# Read an OPTIONAL SSM parameter's value to stdout, classifying the AWS failure so a
# genuinely-absent parameter is a graceful skip while a real misconfiguration is loud.
#
#   parameter exists      -> prints its value, exit 0
#   ParameterNotFound     -> prints nothing,   exit 0   (caller treats empty as "absent")
#   any other AWS failure -> ::error:: to stderr, exit 1 (creds / IAM / region / throttle)
#   AWS_REGION unset      -> ::error:: to stderr, exit 2, before any AWS call
#
# `set -e` is deliberately omitted: `aws ssm get-parameter` exits non-zero on a missing
# parameter and we must inspect stderr to classify it rather than die on the exit code.
#
# Shared by workflows and composite actions that need an optional SSM value.
# Callers propagate every nonzero exit (1 hard AWS failure, 2 missing region) as a
# hard failure, and treat exit-0-with-empty-output as absent.
# Callers and downstream vendors must set AWS_REGION explicitly; this helper
# intentionally does not fall back to AWS_DEFAULT_REGION or profile config.
#
# Usage: bash scripts/ssm-read-optional.sh <parameter-name>
set -uo pipefail

name="${1:?usage: ssm-read-optional.sh <parameter-name>}"
region="${AWS_REGION:-}"

if [[ -z "$region" ]]; then
	echo "::error::AWS_REGION must be set before reading optional SSM parameter ${name}" >&2
	exit 2
fi

err_file="$(mktemp)"
trap 'rm -f "$err_file"' EXIT

if value="$(aws ssm get-parameter \
	--name "$name" \
	--query 'Parameter.Value' \
	--output text \
	--region "$region" 2>"$err_file")"; then
	printf '%s' "$value"
	exit 0
fi

# The AWS CLI emits the API error code in its message. ParameterNotFound is the only
# "soft" shape (absent -> skip); anything else (AccessDenied, ExpiredToken, throttling,
# network) hard-fails so a real misconfiguration is never mistaken for "not published".
if grep -q ParameterNotFound "$err_file"; then
	exit 0
fi

echo "::error::reading SSM parameter ${name} failed for a reason other than ParameterNotFound — investigate IAM / throttling / region / network before merging: $(cat "$err_file")" >&2
exit 1
