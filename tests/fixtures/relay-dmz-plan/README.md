# Relay DMZ Terraform plan fixtures

`sandbox-refresh-false-shapes.json` is a sanitized schema slice of a real
sandbox plan captured on 2026-07-10 with the workflow-pinned Terraform 1.14.3.
The source JSON SHA-256 was
`4221c9b816bcc6e1a104574f23afa8fcb24dd57f2e33abf38fe4aaf8779f4422`.
The saved plan selected AWS provider 6.54.0. The fixture metadata records the
Terraform and provider versions.

Committing the sandbox dependency lock is intentional and broader than this
checker: it pins every normal sandbox Terraform run to the exact provider
selections CI resolved for this capture (including AWS 6.54.0) until an
explicit reviewed lock update. That shared pin is what makes the fixture's
provider-shape provenance enforceable rather than advisory.
The lock records package hashes for CI Linux plus Intel/Apple macOS and Windows
developer hosts, so a normal local `terraform init` does not rewrite this
provenance anchor merely because it ran on another supported platform. Refresh
the platform set together with any reviewed provider-lock update:

```sh
terraform -chdir=terraform/environments/sandbox providers lock \
  -platform=linux_amd64 -platform=darwin_amd64 \
  -platform=darwin_arm64 -platform=windows_amd64
```

`make lint-workflows` gracefully skips the Terraform-executing prod hard-stop
and fixture tests when Terraform is absent. A green local run is therefore not
full parity with CI unless Terraform is installed. Before review, run the exact
CI posture explicitly:

```sh
REQUIRE_TERRAFORM=1 python3 tests/scripts/test_check_relay_dmz_plan.py
```

The source was produced with the PR-plan mode and then rendered as JSON:

```sh
terraform -chdir=terraform/environments/sandbox plan \
  -refresh=false -lock=false -out=tfplan
terraform -chdir=terraform/environments/sandbox show -json tfplan > tfplan.json
```

The committed fixture keeps the nine real relay-network subnet changes, all
eight interface-endpoint private-DNS shapes, telemetry-key rotation, the relay
ALB/ASG and launch-template fields, a durable no-op secret with its pending
`previous_address`, and the nested subnet and route-table-association
configuration shapes used by the checker. Unique IDs, user data, policies,
unrelated resources, and potentially sensitive values were removed. Raw plan or
state JSON must never be committed.

The fixture test deliberately checks the assumptions that prompted the capture:
all nine `map_public_ip_on_launch` values are concrete `false`, the launch
template's `associate_public_ip_address` is concrete `"false"`, their
`after_unknown` entries do not mark those fields unknown, no-op resources remain
active, the state-move source address survives parsing, and nested configuration
modules resolve. The synthetic full-plan fixture remains responsible for the
complete positive contract and mutation coverage.

Refresh and revalidate this fixture whenever either the pinned Terraform
version or the AWS provider version changes in a way that may alter plan-JSON
shape. Treat **every AWS provider version bump**, including minor and patch
updates, as a reference-shape recapture/revalidation event; a Terraform or
AWS-provider major bump always requires a fresh committed slice. Capture a new
real `-refresh=false` plan with the workflow-pinned toolchain.
`test_sanitized_fixture_toolchain_provenance_is_current` discovers every
workflow-level `TF_VERSION` pin across `.github/workflows/*.yml` and
`.github/workflows/*.yaml` and requires all of them to match the fixture capture.
This deliberately means even an otherwise unrelated workflow Terraform bump
fails the relay fixture provenance test: recapture or revalidate the relay slice
with the new common pin rather than weakening the broad toolchain coupling. The
test also requires the recorded AWS provider version to match the committed
sandbox dependency lock. Sanitize the selected capture, update the capture
date/source SHA/toolchain metadata above, and inspect the `after_unknown` and
configuration `references` shapes before running the full checker suite. Never
mechanically edit the fixture to satisfy a failing test.

The workflow-pinned 1.14.3 capture was also compared with a Terraform 1.15.7
rendering over the same focused target set. All 149 relay-relevant resource
addresses and recursive
`after`/`after_unknown` key/type shapes matched; all 352 configuration-reference
paths and values matched; and all 13 relay `previous_address` entries matched.
The checker passed the 1.14.3 JSON. Both raw plans remained uncommitted because
they contain sensitive state-derived values.

PR #3151 intentionally tests the otherwise-inert checker but does not invoke it
against a live plan or classify checker-only edits for a credentialed plan. PR
#3150 exclusively owns that classifier registration, the sandbox PR-plan and
saved-plan pre-apply wiring, and the replacement runbook. That integrated PR plan
provides credentialed live end-to-end coverage against the real full plan in
`.github/workflows/terraform-plan-pr.yml`; its saved-plan pre-apply counterpart
lives in `.github/workflows/build-and-push.yml`. The PR-time invocation
intentionally runs the checker without
`--allow-disabled`: after the atomic DMZ integration, `deploy_relay=false` must
not turn the security check green. `--allow-disabled` is reserved for an
explicit relay-dark/bootstrap caller. `--require-pr0-applied` is reserved for
the final saved-plan pre-apply gate, where pending moves and unresolved critical
policies are blockers.

The #3150 integration handoff and replacement runbook must carry the same
every-provider-bump recapture/revalidation rule so a minor or patch upgrade
cannot be treated as routine dependency churn before this checker runs.

A sanitized full-plan fixture is deliberately not committed: the raw full plan
contains state-derived secrets, while fully sanitizing its broad, high-churn
surface would duplicate the synthetic contract without preserving useful values.
The committed slice instead retains only the provider/configuration shapes that
the synthetic complete positive plan cannot prove empirically.
