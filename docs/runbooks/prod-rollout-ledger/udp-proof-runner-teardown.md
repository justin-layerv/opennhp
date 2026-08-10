# Tear down the orphaned attended-UDP-proof infrastructure

The attended UDP proof was removed in #3799 (files only). Its Terraform
**state was deliberately not touched**, because bundling a live-infra teardown
into a file deletion is how the Hub gets destroyed by accident.

## Pre-rollout tasks

1. ~~`terraform destroy` the `sandbox-udp-proof-runner` root.~~ **DONE
   2026-08-10:** `Apply complete! Resources: 0 added, 0 changed, 72 destroyed.`
   The plan was verified before applying — all 72 targets were
   `module.udp_proof_runner.*`, with nothing matching hub, authority, cell0 or
   cell1. The S3 state object for that root still exists (a destroy empties it,
   it does not delete the file); remove it if you want the orphan gone.
2. Remove the now-unused `proof_policy_*` dispatch inputs and their gate-file
   entries from the Control root. These are **governed** inputs; changing them
   requires the usual reviewed plan/apply with all gates supplied, and the
   colours must keep matching `.github/control-sandbox-runtime-gates.json`
   until both sides are removed together.
3. Drop the `sandbox-udp-proof-runner` exemption from
   `scripts/check-observability-parity.py` once the root is gone.

## Why the rest is not already done

Each of these is a live-infrastructure change against a shared sandbox that
other developers deploy to continuously. They need reviewed plans and a
sequenced apply, not a bulk delete.

Delete this entry once the destroy has been applied and the Control inputs are
gone.
