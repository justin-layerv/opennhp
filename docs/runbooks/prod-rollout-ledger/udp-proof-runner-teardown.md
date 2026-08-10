# Remove Control's orphaned attended-UDP-proof gate inputs

The attended UDP proof was removed in #3799 (files only). Its runner root has
since been destroyed, its emptied Terraform state object deleted, and the
observability-parity exemption dropped. One governed task remains.

## Pre-rollout task

1. Remove the now-unused `proof_policy_*` dispatch inputs and their gate-file
   entries from the Control root. These are **governed** inputs; changing them
   requires the usual reviewed plan/apply with all gates supplied, and the
   colours must keep matching `.github/control-sandbox-runtime-gates.json`
   until both sides are removed together.

   Surfaces: the three `proof_policy_*` inputs in
   `.github/workflows/control-sandbox-update.yml`, their entries in
   `.github/control-sandbox-runtime-gates.json`, and the
   `authority_proof_policy_*` plumbing in
   `terraform/modules/connector-authority-foundation/`. Until this lands,
   `build-and-push.yml` fails closed on any proof-selector apply and points
   back at this task.

## Why it is not already done

It is a live-infrastructure change against a shared sandbox that other
developers deploy to continuously. It needs a reviewed plan and a sequenced
apply, not a bulk delete.

Delete this entry once the Control `proof_policy_*` inputs are gone.
