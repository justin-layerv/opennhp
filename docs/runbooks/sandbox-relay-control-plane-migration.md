# Sandbox relay control-plane migration

This runbook applies PR #3143's Terraform ownership and private-key custody
changes to the existing sandbox relay. Production remains dark with
`deploy_relay=false`; there is no production relay fleet, production relay
traffic, or production rollout task in this change.

The sandbox relay is not customer-used and may be interrupted. The safeguards
below protect Terraform state, identity material, and verification quality—not
an availability commitment. After this migration, the existing sandbox fleet
will be replaced by the single DMZ fleet in the next PR.

## Before apply

1. Record the backend state lineage and serial from `terraform state pull`, plus
   the S3 state-object version ID. Save a live-backend sandbox plan artifact.
   Require the relay identity secret, image pin, canonical ASG parameter,
   certificate, validation record, and DNS alias to be address-only moves or
   in-place updates. Stop on replacement or destruction of any of those
   persistent resources.
2. Confirm the literal certificate-validation record key in the temporary
   `moved` block equals the configured sandbox `relay_dns_name`.
3. Validate the live `AWSCURRENT` relay keypair without printing private
   material. Record the public-key fingerprint and require it to remain
   unchanged after apply.
4. Confirm the plan creates the public-only relay-key SSM parameter and orders
   its validated publication before the server launch-template render.
5. Compare the complete production disabled plan on the branch with the same
   state and inputs on `origin/main`. Require identical resource/output changes,
   proving this PR adds no relay identity, image pin, ASG parameter, certificate,
   DNS, Lambda, IAM permission, server bootstrap, or fleet resource change even
   if unrelated production drift already exists.
6. Confirm the account can reserve the identity Lambda's single concurrency
   slot while retaining Lambda's required unreserved floor:

   ```bash
   UNRESERVED_CONCURRENCY=$(AWS_PROFILE=layerv AWS_REGION=us-east-2 \
     aws lambda get-account-settings \
       --query 'AccountLimit.UnreservedConcurrentExecutions' --output text)
   test "$UNRESERVED_CONCURRENCY" -ge 101
   ```

   Record the value with the saved-plan evidence. A lower value blocks the
   first apply; request quota/headroom rather than removing the serialization
   guard. On a partial-apply retry where the identity Lambda already reports
   `ReservedConcurrentExecutions=1`, require the post-reservation unreserved
   value to remain at least `100` instead of incorrectly requiring the same slot
   twice.

## Apply and converge

1. Apply the exact reviewed saved-plan artifact, not a newly generated plan.
   Stop if the identity publication invocation fails; do not substitute a
   placeholder or rotate the relay secret. Retain the recorded lineage, serial,
   and S3 version ID for partial-apply recovery.
2. Confirm the existing secret ARN and recorded public-key fingerprint are
   unchanged. Confirm the new public-only SSM parameter contains that key.
3. Save a second sandbox plan and require no remaining relay trust or server
   `user_data` diff.
4. Run the server-only blue/green deployment twice at the same active image tag
   so both server ASGs replace every instance. Terraform apply alone only
   publishes a launch-template version.
5. For every `InService` server instance, verify the configured launch-template
   version is current and `/opt/layerv/nhp-server/etc/relay.toml` contains only
   the expected public relay key(s). Confirm the server role and bootstrap
   contain no relay secret ARN/name or `secretsmanager:GetSecretValue` access.
6. Refresh through the unchanged canonical `/sandbox/nhp/relay/asg-name` target
   without advancing the image pin:

   ```bash
   relay_tag=$(AWS_PROFILE=layerv AWS_REGION=us-east-2 \
     aws ssm get-parameter \
       --name /sandbox/nhp/relay/image-tag \
       --query Parameter.Value --output text)
   AWS_PROFILE=layerv AWS_REGION=us-east-2 \
     .github/scripts/deploy-relay.sh sandbox false "$relay_tag"
   ```

   Wait for the helper's instance-refresh convergence result.
7. Run the controlled sandbox browser qURL relay flow and relay smoke test.

## Rollback

Revert the code and use reverse Terraform moves only if the apply did not rotate
or replace identity material. Keep the public-only parameter until all server
instances are confirmed back on the former bootstrap contract. Never regenerate
or overwrite the relay secret as a rollback shortcut.

## Temporary migration cleanup

After every applicable workspace/state has crossed the ownership move, state
proves every source address is gone, PR1 has replaced the fleet successfully,
and rollback to a pre-migration commit is no longer supported, remove the
one-time `moved` blocks and sandbox DNS-name pin. Do not remove them merely
because PR #3143 merged or one state snapshot no longer shows the source.
