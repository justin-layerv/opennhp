#!/usr/bin/env bash
# Is the sandbox ready for the attended UDP proof?
#
# The proof is slow, needs live AWS and a dedicated runner, and is gated on a
# human. So a precondition that broke hours earlier is discovered at the most
# expensive possible moment. Six producer runs died one-precondition-at-a-time in
# a single day, each on something that had been true for a while by then:
#
#   - runtime contract vs live image  an nhp deploy re-registers cell0 from a
#                                     MUTABLE short tag, so the governed contract
#                                     and the running image diverge on every apply
#   - ECS rolloutState                a service mid-roll is not "stably deployed"
#   - per-instance attestation        a freshly rolled instance has not attested
#                                     yet, and the proof requires exactly one
#                                     current attestation per running instance
#
# Running this on a schedule turns each of those into an alert minutes after it
# happens, instead of a failed proof run hours later. It is READ-ONLY: it
# diagnoses, it never mutates.
# shellcheck disable=SC2016
# Every single-quoted `...` in this file is JMESPath, not a shell command
# substitution. Expanding them would corrupt the query.
set -uo pipefail
export AWS_PAGER=""
export AWS_REGION="${AWS_REGION:-us-east-2}"
BUCKET=layerv-nhp-sandbox-runtime-attestations
fail=0

echo "=== 1. runtime contract == live image (both cells) ==="
for pair in "cell0:/sandbox/nhp/qurl-service/runtime-contract" "cell1:/sandbox-cell1/nhp/qurl-service/runtime-contract"; do
  cell="${pair%%:*}"; param="${pair#*:}"
  contract="$(aws ssm get-parameter --name "$param" --query 'Parameter.Value' --output text 2>/dev/null \
              | python3 -c 'import json,sys;print(json.load(sys.stdin).get("image_uri",""))' 2>/dev/null)"
  svc="layerv-nhp-sandbox-${cell}-qurl-api"
  td="$(aws ecs describe-services --cluster "$svc" --services "$svc" --query 'services[0].taskDefinition' --output text 2>/dev/null)"
  live="$(aws ecs describe-task-definition --task-definition "$td" \
          --query 'taskDefinition.containerDefinitions[?name==`qurl-api`].image' --output text 2>/dev/null)"
  if [ "$contract" = "$live" ] && [ -n "$contract" ]; then
    echo "  $cell OK (${td##*/})"
  else
    echo "  $cell DRIFT"; echo "    contract: ${contract:-<none>}"; echo "    live:     $live"; fail=1
  fi
done

echo "=== 2. services stably deployed ==="
for cell in cell0 cell1; do
  svc="layerv-nhp-sandbox-${cell}-qurl-api"
  read -r r d p n roll <<<"$(aws ecs describe-services --cluster "$svc" --services "$svc" \
    --query 'services[0].[runningCount,desiredCount,pendingCount,length(deployments),deployments[0].rolloutState]' --output text 2>/dev/null)"
  if [ "$r" = "$d" ] && [ "$p" = "0" ] && [ "$n" = "1" ] && [ "$roll" = "COMPLETED" ]; then
    echo "  $cell OK ($r/$d $roll)"
  else
    echo "  $cell NOT STABLE ($r/$d pending=$p deployments=$n rollout=$roll)"; fail=1
  fi
done

echo "=== 3. every running server instance has a current attestation ==="
while read -r id name prof; do
  [ -z "$id" ] && continue
  rid="$(aws iam get-instance-profile --instance-profile-name "${prof##*/}" \
         --query 'InstanceProfile.Roles[0].RoleId' --output text 2>/dev/null)"
  latest="$(aws s3api list-object-versions --bucket "$BUCKET" \
            --prefix "runtime/$rid:$id/latest.json" --max-keys 20 \
            --query 'length(Versions[?IsLatest==`true`])' --output text 2>/dev/null)"
  dels="$(aws s3api list-object-versions --bucket "$BUCKET" \
          --prefix "runtime/$rid:$id/latest.json" --max-keys 20 \
          --query 'length(DeleteMarkers[?IsLatest==`true`])' --output text 2>/dev/null)"
  if [ "${latest:-0}" = "1" ] && [ "${dels:-0}" = "0" ]; then
    printf "  %-22s %-38s OK\n" "$id" "$name"
  else
    printf "  %-22s %-38s MISSING (latest=%s deletes=%s)\n" "$id" "$name" "${latest:-0}" "${dels:-0}"; fail=1
  fi
done < <(aws ec2 describe-instances --filters "Name=instance-state-name,Values=running" \
  --query 'Reservations[].Instances[?IamInstanceProfile!=null].[InstanceId,Tags[?Key==`Name`].Value|[0],IamInstanceProfile.Arn]' \
  --output text 2>/dev/null | grep -iE 'server')

echo
[ "$fail" = 0 ] && echo "SANDBOX IS PROOF-READY" || echo "SANDBOX IS NOT PROOF-READY"
exit "$fail"
