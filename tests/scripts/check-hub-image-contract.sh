#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || -z "$1" ]]; then
  echo "usage: $0 <hub-image>" >&2
  exit 2
fi

image=$1
work_dir=$(mktemp -d)
volume="nhp-hub-config-contract-${RANDOM}-$$"
worker="nhp-hub-contract-${RANDOM}-$$"

cleanup() {
  docker rm -f "$worker" >/dev/null 2>&1 || true
  docker volume rm -f "$volume" >/dev/null 2>&1 || true
  rm -rf "$work_dir"
}
trap cleanup EXIT

fail() {
  echo "Hub image contract: $*" >&2
  exit 1
}

metadata=$(docker image inspect "$image")
image_platform=$(
  jq -r '.[0].Os + "/" + .[0].Architecture' <<<"$metadata"
)
run_image() {
  docker run --platform "$image_platform" "$@"
}

jq -e '.[0].Config.User == "65532:65532"' <<<"$metadata" >/dev/null ||
  fail "worker image user is not 65532:65532"
jq -e '.[0].Config.Entrypoint == ["/nhp-hub/nhp-hubd"]' <<<"$metadata" >/dev/null ||
  fail "unexpected entrypoint"
jq -e '.[0].Config.Cmd == ["run"]' <<<"$metadata" >/dev/null ||
  fail "unexpected default command"
jq -e '.[0].Config.Healthcheck.Test == ["CMD", "/nhp-hub/nhp-hubd", "healthcheck"]' \
  <<<"$metadata" >/dev/null || fail "healthcheck does not use the config-driven binary command"
jq -e '
  all(.[0].Config.Env[];
    (startswith("NHP_HUB_PUBLIC_CONFIG_JSON=") or
     startswith("NHP_HUB_PRIVATE_KEY_B64=") or
     startswith("NHP_HUB_ACTIVE_COOKIE_KEY_B64=") or
     startswith("NHP_HUB_PREVIOUS_COOKIE_KEY_B64=") or
     startswith("NHP_HUB_HEALTHCHECK_")) | not
  )
' <<<"$metadata" >/dev/null || fail "image bakes runtime config or duplicate health values into the environment"

if run_image --rm "$image" >"$work_dir/default.stdout" 2>"$work_dir/default.stderr"; then
  fail "placeholder config unexpectedly admitted the default worker"
fi
[[ ! -s "$work_dir/default.stdout" ]] || fail "failed default startup wrote stdout"
[[ $(<"$work_dir/default.stderr") == "connector hub: invalid process configuration" ]] ||
  fail "failed default startup did not return the closed config error"

docker volume create "$volume" >/dev/null

public_config='{"environment":"sandbox","udp_listen_addr":"0.0.0.0:62206","health_listen_addr":"0.0.0.0:62207","aws_region":"us-east-2","aws_account_id":"123456789012","issue_assignment_alias_arn":"arn:aws:lambda:us-east-2:123456789012:function:layerv-nhp-sandbox-ca-ia:blue","refresh_assignment_alias_arn":"arn:aws:lambda:us-east-2:123456789012:function:layerv-nhp-sandbox-ca-ra:blue","issue_credential_recovery_alias_arn":"arn:aws:lambda:us-east-2:123456789012:function:layerv-nhp-sandbox-ca-icr:blue","authority_lambda_timeout":"3s","handler_budget":"3100ms","packet_budget":"3500ms","response_reserve":"400ms","write_budget":"173ms","max_concurrent_packets":4,"packets_per_second":1,"packet_burst":4,"max_concurrent_per_peer":1,"response_queue_capacity":4}'
private_key='AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='
active_cookie_key='AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI='

run_image --rm \
  --user 0:0 \
  --mount "type=volume,src=$volume,dst=/nhp-hub/etc,volume-nocopy" \
  --env "NHP_HUB_PUBLIC_CONFIG_JSON=$public_config" \
  --env "NHP_HUB_PRIVATE_KEY_B64=$private_key" \
  --env "NHP_HUB_ACTIVE_COOKIE_KEY_B64=$active_cookie_key" \
  --env "NHP_HUB_PREVIOUS_COOKIE_KEY_B64=" \
  "$image" materialize-config \
  >"$work_dir/materialize.stdout" 2>"$work_dir/materialize.stderr" ||
  fail "one-shot config materialization failed"
[[ ! -s "$work_dir/materialize.stderr" ]] || fail "successful materialization wrote stderr"
grep -Eq '^config_sha256=sha256:[0-9a-f]{64}$' "$work_dir/materialize.stdout" ||
  fail "materialization output was not the bounded config digest"

config_digest=$(
  run_image --rm --user 0:0 \
    --mount "type=volume,src=$volume,dst=/nhp-hub/etc,readonly,volume-nocopy" \
    --entrypoint /usr/bin/sha256sum "$image" /nhp-hub/etc/hub.toml |
    awk '{print $1}'
)
[[ "config_sha256=sha256:$config_digest" == "$(<"$work_dir/materialize.stdout")" ]] ||
  fail "reported digest did not match the installed bytes"

# The single-quoted checks expand only inside the container shell.
# shellcheck disable=SC2016
run_image --rm --user 0:0 \
  --mount "type=volume,src=$volume,dst=/nhp-hub/etc,readonly,volume-nocopy" \
  --entrypoint /bin/bash "$image" -ceu '
    [[ $(stat -c "%a:%u:%g" /nhp-hub/etc/hub.toml) == "400:65532:65532" ]]
    [[ $(find /nhp-hub/etc -mindepth 1 -maxdepth 1 -printf "." | wc -c) == 1 ]]
  ' || fail "installed config ownership, mode, or single-file contract is wrong"

if run_image --rm \
  --user 0:0 \
  --mount "type=volume,src=$volume,dst=/nhp-hub/etc,volume-nocopy" \
  --env "NHP_HUB_PUBLIC_CONFIG_JSON=$public_config" \
  --env "NHP_HUB_PRIVATE_KEY_B64=$private_key" \
  --env "NHP_HUB_ACTIVE_COOKIE_KEY_B64=$active_cookie_key" \
  "$image" materialize-config \
  >"$work_dir/rewrite.stdout" 2>"$work_dir/rewrite.stderr"; then
  fail "materializer rewrote an existing config"
fi
[[ ! -s "$work_dir/rewrite.stdout" ]] || fail "refused rewrite wrote stdout"
[[ $(<"$work_dir/rewrite.stderr") == "connector hub: config materialization failed" ]] ||
  fail "refused rewrite did not return the closed materialization error"
after_digest=$(
  run_image --rm --user 0:0 \
    --mount "type=volume,src=$volume,dst=/nhp-hub/etc,readonly,volume-nocopy" \
    --entrypoint /usr/bin/sha256sum "$image" /nhp-hub/etc/hub.toml |
    awk '{print $1}'
)
[[ "$after_digest" == "$config_digest" ]] || fail "refused rewrite changed the installed config"

run_image --detach --name "$worker" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --network none \
  --mount "type=volume,src=$volume,dst=/nhp-hub/etc,readonly,volume-nocopy" \
  --env AWS_ACCESS_KEY_ID=contract-test \
  --env AWS_SECRET_ACCESS_KEY=contract-test \
  --env AWS_EC2_METADATA_DISABLED=true \
  "$image" >/dev/null

worker_metadata=$(docker inspect "$worker")
jq -e '
  .[0].Config.User == "65532:65532" and
  .[0].HostConfig.ReadonlyRootfs == true and
  any(.[0].Mounts[]; .Destination == "/nhp-hub/etc" and .RW == false) and
  all(.[0].Config.Env[];
    (startswith("NHP_HUB_PUBLIC_CONFIG_JSON=") or
     startswith("NHP_HUB_PRIVATE_KEY_B64=") or
     startswith("NHP_HUB_ACTIVE_COOKIE_KEY_B64=") or
     startswith("NHP_HUB_PREVIOUS_COOKIE_KEY_B64=")) | not
  )
' <<<"$worker_metadata" >/dev/null ||
  fail "long-lived worker received mutable config or init-only environment"

healthy=false
for _ in $(seq 1 30); do
  if [[ $(docker inspect --format '{{.State.Running}}' "$worker") != "true" ]]; then
    break
  fi
  if docker exec "$worker" /nhp-hub/nhp-hubd healthcheck >/dev/null 2>&1; then
    healthy=true
    break
  fi
  sleep 0.2
done
[[ "$healthy" == "true" ]] || {
  docker logs "$worker" >&2 || true
  fail "config-driven binary TCP healthcheck did not reach the running Hub listener"
}

docker stop --time 5 "$worker" >/dev/null
docker rm "$worker" >/dev/null
worker=

echo "Hub image contract verified: $image"
