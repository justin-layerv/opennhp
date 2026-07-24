#!/usr/bin/env bash
# Terraform expands the single-quoted template placeholders before execution,
# and terminate is invoked through the EXIT trap below.
# shellcheck disable=SC2016,SC2317,SC2329
set -Eeuo pipefail
umask 077

# Never enable xtrace in this bootstrap. The one-time JIT configuration is read
# into a root-only file and handed directly to the runner without being logged.
exec > >(logger --tag udp-proof-bootstrap) 2>&1

install -d -m 0700 /run/udp-proof
install -d -m 0700 /var/lib/udp-proof

cat >/usr/local/sbin/udp-proof-teardown <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
rm -rf /run/udp-proof /opt/actions-runner/_work /var/lib/udp-proof/pcap
sync
shutdown -h now
EOF
chmod 0700 /usr/local/sbin/udp-proof-teardown

cat >/etc/systemd/system/udp-proof-deadline.service <<'EOF'
[Unit]
Description=Terminate the ephemeral UDP proof runner at its hard deadline

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/udp-proof-teardown
EOF

cat >/etc/systemd/system/udp-proof-deadline.timer <<'EOF'
[Unit]
Description=Hard boot-to-termination deadline for the UDP proof runner

[Timer]
OnBootSec=${max_runtime_minutes}min
AccuracySec=30s
Unit=udp-proof-deadline.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now udp-proof-deadline.timer

terminate() {
  local exit_code=$?
  trap - EXIT
  # Delegate to the shared teardown script (written above) so the reap set
  # lives in one place and the boot trap and deadline timer cannot drift.
  /usr/local/sbin/udp-proof-teardown || true
  exit "$exit_code"
}
trap terminate EXIT

retry_command() {
  local attempt
  for attempt in 1 2 3 4; do
    if "$@"; then
      return 0
    fi
    if [[ "$attempt" -eq 4 ]]; then
      return 1
    fi
    sleep "$((attempt * 5))"
  done
}

export DEBIAN_FRONTEND=noninteractive
# Ubuntu cloud images commonly ship regional archive entries as HTTP. Upgrade
# every APT source to HTTPS before the first refresh so bootstrap remains
# compatible with the security group's HTTPS-only package egress.
find /etc/apt -type f \( -name '*.list' -o -name '*.sources' \) \
  -exec sed -i 's|http://|https://|g' {} +
retry_command apt-get -o Acquire::Retries=4 update -qq
retry_command apt-get -o Acquire::Retries=4 install -y --no-install-recommends \
  awscli \
  ca-certificates \
  curl \
  docker.io \
  git \
  iproute2 \
  iptables \
  jq \
  libcap2-bin \
  tar \
  tcpdump
rm -rf /var/lib/apt/lists/*

systemctl enable --now docker
docker info >/dev/null
tc -Version >/dev/null
tcpdump --version >/dev/null

if ! id runner >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash runner
fi
usermod -aG docker runner

install -d -o runner -g runner -m 0700 /opt/actions-runner
install -d -o runner -g runner -m 0700 /var/lib/udp-proof/pcap

curl --fail --location --proto '=https' --tlsv1.2 \
  --retry 4 --retry-all-errors --connect-timeout 10 --max-time 300 \
  --output /run/udp-proof/actions-runner.tar.gz \
  '${runner_archive_url}'
echo '${runner_archive_sha256}  /run/udp-proof/actions-runner.tar.gz' | sha256sum --check --strict
tar --extract --gzip --file /run/udp-proof/actions-runner.tar.gz --directory /opt/actions-runner
rm -f /run/udp-proof/actions-runner.tar.gz
chown -R runner:runner /opt/actions-runner

# The runner install-dependency helper is part of the checksum-pinned archive.
retry_command /opt/actions-runner/bin/installdependencies.sh

# Packet capture is available to the disposable runner without a general sudo
# grant. Network emulation stays in explicit Docker containers launched with
# --cap-add=NET_ADMIN; the host qdisc is never modified by bootstrap.
setcap cap_net_admin,cap_net_raw=eip "$(command -v tcpdump)"
getcap "$(command -v tcpdump)" | grep -Eq 'cap_net_admin,cap_net_raw=eip|cap_net_raw,cap_net_admin=eip'

imds_token="$(retry_command curl --fail --silent --show-error --request PUT \
  --header 'X-aws-ec2-metadata-token-ttl-seconds: 300' \
  --max-time 5 http://169.254.169.254/latest/api/token)"
github_run_id="$(retry_command curl --fail --silent --show-error \
  --header "X-aws-ec2-metadata-token: $imds_token" \
  --max-time 5 http://169.254.169.254/latest/meta-data/tags/instance/GitHubRunId)"
github_run_attempt="$(retry_command curl --fail --silent --show-error \
  --header "X-aws-ec2-metadata-token: $imds_token" \
  --max-time 5 http://169.254.169.254/latest/meta-data/tags/instance/GitHubRunAttempt)"
unset imds_token

if [[ ! "$github_run_id" =~ ^[1-9][0-9]{0,19}$ ]] || [[ ! "$github_run_attempt" =~ ^[1-9][0-9]{0,9}$ ]]; then
  echo 'invalid GitHub run identity instance tags' >&2
  exit 1
fi

secret_id='${jit_secret_prefix}'"$github_run_id"/"$github_run_attempt"
fetch_jit_config() {
  aws --region '${aws_region}' \
    --cli-connect-timeout 10 \
    --cli-read-timeout 30 \
    secretsmanager get-secret-value \
    --secret-id "$secret_id" \
    --query SecretString \
    --output text > /run/udp-proof/jitconfig.tmp
}
retry_command fetch_jit_config
mv /run/udp-proof/jitconfig.tmp /run/udp-proof/jitconfig
chmod 0600 /run/udp-proof/jitconfig

jitconfig="$(< /run/udp-proof/jitconfig)"
jit_length="$(printf %s "$jitconfig" | wc -c)"
if (( jit_length < 32 || jit_length > 32768 )) || [[ ! "$jitconfig" =~ ^[A-Za-z0-9_+/=-]+$ ]]; then
  echo 'JIT runner configuration failed its bounded encoding contract' >&2
  exit 1
fi

# The JIT payload is single-use. Delete its backing secret before any repository
# job can run; the local root-only copy is removed immediately after process
# startup and again by every teardown path.
delete_jit_secret() {
  local error_file=/run/udp-proof/delete-secret.err
  if aws --region '${aws_region}' \
    --cli-connect-timeout 10 \
    --cli-read-timeout 30 \
    secretsmanager delete-secret \
    --secret-id "$secret_id" \
    --force-delete-without-recovery >/dev/null 2>"$error_file"; then
    rm -f "$error_file"
    return 0
  fi

  # A lost success response makes the retry observe an already-deleted secret.
  # Treat only that exact idempotent outcome as success; every other AWS error
  # remains retryable and ultimately fail-closed before the repository job.
  if grep -q 'ResourceNotFoundException' "$error_file"; then
    rm -f "$error_file"
    return 0
  fi
  cat "$error_file" >&2
  return 1
}
retry_command delete_jit_secret

rm -f /run/udp-proof/jitconfig

cd /opt/actions-runner
set +e
runuser --user runner -- ./run.sh --jitconfig "$jitconfig"
runner_exit=$?
set -e
unset jitconfig

exit "$runner_exit"
