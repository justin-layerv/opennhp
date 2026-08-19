#!/bin/sh
# Install Ubuntu runtime packages from the pinned base image's official sources,
# with one clean retry against Canonical's Azure-local mirror. Update + install
# share a wall-clock budget so a slow index or package fetch really falls back.

set -eu

sources_file=${NHP_UBUNTU_SOURCES_FILE:-/etc/apt/sources.list.d/ubuntu.sources}
apt_lists_dir=${NHP_APT_LISTS_DIR:-/var/lib/apt/lists}

fail() {
    echo "ERROR: ubuntu apt mirror fallback: $*" >&2
    exit 1
}

validate_packages() {
    [ "$#" -gt 0 ] || fail "at least one package is required"
    for package in "$@"; do
        case "$package" in
            ""|-*|*[!A-Za-z0-9.+:~=_-]*)
                fail "invalid package argument: $package"
                ;;
        esac
    done
}

validate_packages "$@"

# The server image has the tightest build-and-scan job budget at 15 minutes.
# Two full attempts plus TERM-to-KILL escalation consume at most 370 seconds,
# leaving more than half that job for compilation, SBOM generation, and Trivy.
attempt_timeout=${NHP_APT_ATTEMPT_TIMEOUT_SECONDS:-180}
kill_after=${NHP_APT_KILL_AFTER_SECONDS:-5}
case "$attempt_timeout" in
    ""|*[!0-9]*) fail "attempt timeout must be an integer number of seconds" ;;
esac
case "$kill_after" in
    ""|*[!0-9]*) fail "kill-after timeout must be an integer number of seconds" ;;
esac
if [ "$attempt_timeout" -lt 1 ] || [ "$attempt_timeout" -gt 180 ]; then
    fail "attempt timeout must be between 1 and 180 seconds"
fi
if [ "$kill_after" -lt 1 ] || [ "$kill_after" -gt 10 ]; then
    fail "kill-after timeout must be between 1 and 10 seconds"
fi
command -v timeout >/dev/null 2>&1 || fail "GNU timeout is required"
command -v setsid >/dev/null 2>&1 || fail "setsid is required"

if [ ! -f "$sources_file" ] || [ -L "$sources_file" ]; then
    fail "sources file must be a regular non-symlink: $sources_file"
fi
if [ ! -d "$apt_lists_dir" ] || [ -L "$apt_lists_dir" ]; then
    fail "apt lists directory must be a real directory, not a symlink: $apt_lists_dir"
fi
case "$apt_lists_dir" in
    ""|/|/var|/var/lib)
        fail "refusing unsafe apt lists directory: $apt_lists_dir"
        ;;
esac

# The primary must be the exact official source set from the pinned base, not an
# operator-provided third-party mirror. Parse only active deb822 URIs fields
# (never comments), allow http/https and a cosmetic trailing slash, and reject
# duplicates or additional repositories before any network access.
archive_count=0
security_count=0
ports_count=0
uris=$(awk '/^[[:space:]]*URIs:[[:space:]]+/ { for (i = 2; i <= NF; i++) print $i }' "$sources_file")
[ -n "$uris" ] || fail "pinned base has no active Ubuntu URIs"
for uri in $uris; do
    normalized=${uri%/}
    case "$normalized" in
        http://archive.ubuntu.com/ubuntu|https://archive.ubuntu.com/ubuntu)
            archive_count=$((archive_count + 1))
            ;;
        http://security.ubuntu.com/ubuntu|https://security.ubuntu.com/ubuntu)
            security_count=$((security_count + 1))
            ;;
        http://ports.ubuntu.com/ubuntu-ports|https://ports.ubuntu.com/ubuntu-ports)
            ports_count=$((ports_count + 1))
            ;;
        *)
            fail "pinned base has a non-official or unfamiliar Ubuntu URI: $uri"
            ;;
    esac
done

if [ "$archive_count" -eq 1 ] && [ "$security_count" -eq 1 ] && [ "$ports_count" -eq 0 ]; then
    source_mode=official_then_azure
elif [ "$archive_count" -eq 0 ] && [ "$security_count" -eq 0 ] && [ "$ports_count" -eq 2 ]; then
    # The pinned non-amd64 image has separate distribution and security stanzas
    # with the same ports.ubuntu.com URI. It has no Azure-local equivalent, so
    # that exact official source pair is the sole bounded attempt there.
    source_mode=official_ports
else
    fail "pinned base has an unfamiliar or mixed official source set"
fi

backup=$(mktemp "${TMPDIR:-/tmp}/nhp-ubuntu-sources.XXXXXX") ||
    fail "could not create sources backup"
rewritten=$(mktemp "${TMPDIR:-/tmp}/nhp-ubuntu-sources-rewritten.XXXXXX") || {
    rm -f -- "$backup"
    fail "could not create rewritten sources file"
}
attempt_group_file=$(mktemp "${TMPDIR:-/tmp}/nhp-ubuntu-apt-group.XXXXXX") || {
    rm -f -- "$backup" "$rewritten"
    fail "could not create attempt process-group file"
}
active_attempt_pgid=
active_timeout_pid=

terminate_attempt_group() {
    attempt_pgid=$1
    if ! kill -0 "-$attempt_pgid" 2>/dev/null; then
        return 0
    fi

    kill -TERM "-$attempt_pgid" 2>/dev/null || true
    remaining=$kill_after
    while [ "$remaining" -gt 0 ] && kill -0 "-$attempt_pgid" 2>/dev/null; do
        sleep 1
        remaining=$((remaining - 1))
    done
    if kill -0 "-$attempt_pgid" 2>/dev/null; then
        kill -KILL "-$attempt_pgid" 2>/dev/null || true
    fi

    # KILL is asynchronous. Give the container's reaper one short, bounded
    # window to remove the targeted group before any fallback touches dpkg.
    checks=10
    while [ "$checks" -gt 0 ] && kill -0 "-$attempt_pgid" 2>/dev/null; do
        sleep 0.1
        checks=$((checks - 1))
    done
    ! kill -0 "-$attempt_pgid" 2>/dev/null
}

cleanup() {
    if [ -n "$active_attempt_pgid" ]; then
        terminate_attempt_group "$active_attempt_pgid" ||
            echo "ERROR: ubuntu apt mirror fallback: active package process group survived cleanup" >&2
        active_attempt_pgid=
    fi
    if [ -n "$active_timeout_pid" ]; then
        kill -TERM "$active_timeout_pid" 2>/dev/null || true
        wait "$active_timeout_pid" 2>/dev/null || true
        active_timeout_pid=
    fi
    rm -f -- "$backup" "$rewritten" "$attempt_group_file"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
cp -- "$sources_file" "$backup" || fail "could not back up official sources"

run_bounded_attempt() {
    mode=$1
    shift
    case "$mode" in
        normal)
            attempt='apt-get \
                -o Acquire::Retries=3 \
                -o Acquire::http::Timeout=30 \
                -o Acquire::https::Timeout=30 \
                -o APT::Update::Error-Mode=any \
                update && \
            apt-get \
                -o Acquire::Retries=3 \
                -o Acquire::http::Timeout=30 \
                -o Acquire::https::Timeout=30 \
                install -y "$@"'
            ;;
        repair)
            # A killed apt invocation can leave dpkg's journal requiring
            # explicit configuration before apt can repair dependencies. Let
            # that best-effort pass fail into --fix-broken; the whole sequence
            # remains bounded here and the caller enforces a clean final audit.
            attempt='dpkg --configure -a || true
            apt-get \
                -o Acquire::Retries=3 \
                -o Acquire::http::Timeout=30 \
                -o Acquire::https::Timeout=30 \
                -o APT::Update::Error-Mode=any \
                update && \
            apt-get \
                -o Acquire::Retries=3 \
                -o Acquire::http::Timeout=30 \
                -o Acquire::https::Timeout=30 \
                --fix-broken install -y "$@"'
            ;;
        *)
            fail "invalid attempt mode"
            ;;
    esac
    : >"$attempt_group_file"
    attempt_rc=0
    active_attempt_pgid=
    # The quoted supervisor body is intentionally expanded only by its child
    # shells. The attempt stops before execution until the supervisor verifies
    # that setsid made its PID the dedicated process-group ID.
    # shellcheck disable=SC2016
    timeout \
        --signal=TERM \
        "${attempt_timeout}s" \
        sh -eu -c '
            group_file=$1
            attempt=$2
            shift 2
            setsid sh -eu -c '\''
                kill -STOP "$$"
                attempt=$1
                shift
                exec sh -eu -c "$attempt" nhp-apt-attempt "$@"
            '\'' nhp-apt-session "$attempt" "$@" &
            attempt_pgid=$!
            trap '\''
                kill -KILL "$attempt_pgid" 2>/dev/null || true
                wait "$attempt_pgid" 2>/dev/null || true
                exit 143
            '\'' HUP INT TERM
            pgid_checks=100
            actual_pgid=
            attempt_state=
            while { [ "$actual_pgid" != "$attempt_pgid" ] ||
                    ! printf "%s" "$attempt_state" | grep -q T; } &&
                  [ "$pgid_checks" -gt 0 ]; do
                actual_pgid=$(ps -o pgid= -p "$attempt_pgid" 2>/dev/null | tr -d "[:space:]")
                attempt_state=$(ps -o stat= -p "$attempt_pgid" 2>/dev/null | tr -d "[:space:]")
                if [ "$actual_pgid" != "$attempt_pgid" ] ||
                   ! printf "%s" "$attempt_state" | grep -q T; then
                    sleep 0.01
                fi
                pgid_checks=$((pgid_checks - 1))
            done
            if [ "$actual_pgid" != "$attempt_pgid" ] ||
               ! printf "%s" "$attempt_state" | grep -q T; then
                kill -KILL "$attempt_pgid" 2>/dev/null || true
                wait "$attempt_pgid" 2>/dev/null || true
                exit 125
            fi
            printf "%s\n" "$attempt_pgid" >"$group_file"
            trap '\''
                kill -TERM "-$attempt_pgid" 2>/dev/null || true
                exit 143
            '\'' HUP INT TERM
            kill -CONT "$attempt_pgid"
            wait "$attempt_pgid"
        ' nhp-apt-supervisor "$attempt_group_file" "$attempt" "$@" &
    active_timeout_pid=$!

    group_wait_checks=100
    while [ ! -s "$attempt_group_file" ] &&
          kill -0 "$active_timeout_pid" 2>/dev/null &&
          [ "$group_wait_checks" -gt 0 ]; do
        sleep 0.01
        group_wait_checks=$((group_wait_checks - 1))
    done
    if [ ! -s "$attempt_group_file" ]; then
        wait "$active_timeout_pid" 2>/dev/null || attempt_rc=$?
        active_timeout_pid=
        fail "attempt process group was not established safely"
    fi

    attempt_pgid=$(cat "$attempt_group_file")
    case "$attempt_pgid" in
        ""|*[!0-9]*) fail "attempt process group was not recorded safely" ;;
    esac
    [ "$attempt_pgid" -gt 1 ] || fail "refusing unsafe attempt process group: $attempt_pgid"
    active_attempt_pgid=$attempt_pgid

    wait "$active_timeout_pid" || attempt_rc=$?
    active_timeout_pid=

    if [ "$attempt_rc" -eq 124 ]; then
        terminate_attempt_group "$attempt_pgid" ||
            fail "timed-out package attempt left its process group running"
        active_attempt_pgid=
        return 124
    fi
    if kill -0 "-$attempt_pgid" 2>/dev/null; then
        terminate_attempt_group "$attempt_pgid" ||
            fail "completed package attempt left its process group running"
        active_attempt_pgid=
        fail "package attempt exited while a descendant was still running"
    fi
    active_attempt_pgid=
    return "$attempt_rc"
}

dpkg_is_clean() {
    audit=$(dpkg --audit 2>&1) || {
        echo "WARNING: dpkg audit failed" >&2
        return 1
    }
    if [ -n "$audit" ]; then
        echo "WARNING: dpkg reports an incomplete package state:" >&2
        echo "$audit" >&2
        return 1
    fi
}

if [ "$source_mode" = official_ports ]; then
    ports_rc=0
    run_bounded_attempt normal "$@" || ports_rc=$?
    if [ "$ports_rc" -ne 0 ]; then
        case "$ports_rc" in
            124|137) fail "official ports.ubuntu.com package attempt timed out after ${attempt_timeout}s" ;;
            *) fail "official ports.ubuntu.com package installation failed" ;;
        esac
    fi
    dpkg_is_clean || fail "official ports install left an incomplete dpkg state"
    echo "Ubuntu packages installed from the official ports.ubuntu.com source"
    exit 0
fi

official_rc=0
run_bounded_attempt normal "$@" || official_rc=$?
if [ "$official_rc" -eq 0 ] && dpkg_is_clean; then
    echo "Ubuntu packages installed from the pinned official archive/security sources"
    exit 0
fi

case "$official_rc" in
    124|137) echo "WARNING: official Ubuntu package attempt timed out after ${attempt_timeout}s" >&2 ;;
esac
echo "WARNING: official Ubuntu package attempt failed; retrying once with azure.archive.ubuntu.com" >&2

# A failed or timed-out install may leave valid packages unpacked but
# unconfigured. The bounded supervisor has already sent TERM to the dedicated
# attempt group, escalated to KILL if needed, and verified that no lock holder
# remains. Drop cached archives and partial indexes, update from one coherent
# fallback, then let apt's fix-broken mode complete that dpkg transaction plus
# every requested package. A final dpkg audit must be empty.
apt-get clean || fail "could not clear cached packages before fallback"
rm -rf -- "${apt_lists_dir:?}"/*
sed \
    's|//archive.ubuntu.com|//azure.archive.ubuntu.com|g; s|//security.ubuntu.com|//azure.archive.ubuntu.com|g' \
    "$backup" >"$rewritten" || fail "could not select the Azure-local mirror"
cp -- "$rewritten" "$sources_file" || fail "could not install the Azure-local sources"
grep -Fq 'azure.archive.ubuntu.com' "$sources_file" ||
    fail "Azure mirror substitution did not change the sources file"
if grep -Eq '//(archive|security)\.ubuntu\.com' "$sources_file"; then
    fail "Azure mirror substitution left an official-source entry behind"
fi

azure_rc=0
run_bounded_attempt repair "$@" || azure_rc=$?
if [ "$azure_rc" -ne 0 ]; then
    case "$azure_rc" in
        124|137) fail "Azure fallback package attempt timed out after ${attempt_timeout}s" ;;
        *) fail "both official and Azure Ubuntu package attempts failed" ;;
    esac
fi
dpkg_is_clean || fail "fallback install left an incomplete dpkg state"

echo "Ubuntu packages installed from the azure.archive.ubuntu.com fallback"
