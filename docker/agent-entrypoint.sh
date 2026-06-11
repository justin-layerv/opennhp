#!/bin/sh
set -eu

cert_dir="${NHP_AGENT_CERT_DIR:-/nhp-agent/etc/certs}"
cert_file="${NHP_AGENT_CERT_FILE:-${cert_dir}/server.crt}"
key_file="${NHP_AGENT_KEY_FILE:-${cert_dir}/server.key}"

require_san() {
	printf '%s\n' "$2" | tr ',' '\n' | sed 's/^[[:space:]]*//' | grep -Fx -- "$1" >/dev/null
}

cert_has_expected_identity() {
	subject=$(openssl x509 -in "$cert_file" -noout -subject -nameopt RFC2253 2>/dev/null) || return 1
	case "$subject" in
	subject=CN=localhost) ;;
	*) return 1 ;;
	esac

	cert_sans=$(openssl x509 -in "$cert_file" -noout -ext subjectAltName 2>/dev/null) || return 1
	require_san "DNS:localhost" "$cert_sans" || return 1
	require_san "DNS:loginlocal.opennhp.org" "$cert_sans" || return 1
	require_san "IP Address:127.0.0.1" "$cert_sans" || return 1
	require_san "IP Address:0:0:0:0:0:0:0:1" "$cert_sans" || require_san "IP Address:::1" "$cert_sans" || return 1
}

cert_pair_ready() {
	[ -s "$cert_file" ] && [ -s "$key_file" ] || return 1
	openssl x509 -in "$cert_file" -checkend 0 -noout >/dev/null 2>&1 || return 1
	cert_has_expected_identity || return 1

	cert_pub=$(openssl x509 -in "$cert_file" -noout -pubkey 2>/dev/null) || return 1
	key_pub=$(openssl pkey -in "$key_file" -pubout 2>/dev/null) || return 1
	[ "$cert_pub" = "$key_pub" ]
}

# Docker manages the resolved cert/key paths and regenerates unexpected files; preserve-existing semantics are native-agent only.
if ! cert_pair_ready; then
	mkdir -p "$cert_dir"
	chmod 700 "$cert_dir"
	# Fail Docker startup if its managed local cert cannot be generated; nginx depends on it.
	# Keep validation, key type, duration, and SANs in sync with endpoints/agent/web_console_tls.go.
	(umask 077 && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -days 365 -nodes \
		-keyout "$key_file" \
		-out "$cert_file" \
		-subj "/CN=localhost" \
		-addext "keyUsage=digitalSignature" \
		-addext "extendedKeyUsage=serverAuth" \
		-addext "subjectAltName=DNS:localhost,DNS:loginlocal.opennhp.org,IP:127.0.0.1,IP:::1")
	# Keep explicit modes if the generator command or umask changes later.
	chmod 600 "$key_file"
	chmod 644 "$cert_file"
fi

if [ "$#" -eq 0 ]; then
	set -- tail -f /dev/null
fi

exec "$@"
