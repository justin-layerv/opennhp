package relay

import (
	"bytes"
	"fmt"
	"os"

	"github.com/pelletier/go-toml/v2"
)

// Config configures the NHP-Relay service (#2208). The relay is the
// internet-facing component of the off-internet topology:
//
//	Browser JS-Agent --HTTPS POST--> NHP-Relay --NHP_RLY--> private NHP-Server
//
// It forwards an agent's opaque inner NHP knock to a (private) cell server and
// relays the server's encrypted ACK back to the browser. See
// docs/design/NHP_RELAY_TOPOLOGY.md.
type Config struct {
	// ListenAddr is the host:port the HTTP(S) relay endpoint binds.
	ListenAddr string `toml:"listen_addr"`

	// UDPListenAddr is the host:port the relay's UDP socket binds for sending
	// NHP_RLY to cell servers and receiving their ACKs on the SAME socket.
	// SECURITY: the server pins the relay's source address (CheckRecvAddress)
	// against its relay.toml entry, so this must be stable and reachable from the
	// (private) server, and must match what the server registered. Empty binds
	// an ephemeral port (tests / single-box dev only).
	UDPListenAddr string `toml:"udp_listen_addr"`

	// PrivateKeyBase64 is the relay's NHP static private key (base64, 32 bytes).
	// The relay shares one keypair across the fleet (nhp-{env}-relay); see
	// docs/design/NHP_RELAY_TOPOLOGY.md "Relay fleet".
	PrivateKeyBase64 string `toml:"private_key"`

	// SourceAddrMode selects how the relay derives the client SourceAddr it
	// stamps into RelayForwardMsg — the address the server uses to open the AC
	// pinhole. SECURITY-CRITICAL: see SourceAddrMode.
	SourceAddrMode SourceAddrMode `toml:"source_addr_mode"`

	// Servers is the cell-routing table: one entry per reachable cell server,
	// keyed at runtime by the server's pubkey fingerprint (POST /relay/{id}).
	Servers []ServerConfig `toml:"servers"`

	// EnableTLS terminates TLS directly on the relay (TLSCertFile/TLSKeyFile).
	// Leave false when a front door terminates TLS and the relay binds loopback
	// (see SourceAddrModeTrustedHeader).
	EnableTLS   bool   `toml:"enable_tls"`
	TLSCertFile string `toml:"tls_cert_file"`
	TLSKeyFile  string `toml:"tls_key_file"`

	// TrustedHeader names the HTTP header carrying the real client IP when
	// SourceAddrMode == SourceAddrModeTrustedHeader. Defaults to "X-Real-IP".
	// SECURITY: deriveSourceAddr takes the RIGHTMOST comma-separated entry, which
	// is the trusted value only for an APPEND-style proxy that appends its
	// observation last (the deployment's ALB X-Forwarded-For; single-value headers
	// like X-Real-IP are also fine). Pointing this at a PREPEND-style header —
	// where the trusted value is leftmost — would silently adopt an
	// attacker-supplied rightmost entry.
	TrustedHeader string `toml:"trusted_header"`
}

// ServerConfig is one cell server the relay can route to.
type ServerConfig struct {
	// Name is a human label for logs (e.g. "sandbox-cell1").
	Name string `toml:"name"`
	// PubKeyBase64 is the cell server's NHP static public key (base64). Its
	// fingerprint (utils.PubKeyFingerprint) is the {serverId} in the relay URL.
	PubKeyBase64 string `toml:"public_key"`
	// Host is the server's UDP host (CloudMap DNS, e.g. server.nhp.sandbox.internal).
	Host string `toml:"host"`
	// Port is the server's NHP knock UDP port (62206).
	Port int `toml:"port"`
}

// SourceAddrMode selects the trust source for the relay-reported client IP.
//
// SECURITY: SourceAddr is the SOLE trusted source of the AC-pinhole client IP
// (the server opens a firewall pinhole for it). If the relay is reachable by
// clients AND trusts a client-supplied header, any client can spoof
// SourceAddr and open a pinhole for an arbitrary victim IP. So the
// trusted-header mode is ONLY safe when the relay is unreachable except through
// a trusted hop that overwrites the header.
type SourceAddrMode string

const (
	// SourceAddrModeRemoteAddr (DEFAULT, fail-safe) derives SourceAddr from the
	// actual TCP peer (http.Request.RemoteAddr) and ignores all client headers.
	// Correct when the relay terminates TLS directly and is the client's true
	// peer. Cannot be header-spoofed.
	SourceAddrModeRemoteAddr SourceAddrMode = ""

	// SourceAddrModeTrustedHeader derives SourceAddr from Config.TrustedHeader
	// (e.g. X-Real-IP). ONLY safe behind a trusted front door that terminates
	// TLS, overwrites the header with the real client IP, and to which the relay
	// is the only path (relay bound loopback/private). The front door + bind are
	// provided by the deployment (P7); selecting this mode without them is a
	// spoofing hole.
	SourceAddrModeTrustedHeader SourceAddrMode = "trusted_header"
)

// defaultTrustedHeader is used when SourceAddrModeTrustedHeader is selected but
// TrustedHeader is unset.
const defaultTrustedHeader = "X-Real-IP"

// ListenUDPAddr returns the UDP socket bind address, defaulting to an ephemeral
// port when UDPListenAddr is unset (tests / single-box dev).
func (c *Config) ListenUDPAddr() string {
	if c.UDPListenAddr != "" {
		return c.UDPListenAddr
	}
	return ":0"
}

// LoadConfig reads the relay configuration from the TOML file at path. It is the
// thin IO + decode seam the nhp-relayd daemon (endpoints/relay/main) uses; the
// load-bearing validation — private-key size, source_addr_mode, per-server
// pubkeys and reachability — is deferred to New, which fails closed on bad
// values. Kept in package relay (not main) so it stays unit-testable.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("relay: read config %q: %w", path, err)
	}
	// Strict decode: this config is security-critical (source_addr_mode, the UDP
	// bind the server pins via CheckRecvAddress), and an ignored typo fails *unsafe*
	// — e.g. `udp_listen_adr` would leave UDPListenAddr empty, bind an ephemeral
	// port, and the relay would be silently unreachable from the server. Reject
	// unknown keys at startup instead.
	dec := toml.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("relay: parse config %q: %w", path, err)
	}
	return &cfg, nil
}
