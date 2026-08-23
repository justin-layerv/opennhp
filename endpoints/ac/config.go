package ac

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/utils"
)

var (
	baseConfigWatch io.Closer
	httpConfigWatch io.Closer
	serverPeerWatch io.Closer

	errLoadConfig = errors.New("config load error")
)

// FilterMode selects the AC datapath enforcement mechanism. user_data renders
// the chosen value into config.toml as `FilterMode = <n>`, and the deploy-time
// eBPF object smoke reads it back to gate the EBPFXDP object-layout check.
// These iota values are a lockstep source of truth: the smoke module cannot
// import endpoints/ac (that would make a test package an application
// dependency), so it duplicates the numbers as acFilterModeIPTables /
// acFilterModeEBPFXDP in tests/smoke/ssm_probe.go. Reordering this block or
// inserting a mode shifts EBPFXDP's value and must update those smoke constants
// in the same change — the drift is caught at PR time by
// scripts/check-ebpf-load-path-lockstep.sh (wired into `make lint-workflows`).
const (
	FilterMode_IPTABLES = iota // 0
	FilterMode_EBPFXDP         // 1
)

const (
	// DefaultL3FlushErrorThreshold and DefaultL3FlushErrorWindowSec
	// are the default circuit-breaker parameters for the L3
	// flush-on-expiry feature. Matches the const-block convention in
	// registration.go.
	DefaultL3FlushErrorThreshold = 10
	DefaultL3FlushErrorWindowSec = 60

	// DefaultHealthCheckPort is the TCP port the load balancer HTTP-probes
	// for target health. Traefik receives the probe on this port and routes
	// the qURL/TLS target-group check to nhp-acd readiness. In
	// FilterMode_EBPFXDP the AC admits this port through the XDP whitelist at
	// startup so the probe isn't fail-closed dropped before it reaches the
	// local listener; see the ebpfInfraExemptRules install in (*UdpAC).Start.
	//
	// This default only self-heals a config.toml that predates the
	// HealthCheckPort field, so an in-place AC upgrade fixes health checks
	// without waiting on a user_data re-render. It MUST track
	// local.ac_health_check_port in terraform/modules/ac (which renders
	// config.toml and sources every target-group health_check block plus the
	// SG ingress rule). The terraform render check asserts config.toml carries
	// the terraform value, but nothing cross-checks this Go constant against
	// it — and the self-heal window is exactly when an old instance would fall
	// back to this constant while the TGs probe the new port. Change both.
	DefaultHealthCheckPort = 8080
)

type Config struct {
	PrivateKeyBase64    string          `json:"privateKey"` //nolint:gosec // G117: config struct, never JSON-marshaled — TOML input only
	ACId                string          `json:"acId"`
	DefaultIp           string          `json:"defaultIp"`
	AuthServiceId       string          `json:"aspId"`
	ResourceIds         []string        `json:"resIds"`
	Servers             []*core.UdpPeer `json:"servers"`
	IpPassMode          int             `json:"ipPassMode"` // 0: pass the knock source IP, 1: use pre-access mode and release the access source IP
	LogLevel            int             `json:"logLevel"`
	DefaultCipherScheme int             `json:"defaultCipherScheme"`
	FilterMode          int             `json:"filterMode"`

	// HealthCheckPort is the TCP port the load balancer HTTP-probes for
	// target health. Traefik listens on this port; the qURL/TLS target-group
	// check routes through nhp-acd readiness. FilterMode_EBPFXDP fails closed
	// on every port that isn't per-knock authorized or hardcoded-exempt, so
	// the AC must explicitly admit this port through the XDP whitelist at
	// startup or every target flaps unhealthy and the NLB black-holes all
	// resource traffic. Rendered from config.toml; normalized to
	// DefaultHealthCheckPort when unset (≤0) or out of range (>65535).
	// Ignored in FilterMode_IPTABLES, where user_data opens the same port
	// with an explicit iptables ACCEPT from the VPC CIDR.
	HealthCheckPort int `json:"healthCheckPort"`

	// L3 flush-on-expiry: actively flushes kernel flow state on
	// ipset/BPF entry expiry so existing TCP connections terminate
	// when sessions end. Defense-in-depth on top of L7 enforcement;
	// design + mechanics in docs/design/SESSION_ENFORCEMENT_ARCHITECTURE.md.
	EnableL3FlushOnExpiry bool `json:"enableL3FlushOnExpiry"`

	// L3FlushDryRun gates the scheduler into log-only mode. Auto-
	// defaulted to true when EnableL3FlushOnExpiry is true but
	// L3FlushDryRun is unset — safer than letting an operator
	// accidentally land in real-flush mode by enabling the feature
	// without an explicit opt-out from dry-run.
	L3FlushDryRun bool `json:"l3FlushDryRun"`

	// L3FlushRealModeAcknowledged is the durable operator acknowledgement that
	// permits a fresh process to boot directly into real-flush mode. Without it,
	// the first-load safety still forces dry-run even when L3FlushDryRun=false.
	// This separate bit is necessary because a bool cannot distinguish an
	// omitted TOML field from an explicit false, and session-control readiness
	// must complete inherited-rule teardown before the AC can register.
	L3FlushRealModeAcknowledged bool `json:"l3FlushRealModeAcknowledged"`

	// L3FlushErrorThreshold / L3FlushErrorWindowSec — circuit
	// breaker. Latches the scheduler off when error rate exceeds
	// Threshold for Window-Sec consecutive seconds. Defaults from
	// DefaultL3FlushErrorThreshold and DefaultL3FlushErrorWindowSec.
	L3FlushErrorThreshold int `json:"l3FlushErrorThreshold"`
	L3FlushErrorWindowSec int `json:"l3FlushErrorWindowSec"`

	// L3FlushConntrackBackend selects how FilterMode_IPTABLES tears down
	// kernel conntrack entries on flush: "exec" (default — fork+exec the
	// `conntrack -D` tool, IPv4-only) or "netlink" (direct
	// NFNL_SUBSYS_CTNETLINK, no fork, IPv4+IPv6; the #2165 throughput path
	// and the iptables IPv6 immediate-teardown fix). Empty/unset = "exec",
	// preserving v1 behavior until the netlink path is soak-validated per
	// the #2165 rollout plan. Ignored in FilterMode_EBPFXDP (that mode uses
	// BpfFlusher). Live-reload note: like FilterMode itself, a change here
	// requires an AC restart — the flusher is built once at Start.
	L3FlushConntrackBackend string `json:"l3FlushConntrackBackend"`

	// L3FlushConntrackPoolSize is the number of pre-warmed netlink sockets
	// the "netlink" backend makes available through its free-list pool
	// (concurrency = pool size, since a netlink socket is single-flight). Default
	// defaultConntrackNetlinkPoolSize — the ~4:1 ratio against the worker pool
	// from the #2165 sketch. Each holder keeps its socket through the indexed
	// delete loop (or the O(table) dump fallback if the #2908 event index is
	// unhealthy), so this ratio is deliberately operator-tunable during the soak
	// without a code change + AMI rebuild.
	// Normalized at load: ≤0 → default, and clamped to maxConntrackNetlinkPoolSize
	// so a typo can't exhaust file descriptors. Ignored by the exec backend.
	L3FlushConntrackPoolSize int `json:"l3FlushConntrackPoolSize"`

	// ============================================================================
	// Per-AC Server Assignment Configuration (Required)
	// See docs/design/PLUGGABLE_STORAGE_BACKEND.md section 6.2 for details.
	// These fields enable AC to register with NHP servers and receive
	// its assigned server list via NHP_ARD (redispatch).
	// ============================================================================
	LicenseKey         string `json:"licenseKey"`         // License key for authentication (globally unique)
	ServerEndpoint     string `json:"serverEndpoint"`     // Required: Server endpoint for registration (e.g., "server.nhp.sandbox.internal")
	ACVersion          string `json:"acVersion"`          // AC software version for compatibility
	ServerPubKeyBase64 string `json:"serverPubKeyBase64"` // Required: Shared registration public key (all servers share this for NLB)
	ServerPort         int    `json:"serverPort"`         // Server port for initial registration (default: 443, the public NHP edge)
	Environment        string `json:"environment"`        // Environment name for CloudWatch metrics (e.g., "sandbox", "prod")

	// ============================================================================
	// NHP_ARD peer-list allowlist (#1156).
	//
	// An NHP_ARD message ("redispatch") directs this AC at a list of server
	// peers. Pre-#1156, any pubkey inside an ARD target was trusted verbatim
	// — a single compromised server that could send ARD to this AC could
	// inject attacker-controlled pubkeys as new server peers and then
	// exfiltrate the AC's license key over NHP_AOL. The shared-ASG
	// registration keypair amplifies this: one popped server = authority
	// to ARD every AC in the fleet.
	//
	// The allowlist is the set of server pubkeys this AC will accept from
	// ARD. The effective allowlist is the union of three sources (the
	// trust check is a single map lookup; the enumeration is for
	// documentation, not precedence):
	//   - ServerPubKeyBase64 (the shared registration key, always
	//     trusted — nothing changes about initial bootstrap)
	//   - The server peers loaded from server.toml
	//   - ServerPubKeyAllowlist below (operator-managed extras, e.g.
	//     per-region or per-tenant pubkeys rotated in out-of-band)
	//
	// Rollout: RequireServerPubKeyAllowlist defaults to false (permit mode).
	// Permit mode logs + emits a metric on unknown pubkeys but still
	// accepts them — this is for sandbox burn-in so we can verify the
	// allowlist is correct before flipping to strict. Flip to true once
	// MetricARDPubkeyPermitUnknown stays at zero across a full deploy
	// cycle.
	// ServerPubKeyAllowlist is the raw-from-TOML extras list. The
	// runtime source of truth for pubkey-allowlist lookup is
	// UdpAC.serverPubKeyAllowlist (the normalized set). Under
	// cosmetic-only edits to this slice (reordering, whitespace,
	// duplicate-only), reloadARDTrust intentionally leaves this
	// staging copy as-is so the "allowlist changed" signal
	// tracks semantic changes only (see #1156 / #1239 for rationale).
	ServerPubKeyAllowlist        []string `json:"serverPubKeyAllowlist"`        // Optional extra trusted server pubkeys (base64)
	RequireServerPubKeyAllowlist bool     `json:"requireServerPubKeyAllowlist"` // Strict mode: reject ARD targets with non-allowlisted pubkeys

	// ============================================================================
	// Resilience knobs (optional). The defaults are tuned for the standard
	// NHP fleet — these overrides exist so an operator can dial the
	// safety nets up or down per environment without a code change. See
	// registration.go for the constants used when the value is zero.
	// ============================================================================

	// NLBReregistrationIntervalSeconds overrides
	// DefaultNLBReregistrationInterval. Values below
	// MinNLBReregistrationInterval are clamped up. The floor itself
	// is defined symbolically against KeepaliveInterval — see
	// MinNLBReregistrationInterval in registration.go for the current
	// resolved value.
	NLBReregistrationIntervalSeconds int `json:"nlbReregistrationIntervalSeconds"`

	// AllUnconnectedThresholdTicks overrides DefaultAllUnconnectedThreshold.
	// Values below MinAllUnconnectedThreshold (2) are clamped up so a
	// single transient tick cannot trip a re-registration.
	AllUnconnectedThresholdTicks int `json:"allUnconnectedThresholdTicks"`
}

type HttpConfig struct {
	EnableHttp     bool
	EnableTLS      bool
	HttpListenPort int
	TLSCertFile    string
	TLSKeyFile     string
}

type Peers struct {
	Servers []*core.UdpPeer
}

func (a *UdpAC) loadBaseConfig() error {
	// config.toml - REQUIRED for AC to start
	fileName := filepath.Join(ExeDirPath, "etc", "config.toml")
	content, err := os.ReadFile(fileName)
	if err != nil {
		return fmt.Errorf("failed to read base config %s: %w", fileName, err)
	}

	var conf Config
	if err := toml.Unmarshal(content, &conf); err != nil {
		return fmt.Errorf("failed to parse base config %s: %w", fileName, err)
	}

	// Validate required fields before proceeding
	if conf.PrivateKeyBase64 == "" {
		return fmt.Errorf("privateKeyBase64 is required in %s", fileName)
	}

	if err := a.updateBaseConfig(conf); err != nil {
		return fmt.Errorf("failed to apply base config: %w", err)
	}

	baseConfigWatch = utils.WatchFile(fileName, func() {
		log.Info("[AC] base config %s has been updated, reloading", fileName)
		// The server-peer watcher decodes into a fresh Peers each reload to keep
		// *UdpPeer structs out of the boot-loop snapshot (#3085). Reusing the
		// captured conf here has no such hazard today: updateBaseConfig copies
		// each reload-mutable field into the separate a.config struct — DefaultIp
		// is a value-typed string, and ServerPubKeyAllowlist is slices.Clone'd
		// before publish (see reloadARDTrust) — so no serverPeerMutex snapshot
		// reader aliases this decoder-owned conf. A future field published as a
		// raw decoder-owned pointer/slice would reintroduce that hazard; unifying
		// all three watchers on fresh-decode (+ logging the reload parse error
		// this one still swallows) is tracked in #3102.
		if content, err = a.loadConfigFile(fileName); err == nil {
			if err = toml.Unmarshal(content, &conf); err == nil {
				if updateErr := a.updateBaseConfig(conf); updateErr != nil {
					log.Error("[AC] failed to apply base config update from %s: %v", fileName, updateErr)
				}
			}

		}
	})
	return nil
}

func (a *UdpAC) loadHttpConfig() error {
	// http.toml - optional, enables HTTP endpoint
	fileName := filepath.Join(ExeDirPath, "etc", "http.toml")
	content, err := os.ReadFile(fileName)
	if err != nil {
		if os.IsNotExist(err) {
			log.Info("http.toml not found, HTTP endpoint disabled")
			return nil
		}
		return fmt.Errorf("failed to read http config %s: %w", fileName, err)
	}

	var httpConf HttpConfig
	if err := toml.Unmarshal(content, &httpConf); err != nil {
		return fmt.Errorf("failed to parse http config %s: %w", fileName, err)
	}

	if err := a.updateHttpConfig(httpConf); err != nil {
		return fmt.Errorf("failed to apply http config: %w", err)
	}

	httpConfigWatch = utils.WatchFile(fileName, func() {
		log.Info("[AC] http config %s has been updated, reloading", fileName)
		if content, err = a.loadConfigFile(fileName); err == nil {
			if err = toml.Unmarshal(content, &httpConf); err == nil {
				if updateErr := a.updateHttpConfig(httpConf); updateErr != nil {
					log.Error("[AC] failed to apply http config update from %s: %v", fileName, updateErr)
				}
			}
		}
	})
	return nil
}

func (a *UdpAC) loadPeers() error {
	// server.toml - contains NHP server peer configurations
	fileName := filepath.Join(ExeDirPath, "etc", "server.toml")
	log.Info("loading server peers from: %s (ExeDirPath=%s)", fileName, ExeDirPath)
	content, err := os.ReadFile(fileName)
	if err != nil {
		if os.IsNotExist(err) {
			log.Info("server.toml not found at %s, no server peers configured", fileName)
			return nil
		}
		return fmt.Errorf("failed to read server peer config %s: %w", fileName, err)
	}

	log.Debug("loaded server.toml content (%d bytes): %s", len(content), string(content))
	var peers Peers
	if err := toml.Unmarshal(content, &peers); err != nil {
		return fmt.Errorf("failed to parse server peer config %s: %w", fileName, err)
	}
	log.Info("parsed %d server peers from server.toml", len(peers.Servers))

	if err := a.updateServerPeers(peers.Servers); err != nil {
		return fmt.Errorf("failed to apply server peers: %w", err)
	}

	serverPeerWatch = utils.WatchFile(fileName, func() {
		log.Info("[AC] server peer config %s has been updated, reloading", fileName)
		// Decode into a FRESH Peers (and fresh content/err locals) each reload.
		// The unconditional win: reload parse errors are logged below instead of
		// being silently swallowed by the previous reused-variable form. Secondary
		// (future-proofing): the boot-loop snapshot copies a.config.Servers' slice
		// header, then dereferences server.Ip / server.Hostname after releasing
		// serverPeerMutex. Those fields are immutable after construction
		// (nhp/core/peer.go) and go-toml allocates fresh elements today, so no
		// live aliasing hazard exists — but decoding into a fresh struct
		// guarantees no *UdpPeer is ever shared with a prior parse a reader still
		// holds, independent of decoder behavior (#3085 review).
		content, err := a.loadConfigFile(fileName)
		if err != nil {
			return // loadConfigFile already logged the read error
		}
		var peers Peers
		if err := toml.Unmarshal(content, &peers); err != nil {
			log.Error("[AC] failed to parse server peer update from %s: %v", fileName, err)
			return
		}
		if updateErr := a.updateServerPeers(peers.Servers); updateErr != nil {
			log.Error("[AC] failed to apply server peer update from %s: %v", fileName, updateErr)
		}
	})

	return nil
}

func (a *UdpAC) updateBaseConfig(conf Config) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	if a.config == nil {
		// First-load path. Fail Start if the operator asked for
		// strict enforcement AND the allowlist contains entries we
		// had to drop (malformed base64) — a silent drop here would
		// mean the strict-mode AC can't talk to a server the
		// operator believed was trusted, causing a knock-path
		// outage at the next ARD. Deploy-time fail is cheaper
		// than prod-time runtime fail.
		set, dropped := normalizeAllowlistWithDrops(conf.ServerPubKeyAllowlist)
		if dropped > 0 && conf.RequireServerPubKeyAllowlist {
			return fmt.Errorf("ServerPubKeyAllowlist has %d malformed base64 entries and RequireServerPubKeyAllowlist=true; fix config.toml", dropped)
		}
		// Group a.config assignment with the allowlist swap under a
		// single lock so a concurrent reader (hypothetical: a future
		// refactor that kicks off any setup work before Start
		// returns) cannot observe a.config != nil with a nil
		// a.serverPubKeyAllowlist. Today Start is single-threaded
		// up to this point, but the invariant is cheap to enforce
		// structurally.
		//
		// slices.Clone for symmetry with reloadARDTrust — detaches
		// a.config.ServerPubKeyAllowlist from the caller's slice.
		// Today the caller is toml.Unmarshal (fresh slice per
		// parse) so this is belt-and-braces, but a future
		// in-process or test caller must not be able to mutate
		// a.config's slice out from under us.
		conf.ServerPubKeyAllowlist = slices.Clone(conf.ServerPubKeyAllowlist)
		// Symmetric to the reload-path safety: a fresh boot that enables
		// real flushing without the separate durable acknowledgement must
		// land in dry-run. This keeps an omitted false-valued TOML field from
		// being interpreted as rollout approval.
		if conf.EnableL3FlushOnExpiry && !conf.L3FlushDryRun && !conf.L3FlushRealModeAcknowledged {
			log.Warning("L3 flush-on-expiry enabled at boot with L3FlushDryRun unset/false and no durable real-mode acknowledgement; forcing dry-run for the first boot. Set L3FlushRealModeAcknowledged=true only after the dry-run rollout gates pass.")
			conf.L3FlushDryRun = true
		}
		// Normalize breaker tunables in the first-load path. Without
		// this, a TOML that omits L3FlushErrorThreshold lands with the
		// Go zero value 0 and WithBreakerThreshold(0) makes
		// `count >= 0` true on the first flush error — breaker opens
		// instantly and UdpAC refuses every NHP-AOP. The reload-path
		// already applies intOrDefault; this mirrors it for first-load
		//
		conf.L3FlushErrorThreshold = intOrDefault(conf.L3FlushErrorThreshold, DefaultL3FlushErrorThreshold)
		conf.L3FlushErrorWindowSec = intOrDefault(conf.L3FlushErrorWindowSec, DefaultL3FlushErrorWindowSec)
		// Normalize the conntrack backend selector so an unknown value (a
		// typo in ac.toml) surfaces at boot as a Warning + safe fallback to
		// exec, rather than a silent mis-select at flusher construction.
		// Empty is valid ("" → exec); only a non-empty unknown warns.
		if normalized, ok := ParseConntrackBackend(conf.L3FlushConntrackBackend); !ok {
			log.Warning("unknown l3FlushConntrackBackend %q; falling back to %q (valid: exec, netlink)", conf.L3FlushConntrackBackend, normalized)
			a.lastInvalidL3FlushConntrackBackend = conf.L3FlushConntrackBackend
			conf.L3FlushConntrackBackend = normalized.String()
		} else {
			a.lastInvalidL3FlushConntrackBackend = ""
		}
		// Normalize the netlink pool size: ≤0 → default 16, and clamp a
		// too-large value (typo) so it can't exhaust file descriptors.
		conf.L3FlushConntrackPoolSize = normalizeConntrackPoolSize(conf.L3FlushConntrackPoolSize)
		// Normalize the LB health-check port. Consumed once at Start to seed
		// the FilterMode_EBPFXDP whitelist exemption (like FilterMode itself,
		// a start-time-only setting — a live reload does not re-install the
		// rule), so it only needs defaulting on the first-load path. ≤0 →
		// DefaultHealthCheckPort so a config.toml that predates the field
		// still admits the probe instead of fail-closed dropping it.
		conf.HealthCheckPort = intOrDefault(conf.HealthCheckPort, DefaultHealthCheckPort)
		// EbpfRuleAdd narrows DstPort to uint16, so a >65535 typo would
		// silently truncate and seed a rule for the wrong port — re-introducing
		// this outage in a hard-to-spot way. Surface it at boot and fall back.
		if conf.HealthCheckPort > 65535 {
			log.Warning("HealthCheckPort=%d out of range (1-65535); falling back to %d", conf.HealthCheckPort, DefaultHealthCheckPort)
			conf.HealthCheckPort = DefaultHealthCheckPort
		}
		a.serverPeerMutex.Lock()
		a.config = &conf
		a.serverPubKeyAllowlist = set
		a.serverPeerMutex.Unlock()
		a.log.SetLogLevel(conf.LogLevel)

		if !conf.RequireServerPubKeyAllowlist {
			// Permit mode means the #1156 mitigation is *counting*
			// unknown pubkeys but still accepting them — fully
			// vulnerable to the exfil attack. A single Warning at
			// Start makes "we forgot to flip strict" visible in
			// routine log review instead of only visible via the
			// MetricARDPubkeyPermitUnknown counter.
			log.Warning("ARD pubkey allowlist in PERMIT mode — #1156 mitigation not enforced. Flip RequireServerPubKeyAllowlist=true in config.toml once MetricARDPubkeyPermitUnknown stays flat across a full deploy cycle.")
		}
		return nil
	}

	// update — the fields below (except DefaultIp, see next paragraph) are
	// NOT read under serverPeerMutex by any concurrent reader, so they're
	// patched without the mutex (existing convention). If you add a new field
	// to ardTrustSnapshot's read set — or otherwise start reading a field
	// under serverPeerMutex — the corresponding write MUST move into
	// reloadARDTrust's grouped-under-lock block (or its own locked section) to
	// preserve the "snapshot-read fields written under serverPeerMutex"
	// invariant.
	//
	// DefaultIp IS such a snapshot-read field: Start's eBPF boot loop reads it
	// under serverPeerMutex (see the ebpfInfraExemptRules caller), so its
	// reload write below is taken under the same lock. The base-config watcher
	// is installed before the boot loop runs, so without this an operator
	// editing DefaultIp during the boot window would race the loop's read
	// (#3085, adapted from OpenNHP 3e56ffc7).
	if a.config.LogLevel != conf.LogLevel {
		log.Info("set base log level to %d", conf.LogLevel)
		a.log.SetLogLevel(conf.LogLevel)
		a.config.LogLevel = conf.LogLevel
	}

	// The compare-read is unlocked while the write below takes serverPeerMutex.
	// That asymmetry is safe: updateBaseConfig runs only on the single
	// config-watcher goroutine, so it is the sole writer of DefaultIp and never
	// races its own read. The lock exists solely to publish the write to the
	// boot-loop RLock reader (the ebpfInfraExemptRules caller).
	if a.config.DefaultIp != conf.DefaultIp {
		log.Info("set default ip mode to %s", conf.DefaultIp)
		a.serverPeerMutex.Lock()
		a.config.DefaultIp = conf.DefaultIp
		a.serverPeerMutex.Unlock()
	}

	if a.config.IpPassMode != conf.IpPassMode {
		log.Info("set ip pass mode to %d", conf.IpPassMode)
		a.config.IpPassMode = conf.IpPassMode
	}

	if a.config.DefaultCipherScheme != conf.DefaultCipherScheme {
		log.Info("set default cipher scheme to %d", conf.DefaultCipherScheme)
		a.config.DefaultCipherScheme = conf.DefaultCipherScheme
	}

	newConntrackBackendRaw := conf.L3FlushConntrackBackend
	newConntrackBackend, ok := ParseConntrackBackend(newConntrackBackendRaw)
	if !ok {
		if newConntrackBackendRaw != a.lastInvalidL3FlushConntrackBackend {
			log.Warning("unknown l3FlushConntrackBackend %q; falling back to %q (valid: exec, netlink)", newConntrackBackendRaw, newConntrackBackend)
			a.lastInvalidL3FlushConntrackBackend = newConntrackBackendRaw
		}
	} else {
		a.lastInvalidL3FlushConntrackBackend = ""
	}
	oldConntrackBackend, _ := ParseConntrackBackend(a.config.L3FlushConntrackBackend)
	if oldConntrackBackend != newConntrackBackend {
		log.Warning("[L3FlushSched] l3FlushConntrackBackend reload from %q to %q requires AC restart to affect the constructed ConntrackFlusher (the flusher is built once at Start).",
			oldConntrackBackend, newConntrackBackend)
		a.config.L3FlushConntrackBackend = newConntrackBackend.String()
	}
	newConntrackPoolSize := normalizeConntrackPoolSize(conf.L3FlushConntrackPoolSize)
	if a.config.L3FlushConntrackPoolSize != newConntrackPoolSize {
		log.Warning("[L3FlushSched] l3FlushConntrackPoolSize reload from %d to %d requires AC restart to affect the constructed ConntrackFlusher socket pool (the pool is built once at Start).",
			a.config.L3FlushConntrackPoolSize, newConntrackPoolSize)
		a.config.L3FlushConntrackPoolSize = newConntrackPoolSize
	}

	// L3 flush-on-expiry config. Logging on change matches the
	// convention used by the IpPassMode / DefaultCipherScheme blocks
	// above.
	//
	// Capture prevEnabled BEFORE the assignment below — the auto-
	// dry-run safety branch needs the previous state to detect the
	// "false → true" transition. Reading a.config.EnableL3FlushOnExpiry
	// after the assignment is always-true and the safety check becomes
	// dead code
	prevEnabled := a.config.EnableL3FlushOnExpiry
	if a.config.EnableL3FlushOnExpiry != conf.EnableL3FlushOnExpiry {
		log.Info("set L3 flush-on-expiry to %t", conf.EnableL3FlushOnExpiry)
		// Lifecycle-change Warning: the scheduler is constructed in
		// udpac.go's Start() and not re-instantiated on reload. A
		// reload that flips this flag updates the config field but
		// leaves the running scheduler's state as-is. To actually
		// stop a running scheduler or start a new one the operator
		// must restart the AC. Without this warning, the reload
		// success log line would mislead the operator into thinking
		// the change took full effect
		log.Warning("[L3FlushSched] EnableL3FlushOnExpiry reload from %t → %t requires AC restart to fully take effect (the running scheduler is not re-instantiated on config reload; dry-run and breaker tunables ARE live-tunable via SetDryRun/SetBreakerParams).", prevEnabled, conf.EnableL3FlushOnExpiry)
		a.config.EnableL3FlushOnExpiry = conf.EnableL3FlushOnExpiry
	}
	// Auto-enable dry-run when the feature is freshly enabled with the
	// false zero value but without the distinct durable acknowledgement.
	// Operators may either stage the historical two-reload transition or
	// set L3FlushRealModeAcknowledged only after the rollout gates pass.
	effectiveDryRun := conf.L3FlushDryRun
	if conf.EnableL3FlushOnExpiry && !conf.L3FlushDryRun && !prevEnabled && !conf.L3FlushRealModeAcknowledged {
		log.Warning("L3 flush-on-expiry was just enabled with L3FlushDryRun unset/false and no durable real-mode acknowledgement; forcing dry-run for the first reload. Set L3FlushRealModeAcknowledged=true only after the dry-run rollout gates pass.")
		effectiveDryRun = true
	}
	if a.config.L3FlushDryRun != effectiveDryRun {
		log.Info("set L3 flush dry-run to %t", effectiveDryRun)
		a.config.L3FlushDryRun = effectiveDryRun
	}
	a.config.L3FlushRealModeAcknowledged = conf.L3FlushRealModeAcknowledged
	breakerTunablesChanged := false
	if newThreshold := intOrDefault(conf.L3FlushErrorThreshold, DefaultL3FlushErrorThreshold); a.config.L3FlushErrorThreshold != newThreshold {
		log.Info("set L3 flush error threshold to %d", newThreshold)
		a.config.L3FlushErrorThreshold = newThreshold
		breakerTunablesChanged = true
	}
	if newWindow := intOrDefault(conf.L3FlushErrorWindowSec, DefaultL3FlushErrorWindowSec); a.config.L3FlushErrorWindowSec != newWindow {
		log.Info("set L3 flush error window to %ds", newWindow)
		a.config.L3FlushErrorWindowSec = newWindow
		breakerTunablesChanged = true
	}

	// Propagate scheduler-tunable changes to the live scheduler so an
	// operator who reloads config.toml doesn't have to restart the AC
	// for the change to take effect. The scheduler is constructed in
	// udpac.go's Start() only after this function runs on first load,
	// so a.expirySched is nil during the first-load path (handled
	// above) — only patch on subsequent reloads
	//
	// SetDryRun is unconditional because its read is atomic + cheap.
	// SetBreakerParams takes breakerErrMu so only call it when the
	// tunables actually changed
	if a.expirySched != nil {
		a.expirySched.SetDryRun(a.config.L3FlushDryRun)
		if breakerTunablesChanged {
			newThreshold := a.config.L3FlushErrorThreshold
			newWindow := time.Duration(a.config.L3FlushErrorWindowSec) * time.Second
			// SetBreakerParams handles the threshold-exceeds-ring
			// case internally: it clamps to ring size and logs the
			// actionable warning ("restart the AC to grow the ring").
			// No duplicate warning here — the previous config-side
			// log was forensics-redundant.
			a.expirySched.SetBreakerParams(newThreshold, newWindow)
		}
	}

	a.reloadARDTrust(conf)

	return nil
}

// reloadARDTrust applies the ARD-trust reload semantics:
//
//   - All three fields (strict flag, extras set, pre-/post-values of
//     ServerPubKeyBase64) are diffed and mutated under a single
//     serverPeerMutex acquisition so a concurrent snapshot reader
//     (filterRedispatchTargets) can never observe a half-applied
//     reload.
//   - ServerPubKeyBase64 is immutable after first-load (see
//     ardTrustSnapshot source 1). If a reload tries to change it,
//     log loud and drop — silently accepting would make
//     ardTrustSnapshot reads inconsistent until the next ARD since
//     the field is not part of the grouped write.
//   - normalizeAllowlistWithDrops runs BEFORE lock acquisition so
//     the under-lock diff can compare the normalized sets
//     (maps.Equal) rather than the raw slices (slices.Equal would
//     mark a cosmetic reorder as a semantic change). normalize is
//     pure — no shared state touched — so running it outside the
//     lock is race-clean.
//   - Log calls happen AFTER the lock release so a blocking
//     log backend can't stall a snapshot reader.
func (a *UdpAC) reloadARDTrust(conf Config) {
	// Normalize outside the lock so the diff-under-lock compares
	// semantic sets, not raw slice order. Previously an operator
	// reordering entries in config.toml (or adding whitespace that
	// gets trimmed) would trip the "allowlist changed" log even
	// though the effective trusted set was identical — false
	// positives on the primary "TOML edit took effect" signal (cr
	// round 4). The normalize cost is µs-per-entry; allowlists are
	// short and reloads are rare.
	newSet, dropped := normalizeAllowlistWithDrops(conf.ServerPubKeyAllowlist)

	var (
		oldServerPubKey string
		strictAfter     bool
	)
	a.serverPeerMutex.Lock()
	reqChanged := a.config.RequireServerPubKeyAllowlist != conf.RequireServerPubKeyAllowlist
	allowlistChanged := !maps.Equal(a.serverPubKeyAllowlist, newSet)
	// Snapshot the pre-reload registration pubkey inside the lock
	// so the drift log emitted below uses the values captured at
	// detection time. Reading it unlocked later would be safe
	// today (field is immutable post-load) but couples the log
	// line to that invariant — snapshotting keeps the "mutable-
	// fields reads under the lock" convention consistent across
	// this function.
	oldServerPubKey = a.config.ServerPubKeyBase64
	pubkeyBaseDrift := oldServerPubKey != conf.ServerPubKeyBase64
	if reqChanged {
		a.config.RequireServerPubKeyAllowlist = conf.RequireServerPubKeyAllowlist
	}
	if allowlistChanged {
		a.serverPubKeyAllowlist = newSet
		// slices.Clone detaches the backing array from the caller's
		// slice. In the prod TOML-reload path the slice is freshly
		// allocated by toml.Unmarshal so aliasing would be benign,
		// but a future in-process caller that reuses a config
		// struct (or the race test's shallow copy of ac.config)
		// must not be able to mutate a.config.ServerPubKeyAllowlist
		// out from under us.
		a.config.ServerPubKeyAllowlist = slices.Clone(conf.ServerPubKeyAllowlist)
	}
	strictAfter = a.config.RequireServerPubKeyAllowlist
	a.serverPeerMutex.Unlock()

	if pubkeyBaseDrift {
		log.Error("ServerPubKeyBase64 reload attempted but field is immutable after first-load (see ardTrustSnapshot); ignoring change from %s to %s — restart AC to pick up a rotated registration key",
			pubKeyPrefix(oldServerPubKey), pubKeyPrefix(conf.ServerPubKeyBase64))
	}
	// Malformed base64 on reload can't fail Start (we're already
	// running) but it's the same operator-error class as the
	// first-load strict check — escalate to log.Error so it's not
	// buried in the per-entry Warning from normalizeAllowlist.
	//
	// Intentionally NOT gated on allowlistChanged:
	// a permit → strict flip with no allowlist edit would
	// otherwise leave the Error silent while the AC silently
	// upgrades to strict mode with a broken allowlist. Firing the
	// Error on every reload while the condition holds is the
	// right operator signal — reloads are file-watcher-triggered
	// (rare), and the Error stops once config.toml is fixed.
	if dropped > 0 && strictAfter {
		log.Error("ServerPubKeyAllowlist has %d malformed base64 entries under strict mode — those pubkeys will be rejected at the next ARD. Fix config.toml to restore them.", dropped)
	}
	if reqChanged {
		if conf.RequireServerPubKeyAllowlist {
			// Report the post-normalization set size, not the raw
			// slice length — a TOML paste with duplicates,
			// whitespace-only entries, or malformed-base64 drops
			// would otherwise report a misleadingly high number
			// and mask the discrepancy with the "now trusts N
			// pubkeys" line below.
			log.Info("set ARD pubkey allowlist strict mode to true (allowlist extras=%d)",
				len(newSet))
		} else {
			// Flipping strict → permit puts the AC back in the
			// vulnerable #1156 configuration. The first-load
			// permit-mode warning handles fresh-boot visibility;
			// this branch handles the mid-run rollback case. Same
			// severity (Warning) so ops sees both identically.
			log.Warning("ARD pubkey allowlist strict mode flipped to PERMIT — #1156 mitigation no longer enforced (mid-run rollback). Re-enable by setting RequireServerPubKeyAllowlist=true in config.toml.")
		}
	}
	if allowlistChanged {
		// Emit the current union of trusted pubkeys so an operator
		// can verify the TOML edit took effect without grepping
		// multiple log lines. Prefixes only — full base64 pubkeys
		// would bloat the line for fleets with many servers.
		//
		// The snapshot is taken AFTER the lock release. A second
		// reload sneaking in between the unlock and this read
		// would make the log line reflect the newer state — which
		// is the operationally-correct "what's trusted right now"
		// view rather than "what this specific reload committed."
		// That's the right framing for operators verifying a TOML
		// edit.
		sources := a.allowlistPubkeySources()
		prefixes := make([]string, 0, len(sources))
		for _, s := range sources {
			prefixes = append(prefixes, pubKeyPrefix(s))
		}
		log.Info("ARD pubkey allowlist now trusts %d pubkeys %v",
			len(sources), prefixes)
	}
}

func (a *UdpAC) updateHttpConfig(httpConf HttpConfig) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	// update
	if httpConf.EnableHttp {
		// start http server
		if a.httpServer == nil || !a.httpServer.IsRunning() {
			if a.httpServer != nil {
				// stop old http server
				go a.httpServer.Stop()
			}
			hs := &HttpAC{}
			a.httpServer = hs
			err = hs.Start(a, &httpConf)
			if err != nil {
				return err
			}
		}
	} else {
		// stop http server
		if a.httpServer != nil && a.httpServer.IsRunning() {
			go a.httpServer.Stop()
			a.httpServer = nil
		}
	}

	a.httpConfig = &httpConf
	return nil
}

func (a *UdpAC) updateServerPeers(peers []*core.UdpPeer) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	log.Info("updating server peers: count=%d", len(peers))
	serverPeerMap := make(map[string]*core.UdpPeer)
	for _, p := range peers {
		log.Debug("loading server peer: host=%s, ip=%s, port=%d, pubKeyBase64=%q, pubKeyLen=%d",
			p.Hostname, p.Ip, p.Port, p.PubKeyBase64, len(p.PublicKey()))
		p.Type = core.NHP_SERVER
		a.device.AddPeer(p)
		serverPeerMap[p.PublicKeyBase64()] = p
	}

	// remove old peers from device
	a.serverPeerMutex.Lock()
	defer a.serverPeerMutex.Unlock()
	// Assign a.config.Servers under serverPeerMutex — the same lock that
	// guards a.serverPeerMap. The config-reload watcher runs updateServerPeers
	// concurrently with Start's eBPF boot-loop reader (see ebpfInfraExemptRules
	// caller) and any GetConfig() reader; an unlocked slice-header write here
	// raced those reads under reload pressure (a -race-detectable data race).
	// Adapted from OpenNHP 3e56ffc7 (#3085).
	a.config.Servers = peers
	for pubKey := range a.serverPeerMap {
		if _, found := serverPeerMap[pubKey]; !found {
			a.device.RemovePeer(pubKey)
		}
	}
	a.serverPeerMap = serverPeerMap

	return nil
}

func (a *UdpAC) loadConfigFile(file string) (content []byte, err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})
	content, err = os.ReadFile(file)
	if err != nil {
		log.Error("[AC] failed to read config file %s: %v", file, err)
	}
	return
}

func (a *UdpAC) IpPassMode() int {
	return a.config.IpPassMode
}

func (a *UdpAC) StopConfigWatch() {
	for _, w := range []io.Closer{baseConfigWatch, httpConfigWatch, serverPeerWatch} {
		if w != nil {
			_ = w.Close()
		}
	}
}

// intOrDefault returns v if v > 0, else def. Used for config fields
// where 0 (Go zero) means "unset, use default" — the alternative is
// pointer fields, which complicate TOML unmarshal for this codebase.
//
// A negative v is treated as "use default" but loud — operators
// who typo a negative threshold in TOML get a warning instead of
// the value silently disappearing into the default
func intOrDefault(v, def int) int {
	if v > 0 {
		return v
	}
	if v < 0 {
		log.Warning("[L3FlushSched] config value %d is negative; using default %d. Negative values are not valid for this field.", v, def)
	}
	return def
}
