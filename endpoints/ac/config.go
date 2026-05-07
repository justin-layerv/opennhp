package ac

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"

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

const (
	FilterMode_IPTABLES = iota // 0
	FilterMode_EBPFXDP         // 1
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
	ServerPort         int    `json:"serverPort"`         // Server port for initial registration (default: 62206)
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
		if content, err = a.loadConfigFile(fileName); err == nil {
			if err = toml.Unmarshal(content, &peers); err == nil {
				if updateErr := a.updateServerPeers(peers.Servers); updateErr != nil {
					log.Error("[AC] failed to apply server peer update from %s: %v", fileName, updateErr)
				}
			}
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

	// update — the fields below are NOT read by ardTrustSnapshot
	// so they're patched without the mutex (existing convention).
	// If you add a new field to ardTrustSnapshot's read set, the
	// corresponding write MUST move into reloadARDTrust's
	// grouped-under-lock block (or its own locked section) to
	// preserve the "snapshot-read fields written under
	// serverPeerMutex" invariant.
	if a.config.LogLevel != conf.LogLevel {
		log.Info("set base log level to %d", conf.LogLevel)
		a.log.SetLogLevel(conf.LogLevel)
		a.config.LogLevel = conf.LogLevel
	}

	if a.config.DefaultIp != conf.DefaultIp {
		log.Info("set default ip mode to %s", conf.DefaultIp)
		a.config.DefaultIp = conf.DefaultIp
	}

	if a.config.IpPassMode != conf.IpPassMode {
		log.Info("set ip pass mode to %d", conf.IpPassMode)
		a.config.IpPassMode = conf.IpPassMode
	}

	if a.config.DefaultCipherScheme != conf.DefaultCipherScheme {
		log.Info("set default cipher scheme to %d", conf.DefaultCipherScheme)
		a.config.DefaultCipherScheme = conf.DefaultCipherScheme
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
	a.config.Servers = peers

	// remove old peers from device
	a.serverPeerMutex.Lock()
	defer a.serverPeerMutex.Unlock()
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
