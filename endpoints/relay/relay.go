// Package relay implements the stateless NHP relay: the internet-facing DMZ
// hop that forwards an agent's opaque NHP packet to a cell's internal NHP-Server endpoint
// and returns the server's opaque reply to the exact originating client.
//
//	Browser JS-Agent --HTTPS POST /relay/{serverId}--> NHP-Relay
//	    --internal NHP_RLY{SourceAddr, InnerPacket, RequestID}--> NHP-Server
//
// Trust / crypto model:
//   - The inner packet is end-to-end agent<->server (the relay CANNOT read it);
//     the relay inspects only bounded cleartext header metadata for admission.
//   - The OUTER NHP_RLY is encrypted relay<->server (Noise IK); the relay must
//     be a registered NHP_RELAY peer on the server (relay.toml). The server
//     wraps its opaque inner ACK/COK/RAK in an authenticated RelayReturnMsg;
//     the relay validates the server key and dispatches by a random RequestID.
//   - SourceAddr — the client IP the server opens the AC pinhole for — is the
//     ONLY trusted source of that IP. HTTPS defaults to the TCP peer;
//     trusted-header mode is opt-in and only safe
//     behind a front door (see SourceAddrMode).
//
// The relay strips upstream OpenNHP's load-balance package: each serverId maps
// to the stable internal NLB endpoint for one cell. See
// docs/design/NHP_RELAY_TOPOLOGY.md.
package relay

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/utils"
)

// MetricRelayShed counts HTTPS backpressure sheds. A shed is a real incident
// signal — a cell is stuck/slow
// or the relay is under flood — so this is the graphable/alertable
// counterpart to logShed's throttled Warning, alarmed in
// terraform/modules/relay/monitoring.tf (#2649). Published into the shared
// LayerV/NHP namespace via the same endpoints/metrics publisher nhp-server uses
// (recordShed below), so the relay's first metric is consistent with the rest
// of the fleet rather than a parallel convention.
const MetricRelayShed = "RelayShed"

// MetricRelayOTPForward counts successfully forwarded fire-and-forget HTTPS
// OTP requests.
const MetricRelayOTPForward = "RelayOTPForward"

// MetricRelayReturnServerMismatch counts authenticated returns whose random
// request ID is active but bound to a different configured server. Delivery is
// still rejected; the counter makes version drift or a misbehaving cell visible.
const MetricRelayReturnServerMismatch = "RelayReturnServerMismatch"

// dimNameCell is the CloudWatch dimension naming the cell a shed was routed to.
// Its value is the relay's configured cell_servers[].Name; a per-cell relay shed
// series sits alongside that cell's server metrics ONLY insofar as that name
// matches the server's NHP_CELL_ID (e.g. "cell0") — a config-consistency
// assumption, not an enforced guarantee. Dashboard attribution only; the
// relay_shedding alarm keys on the base [Environment] stream, unaffected.
var dimNameCell = aws.String("Cell")

const (
	// relayResponseTimeout bounds how long an HTTP request waits for the
	// server's authenticated return before returning 504.
	relayResponseTimeout = 5 * time.Second

	// encryptTimeout bounds the device encryption hand-off for an NHP_RLY.
	encryptTimeout = 2 * time.Second

	// requestIDCollisionAttempts keeps a broken/random-source failure bounded.
	// One retry is already overwhelming defense for a 128-bit ID; four draws
	// preserve that margin without allowing an accidental infinite loop.
	requestIDCollisionAttempts = 4

	// placeholderSourcePort is stamped into SourceAddr when only the client IP
	// is known (trusted-header mode). The AC firewall rule keys on (src IP, dst
	// port, dst IP) — the source port is never used (endpoints/ac/msghandler.go)
	// — but the server's validateRelaySourceAddr requires a non-zero port, so we
	// supply one.
	placeholderSourcePort = 1

	// maxInFlightPerServer bounds concurrent HTTPS requests held for
	// one cell server (#2553). Each in-flight request
	// parks a goroutine and a `pending` map entry for up to relayResponseTimeout
	// (5s); without a cap, a slow or unreachable cell under re-knock volume grows
	// both UNBOUNDED — and a stuck cell is exactly when that bites (an
	// unbounded-goroutine DoS). When this cap is reached the relay sheds the
	// request (503) instead of queueing more work behind a backend that is already
	// failing — fast-fail beats unbounded growth. (Upstream OpenNHP had a
	// per-instance in-flight semaphore that was stripped when we dropped its
	// `loadbalance` package; this restores that backpressure for our routing model.)
	//
	// The bound is PER cell server (a buffered channel on each serverRuntime), so a
	// stuck cell sheds its own load without starving healthy cells. The total
	// goroutine bound is maxInFlightPerServer × len(servers) (= one cell today).
	//
	// WHY 256: prod knock traffic is sparse (~1–2 knocks/hr) and each forward
	// resolves in well under the 5s timeout, so legitimate concurrent in-flight is
	// effectively ~0. 256 is orders of magnitude above any real peak — a healthy
	// relay never sheds — yet it bounds the handlers that PARK on the forward wait
	// (~5s) and the `pending` map at a few hundred entries even when a cell is fully
	// stuck or under a flood. (net/http still spawns a goroutine per accepted
	// connection; a shed returns immediately — what's capped is the long-lived
	// parked growth, which is the actual DoS vector.) It is not an
	// operator knob on purpose: the safe value is "comfortably above real peak, far
	// below unbounded", which this is, and a config surface would just be one more
	// thing to misconfigure (cf. relay.toml's deliberately small surface).
	//
	// The cap's effectiveness leans on the server timeouts that bound how long a
	// slot is held: ReadTimeout (10s) caps a slow body read and responseTimeout
	// (5s) caps the forward wait, so a slot is held ~15s worst case — a slow sender
	// cannot pin the cap indefinitely. Keep those bounded if this cap is to hold.
	maxInFlightPerServer = 256

	// shedLogWindow throttles the per-shed Warning log. Shedding happens exactly
	// under a flood or a stuck cell, so a log per shed request would itself flood
	// CloudWatch (one Warning per inbound request). Instead the relay logs at most
	// once per window PER cell, carrying the count of sheds since the last log, so a
	// flood produces a steady trickle rather than a torrent. RelayShed is the
	// graphable per-event signal; this log is deliberately only diagnostic detail.
	shedLogWindow = 10 * time.Second
)

// relayPendingEntry binds an HTTPS request ID to the one configured cell that
// received it. Request IDs are unguessable, but the authenticated sender check
// is still required: a configured cell must not be able to satisfy another
// cell's pending browser request if an ID is disclosed or a cell is compromised.
type relayPendingEntry struct {
	serverID string
	reply    chan []byte
}

// serverRuntime is one cell server the relay routes to.
type serverRuntime struct {
	id     string // pubkey fingerprint = {serverId} in the URL
	name   string
	pubKey []byte
	addr   *net.UDPAddr
	// inFlight is a counting semaphore (buffered channel) bounding the concurrent
	// in-flight POST /relay/ requests for THIS cell at maxInFlightPerServer. A
	// non-blocking send acquires a slot; a full channel means the cap is reached
	// and the request is shed (503). See maxInFlightPerServer for the rationale.
	// MUST be non-nil: a nil channel is never ready in the acquire select, so the
	// default (shed) branch would fire and the cell would shed 100% of traffic
	// silently. Both construction sites (New + the test) initialize it.
	inFlight chan struct{}

	// shedCount and lastShedLogNano throttle the shed Warning to once per
	// shedLogWindow per cell. Every shed bumps shedCount; the first shedder in a
	// window wins a CAS on lastShedLogNano, swaps shedCount to 0, and logs the
	// drained total (which includes its own shed). atomics — not a mutex — to match
	// relay.go's existing lock-free idioms on the hot path. See logShed.
	shedCount       atomic.Uint64
	lastShedLogNano atomic.Int64

	// shedDims is the per-cell CloudWatch breakdown dimension ([Cell=name]),
	// built once at construction because it's constant per cell — recordShed
	// reuses it rather than allocating a fresh slice + aws.String on every shed
	// (the backpressure path runs hot under exactly the flood the cap targets).
	// Safe to share: the publisher's AddCounterWithDims copies extraDims.
	shedDims []types.Dimension
}

// logShed records one shed and emits a throttled Warning: at most one line per
// shedLogWindow per cell, carrying the count of sheds drained since the last
// emit. Concurrency-safe and lock-free (sheds are the flood/stuck-cell hot path):
//   - Add(1) FIRST so this shed is counted no matter who logs it.
//   - The first shedder past the window wins the CompareAndSwap on lastShedLogNano
//     and is the sole emitter for the window; concurrent shedders either fail the
//     window check or lose the CAS and stay silent (their shed still counted).
//   - The winner Swaps shedCount to 0 and logs the drained total (which includes
//     its own +1). lastShedLogNano's zero value makes the very first shed — and
//     the first shed after any quiet period — log immediately.
func (srv *serverRuntime) logShed() {
	srv.shedCount.Add(1)
	// Wall clock (not monotonic): a backward NTP step can briefly suppress an emit
	// until the clock catches up, but shedCount is never lost (drained by the next
	// Swap(0)), so only the log cadence can drift — the count stays accurate.
	now := time.Now().UnixNano()
	last := srv.lastShedLogNano.Load()
	if now-last < int64(shedLogWindow) {
		return // within the window; another shedder already logged (or will)
	}
	if !srv.lastShedLogNano.CompareAndSwap(last, now) {
		return // lost the race to another shedder this window
	}
	n := srv.shedCount.Swap(0)
	log.Warning("relay: shed %d request(s) to %s in the last %s — in-flight cap (%d) reached",
		n, srv.name, shedLogWindow, maxInFlightPerServer)
}

// buildRelayMetricDimensions returns the relay publisher's base CloudWatch
// dimensions, read from the same NHP_ENVIRONMENT env var nhp-server reads
// (endpoints/server/udpserver.go::buildServerMetricDimensions). The relay base
// set is [Environment] ONLY — deliberately NOT the server's [Environment, Cell],
// because a relay fleet fronts ALL cells (it routes per-cell by serverId), so
// there is no single Cell value for the process. The target Cell is attached
// per-shed as an extra dimension instead (see recordShed), which both keeps the
// base counter the alarm matches on at a clean [Environment] dim set and gives
// dashboards a per-cell breakdown — the dual-publish pattern terraform/CLAUDE.md
// prescribes for Go-side alarms.
//
// NB: NHP_ENVIRONMENT is load-bearing — the relay_shedding alarm matches on this
// Environment value (sourced from the same var.environment via user_data). If a
// future boot path drops it, the metric lands at Environment="unknown", the alarm
// stops matching, and treat_missing_data="notBreaching" keeps it green — a shed
// storm would go invisible. Keep the user_data -e NHP_ENVIRONMENT wiring intact.
func buildRelayMetricDimensions() []types.Dimension {
	environment := os.Getenv("NHP_ENVIRONMENT")
	if environment == "" {
		environment = "unknown"
	}
	return []types.Dimension{
		{Name: aws.String("Environment"), Value: aws.String(environment)},
	}
}

// recordShed increments the RelayShed counter on each HTTPS backpressure shed
// (#2649).
// It DUAL-PUBLISHES, exactly as terraform/CLAUDE.md prescribes for Go-side
// alarms: a base counter at the publisher's [Environment] dims (the clean stream
// the relay_shedding alarm matches on) PLUS a per-cell breakdown carrying the
// target Cell (for dashboards / attribution). nil-safe via the publisher's nil
// receiver, so it is unconditional on the shed hot path.
//
// Counted per shed, independently of logShed's throttled Warning:
// the log is rate-limited to once per window to avoid flooding CloudWatch Logs,
// but the metric is a cheap in-memory atomic add batched by the publisher's
// flush loop, so it carries the exact shed rate the alarm needs.
func (rs *RelayServer) recordShed(srv *serverRuntime) {
	rs.metrics.IncrCounter(MetricRelayShed)
	// srv.shedDims is prebuilt (constant per cell) — see the field comment.
	rs.metrics.IncrCounterWithDims(MetricRelayShed, srv.shedDims)
}

// RelayServer is the NHP-Relay HTTP front backed by an NHP_RELAY device.
type RelayServer struct {
	config     *Config
	device     *core.Device
	httpServer *http.Server
	udpConn    *net.UDPConn              // private NHP_RLY send + authenticated return socket
	servers    map[string]*serverRuntime // by pubkey fingerprint
	cors       corsAllowlist             // browser CORS allowlist (#2631)

	// metrics publishes the relay's CloudWatch metrics into the shared
	// LayerV/NHP namespace (the relay's first metrics emission, #2649). Booted in
	// New via the same endpoints/metrics publisher nhp-server uses; nil when AWS
	// config is unavailable (local/dev) — the publisher's methods are nil-safe
	// no-ops, so recordShed never needs a guard. See recordShed.
	metrics *metrics.Publisher

	responseTimeout time.Duration // how long a handler waits for the server return

	pendingMu sync.Mutex
	pending   map[string]relayPendingEntry // reserved relay request ID -> expected cell and exact HTTP waiter

	wg             sync.WaitGroup
	handlerStartMu sync.Mutex
	stopCh         chan struct{}
	running        atomic.Bool
	closeOnce      sync.Once // guards udpConn.Close (Stop may run with/without a prior Start)
}

// New builds a RelayServer from cfg. It decodes the relay key, creates the
// NHP_RELAY device, binds the shared UDP socket, and builds the cell-routing
// table. Call Start to serve.
func New(cfg *Config) (*RelayServer, error) {
	if cfg == nil {
		return nil, errors.New("relay: nil config")
	}
	// Shallow-copy cfg before normalizing scalar fields; New only reads slice
	// fields (Servers/CORSAllowedOrigins), so a deep copy would not buy safety.
	cfgCopy := *cfg
	cfg = &cfgCopy

	prk, err := base64.StdEncoding.DecodeString(cfg.PrivateKeyBase64)
	if err != nil || len(prk) != 32 {
		return nil, fmt.Errorf("relay: invalid private_key (want base64 of 32 bytes): %w", err)
	}

	// Reject an unknown source_addr_mode at startup. deriveSourceAddr falls back
	// to RemoteAddr for anything that isn't exactly the trusted-header value, so
	// a typo (e.g. "trusted-header") would silently use the front-door IP as
	// SourceAddr — opening every client's AC pinhole for the wrong IP with no
	// error. Fail closed.
	switch cfg.SourceAddrMode {
	case SourceAddrModeRemoteAddr, SourceAddrModeTrustedHeader:
	default:
		return nil, fmt.Errorf("relay: unknown source_addr_mode %q (want \"\" or %q)", cfg.SourceAddrMode, SourceAddrModeTrustedHeader)
	}
	if cfg.EnableTLS {
		cfg.TLSCertFile = strings.TrimSpace(cfg.TLSCertFile)
		cfg.TLSKeyFile = strings.TrimSpace(cfg.TLSKeyFile)
		if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
			return nil, errors.New("relay: enable_tls=true requires non-empty tls_cert_file and tls_key_file")
		}
		// File existence/readability is validated lazily by ListenAndServeTLS in
		// Start, after New has bound the shared UDP socket but before HTTP serving.
	}

	// Boot-time guard against the documented source-IP-spoofing combo (#2553).
	// SourceAddr is the SOLE trusted source of the AC-pinhole client IP; in
	// trusted_header mode the relay reads it from a client-supplied header, which
	// is only safe when a trusted front door OVERWRITES (or attests) that header
	// and is the relay's ONLY ingress path. Refuse to even start on a config that
	// provably defeats that precondition, so a deploy can't silently stand up a
	// spoofing hole that opens AC pinholes for arbitrary victim IPs.
	if err := assertTrustedHeaderBindCoherent(cfg); err != nil {
		return nil, err
	}
	if cfg.SourceAddrMode == SourceAddrModeTrustedHeader {
		// Surface the load-bearing security dependency at boot / for incident
		// triage, not only in code comments: in trusted_header mode the source IP
		// comes from a client-supplied header, safe ONLY because a trusted front
		// door overwrites it and the relay_http_from_alb SG rule is the sole
		// ingress — the residual the boot guard cannot verify in-process.
		log.Info("relay: source_addr_mode=trusted_header — source IP read from a client header; the trusted front door + relay_http_from_alb SG rule (sole ingress) is the load-bearing control")
	}
	if cfg.TrustedProxy {
		if cfg.SourceAddrMode == SourceAddrModeTrustedHeader && cfg.EnableTLS {
			log.Info("relay: trusted_proxy=true is enabling source_addr_mode=trusted_header with enable_tls=true — the trusted front door must overwrite/attest the header and be the relay's sole ingress path")
		} else {
			log.Info("relay: trusted_proxy=true is inert unless source_addr_mode=trusted_header and enable_tls=true")
		}
	}

	// Server return envelopes are Noise-authenticated below against the configured
	// server pubkeys. Disable the core address-pinned peer lookup because the
	// internal NLB preserves a dynamic server-instance source address.
	device := core.NewDevice(core.NHP_RELAY, prk, &core.DeviceOptions{DisableServerPeerValidation: true})
	if device == nil {
		return nil, errors.New("relay: failed to create NHP device")
	}

	servers := make(map[string]*serverRuntime, len(cfg.Servers))
	for _, sc := range cfg.Servers {
		pub, err := base64.StdEncoding.DecodeString(sc.PubKeyBase64)
		if err != nil || len(pub) != 32 {
			return nil, fmt.Errorf("relay: server %q has invalid public_key: %w", sc.Name, err)
		}
		udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", sc.Host, sc.Port))
		if err != nil {
			return nil, fmt.Errorf("relay: server %q unresolvable %s:%d: %w", sc.Name, sc.Host, sc.Port, err)
		}
		id := utils.PubKeyFingerprint(pub)
		if existing := servers[id]; existing != nil {
			return nil, fmt.Errorf(
				"relay: server %q duplicates public key fingerprint %s already used by %q",
				sc.Name, id, existing.name,
			)
		}
		servers[id] = &serverRuntime{
			id:       id,
			name:     sc.Name,
			pubKey:   pub,
			addr:     udpAddr,
			inFlight: make(chan struct{}, maxInFlightPerServer),
			shedDims: []types.Dimension{{Name: dimNameCell, Value: aws.String(sc.Name)}},
		}
		log.Info("relay: routing %s (fingerprint=%s) -> %s", sc.Name, id, udpAddr)
	}

	listenAddr, err := net.ResolveUDPAddr("udp", cfg.ListenUDPAddr())
	if err != nil {
		return nil, fmt.Errorf("relay: invalid udp listen addr: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("relay: failed to bind udp socket: %w", err)
	}

	rs := &RelayServer{
		config:          cfg,
		device:          device,
		udpConn:         udpConn,
		servers:         servers,
		cors:            newCORSAllowlist(cfg.CORSAllowedOrigins),
		pending:         make(map[string]relayPendingEntry),
		responseTimeout: relayResponseTimeout,
		stopCh:          make(chan struct{}),
	}

	// Boot the CloudWatch metrics publisher (#2649) — the relay's first metrics
	// emission. Same endpoints/metrics.Publisher + LayerV/NHP namespace nhp-server
	// uses (endpoints/server/udpserver.go), so the relay's metric is consistent
	// with the rest of the fleet and Terraform can alarm on it the same way.
	// NewPublisher returns nil if AWS config can't load (local/dev with no
	// region/creds); every publisher method is then a nil-safe no-op, so the relay
	// runs fine without metrics off-cloud. Checkpointing is intentionally NOT
	// enabled: the shed counter is a best-effort observability signal, and the
	// relay is a stateless forwarder with no checkpoint dir in its container.
	rs.metrics = metrics.NewPublisher(metrics.Config{
		Namespace:  "LayerV/NHP",
		Dimensions: buildRelayMetricDimensions(),
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/relay/", rs.handleRelay)
	mux.HandleFunc("/health/live", rs.handleHealthLive)
	rs.httpServer = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second, // the POST body is one small NHP packet
		// WriteTimeout must exceed responseTimeout — it spans the handler's wait
		// for the server return plus the response write, measured from request read.
		WriteTimeout: relayResponseTimeout + 10*time.Second,
		IdleTimeout:  60 * time.Second,
	}
	if cfg.EnableTLS {
		// Pin a TLS floor for both direct termination and trusted-proxy
		// backend re-encryption.
		rs.httpServer.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return rs, nil
}

func (rs *RelayServer) reservePending(serverID string, reply chan []byte) (string, error) {
	for range requestIDCollisionAttempts {
		id, err := common.NewRelayRequestID()
		if err != nil {
			return "", err
		}
		rs.pendingMu.Lock()
		_, exists := rs.pending[id]
		if !exists {
			rs.pending[id] = relayPendingEntry{serverID: serverID, reply: reply}
		}
		rs.pendingMu.Unlock()
		if !exists {
			return id, nil
		}
	}
	return "", errors.New("relay: repeated random request ID collision")
}

func (rs *RelayServer) releasePending(id string) {
	// Release makes this value eligible for a future reservation. A late return
	// plus a fresh 128-bit RNG collision for the same configured server could
	// therefore reach the new waiter after this point. The relay treats the
	// inner packet as opaque agent ciphertext, so that collision can at worst
	// cause a spurious protocol failure; it cannot expose cross-client plaintext.
	// Keeping server-fingerprint binding in dispatch is load-bearing
	// for that property.
	rs.pendingMu.Lock()
	delete(rs.pending, id)
	rs.pendingMu.Unlock()
}

// startBackground launches the NHP device and the UDP receive loop (everything
// except the blocking HTTP serve). Separated so tests can drive handleRelay
// directly without binding/serving HTTP.
func (rs *RelayServer) startBackground() {
	rs.device.Start()
	rs.running.Store(true)
	rs.wg.Add(1)
	go rs.recvLoop()
}

// Start launches the device, the UDP receive loop, and the HTTP server. It
// blocks until the HTTP server stops (or Stop is called). If it returns a
// non-nil error (e.g. the listen address is in use), the device and recvLoop
// are still running — the caller MUST call Stop to release them.
func (rs *RelayServer) Start() error {
	rs.startBackground()

	var serveErr error
	if rs.config.EnableTLS {
		serveErr = rs.httpServer.ListenAndServeTLS(rs.config.TLSCertFile, rs.config.TLSKeyFile)
	} else {
		serveErr = rs.httpServer.ListenAndServe()
	}
	if errors.Is(serveErr, http.ErrServerClosed) {
		return nil
	}
	return serveErr
}

// Stop gracefully shuts the relay down.
func (rs *RelayServer) Stop(ctx context.Context) error {
	if !rs.running.CompareAndSwap(true, false) {
		// Never started (or already stopped) — still release the socket New
		// opened, so a New()-then-Stop() bring-up error path doesn't leak it.
		rs.closeSockets()
		// New always boots the publisher, so flush it on the never-started path
		// too (idempotent; nil-safe). Otherwise a New()-then-Stop() bring-up
		// failure would leak the publisher's flush goroutine.
		rs.metrics.Stop()
		return nil
	}
	// Close stopCh FIRST so handlers parked in their select (on respCh / timeout
	// / stopCh) return 503 immediately — otherwise httpServer.Shutdown would
	// block on them until the 5s relayResponseTimeout, since the stopCh case
	// would only become live after Shutdown returns.
	close(rs.stopCh)
	err := rs.httpServer.Shutdown(ctx)
	rs.closeSockets() // unblocks the private UDP receive loop
	// A handler takes handlerStartMu while checking running and registering its
	// wg ownership. Stop flipped running false above; this barrier guarantees
	// every handler that observed the old true state completed Add before Wait,
	// even when HTTP Shutdown returned early on a context deadline.
	rs.handlerStartMu.Lock()
	rs.handlerStartMu.Unlock()
	rs.wg.Wait()
	rs.device.Stop()
	// Flush any sheds accumulated since the last 60s flush before exit (nil-safe).
	rs.metrics.Stop()
	return err
}

func (rs *RelayServer) closeSockets() {
	rs.closeOnce.Do(func() {
		_ = rs.udpConn.Close()
	})
}

// handleHealthLive is the liveness probe (GET /health/live -> 200 "ok").
// Process-up only — it does not check server reachability, so the relay reports
// healthy even when a cell server is down (the relay is still correctly
// forwarding; a down server is the server's health concern, not the relay's).
func (rs *RelayServer) handleHealthLive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// handleRelay handles POST and OPTIONS (CORS preflight) on /relay/{serverId}.
func (rs *RelayServer) handleRelay(w http.ResponseWriter, r *http.Request) {
	// CORS (#2631): the relay's only cross-origin caller is the qURL knock page
	// (qurl.link, per env) — see cors.go. Echo it back for an allowlisted origin
	// (never "*"); the resource domains (*.qurl.site / custom whitelabel) are the
	// data plane and never call the relay. Set the headers first so every path
	// (preflight, success, AND the http.Error failures below) carries them, letting
	// the browser read failure statuses. Vary: Origin UNCONDITIONALLY — the response
	// varies by Origin (a matched origin gets Access-Control-Allow-Origin, others
	// don't), so a shared cache must not serve one origin's response to another.
	w.Header().Set("Vary", "Origin")
	if origin := r.Header.Get("Origin"); rs.cors.allowed(origin) {
		rs.cors.setHeaders(w, origin)
	}
	rs.handlerStartMu.Lock()
	if !rs.running.Load() {
		rs.handlerStartMu.Unlock()
		http.Error(w, "shutting down", http.StatusServiceUnavailable)
		return
	}
	rs.wg.Add(1)
	rs.handlerStartMu.Unlock()
	defer rs.wg.Done()

	// Answer the preflight BEFORE the serverId lookup — a preflight asks about
	// method/headers, not resource existence, so an unknown serverId must not 404 it.
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	serverID := strings.TrimPrefix(r.URL.Path, "/relay/")
	srv := rs.servers[serverID]
	if srv == nil {
		http.Error(w, "unknown server", http.StatusNotFound)
		return
	}

	// Backpressure (#2553): try to claim an in-flight slot for this cell BEFORE
	// doing any work (reading the body, registering a pending waiter, forwarding).
	// A non-blocking send sheds the request with 503 the instant the cap is hit,
	// rather than parking another goroutine + map entry behind a cell that is
	// already slow/stuck. Releasing on the SAME path the slot was taken (defer)
	// keeps the count exact across every return below. Retry-After tells a
	// well-behaved client to back off instead of hot-looping the overloaded relay.
	select {
	case srv.inFlight <- struct{}{}:
		defer func() { <-srv.inFlight }()
	default:
		srv.logShed()
		// Graphable/alertable counterpart to the throttled logShed Warning (#2649):
		// counted on EVERY 503 so the alarm sees the true shed rate, not the
		// once-per-window log cadence.
		rs.recordShed(srv)
		// 1s is intentional, not arbitrary headroom: knock cadence is sparse
		// (~1-2/hr) and shedding is the rare pathological case, so a well-behaved
		// client retrying after 1s is fine.
		w.Header().Set("Retry-After", "1")
		http.Error(w, "relay busy", http.StatusServiceUnavailable)
		return
	}

	inner, err := io.ReadAll(io.LimitReader(r.Body, maxInnerPacketSize+1))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	if len(inner) == 0 || len(inner) > maxInnerPacketSize {
		http.Error(w, "invalid packet size", http.StatusBadRequest)
		return
	}

	innerType, err := rs.innerType(inner)
	if err != nil {
		log.Warning("relay: rejecting malformed inner packet from %s: %v", r.RemoteAddr, err)
		http.Error(w, "malformed packet", http.StatusBadRequest)
		return
	}
	// HTTPS carries only NHP agent requests. DHP_KNK and server reply types must
	// be rejected here instead of consuming a waiter and
	// a relay/server round trip before the server drops them.
	if !httpsAgentTypeAllowed(innerType) {
		log.Warning("relay: rejecting unsupported HTTPS inner type %s from %s", core.HeaderTypeToString(innerType), r.RemoteAddr)
		http.Error(w, "unsupported packet type", http.StatusBadRequest)
		return
	}

	sourceAddr := rs.deriveSourceAddr(r)
	if innerType == core.NHP_OTP {
		// OTP is fire-and-forget, so this ID is intentionally unreserved: there
		// is no response waiter or return that could collide with an active ID.
		requestID, err := common.NewRelayRequestID()
		if err != nil {
			http.Error(w, "relay unavailable", http.StatusServiceUnavailable)
			return
		}
		if err := rs.forward(srv, sourceAddr, inner, requestID); err != nil {
			log.Error("relay: OTP forward to %s failed: %v", srv.name, err)
			http.Error(w, "forward failed", http.StatusBadGateway)
			return
		}
		rs.metrics.IncrCounter(MetricRelayOTPForward)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	// Reserve and populate the exact waiter atomically so request-ID collision
	// detection and return dispatch share one lifecycle map and one lock.
	respCh := make(chan []byte, 1)
	requestID, err := rs.reservePending(srv.id, respCh)
	if err != nil {
		log.Error("relay: reserve request ID: %v", err)
		http.Error(w, "relay unavailable", http.StatusServiceUnavailable)
		return
	}
	defer rs.releasePending(requestID)

	if err := rs.forward(srv, sourceAddr, inner, requestID); err != nil {
		log.Error("relay: forward to %s failed: %v", srv.name, err)
		http.Error(w, "forward failed", http.StatusBadGateway)
		return
	}

	select {
	case ackBytes := <-respCh:
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(ackBytes)
	case <-time.After(rs.responseTimeout):
		http.Error(w, "server timeout", http.StatusGatewayTimeout)
	case <-rs.stopCh:
		http.Error(w, "shutting down", http.StatusServiceUnavailable)
	}
}

// forward wraps the inner packet in an NHP_RLY and sends it to the cell server
// from the shared UDP socket (so the authenticated return reaches this socket).
func (rs *RelayServer) forward(srv *serverRuntime, sourceAddr *net.UDPAddr, inner []byte, requestID string) error {
	rlyMsg := &common.RelayForwardMsg{
		SourceAddr:  &common.NetAddress{Ip: sourceAddr.IP.String(), Port: sourceAddr.Port},
		InnerPacket: base64.StdEncoding.EncodeToString(inner),
		RequestID:   requestID,
	}
	msgBytes, err := json.Marshal(rlyMsg)
	if err != nil {
		return fmt.Errorf("marshal RelayForwardMsg: %w", err)
	}

	encCh := make(chan *core.MsgAssemblerData, 1)
	md := &core.MsgData{
		HeaderType:     core.NHP_RLY,
		Compress:       false,
		Message:        msgBytes,
		PeerPk:         srv.pubKey,
		RemoteAddr:     srv.addr,
		ExternalPacket: rs.device.AllocateRelayPacket(),
		EncryptedPktCh: encCh,
	}
	rs.device.SendMsgToPacket(md)

	select {
	case mad := <-encCh:
		packet, err := core.ConsumeEncryptedPacket(mad)
		if err != nil {
			return fmt.Errorf("encrypt NHP_RLY: %w", err)
		}
		if _, err := rs.udpConn.WriteToUDP(packet, srv.addr); err != nil {
			return fmt.Errorf("write NHP_RLY: %w", err)
		}
		return nil
	case <-time.After(encryptTimeout):
		// SendMsgToPacket is asynchronous. If its worker completes after our
		// timeout, the buffered channel owns a pooled packet until it is drained.
		// Reap one late result so normal late completions return it to the pool.
		// We cannot release the packet before the worker delivers without a
		// use-after-release race. If a worker never delivers, it retains one 6 KiB
		// buffer; surrounding per-cell admission and the fixed device queue bound
		// cap that ownership instead of letting it grow per public datagram.
		rs.reapLateEncryptedPacket(encCh)
		return errors.New("timeout encrypting NHP_RLY")
	}
}

// reapLateEncryptedPacket tracks the bounded late-result drain in the relay's
// shutdown barrier. handleRelay registers ownership behind handlerStartMu, so
// Add always happens while the counter is non-zero and before Stop reaches
// wg.Wait.
func (rs *RelayServer) reapLateEncryptedPacket(encCh <-chan *core.MsgAssemblerData) {
	rs.wg.Add(1)
	go func() {
		defer rs.wg.Done()
		defer func() {
			if recovered := recover(); recovered != nil {
				log.Error("relay: recovered from panic draining late encryption result: %v", recovered)
			}
		}()
		select {
		case mad := <-encCh:
			if mad != nil {
				mad.Destroy()
			}
		case <-time.After(encryptTimeout):
		}
	}()
}

// recvLoop reads authenticated server return envelopes off the private socket
// and dispatches each opaque inner reply by its random relay request ID.
func (rs *RelayServer) recvLoop() {
	defer rs.wg.Done()
	// Sized one byte beyond the maximum return envelope so an oversized datagram
	// is distinguishable from an exact maximum and rejected by decodeRelayReturn.
	// One extra byte makes truncation observable. Authenticated relay envelopes
	// may be larger than a direct NHP packet because they contain a complete
	// 4096-byte inner packet plus request-correlation metadata.
	buf := make([]byte, maxAckPacketSize+1)
	for {
		select {
		case <-rs.stopCh:
			return
		default:
		}
		n, from, err := rs.udpConn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Closed socket (Stop) returns here; for a transient error (e.g. a
			// prior ICMP port-unreachable surfacing as ECONNREFUSED on the next
			// read) back off briefly so a persistent condition can't busy-spin
			// the CPU.
			select {
			case <-rs.stopCh:
				return
			case <-time.After(10 * time.Millisecond):
			}
			continue
		}
		outer := append([]byte(nil), buf[:n]...)
		// Per-datagram recover: one malformed or unauthenticated return must never
		// kill the private receive loop.
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Error("relay: recovered from panic processing datagram (%d bytes): %v", n, r)
				}
			}()
			requestID, serverID, inner, perr := rs.decodeRelayReturn(outer, from)
			if perr != nil {
				return
			}
			rs.dispatch(requestID, serverID, inner)
		}()
	}
}

func (rs *RelayServer) decodeRelayReturn(raw []byte, from *net.UDPAddr) (string, string, []byte, error) {
	if len(raw) < core.RelayPacketMinimalLength || len(raw) > maxAckPacketSize {
		return "", "", nil, errors.New("invalid relay return packet size")
	}
	// ConnectionData allocation precedes Noise authentication. This is acceptable
	// on the SG-restricted private UDP 62207 return socket: the receive loop is
	// synchronous (at most one such allocation at a time), and legitimate return
	// volume is bounded by the relay's in-flight request limits. A future change
	// to concurrent return decoding must re-budget or reuse ConnectionData before
	// introducing parallel copies of its channel set.
	conn := &core.ConnectionData{
		Device:               rs.device,
		RemoteAddr:           from,
		CookieStore:          &core.CookieStore{},
		SendQueue:            make(chan *core.Packet, 1),
		RecvQueue:            make(chan *core.Packet, 1),
		BlockSignal:          make(chan struct{}, 1),
		SetTimeoutSignal:     make(chan struct{}, 1),
		StopSignal:           make(chan struct{}),
		RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
	}
	defer conn.Close()
	ppd, err := rs.device.PacketToMsg(&core.PacketData{
		BasePacket: &core.Packet{Content: raw},
		ConnData:   conn,
		InitTime:   time.Now().UnixNano(),
	})
	if err != nil {
		return "", "", nil, fmt.Errorf("decrypt relay return: %w", err)
	}
	if ppd == nil {
		return "", "", nil, errors.New("decrypt relay return returned no packet")
	}
	if ppd.HeaderType != core.NHP_ACK {
		return "", "", nil, fmt.Errorf("unexpected relay return outer type %s", core.HeaderTypeToString(ppd.HeaderType))
	}
	serverID := utils.PubKeyFingerprint(ppd.RemotePubKey)
	if rs.servers[serverID] == nil {
		return "", "", nil, errors.New("relay return sender is not a configured server")
	}
	var returned common.RelayReturnMsg
	if err := common.DecodeRelayJSONStrict(ppd.BodyMessage, &returned); err != nil {
		return "", "", nil, fmt.Errorf("parse RelayReturnMsg: %w", err)
	}
	if !common.ValidRelayRequestID(returned.RequestID) {
		return "", "", nil, errors.New("invalid relay return request ID")
	}
	if returned.InnerPacket == "" || len(returned.InnerPacket) > base64.StdEncoding.EncodedLen(maxInnerPacketSize) {
		return "", "", nil, errors.New("invalid relay return inner packet size")
	}
	inner, err := base64.StdEncoding.DecodeString(returned.InnerPacket)
	if err != nil || len(inner) == 0 || len(inner) > maxInnerPacketSize {
		return "", "", nil, errors.New("invalid relay return inner packet")
	}
	innerType, err := rs.innerType(inner)
	if err != nil {
		return "", "", nil, errors.New("malformed relay return inner packet")
	}
	if !relayReturnTypeAllowed(innerType) {
		return "", "", nil, fmt.Errorf("unexpected relay return inner type %s", core.HeaderTypeToString(innerType))
	}
	return returned.RequestID, serverID, inner, nil
}

// Keep this response set, httpsAgentTypeAllowed's request set, and core's
// NHP_RELAY receive gate in lockstep; the union invariant is tested below.
func relayReturnTypeAllowed(headerType int) bool {
	switch headerType {
	case core.NHP_ACK, core.NHP_COK, core.NHP_RAK, core.NHP_LRT:
		return true
	default:
		return false
	}
}

func httpsAgentTypeAllowed(headerType int) bool {
	switch headerType {
	case core.NHP_KNK, core.NHP_RKN, core.NHP_EXT, core.NHP_OTP, core.NHP_REG, core.NHP_LST:
		return true
	default:
		return false
	}
}

// dispatch delivers an authenticated inner reply to its exact random request ID.
func (rs *RelayServer) dispatch(requestID, serverID string, raw []byte) {
	rs.pendingMu.Lock()
	entry, ok := rs.pending[requestID]
	rs.pendingMu.Unlock()
	if ok {
		// A cryptographically authenticated but unexpected configured server
		// must not satisfy this exact waiter.
		if entry.serverID != serverID {
			rs.metrics.IncrCounter(MetricRelayReturnServerMismatch)
			return
		}
		select {
		case entry.reply <- raw:
		default:
		}
	}
}

func (rs *RelayServer) innerType(raw []byte) (int, error) {
	// Length guard BEFORE RecvPrecheck. Unlike PacketToMsg, RecvPrecheck is not
	// wrapped in recover() and reads the header (Content[0:4], [4:8], …) without
	// a lower-bound check. An undersized HTTPS body or malformed authenticated
	// RelayReturn inner packet must be rejected instead of panicking the process.
	if len(raw) < core.HeaderCommonSize {
		return 0, errors.New("packet too short")
	}
	if len(raw) > maxInnerPacketSize {
		return 0, errors.New("packet too large")
	}
	pkt := rs.device.AllocatePoolPacket()
	if pkt == nil {
		return 0, errors.New("packet pool exhausted")
	}
	defer rs.device.ReleasePoolPacket(pkt)
	copy(pkt.Buf[:len(raw)], raw)
	pkt.Content = pkt.Buf[:len(raw)]
	headerType, _, err := rs.device.RecvPrecheck(pkt)
	if err != nil {
		return 0, err
	}
	return headerType, nil
}

// assertTrustedHeaderBindCoherent fails closed (#2553) on a relay config that
// provably defeats the precondition for SourceAddrModeTrustedHeader being safe:
// that the relay sits behind a trusted front door which overwrites/attests the
// source-IP header and is the relay's ONLY ingress path. In RemoteAddr mode the
// source IP is the spoof-proof TCP peer, so none of this applies — return nil.
//
// We reject two configs we can prove are dangerous at the process level:
//
//  1. trusted_header + enable_tls=true without trusted_proxy=true. We cannot
//     tell a relay that terminates client TLS itself (the direct internet front
//     — any client is the relay's TCP peer and sets the header freely, a
//     spoofing hole) from a trusted front door that terminates client TLS,
//     attests/overwrites the header, and re-encrypts to this backend over TLS
//     (safe — both present enable_tls=true).
//     The attestation is not observable at the process level (same limitation as
//     the bind RESIDUAL below), so we FAIL CLOSED on the ambiguous combo unless
//     the operator explicitly asserts the trusted front-door precondition.
//     RemoteAddr is correct for a direct-terminating relay; the safe re-encrypt
//     topology must set trusted_proxy=true (#2663).
//
//  2. trusted_header + a ListenAddr host that parses to a concrete routable
//     PUBLIC IP. Binding a public address means clients can reach the relay
//     directly (no front door in front of that interface), so a client-supplied
//     header is attacker-controlled.
//     trusted_proxy=true intentionally does NOT override this check; the opt-in
//     only resolves the TLS re-encryption ambiguity.
//
// What we deliberately ALLOW (these are coherent; production uses the
// trusted_proxy re-encrypt exception from #1 plus the unspecified bind below —
// see terraform/modules/relay/user_data.sh.tpl):
//   - loopback (127.0.0.0/8, ::1) or RFC1918/private host — a private/loopback
//     interface is not directly internet-reachable.
//   - an UNSPECIFIED / empty host ("", ":8080", "0.0.0.0:8080", "[::]:8080") —
//     binding all interfaces is how the relay listens behind the ALB whose SG
//     rule (relay_http_from_alb) is the real "sole path" control. The relay
//     process cannot introspect that SG, so we cannot verify it here.
//   - a non-IP hostname — we cannot classify it without resolving (and a resolve
//     at boot is brittle), so we do not block on it.
//
// DEVIATION FROM THE LITERAL #2553 ACCEPTANCE: the issue says to require a
// loopback/private bind for trusted_header. A literal loopback requirement is
// IMPOSSIBLE in this deployment — the ALB target group is target_type="instance"
// (terraform/modules/relay/alb.tf), so the ALB reaches the relay over the network
// at the instance IP; a loopback-only bind would be unreachable by the ALB. The
// real "sole path" guarantee is the ALB-only security-group rule, not a loopback
// bind. So this guard enforces the issue's INTENT (fail closed on the provable
// spoofing combos) while permitting the unspecified-bind-behind-an-ALB config the
// deployment actually uses.
//
// RESIDUAL (not detectable here): trusted_header + enable_tls=false + a
// 0.0.0.0 bind with NO security-group fence in front is still a spoofing hole,
// but it is indistinguishable at the process level from the safe behind-an-ALB
// config above. That last mile is enforced by terraform (the relay_http_from_alb
// SG rule), not by this assertion.
func assertTrustedHeaderBindCoherent(cfg *Config) error {
	if cfg.SourceAddrMode != SourceAddrModeTrustedHeader {
		return nil
	}
	if cfg.EnableTLS && !cfg.TrustedProxy {
		return fmt.Errorf("relay: source_addr_mode=%q with enable_tls=true is rejected (fail-closed): the relay cannot "+
			"verify whether a trusted front door attests the source-IP header (the safe TLS-re-encrypt topology) or the relay "+
			"is the direct internet front (any client sets the header — spoofable), so it refuses the ambiguous combo. Use "+
			"source_addr_mode=\"\" (RemoteAddr), run this leg as enable_tls=false behind a trusted proxy, or set "+
			"trusted_proxy=true only when a trusted front door overwrites/attests the header and is the relay's sole ingress path (#2663)",
			SourceAddrModeTrustedHeader)
	}
	// Classify the bind host. SplitHostPort fails for a bare host with no port;
	// fall back to treating the whole string as the host so "127.0.0.1" (no port)
	// is still classified rather than skipped.
	host := cfg.ListenAddr
	if h, _, err := net.SplitHostPort(cfg.ListenAddr); err == nil {
		host = h
	}
	if host == "" {
		return nil // unspecified bind (":8080" / "") — the behind-an-ALB config
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil // a hostname (or already-rejected garbage) — not classifiable here
	}
	// The allowlist is deliberately CONSERVATIVE / fail-closed: only a provably
	// unspecified, loopback, or RFC1918/ULA-private (Go's IsPrivate) bind is
	// allowed. Anything else — including IPv4 link-local (169.254.0.0/16), CGNAT
	// shared space (100.64.0.0/10), and IPv6 link-local (fe80::/10), none of which
	// IsPrivate covers — is treated as "public" and therefore REJECTED under
	// trusted_header. None are plausible relay binds; rejecting them just means a
	// future operator who picks one gets a clear boot failure instead of a silent
	// spoofing hole. Do NOT broaden this set to "fix" such a config — fail-closed
	// is the intended posture.
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() {
		return nil // 0.0.0.0 / ::, loopback, RFC1918 — not directly internet-reachable
	}
	return fmt.Errorf("relay: source_addr_mode=%q while listen_addr %q binds a routable public IP %s is a source-IP-spoofing hole: "+
		"a directly-reachable relay lets any client spoof the source-IP header. "+
		"Bind loopback/private (behind a trusted front door that overwrites the header) or use source_addr_mode=\"\" (RemoteAddr)",
		SourceAddrModeTrustedHeader, cfg.ListenAddr, ip)
}

// deriveSourceAddr returns the client address the server should open the AC
// pinhole for. SECURITY-CRITICAL — see SourceAddrMode.
func (rs *RelayServer) deriveSourceAddr(r *http.Request) *net.UDPAddr {
	if rs.config.SourceAddrMode == SourceAddrModeTrustedHeader {
		header := rs.config.TrustedHeader
		if header == "" {
			header = defaultTrustedHeader
		}
		// Trust root: trusting any X-Forwarded-For entry is only safe because the
		// relay HTTP listener accepts ingress ONLY from the ALB security group
		// (terraform/modules/relay/compute.tf: relay_http_from_alb) — an attacker
		// who could reach the relay directly would control the header too. That SG
		// rule is as load-bearing as append mode below.
		//
		// The fronting ALB runs X-Forwarded-For in APPEND mode
		// (terraform/modules/relay/alb.tf: xff_header_processing_mode="append"),
		// so the AWS-observed source IP is the entry the ALB appends LAST. A client
		// can send several X-Forwarded-For header LINES, so JOIN them all before
		// splitting — that makes the appended entry the GLOBAL rightmost no matter
		// whether the ALB consolidates the lines or appends to the last one.
		// (r.Header.Get would read only the FIRST line, whose rightmost can be
		// fully attacker-controlled.) Take ONLY that rightmost entry; entries to
		// its left are attacker-supplied (a caller can put anything in
		// X-Forwarded-For), so never walk left. If the rightmost entry fails to
		// parse, fail safe to RemoteAddr rather than trusting a left-of-rightmost
		// value. A single-value header (e.g. X-Real-IP) joins to one entry, so this
		// is correct there too. The rightmost is assumed PORTLESS: the relay ALB
		// leaves routing.http.xff_client_port disabled (AWS default), so the appended
		// entry is a bare IP; enabling it (ip:port) would fail ParseIP and fall back
		// to RemoteAddr — the #2622 symptom via a different trigger. (#2622)
		if raw := strings.Join(r.Header.Values(header), ","); raw != "" {
			parts := strings.Split(raw, ",")
			if ipStr := strings.TrimSpace(parts[len(parts)-1]); ipStr != "" {
				if ip := net.ParseIP(ipStr); ip != nil {
					return &net.UDPAddr{IP: ip, Port: placeholderSourcePort}
				}
			}
		}
		// Fail safe: a trusted-header deployment with a missing/garbage header
		// falls back to the real peer rather than fabricating an address.
		log.Warning("relay: trusted-header mode but %q absent/invalid; falling back to RemoteAddr", header)
	}
	// Default: the real TCP peer. Cannot be header-spoofed.
	if host, portStr, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			port := placeholderSourcePort
			if p, perr := strconv.Atoi(portStr); perr == nil && p > 0 && p <= 65535 {
				port = p
			}
			return &net.UDPAddr{IP: ip, Port: port}
		}
	}
	return &net.UDPAddr{IP: net.IPv4zero, Port: placeholderSourcePort}
}

// maxInnerPacketSize caps the inbound POST body (one NHP packet).
const maxInnerPacketSize = core.PacketBufferSize

// maxAckPacketSize is the receive bound for the authenticated server return
// envelope carrying an opaque ACK/COK/RAK/LRT. The inner packet remains capped
// at one standard pool buffer; only the authenticated outer envelope gets the
// dedicated larger bound.
const maxAckPacketSize = core.RelayPacketBufferSize
