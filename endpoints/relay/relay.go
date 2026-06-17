// Package relay implements the NHP-Relay service (#2208): the internet-facing
// front that forwards a browser JS-Agent's opaque inner NHP knock to a private
// cell NHP-Server as an NHP_RLY packet and relays the server's encrypted ACK
// back to the browser.
//
//	Browser JS-Agent --HTTPS POST /relay/{serverId}--> NHP-Relay
//	    --NHP_RLY{SourceAddr, InnerPacket}--> private NHP-Server --> AC
//
// Trust / crypto model:
//   - The inner packet is end-to-end agent<->server (the relay CANNOT read it);
//     the relay only wraps it and reads its cleartext header counter for ACK
//     correlation.
//   - The OUTER NHP_RLY is encrypted relay<->server (Noise IK); the relay must
//     be a registered NHP_RELAY peer on the server (relay.toml) and must send
//     from the same UDP socket it listens on (the server replies to the
//     packet's source address). See endpoints/server/relay.go (PR-B).
//   - SourceAddr — the client IP the server opens the AC pinhole for — is the
//     ONLY trusted source of that IP. It defaults to the real TCP peer
//     (spoof-proof); a trusted-header mode is opt-in and only safe behind a
//     front door (see SourceAddrMode).
//
// The relay strips upstream OpenNHP's load-balance package: our cloud reaches a
// cell server via CloudMap and the server fans out via NHP_FWD, so the relay
// routes by serverId to one endpoint per cell. See docs/design/NHP_RELAY_TOPOLOGY.md.
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

// MetricRelayShed counts backpressure sheds: each POST /relay/{serverId} the
// relay rejects with 503 because the target cell's in-flight cap is reached
// (see maxInFlightPerServer). A shed is a real incident signal — a cell is
// stuck/slow or the relay is under flood — so this is the graphable/alertable
// counterpart to logShed's throttled Warning, alarmed in
// terraform/modules/relay/monitoring.tf (#2649). Published into the shared
// LayerV/NHP namespace via the same endpoints/metrics publisher nhp-server uses
// (recordShed below), so the relay's first metric is consistent with the rest
// of the fleet rather than a parallel convention.
const MetricRelayShed = "RelayShed"

// dimNameCell is the CloudWatch dimension naming the cell a shed was routed to.
// Its value is the relay's configured cell_servers[].Name; a per-cell relay shed
// series sits alongside that cell's server metrics ONLY insofar as that name
// matches the server's NHP_CELL_ID (e.g. "cell0") — a config-consistency
// assumption, not an enforced guarantee. Dashboard attribution only; the
// relay_shedding alarm keys on the base [Environment] stream, unaffected.
var dimNameCell = aws.String("Cell")

const (
	// relayResponseTimeout bounds how long an HTTP request waits for the
	// server's ACK before returning 504.
	relayResponseTimeout = 5 * time.Second

	// encryptTimeout bounds the device encryption hand-off for an NHP_RLY.
	encryptTimeout = 2 * time.Second

	// placeholderSourcePort is stamped into SourceAddr when only the client IP
	// is known (trusted-header mode). The AC firewall rule keys on (src IP, dst
	// port, dst IP) — the source port is never used (endpoints/ac/msghandler.go)
	// — but the server's validateRelaySourceAddr requires a non-zero port, so we
	// supply one.
	placeholderSourcePort = 1

	// maxInFlightPerServer bounds the concurrent POST /relay/{serverId} requests
	// the relay will hold open for one cell server (#2553). Each in-flight request
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
	// flood produces a steady trickle rather than a torrent. A graphable shed
	// counter + alarm is the better long-term signal, but the relay has no metrics
	// infrastructure yet — tracked in #2649.
	shedLogWindow = 10 * time.Second
)

// pendingKey correlates a server ACK to a waiting HTTP handler. A per-request
// monotonic seq makes every registration unique so two concurrent requests that
// share a counter (a browser retrying the same client+counter is the realistic
// case) cannot overwrite each other in the map, and each handler deletes only
// its own entry. clientAddr is retained for debugging. Dispatch is by counter
// alone (the opaque ACK carries no client identity), so every waiter on a
// counter receives the bytes and only the intended client can decrypt them — a
// collision costs the others a spurious re-knock, never a cross-client leak.
type pendingKey struct {
	counter    uint64
	clientAddr string
	seq        uint64
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

// recordShed increments the RelayShed counter on each backpressure 503 (#2649).
// It DUAL-PUBLISHES, exactly as terraform/CLAUDE.md prescribes for Go-side
// alarms: a base counter at the publisher's [Environment] dims (the clean stream
// the relay_shedding alarm matches on) PLUS a per-cell breakdown carrying the
// target Cell (for dashboards / attribution). nil-safe via the publisher's nil
// receiver, so it is unconditional on the shed hot path.
//
// Counted per shed (every 503), independently of logShed's throttled Warning:
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
	udpConn    *net.UDPConn              // shared send+recv socket
	servers    map[string]*serverRuntime // by pubkey fingerprint
	cors       corsAllowlist             // browser CORS allowlist (#2631)

	// metrics publishes the relay's CloudWatch metrics into the shared
	// LayerV/NHP namespace (the relay's first metrics emission, #2649). Booted in
	// New via the same endpoints/metrics publisher nhp-server uses; nil when AWS
	// config is unavailable (local/dev) — the publisher's methods are nil-safe
	// no-ops, so recordShed never needs a guard. See recordShed.
	metrics *metrics.Publisher

	responseTimeout time.Duration // how long a handler waits for the server ACK

	pendingMu sync.Mutex
	pending   map[pendingKey]chan []byte
	seq       atomic.Uint64 // per-request registration id

	wg        sync.WaitGroup
	stopCh    chan struct{}
	running   atomic.Bool
	closeOnce sync.Once // guards udpConn.Close (Stop may run with/without a prior Start)
}

// New builds a RelayServer from cfg. It decodes the relay key, creates the
// NHP_RELAY device, binds the shared UDP socket, and builds the cell-routing
// table. Call Start to serve.
func New(cfg *Config) (*RelayServer, error) {
	if cfg == nil {
		return nil, errors.New("relay: nil config")
	}
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

	device := core.NewDevice(core.NHP_RELAY, prk, nil)
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
		pending:         make(map[pendingKey]chan []byte),
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
	// Liveness probe for the container HEALTHCHECK and the deploy's LB target
	// group (the relay path itself is POST-only, so it can't double as a GET
	// health check). Path matches nhp-server's /health/live so the fleet has one
	// health convention (one LB target-group + dashboard pattern). Cheap and
	// unauthenticated — it reveals only that the process is up, never any
	// routing/peer state.
	mux.HandleFunc("/health/live", rs.handleHealthLive)
	rs.httpServer = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second, // the POST body is one small NHP packet
		// WriteTimeout must exceed responseTimeout — it spans the handler's wait
		// for the server ACK plus the response write, measured from request read.
		WriteTimeout: relayResponseTimeout + 10*time.Second,
		IdleTimeout:  60 * time.Second,
	}
	if cfg.EnableTLS {
		// Pin a TLS floor for the internet-facing direct-terminate path.
		rs.httpServer.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return rs, nil
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
		rs.closeOnce.Do(func() { _ = rs.udpConn.Close() })
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
	rs.closeOnce.Do(func() { _ = rs.udpConn.Close() }) // unblocks recvLoop's ReadFromUDP
	rs.wg.Wait()
	rs.device.Stop()
	// Flush any sheds accumulated since the last 60s flush before exit (nil-safe).
	rs.metrics.Stop()
	return err
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

	counter, err := rs.innerCounter(inner)
	if err != nil {
		log.Warning("relay: rejecting malformed inner packet from %s: %v", r.RemoteAddr, err)
		http.Error(w, "malformed packet", http.StatusBadRequest)
		return
	}

	sourceAddr := rs.deriveSourceAddr(r)
	clientKey := sourceAddr.String()

	// Register the ACK waiter BEFORE sending so a fast server reply can't race us.
	// The per-request seq keeps two same-(counter,client) requests from
	// overwriting each other and ensures each deletes only its own entry.
	respCh := make(chan []byte, 1)
	key := pendingKey{counter: counter, clientAddr: clientKey, seq: rs.seq.Add(1)}
	rs.pendingMu.Lock()
	rs.pending[key] = respCh
	rs.pendingMu.Unlock()
	defer func() {
		rs.pendingMu.Lock()
		delete(rs.pending, key)
		rs.pendingMu.Unlock()
	}()

	if err := rs.forward(srv, sourceAddr, inner); err != nil {
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
// from the shared UDP socket (so the server's ACK returns to this socket).
func (rs *RelayServer) forward(srv *serverRuntime, sourceAddr *net.UDPAddr, inner []byte) error {
	rlyMsg := &common.RelayForwardMsg{
		SourceAddr:  &common.NetAddress{Ip: sourceAddr.IP.String(), Port: sourceAddr.Port},
		InnerPacket: base64.StdEncoding.EncodeToString(inner),
	}
	msgBytes, err := json.Marshal(rlyMsg)
	if err != nil {
		return fmt.Errorf("marshal RelayForwardMsg: %w", err)
	}

	encCh := make(chan *core.MsgAssemblerData, 1)
	md := &core.MsgData{
		HeaderType:     core.NHP_RLY,
		Message:        msgBytes,
		PeerPk:         srv.pubKey,
		RemoteAddr:     srv.addr,
		EncryptedPktCh: encCh,
	}
	rs.device.SendMsgToPacket(md)

	select {
	case mad := <-encCh:
		if mad.Error != nil {
			return fmt.Errorf("encrypt NHP_RLY: %w", mad.Error)
		}
		packet := append([]byte(nil), mad.BasePacket.Content...)
		mad.Destroy()
		if _, err := rs.udpConn.WriteToUDP(packet, srv.addr); err != nil {
			return fmt.Errorf("write NHP_RLY: %w", err)
		}
		return nil
	case <-time.After(encryptTimeout):
		return errors.New("timeout encrypting NHP_RLY")
	}
}

// recvLoop reads server ACKs off the shared socket and dispatches them to
// waiting handlers by inner counter.
func (rs *RelayServer) recvLoop() {
	defer rs.wg.Done()
	// Sized to the max ACK; a larger datagram is truncated by ReadFromUDP and
	// then fails RecvPrecheck's size check — dropped, not relayed.
	buf := make([]byte, maxAckPacketSize)
	for {
		select {
		case <-rs.stopCh:
			return
		default:
		}
		n, _, err := rs.udpConn.ReadFromUDP(buf)
		if err != nil {
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
		raw := append([]byte(nil), buf[:n]...)
		// Per-datagram recover: the length guard in innerCounter already makes a
		// malformed datagram safe, but one bad packet must never kill the recv
		// loop (and with it the relay's entire return path).
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Error("relay: recovered from panic processing datagram (%d bytes): %v", n, r)
				}
			}()
			counter, perr := rs.innerCounter(raw)
			if perr != nil {
				return // not a well-formed NHP packet; drop
			}
			rs.dispatch(counter, raw)
		}()
	}
}

// dispatch delivers a raw server ACK to every handler waiting on counter.
func (rs *RelayServer) dispatch(counter uint64, raw []byte) {
	rs.pendingMu.Lock()
	chans := make([]chan []byte, 0, 1)
	for k, ch := range rs.pending {
		if k.counter == counter {
			chans = append(chans, ch)
		}
	}
	rs.pendingMu.Unlock()
	// raw is shared across all waiters on this counter; consumers (handleRelay)
	// only read it (w.Write), never mutate, so sharing the buffer is safe.
	for _, ch := range chans {
		select {
		case ch <- raw:
		default: // waiter already served or gone
		}
	}
}

// innerCounter validates a raw NHP packet's header and returns its cleartext
// transaction counter — readable without decryption, the same value the agent
// matches its ACK on.
func (rs *RelayServer) innerCounter(raw []byte) (uint64, error) {
	// Length guard BEFORE RecvPrecheck. Unlike PacketToMsg, RecvPrecheck is not
	// wrapped in recover() and reads the header (Content[0:4], [4:8], …) without
	// a lower-bound check — a short/empty datagram would panic. A bare 0-length
	// UDP datagram arrives as (n=0, err=nil), so this is reachable by anything
	// that can route UDP to the relay's socket; without the guard recvLoop would
	// panic and crash the process (remote DoS). Mirrors the server's
	// recvPacketRoutine MinimalLength discard.
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
	if _, _, err := rs.device.RecvPrecheck(pkt); err != nil {
		return 0, err
	}
	return pkt.Counter(), nil
}

// assertTrustedHeaderBindCoherent fails closed (#2553) on a relay config that
// provably defeats the precondition for SourceAddrModeTrustedHeader being safe:
// that the relay sits behind a trusted front door which overwrites/attests the
// source-IP header and is the relay's ONLY ingress path. In RemoteAddr mode the
// source IP is the spoof-proof TCP peer, so none of this applies — return nil.
//
// We reject two configs we can prove are dangerous at the process level:
//
//  1. trusted_header + enable_tls=true. We cannot tell a relay that terminates
//     client TLS itself (the direct internet front — any client is the relay's
//     TCP peer and sets the header freely, a spoofing hole) from a trusted front
//     door that terminates client TLS, attests/overwrites the header, and
//     re-encrypts to this backend over TLS (safe — both present enable_tls=true).
//     The attestation is not observable at the process level (same limitation as
//     the bind RESIDUAL below), so we FAIL CLOSED on the ambiguous combo.
//     RemoteAddr is correct for a direct-terminating relay; the safe re-encrypt
//     topology is unsupported by design until an explicit trusted-proxy opt-in
//     exists (#2663).
//
//  2. trusted_header + a ListenAddr host that parses to a concrete routable
//     PUBLIC IP. Binding a public address means clients can reach the relay
//     directly (no front door in front of that interface), so a client-supplied
//     header is attacker-controlled.
//
// What we deliberately ALLOW (these are coherent, and #2 below is the actual
// production config — see terraform/modules/relay/user_data.sh.tpl):
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
	if cfg.EnableTLS {
		return fmt.Errorf("relay: source_addr_mode=%q with enable_tls=true is rejected (fail-closed): the relay cannot "+
			"verify whether a trusted front door attests the source-IP header (the safe TLS-re-encrypt topology) or the relay "+
			"is the direct internet front (any client sets the header — spoofable), so it refuses the ambiguous combo. Use "+
			"source_addr_mode=\"\" (RemoteAddr), or run this leg as enable_tls=false behind a trusted proxy. End-to-end TLS "+
			"re-encryption with trusted_header is unsupported by design (#2663)",
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

// maxAckPacketSize is the recv-buffer bound for the server's ACK. An NHP_ACK
// fits one pool buffer — the assembler caps the body at PacketBufferSize -
// header size (nhp/core/initiator.go). Same value as maxInnerPacketSize, named
// separately so the inbound-vs-recv bounds are self-documenting.
const maxAckPacketSize = core.PacketBufferSize
