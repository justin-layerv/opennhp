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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/utils"
)

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
}

// RelayServer is the NHP-Relay HTTP front backed by an NHP_RELAY device.
type RelayServer struct {
	config     *Config
	device     *core.Device
	httpServer *http.Server
	udpConn    *net.UDPConn              // shared send+recv socket
	servers    map[string]*serverRuntime // by pubkey fingerprint

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
		servers[id] = &serverRuntime{id: id, name: sc.Name, pubKey: pub, addr: udpAddr}
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
		pending:         make(map[pendingKey]chan []byte),
		responseTimeout: relayResponseTimeout,
		stopCh:          make(chan struct{}),
	}

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

// handleRelay handles POST /relay/{serverId}.
func (rs *RelayServer) handleRelay(w http.ResponseWriter, r *http.Request) {
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
