package server

import (
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// Regression fence for #1157 F3 reliability angle at the production
// HandleACOnline call site. The pure-helper tests in
// ac_connection_admit_test.go cover admission logic; this file
// covers the wrapper-owned side effects the helper itself can't see.
//
// Two wrapper-test scenarios are covered:
//
//  1. Same-pubkey reconnect from a new IP (NAT rebind / EIP swap) —
//     THE primary bug class the PR fixes. Wrapper-owned invariants
//     asserted: remoteConnectionMap delete fires for the old addr,
//     staleConn.Close() fires on the goroutine, MetricACConnEviction
//     stays at 0 (replace ≠ FIFO), and the slice does an in-place
//     replace (length unchanged).
//  2. Distinct-pubkey overflow (FIFO eviction at MaxACConnsPerID) —
//     the secondary case. Wrapper-owned invariants asserted:
//     MetricACConnEviction emission (alarm signal #1969 wires),
//     FIFO-then-append slice shape, remoteConnectionMap cleanup,
//     and the same Close()-on-goroutine lifecycle.
//
// What these tests do NOT assert directly: the textual log lines
// (evict-Warning, replace-Info, registration-Info) themselves —
// no log capture is wired. The metric + slice + map assertions
// fence the load-bearing behavior; the log dual-emit on the FIFO
// path is documented as a structural invariant at the call site
// (msghandler.go) and would require log capture to fence directly.

// closeWaitTimeout / closeWaitTick are referenced from waitForClosed
// below — they sit at the bottom of the file (alongside the helper
// they tune) but are declared up here so the wrapper-test bodies can
// reference closeWaitTimeout in their assertion messages. Moving the
// timing-tuning surface to a single colocated block would mean
// inlining the constant into the message string, which costs
// grep-ability for future tuning passes. Net: this layout keeps
// "tunable knob" + "consumer" both visible at a glance.
const (
	// 5s is generous for "goroutine launch + a handful of channel
	// closes" (the only work Close() does in this fixture) and
	// absorbs heavily-loaded CI runners where 2s deadlines have
	// been observed to drift. The happy path completes in
	// milliseconds, so a longer timeout doesn't slow the suite —
	// it only matters when waitForClosed would otherwise spuriously
	// fail. 5ms tick keeps the test fast.
	closeWaitTimeout = 5 * time.Second
	closeWaitTick    = 5 * time.Millisecond
)

// newClosableConnData returns a ConnectionData wired with the
// channels Close() needs to run without panicking. SendQueue /
// RecvQueue stay empty so the flush loop's default arm fires
// immediately and never dereferences c.Device (which is nil).
func newClosableConnData(remoteAddr *net.UDPAddr) *core.ConnectionData {
	return &core.ConnectionData{
		RemoteAddr:       remoteAddr,
		StopSignal:       make(chan struct{}),
		SendQueue:        make(chan *core.Packet, 1),
		RecvQueue:        make(chan *core.Packet, 1),
		BlockSignal:      make(chan struct{}),
		SetTimeoutSignal: make(chan struct{}, 1),
	}
}

// newUdpServerForACOnlineTest builds a minimally-wired *UdpServer
// for the HandleACOnline wrapper tests: only the fields touched
// between body-parse and forwardToTransaction are populated, plus
// the maps each test mutates. Callers seed acPeerMap /
// acConnectionMap / remoteConnectionMap themselves.
//
// Future authors: don't assume any other UdpServer state is
// initialized. Wiring the whole NewUdpServer would couple these
// tests to startup-init order changes that have nothing to do
// with the admission policy being fenced.
func newUdpServerForACOnlineTest(t *testing.T) *UdpServer {
	t.Helper()
	return &UdpServer{
		metrics: metrics.NewPublisherForTest(t),
		// device + listenAddr satisfy the AAK build path
		// (serverAddr fmt + ServerPubKey lookup) between the
		// admit helper and forwardToTransaction.
		device:     core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil),
		listenAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 62206},
		localIp:    "127.0.0.1",
		acPeerMap:  map[string]*core.UdpPeer{},
		// Permit mode for F3: cap-Exceeded verdict logs+meters
		// but proceeds, so the admit helper actually runs and
		// the FIFO test can fence its branch. cloudMode is
		// implicitly false (storage / storageConfig both nil),
		// which skips the F5 hoist, F3 strict pre-check,
		// validateACLicense, and handleACServerAssignment.
		acPubkeyCapVerifyRequire: false,
	}
}

// TestHandleACOnline_SamePubkeyNewIP_ClosesStaleAndUpdatesRemoteMap
// fences the wrapper-owned side effects on THE primary bug class
// this PR fixes: a same-pubkey reconnect from a NEW (IP, port) —
// the NAT-rebind / EIP-swap / AC-daemon-restart shape that
// originally triggered sandbox failure 25875514676.
//
// Pre-fix the IP-keyed loop missed the match, appended a new slot,
// and tripped FIFO on a DIFFERENT pubkey. Post-fix the helper
// replaces in place AND returns stale = the displaced ACConn so
// the wrapper closes the old UDP socket. The helper test
// TestReplaceOrAppendACConn_SamePubkeyNewIP_ReplacesInPlace pins
// the admission half; this test pins the close-the-old-socket
// half — without it, a regression like "helper returns stale
// correctly but caller drops the close" would silently leak the
// old UdpConn on every NAT-rebind in production.
//
// Setup uses non-cloud mode for the same reason the FIFO test
// does — F5 hoist, F3 strict pre-check, validateACLicense, and
// handleACServerAssignment are all skipped, so the test reaches
// the admit helper deterministically.
func TestHandleACOnline_SamePubkeyNewIP_ClosesStaleAndUpdatesRemoteMap(t *testing.T) {
	const acId = "ac-1157-samepk-newip-wrapper"
	pubkeyB64 := testPubkeyB64(0x42)
	pubkey := testPubkey(0x42)

	oldAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 47051}
	newAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 38229}

	// One existing slot under acId carrying the same pubkey at the
	// OLD addr. ConnData is closable so the goroutine-launched
	// Close() doesn't panic.
	existing := &ACConn{
		ACPeer:   &core.UdpPeer{PubKeyBase64: pubkeyB64},
		ConnData: newClosableConnData(oldAddr),
		ACId:     acId,
	}
	staleUdpConn := &UdpConn{ConnData: existing.ConnData, isACConnection: true}

	s := newUdpServerForACOnlineTest(t)
	s.acPeerMap[pubkeyB64] = &core.UdpPeer{
		Hostname:     acId,
		PubKeyBase64: pubkeyB64,
		Type:         core.NHP_AC,
	}
	s.acConnectionMap = map[string][]*ACConn{acId: {existing}}
	s.remoteConnectionMap = map[string]*UdpConn{oldAddr.String(): staleUdpConn}

	body, marshalErr := json.Marshal(common.ACOnlineMsg{ACId: acId, LicenseKey: ""})
	if marshalErr != nil {
		t.Fatalf("marshal body: %v", marshalErr)
	}
	ppd := &core.PacketParserData{
		HeaderType:   core.NHP_AOL,
		BodyMessage:  body,
		SenderTrxId:  1,
		RemotePubKey: pubkey,
		ConnData: &core.ConnectionData{
			RemoteAddr: newAddr,
		},
	}

	err := s.HandleACOnline(ppd)

	// Same COUPLING NOTE as the sibling test — see file-level
	// godoc. ErrTransactionIdNotFound proves admit + cleanup
	// completed before forwardToTransaction.
	if !errors.Is(err, common.ErrTransactionIdNotFound) {
		t.Fatalf("HandleACOnline err=%v, want ErrTransactionIdNotFound (forwardToTransaction terminal — proves the admit path completed)", err)
	}

	// Side effect 1: NOT a FIFO eviction. The same-pubkey replace
	// path returns replaced=true; a regression where the helper
	// reverted to IP-keyed match would append and (since the slot
	// count is 1, well under cap) NOT fire the eviction metric.
	// But a regression where the wrapper fired the eviction metric
	// on every replace would silently inflate the alarm baseline.
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACConnEviction]; c != 0 {
		t.Errorf("MetricACConnEviction counter = %v, want 0 (replace path must NOT emit eviction metric)", c)
	}

	// Side effect 2: acConnectionMap[acId] still has length 1 (in
	// place replace), and the slot's RemoteAddr is the NEW addr.
	s.acConnectionMapMutex.Lock()
	finalConns := s.acConnectionMap[acId]
	s.acConnectionMapMutex.Unlock()
	if got, want := len(finalConns), 1; got != want {
		t.Fatalf("acConnectionMap[%s] length = %d, want %d (replace must be in-place)", acId, got, want)
	}
	if got := finalConns[0].ConnData.RemoteAddr.String(); got != newAddr.String() {
		t.Errorf("slot[0] addr = %s, want %s (slot must carry the NEW conn)", got, newAddr.String())
	}

	// Side effect 3: remoteConnectionMap no longer contains the OLD
	// addr. The lookup is by the old addr because the new ConnData
	// hasn't been registered in remoteConnectionMap by this fixture
	// (a real connectionRoutine would do that; HandleACOnline's
	// only job here is to clean up the OLD entry).
	s.remoteConnectionMapMutex.Lock()
	_, foundOld := s.remoteConnectionMap[oldAddr.String()]
	s.remoteConnectionMapMutex.Unlock()
	if foundOld {
		t.Errorf("remoteConnectionMap still contains old addr %s; stale-cleanup did not run on same-pubkey-new-IP", oldAddr.String())
	}

	// Side effect 4: the stale UdpConn was Close()'d on the
	// goroutine. THE load-bearing assertion: without this, every
	// NAT-rebind / EIP-swap in production leaks the old UdpConn's
	// goroutine + buffered channels.
	if !waitForClosed(staleUdpConn.ConnData, closeWaitTimeout) {
		t.Errorf("staleConn.Close() did not fire within %s; UDP socket leaked on same-pubkey-new-IP reconnect", closeWaitTimeout)
	}
}

// TestHandleACOnline_DistinctPubkeyOverflow_FIFOEvict_EmitsMetricAndClosesStale
// drives the production HandleACOnline call site through the FIFO
// branch and asserts the side effects only the wrapper owns.
//
// Setup uses non-cloud mode (storage == nil, storageConfig == nil)
// so the F5 hoist, F3 strict pre-check, and validateACLicense are
// all skipped — the test reaches the admit helper deterministically
// without wiring DDB/license/cloudMap state. Permit mode for the F3
// in-lock check (acPubkeyCapVerifyRequire = false) lets a brand-new
// pubkey at MaxACConnsPerID through to the admit helper, where the
// FIFO branch fires.
//
// HandleACOnline ultimately errors at forwardToTransaction with
// ErrTransactionIdNotFound (no transaction is registered in the
// fixture's ConnData), but the side effects we fence here all
// happen BEFORE that — they're observable on a non-nil error
// return.
func TestHandleACOnline_DistinctPubkeyOverflow_FIFOEvict_EmitsMetricAndClosesStale(t *testing.T) {
	const acId = "ac-1157-fifo-evict-wrapper"
	// 0xFE matches `outsiderPubkeySeed` reserved in
	// ac_connection_admit_test.go — keeps the "brand-new arrival
	// in distinct-pubkey overflow" seed unified across both files,
	// so a future MaxACConnsPerID bump (which trips that file's
	// `>= int(outsiderPubkeySeed)` skip guard) also surfaces this
	// test's reliance on the same reservation.
	incomingPubkey := testPubkey(outsiderPubkeySeed)
	incomingPubkeyB64 := testPubkeyB64(outsiderPubkeySeed)

	// Saturate acConnectionMap[acId] with MaxACConnsPerID distinct
	// pubkeys, each owning its own RemoteAddr. Slot 0 is the
	// FIFO-evict target and gets the closable ConnData fixture so
	// `go staleConn.Close()` doesn't panic.
	saturated := make([]*ACConn, MaxACConnsPerID)
	for i := 0; i < MaxACConnsPerID; i++ {
		addr := &net.UDPAddr{IP: net.ParseIP("10.0.0." + strconv.Itoa(i+1)), Port: 47051}
		connData := &core.ConnectionData{RemoteAddr: addr}
		if i == 0 {
			connData = newClosableConnData(addr)
		}
		saturated[i] = &ACConn{
			ACPeer:   &core.UdpPeer{PubKeyBase64: testPubkeyB64(byte(i + 1))},
			ConnData: connData,
			ACId:     acId,
		}
	}
	oldestAddrStr := saturated[0].ConnData.RemoteAddr.String()

	// The oldest slot also owns a remoteConnectionMap entry; this
	// is the realistic shape — every conn the server admits ends
	// up in both maps.
	staleUdpConn := &UdpConn{ConnData: saturated[0].ConnData, isACConnection: true}

	s := newUdpServerForACOnlineTest(t)
	// Pre-populate the incoming pubkey's peer so the non-cloud
	// path skips validateACLicense (gated on `acPeer == nil &&
	// cloudMode`).
	s.acPeerMap[incomingPubkeyB64] = &core.UdpPeer{
		Hostname:     acId,
		PubKeyBase64: incomingPubkeyB64,
		Type:         core.NHP_AC,
	}
	s.acConnectionMap = map[string][]*ACConn{acId: saturated}
	s.remoteConnectionMap = map[string]*UdpConn{oldestAddrStr: staleUdpConn}

	body, marshalErr := json.Marshal(common.ACOnlineMsg{ACId: acId, LicenseKey: ""})
	if marshalErr != nil {
		t.Fatalf("marshal body: %v", marshalErr)
	}
	ppd := &core.PacketParserData{
		HeaderType:   core.NHP_AOL,
		BodyMessage:  body,
		SenderTrxId:  1,
		RemotePubKey: incomingPubkey,
		ConnData: &core.ConnectionData{
			RemoteAddr: &net.UDPAddr{IP: net.ParseIP("10.0.99.1"), Port: 47051},
		},
	}

	err := s.HandleACOnline(ppd)

	// HandleACOnline runs all the way through the admit helper +
	// stale-cleanup, then errors at forwardToTransaction because
	// no transaction is registered. The error is expected; the
	// side effects below are what we fence.
	//
	// COUPLING NOTE: this assertion is an indirect signal that the
	// admit path ran to completion — a future refactor that
	// inserts a new check between the admit helper and
	// forwardToTransaction (e.g., a per-AC quota check on AAK
	// build) would change this terminal error and this test would
	// need updating in lockstep. See the file-level godoc for the
	// design rationale.
	if !errors.Is(err, common.ErrTransactionIdNotFound) {
		t.Fatalf("HandleACOnline err=%v, want ErrTransactionIdNotFound (forwardToTransaction terminal — proves the admit path completed)", err)
	}

	// Side effect 1: MetricACConnEviction fired exactly once.
	// This is the alarm signal #1969 will wire — a regression
	// where the switch reorders cases or drops the metric line
	// silently disables the alarm.
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACConnEviction]; c != 1 {
		t.Errorf("MetricACConnEviction counter = %v, want 1 (FIFO branch must emit)", c)
	}

	// Side effect 2: acConnectionMap[acId] is at cap with the
	// incoming entry appended at the end and slot 0 evicted.
	s.acConnectionMapMutex.Lock()
	finalConns := s.acConnectionMap[acId]
	s.acConnectionMapMutex.Unlock()
	if got, want := len(finalConns), MaxACConnsPerID; got != want {
		t.Fatalf("acConnectionMap[%s] length = %d, want %d", acId, got, want)
	}
	if got := finalConns[len(finalConns)-1].ACPeer.PubKeyBase64; got != incomingPubkeyB64 {
		t.Errorf("last slot pubkey = %s, want incoming %s", got, incomingPubkeyB64)
	}

	// Side effect 3: remoteConnectionMap no longer contains the
	// evicted slot's addr. The delete fires synchronously inside
	// the lock; no polling needed.
	s.remoteConnectionMapMutex.Lock()
	_, found := s.remoteConnectionMap[oldestAddrStr]
	s.remoteConnectionMapMutex.Unlock()
	if found {
		t.Errorf("remoteConnectionMap still contains evicted slot's addr %s; stale-cleanup did not run", oldestAddrStr)
	}

	// Side effect 4: the stale UdpConn was Close()'d. Close runs
	// in a goroutine, so poll with a short timeout. A regression
	// that swaps `go staleConn.Close()` for a stale-only delete
	// would leak the UDP socket.
	if !waitForClosed(staleUdpConn.ConnData, closeWaitTimeout) {
		t.Errorf("staleConn.Close() did not fire within %s; UDP socket leaked on FIFO eviction", closeWaitTimeout)
	}
}

func waitForClosed(c *core.ConnectionData, timeout time.Duration) bool {
	if c.IsClosed() {
		return true
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(closeWaitTick)
	defer ticker.Stop()
	for {
		select {
		case <-timer.C:
			return c.IsClosed()
		case <-ticker.C:
			if c.IsClosed() {
				return true
			}
		}
	}
}
