package server

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
)

// Regression fence for the silently-broken server-to-server knock forward:
// the sender shipped a request missing resId and every receiver 400'd it. See
// buildForwardedKnock (http_forward.go) for the full root-cause rationale.

// TestBuildForwardedKnock_CarriesResId asserts the forwarded request and
// caller resource carry the (aspId, resId) identity, and that the shared
// caller req is not mutated.
func TestBuildForwardedKnock_CarriesResId(t *testing.T) {
	// req mirrors the /plugins/:aspid entrypoint: aspId set, resId empty.
	req := &common.HttpKnockRequest{AuthServiceId: "qurl", SrcIp: "10.0.1.50"}
	// res carries only the scalars buildForwardedKnock reads (ResourceId,
	// OpenTime); the resolved sub-Resources map is not consulted.
	res := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			AuthServiceId: "qurl",
			ResourceId:    "r_test",
			OpenTime:      77,
		},
	}

	fwdReq, fwdRes := buildForwardedKnock(req, res)

	// resId is carried from res.ResourceId — the value the receiver resolves
	// by — independent of the inner res.Resources key.
	if fwdReq.AuthServiceId != "qurl" || fwdReq.ResourceId != "r_test" {
		t.Fatalf("forwarded req must carry (aspId,resId)=(qurl,r_test), got (%q,%q)", fwdReq.AuthServiceId, fwdReq.ResourceId)
	}
	// The shared caller req must not be mutated — the forward branch reuses it
	// across the resource loop.
	if req.ResourceId != "" {
		t.Fatalf("buildForwardedKnock mutated caller req.ResourceId to %q", req.ResourceId)
	}
	// callerResource carries the (aspId, resId) the receiver's consistency
	// check compares and the OpenTime it bounds the open window by; it does
	// not ship sub-resources (the receiver never reads them).
	if fwdRes.AuthServiceId != "qurl" || fwdRes.ResourceId != "r_test" {
		t.Fatalf("forwarded caller resource (aspId,resId)=(%q,%q), want (qurl,r_test)", fwdRes.AuthServiceId, fwdRes.ResourceId)
	}
	if len(fwdRes.Resources) != 0 {
		t.Fatalf("forwarded caller resource must not ship sub-resources, got %v", fwdRes.Resources)
	}
	if fwdRes.OpenTime != 77 {
		t.Fatalf("forwarded caller resource OpenTime=%d, want 77", fwdRes.OpenTime)
	}
}

// TestHandleInternalKnock_RejectsResIdlessForward pins the receiver contract
// the sender must satisfy: a forward whose request omits resId is rejected
// 400 "missing aspId or resId". This is exactly the bare req the pre-fix
// sender shipped — so this test fails against the pre-fix forwarder shape.
func TestHandleInternalKnock_RejectsResIdlessForward(t *testing.T) {
	gin.SetMode(gin.TestMode)
	hs := newForwardingTestServer(NewMemoryStorage())

	bare := HttpKnockForwardRequest{
		Request: &common.HttpKnockRequest{AuthServiceId: "qurl"}, // resId empty
		// Source empty = server-to-server forward
	}
	w := callHandleInternalKnock(t, hs, bare)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("resId-less forward must be rejected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// newForwardE2E wires a sender that has NO local AC connection for "test-ac"
// to a peer that HOLDS it, over the wire, with the peer running the real
// handleInternalKnock handler (not a stub). It returns the sender and a
// pointer to the openTime the peer's AC operation was actually invoked with,
// so callers can assert that the effective open window survived the forward.
// The httptest server is torn down via t.Cleanup.
//
// peerOpenTime is atomic: it's written on the receiver's per-resource AC
// goroutine and read by the caller after the forward returns. The HTTP
// round-trip plus the receiver's acWg.Wait() already establish happens-before,
// but the atomic keeps the cross-goroutine capture self-evident and safe if a
// multi-resource group ever drives concurrent writes (see #2452).
func newForwardE2E(t *testing.T) (sender *HttpServer, peerOpenTime *atomic.Uint32) {
	t.Helper()
	peerOpenTime = &atomic.Uint32{}

	// Receiver: real server that holds the AC connection and serves the knock,
	// recording the openTime its AC operation was called with.
	recv := newForwardingTestServer(NewMemoryStorage())
	recv.udpServer.metrics = metrics.NewPublisherForTest(t)
	recv.udpServer.tokenStore = common.NewTokenStore[*ACTokenEntry]()
	recv.udpServer.acConnectionMap["test-ac"] = []*ACConn{newACConnWithLastRecv(time.Now().UnixNano())}
	recv.udpServer.processACOperationBroadcastFn = func(
		_ context.Context,
		_ *common.AgentKnockMsg,
		_ []*ACConn,
		_ *common.NetAddress,
		_ []*common.NetAddress,
		openTime uint32,
		_ *common.ResourceData,
	) (*common.ACOpsResultMsg, error) {
		peerOpenTime.Store(openTime)
		return &common.ACOpsResultMsg{
			ErrCode:         common.ErrSuccess.ErrorCode(),
			ACToken:         "ac-token-from-peer",
			OpenTime:        openTime,
			PreAccessAction: &common.PreAccessInfo{AccessIp: "10.0.0.7"},
		}, nil
	}

	router := gin.New()
	router.POST("/nhp/internal/knock", recv.handleInternalKnock)
	ts := httptest.NewServer(router)
	t.Cleanup(ts.Close)
	host, portStr, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split httptest addr: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	// Sender: NO local AC for test-ac; the assignment points at the receiver.
	storage := newMockStorageBackend()
	storage.assignments["test-ac"] = &ACAssignment{
		ACID:            "test-ac",
		AssignedServers: []ServerInfo{{ID: "peer", InternalIP: host}},
	}
	sender = &HttpServer{
		udpServer: &UdpServer{
			acConnectionMap: make(map[string][]*ACConn),
			metrics:         metrics.NewPublisherForTest(t),
		},
		// httpPort is the receiver's port so forwardToServer dials the httptest server.
		httpForwarder: NewHttpKnockForwarder(storage, nil, "10.0.0.250", port, nil, nil),
	}
	return sender, peerOpenTime
}

// qurlForwardKnock returns a knock for resId "r_test" on AC "test-ac" shaped
// like the /plugins/:aspid entrypoint: req carries aspId only (resId empty,
// resolved into res). OpenTime 77 is the group window.
func qurlForwardKnock() (*common.HttpKnockRequest, *common.ResourceData) {
	req := &common.HttpKnockRequest{
		AuthServiceId: "qurl",
		SrcIp:         "10.0.1.50",
		Ctx:           context.Background(),
	}
	res := &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			AuthServiceId: "qurl",
			ResourceId:    "r_test",
			OpenTime:      77,
			Resources: map[string]*common.ResourceInfo{
				"r_test": {ACId: "test-ac", Addr: &common.NetAddress{Ip: "10.0.2.100", Port: 443}},
			},
		},
	}
	return req, res
}

// TestHandleHttpOpenResource_ForwardsResIdToPeer_EndToEnd is the deterministic
// proof that the fix restores the forwarding safety net end to end: a sender
// with NO local AC connection for the resource's AC forwards over the wire to a
// peer that HAS it, and the resolve succeeds. The receiver runs the real
// handleInternalKnock handler, so this exercises resId resolution + the
// internal-knock validation, not a stub.
//
// Pre-fix the receiver rejected the bare forward 400 "missing aspId or resId",
// the forward failed, and handleHttpOpenResource returned ErrACConnectionNotFound.
func TestHandleHttpOpenResource_ForwardsResIdToPeer_EndToEnd(t *testing.T) {
	gin.SetMode(gin.TestMode)
	sender, peerOpenTime := newForwardE2E(t)
	req, res := qurlForwardKnock()

	ack, err := sender.handleHttpOpenResource(req, res)
	if err != nil {
		t.Fatalf("forwarded resolve must succeed; got error: %v\n(pre-fix the receiver 400s \"missing aspId or resId\" and this returns ErrACConnectionNotFound)", err)
	}
	if ack == nil || ack.ErrCode != common.ErrSuccess.ErrorCode() {
		t.Fatalf("forwarded ack must be success (ErrCode=%q), got %+v", common.ErrSuccess.ErrorCode(), ack)
	}
	// A normal (non-exit) knock forwards the group window unchanged.
	if got := peerOpenTime.Load(); got != 77 {
		t.Fatalf("peer AC op openTime = %d, want 77 (the forwarded group window)", got)
	}
}

// TestHandleHttpOpenResource_ForwardsExitCommand_ShortWindow pins that an
// exit (NHP_EXT) knock's 1-second pinhole survives the forward. buildForwardedKnock
// forwards res.OpenTime (the group's 77s), NOT the openTime=1 override
// handleHttpOpenResource applies for NHP_EXT — so the short window must be
// re-derived on the peer from the forwarded req.Command. This asserts that
// Command propagates across the cross-server forward and the peer's effective
// open window is the 1s one, not the forwarded 77s.
func TestHandleHttpOpenResource_ForwardsExitCommand_ShortWindow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	sender, peerOpenTime := newForwardE2E(t)
	req, res := qurlForwardKnock()
	req.Command = "exit" // flips the peer to NHP_EXT → openTime=1

	if _, err := sender.handleHttpOpenResource(req, res); err != nil {
		t.Fatalf("forwarded exit knock must succeed; got error: %v", err)
	}
	if got := peerOpenTime.Load(); got != 1 {
		t.Fatalf("peer AC op openTime = %d, want 1 — the NHP_EXT 1s pinhole must survive the forward via req.Command (forwarded OpenTime is the group's 77)", got)
	}
}

// TestHandleHttpOpenResource_EmptyResourceId_SkipsForward pins the defensive
// guard: a malformed catalog entry with populated Resources but an empty group
// id (res.ResourceId == "") must NOT emit a forward — a forward carries
// res.ResourceId as the resId and an empty one would 400 "missing aspId or
// resId" at the peer, silently reintroducing the bug this fix addresses. The
// forward is skipped (no assignment lookup) and the resolve fails closed.
func TestHandleHttpOpenResource_EmptyResourceId_SkipsForward(t *testing.T) {
	gin.SetMode(gin.TestMode)

	storage := NewMemoryStorage()
	sender := &HttpServer{
		udpServer: &UdpServer{
			acConnectionMap: make(map[string][]*ACConn),
			metrics:         metrics.NewPublisherForTest(t),
		},
		httpForwarder: NewHttpKnockForwarder(storage, nil, "10.0.0.250", 8888, nil, nil),
	}

	req, res := qurlForwardKnock()
	res.ResourceId = "" // malformed: populated Resources, empty group id

	if _, err := sender.handleHttpOpenResource(req, res); err == nil {
		t.Fatal("empty res.ResourceId must fail closed, not produce a successful forward")
	}
	if n := storage.GetCallCount("GetACAssignment"); n != 0 {
		t.Fatalf("forward must be skipped on empty res.ResourceId (no assignment lookup), got %d GetACAssignment call(s)", n)
	}
}

// TestHandleInternalKnock_HopStrict_SenderBuiltForwardProceeds proves a
// forward built the way the fixed sender builds it — from a req carrying only
// aspId, with resId pulled from the resolved resource — clears BOTH gates a
// server-to-server forward must pass under strict hop attestation: resId
// resolution (no 400 "missing aspId or resId") AND attestation verification.
func TestHandleInternalKnock_HopStrict_SenderBuiltForwardProceeds(t *testing.T) {
	gin.SetMode(gin.TestMode)
	a := hopEcdh(t, 1)
	hs, b := newHopVerifyingServer(t, true, a.PublicKeyBase64())

	senderReq := &common.HttpKnockRequest{AuthServiceId: "qurl", SrcIp: "10.0.1.50"} // resId empty
	resInfo := &common.ResourceInfo{ACId: "test-ac"}
	senderRes := &common.ResourceData{ResourceGroup: common.ResourceGroup{
		AuthServiceId: "qurl",
		ResourceId:    "r_test",
		OpenTime:      300,
		Resources:     map[string]*common.ResourceInfo{"r_test": resInfo},
	}}
	reqMsg, callerRes := buildForwardedKnock(senderReq, senderRes)
	fwdReq := HttpKnockForwardRequest{Request: reqMsg, Resource: callerRes}

	att, err := buildForwardHopAttestation(a, a.PublicKeyBase64(), b.PublicKeyBase64(), 1, time.Now(), "", fwdReq.Request)
	if err != nil {
		t.Fatalf("build attestation: %v", err)
	}
	fwdReq.Attestation = att

	w := callHandleInternalKnock(t, hs, fwdReq)
	if w.Code != http.StatusOK {
		t.Fatalf("sender-built forward with valid attestation should proceed in strict mode, got %d: %s", w.Code, w.Body.String())
	}
}
