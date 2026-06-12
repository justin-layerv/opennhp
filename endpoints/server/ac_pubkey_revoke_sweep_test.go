package server

import (
	"container/list"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/layervai/nhp/internalauth"
)

func newRevocationSweepTestServer(t *testing.T) *UdpServer {
	t.Helper()
	return &UdpServer{
		metrics:             metrics.NewPublisherForTest(t),
		device:              core.NewDevice(core.NHP_SERVER, testPrivateKey(), nil),
		storage:             NewMemoryStorage(),
		acPeerMap:           map[string]*core.UdpPeer{},
		acConnectionMap:     map[string][]*ACConn{},
		remoteConnectionMap: map[string]*UdpConn{},
		connectionsByIP:     map[string]*list.List{},
	}
}

func newRevocationSweepConn(acId, pubkey, ip string, port int) (*ACConn, *UdpConn) {
	connData := newClosableConnData(&net.UDPAddr{IP: net.ParseIP(ip), Port: port})
	acPeer := &core.UdpPeer{
		Hostname:     acId,
		Ip:           ip,
		Port:         port,
		PubKeyBase64: pubkey,
		Type:         core.NHP_AC,
	}
	return &ACConn{
			ConnData: connData,
			ACPeer:   acPeer,
			ACId:     acId,
		}, &UdpConn{
			ConnData:       connData,
			isACConnection: true,
			evictSignal:    make(chan struct{}),
		}
}

func seedRevocationSweepConn(s *UdpServer, acId string, acConn *ACConn, udpConn *UdpConn, bucketPerIP bool) {
	s.acConnectionMap[acId] = append(s.acConnectionMap[acId], acConn)
	s.remoteConnectionMap[udpConn.ConnData.RemoteAddr.String()] = udpConn
	s.acPeerMap[acConn.ACPeer.PubKeyBase64] = acConn.ACPeer
	if bucketPerIP {
		ipKey := udpConn.ConnData.RemoteAddr.IP.String()
		bucket := s.connectionsByIP[ipKey]
		if bucket == nil {
			bucket = list.New()
			s.connectionsByIP[ipKey] = bucket
		}
		udpConn.perIPElem = bucket.PushBack(udpConn)
	}
}

func TestDropRevokedACPubkeyConnections_DropsOnlyRevokedConn(t *testing.T) {
	const acId = "ac-1157-f5-drop"
	revokedPubkey := testPubkeyB64(0xA1)
	legitimatePubkey := testPubkeyB64(0xB2)
	s := newRevocationSweepTestServer(t)

	revokedAC, revokedUDP := newRevocationSweepConn(acId, revokedPubkey, "10.0.0.11", 47051)
	legitAC, legitUDP := newRevocationSweepConn(acId, legitimatePubkey, "10.0.0.12", 47052)
	seedRevocationSweepConn(s, acId, revokedAC, revokedUDP, true)
	seedRevocationSweepConn(s, acId, legitAC, legitUDP, false)
	s.storage.(*MemoryStorage).PutACAssignment(&ACAssignment{ACID: acId, RevokedPubKeys: []string{revokedPubkey}})

	dropped, err := s.dropRevokedACPubkeyConnections(t.Context(), "test")
	if err != nil {
		t.Fatalf("dropRevokedACPubkeyConnections: %v", err)
	}
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}

	conns := s.acConnectionMap[acId]
	if len(conns) != 1 || conns[0].ACPeer.PubKeyBase64 != legitimatePubkey {
		t.Fatalf("acConnectionMap[%s] = %#v, want only legitimate pubkey", acId, conns)
	}
	if _, ok := s.remoteConnectionMap[revokedUDP.ConnData.RemoteAddr.String()]; ok {
		t.Fatal("remoteConnectionMap still contains revoked connection")
	}
	if _, ok := s.remoteConnectionMap[legitUDP.ConnData.RemoteAddr.String()]; !ok {
		t.Fatal("remoteConnectionMap lost legitimate connection")
	}
	if _, ok := s.acPeerMap[revokedPubkey]; ok {
		t.Fatal("acPeerMap still contains revoked pubkey")
	}
	if _, ok := s.acPeerMap[legitimatePubkey]; !ok {
		t.Fatal("acPeerMap lost legitimate pubkey")
	}
	if revokedUDP.perIPElem != nil {
		t.Fatal("revoked connection perIPElem was not cleared")
	}
	if bucket := s.connectionsByIP["10.0.0.11"]; bucket != nil {
		t.Fatalf("connectionsByIP bucket for revoked IP still present with len=%d", bucket.Len())
	}
	if !waitForClosed(revokedUDP.ConnData, closeWaitTimeout) {
		t.Fatalf("revoked connection was not closed within %s", closeWaitTimeout)
	}
	if legitUDP.ConnData.IsClosed() {
		t.Fatal("legitimate connection was closed")
	}
	counters, _ := s.metrics.CountersForTest(t)
	if got := counters[MetricACPubkeyRevokedConnDropped]; got != 1 {
		t.Fatalf("%s counter = %v, want 1", MetricACPubkeyRevokedConnDropped, got)
	}
}

func TestDropRevokedACPubkeyConnections_IdempotentAfterDrop(t *testing.T) {
	const acId = "ac-1157-f5-idempotent"
	revokedPubkey := testPubkeyB64(0xC3)
	s := newRevocationSweepTestServer(t)

	revokedAC, revokedUDP := newRevocationSweepConn(acId, revokedPubkey, "10.0.1.11", 47051)
	seedRevocationSweepConn(s, acId, revokedAC, revokedUDP, false)
	s.storage.(*MemoryStorage).PutACAssignment(&ACAssignment{ACID: acId, RevokedPubKeys: []string{revokedPubkey}})

	first, err := s.dropRevokedACPubkeyConnections(t.Context(), "test")
	if err != nil {
		t.Fatalf("first drop: %v", err)
	}
	second, err := s.dropRevokedACPubkeyConnections(t.Context(), "test")
	if err != nil {
		t.Fatalf("second drop: %v", err)
	}
	if first != 1 || second != 0 {
		t.Fatalf("drops = (%d, %d), want (1, 0)", first, second)
	}
	counters, _ := s.metrics.CountersForTest(t)
	if got := counters[MetricACPubkeyRevokedConnDropped]; got != 1 {
		t.Fatalf("%s counter = %v, want exactly 1", MetricACPubkeyRevokedConnDropped, got)
	}
}

func TestInternalACRevocationSweepEndpoint_DropsRevokedConn(t *testing.T) {
	const path = "/nhp/internal/ac/revocations/sweep"
	const acId = "ac-1157-f5-http"
	revokedPubkey := testPubkeyB64(0xD4)
	s := newRevocationSweepTestServer(t)
	s.acPubkeyRevokeVerifyRequire = true

	revokedAC, revokedUDP := newRevocationSweepConn(acId, revokedPubkey, "10.0.2.11", 47051)
	seedRevocationSweepConn(s, acId, revokedAC, revokedUDP, false)
	s.storage.(*MemoryStorage).PutACAssignment(&ACAssignment{ACID: acId, RevokedPubKeys: []string{revokedPubkey}})

	gin.SetMode(gin.TestMode)
	signer, err := internalauth.New(testInternalKnockSecret)
	if err != nil {
		t.Fatalf("internalauth.New: %v", err)
	}
	hs := &HttpServer{
		udpServer:           s,
		internalAuthSigner:  signer,
		internalAuthRequire: true,
	}
	r := gin.New()
	if err := r.SetTrustedProxies(nil); err != nil {
		t.Fatalf("SetTrustedProxies(nil): %v", err)
	}
	r.POST(path, hs.handleInternalACRevocationSweep)

	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set(internalauth.Header, signer.Sign(http.MethodPost, path, nil))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200. body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Dropped int `json:"dropped"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if body.Dropped != 1 {
		t.Fatalf("dropped = %d, want 1", body.Dropped)
	}
	if _, ok := s.acConnectionMap[acId]; ok {
		t.Fatal("acConnectionMap still contains revoked acId after on-demand sweep")
	}
	if !waitForClosed(revokedUDP.ConnData, closeWaitTimeout) {
		t.Fatalf("revoked connection was not closed within %s", closeWaitTimeout)
	}
}

func TestInternalACRevocationSweepEndpoint_RejectsWhenGatePermitMode(t *testing.T) {
	const path = "/nhp/internal/ac/revocations/sweep"
	s := newRevocationSweepTestServer(t)
	gin.SetMode(gin.TestMode)
	signer, err := internalauth.New(testInternalKnockSecret)
	if err != nil {
		t.Fatalf("internalauth.New: %v", err)
	}
	hs := &HttpServer{
		udpServer:          s,
		internalAuthSigner: signer,
	}
	r := gin.New()
	if err := r.SetTrustedProxies(nil); err != nil {
		t.Fatalf("SetTrustedProxies(nil): %v", err)
	}
	r.POST(path, hs.handleInternalACRevocationSweep)

	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set(internalauth.Header, signer.Sign(http.MethodPost, path, nil))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("code = %d, want 409. body=%s", rec.Code, rec.Body.String())
	}
}

func TestInternalACRevocationSweepEndpoint_RejectsWithoutSigner(t *testing.T) {
	const path = "/nhp/internal/ac/revocations/sweep"
	s := newRevocationSweepTestServer(t)
	s.acPubkeyRevokeVerifyRequire = true
	gin.SetMode(gin.TestMode)
	hs := &HttpServer{udpServer: s}
	r := gin.New()
	if err := r.SetTrustedProxies(nil); err != nil {
		t.Fatalf("SetTrustedProxies(nil): %v", err)
	}
	r.POST(path, hs.handleInternalACRevocationSweep)

	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.RemoteAddr = "127.0.0.1:54321"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401. body=%s", rec.Code, rec.Body.String())
	}
}
