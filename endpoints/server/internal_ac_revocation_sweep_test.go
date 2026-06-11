package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/layervai/nhp/internalauth"
)

func newACRevocationSweepRouter(hs *HttpServer) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	group := router.Group("/nhp/internal")
	group.POST("/ac-revocations/sweep", hs.handleInternalACRevocationSweep)
	group.POST("/ac-revocations/sweep/:ac_id", hs.handleInternalACRevocationSweep)
	return router
}

func TestInternalACRevocationSweepEndpoint_TriggersDrop(t *testing.T) {
	const acID = "ac-1535-http"
	s := newRevokeDropTestServer(t)
	revoked, _ := putRevokeDropConn(s, acID, 0xC1, &net.UDPAddr{IP: net.ParseIP("10.0.0.21"), Port: 47021})

	mem := NewMemoryStorage()
	mem.PutACAssignment(&ACAssignment{
		ACID:           acID,
		Version:        1,
		RevokedPubKeys: []string{revoked.ACPeer.PubKeyBase64},
	})
	s.storage = mem
	s.storageConfig = &StorageConfig{Backend: StorageBackendDynamoDB}
	s.acPubkeyRevokeVerifyRequire = true

	hs := &HttpServer{udpServer: s}
	router := newACRevocationSweepRouter(hs)

	req := httptest.NewRequest(http.MethodPost, "/nhp/internal/ac-revocations/sweep/"+acID, nil)
	req.RemoteAddr = "10.0.0.5:53100"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	if len(s.acConnectionMap[acID]) != 0 {
		t.Fatalf("revoked conn still present after endpoint trigger")
	}
	counters, _ := s.metrics.CountersForTest(t)
	if c := counters[MetricACPubkeyRevokedConnDropped]; c != 1 {
		t.Errorf("%s counter=%v, want 1", MetricACPubkeyRevokedConnDropped, c)
	}
}

func TestInternalACRevocationSweepEndpoint_SuffixlessSweepsActiveACIDs(t *testing.T) {
	const (
		firstACID  = "ac-1535-http-all-a"
		secondACID = "ac-1535-http-all-b"
	)
	s := newRevokeDropTestServer(t)
	first, _ := putRevokeDropConn(s, firstACID, 0xC6, &net.UDPAddr{IP: net.ParseIP("10.0.0.26"), Port: 47026})
	second, _ := putRevokeDropConn(s, secondACID, 0xC7, &net.UDPAddr{IP: net.ParseIP("10.0.0.27"), Port: 47027})

	mem := NewMemoryStorage()
	mem.PutACAssignment(&ACAssignment{
		ACID:           firstACID,
		Version:        1,
		RevokedPubKeys: []string{first.ACPeer.PubKeyBase64},
	})
	mem.PutACAssignment(&ACAssignment{
		ACID:           secondACID,
		Version:        1,
		RevokedPubKeys: []string{second.ACPeer.PubKeyBase64},
	})
	s.storage = mem
	s.storageConfig = &StorageConfig{Backend: StorageBackendDynamoDB}
	s.acPubkeyRevokeVerifyRequire = true

	hs := &HttpServer{udpServer: s}
	router := newACRevocationSweepRouter(hs)

	req := httptest.NewRequest(http.MethodPost, "/nhp/internal/ac-revocations/sweep", nil)
	req.RemoteAddr = "10.0.0.5:53105"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var stats acPubkeyRevokedConnDropStats
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatalf("decode stats: %v", err)
	}
	if stats.CheckedACIDs != 2 {
		t.Errorf("CheckedACIDs=%d, want 2", stats.CheckedACIDs)
	}
	if stats.AffectedACIDs != 2 {
		t.Errorf("AffectedACIDs=%d, want 2", stats.AffectedACIDs)
	}
	if stats.DroppedConns != 2 {
		t.Errorf("DroppedConns=%d, want 2", stats.DroppedConns)
	}
	if got := mem.GetCallCount("GetACAssignment"); got != 2 {
		t.Errorf("GetACAssignment call count=%d, want 2", got)
	}
	if len(s.acConnectionMap[firstACID]) != 0 {
		t.Fatalf("first AC revoked conn still present after suffixless sweep")
	}
	if len(s.acConnectionMap[secondACID]) != 0 {
		t.Fatalf("second AC revoked conn still present after suffixless sweep")
	}
}

func TestInternalACRevocationSweepEndpoint_CanceledRequestReportsTruncated(t *testing.T) {
	const acID = "ac-1535-http-canceled"
	s := newRevokeDropTestServer(t)
	putRevokeDropConn(s, acID, 0xC8, &net.UDPAddr{IP: net.ParseIP("10.0.0.28"), Port: 47028})

	s.storage = NewMemoryStorage()
	s.storageConfig = &StorageConfig{Backend: StorageBackendDynamoDB}
	s.acPubkeyRevokeVerifyRequire = true

	hs := &HttpServer{udpServer: s}
	router := newACRevocationSweepRouter(hs)

	requestCtx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/nhp/internal/ac-revocations/sweep", nil).WithContext(requestCtx)
	req.RemoteAddr = "10.0.0.5:53106"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200 with truncated stats", rec.Code, rec.Body.String())
	}
	var stats acPubkeyRevokedConnDropStats
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatalf("decode stats: %v", err)
	}
	if !stats.Truncated {
		t.Errorf("Truncated=false, want true for canceled request")
	}
	if stats.CheckedACIDs != 0 {
		t.Errorf("CheckedACIDs=%d, want 0 when request is already canceled", stats.CheckedACIDs)
	}
}

func TestInternalACRevocationSweepEndpoint_DisabledWhenStrictGateOff(t *testing.T) {
	s := newRevokeDropTestServer(t)
	s.storage = NewMemoryStorage()
	s.storageConfig = &StorageConfig{Backend: StorageBackendDynamoDB}
	s.acPubkeyRevokeVerifyRequire = false

	hs := &HttpServer{udpServer: s}
	router := newACRevocationSweepRouter(hs)

	req := httptest.NewRequest(http.MethodPost, "/nhp/internal/ac-revocations/sweep", nil)
	req.RemoteAddr = "10.0.0.5:53101"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409", rec.Code, rec.Body.String())
	}
}

func TestInternalACRevocationSweepEndpoint_RejectsPublicSource(t *testing.T) {
	hs := &HttpServer{udpServer: newRevokeDropTestServer(t)}
	router := newACRevocationSweepRouter(hs)

	req := httptest.NewRequest(http.MethodPost, "/nhp/internal/ac-revocations/sweep", nil)
	req.RemoteAddr = "198.51.100.5:53102"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s, want 403", rec.Code, rec.Body.String())
	}
}

func TestInternalACRevocationSweepEndpoint_StrictAuthRejectsUnsigned(t *testing.T) {
	signer, err := internalauth.New("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("internalauth.New: %v", err)
	}
	counts := map[string]int{}
	hs := &HttpServer{
		udpServer:           newRevokeDropTestServer(t),
		internalAuthSigner:  signer,
		internalAuthRequire: true,
		internalAuthEmit: func(name string) {
			counts[name]++
		},
	}
	router := newACRevocationSweepRouter(hs)

	req := httptest.NewRequest(http.MethodPost, "/nhp/internal/ac-revocations/sweep", nil)
	req.RemoteAddr = "10.0.0.5:53103"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s, want 401", rec.Code, rec.Body.String())
	}
	if counts[MetricInternalAuthFailStrict] != 1 {
		t.Errorf("%s count=%d, want 1", MetricInternalAuthFailStrict, counts[MetricInternalAuthFailStrict])
	}
	if counts[MetricInternalAuthSuccess] != 0 {
		t.Errorf("%s count=%d, want 0", MetricInternalAuthSuccess, counts[MetricInternalAuthSuccess])
	}
}

func TestInternalACRevocationSweepEndpoint_StrictAuthSignedSuccess(t *testing.T) {
	signer, err := internalauth.New("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("internalauth.New: %v", err)
	}
	counts := map[string]int{}
	s := newRevokeDropTestServer(t)
	s.storage = NewMemoryStorage()
	s.storageConfig = &StorageConfig{Backend: StorageBackendDynamoDB}
	s.acPubkeyRevokeVerifyRequire = true
	hs := &HttpServer{
		udpServer:           s,
		internalAuthSigner:  signer,
		internalAuthRequire: true,
		internalAuthEmit: func(name string) {
			counts[name]++
		},
	}
	router := newACRevocationSweepRouter(hs)

	const path = "/nhp/internal/ac-revocations/sweep"
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.RemoteAddr = "10.0.0.5:53104"
	req.Header.Set(internalauth.Header, signer.Sign(http.MethodPost, path, nil))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	if counts[MetricInternalAuthSuccess] != 1 {
		t.Errorf("%s count=%d, want 1", MetricInternalAuthSuccess, counts[MetricInternalAuthSuccess])
	}
	if counts[MetricInternalAuthFailStrict] != 0 {
		t.Errorf("%s count=%d, want 0", MetricInternalAuthFailStrict, counts[MetricInternalAuthFailStrict])
	}
}
