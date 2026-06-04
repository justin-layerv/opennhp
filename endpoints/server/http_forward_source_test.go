package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// newForwardingTestServer creates a minimal HttpServer with an initialized UdpServer
// (empty AC connection map) and an HttpKnockForwarder backed by the given storage.
// This is sufficient to exercise handleInternalKnock through to the forwarding
// decision in handleHttpOpenResource.
func newForwardingTestServer(storage StorageBackend) *HttpServer {
	udpSrv := &UdpServer{
		acConnectionMap: make(map[string][]*ACConn),
		authServiceMap: common.AuthSvcProviderMap{
			"qurl": {
				AuthSvcId: "qurl",
				ResourceGroups: common.ResourceGroupMap{
					"r_test": {
						ResourceGroup: common.ResourceGroup{
							AuthServiceId: "qurl",
							ResourceId:    "r_test",
							OpenTime:      77,
							Resources: map[string]*common.ResourceInfo{
								"default": {
									ACId: "test-ac",
									Addr: &common.NetAddress{Ip: "10.0.2.100", Port: 443},
								},
							},
						},
					},
				},
			},
		},
		// metrics is nil — Publisher.IncrCounter is nil-safe
	}
	hs := &HttpServer{
		udpServer:     udpSrv,
		httpForwarder: NewHttpKnockForwarder(storage, nil, "10.0.0.1", 8888, nil, nil),
	}
	return hs
}

// buildKnockRequest creates a valid HttpKnockForwardRequest. Resource only
// carries optional caller metadata; routing data is resolved by the server.
func buildKnockRequest(source string) HttpKnockForwardRequest {
	return HttpKnockForwardRequest{
		Request: &common.HttpKnockRequest{
			AuthServiceId: "qurl",
			ResourceId:    "r_test",
			SrcIp:         "10.0.1.50",
		},
		Resource: &common.ResourceData{
			ResourceGroup: common.ResourceGroup{
				AuthServiceId: "qurl",
				ResourceId:    "r_test",
				OpenTime:      300,
			},
		},
		Source: source,
	}
}

// callHandleInternalKnock exercises the handler with the given request and
// returns the HTTP response recorder.
func callHandleInternalKnock(t *testing.T, hs *HttpServer, fwdReq HttpKnockForwardRequest) *httptest.ResponseRecorder {
	t.Helper()

	body, err := json.Marshal(fwdReq)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/nhp/internal/knock", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request.RemoteAddr = "10.0.1.100:12345" // private IP to pass source check

	hs.handleInternalKnock(c)
	return w
}

// TestHandleInternalKnock_APISource_AllowsForwarding verifies that when
// Source=SourceAPI, the handler does NOT set Forwarded=true, allowing the
// knock to be forwarded to another server. We verify this by checking that
// the httpForwarder's storage backend (GetACAssignment) IS called.
func TestHandleInternalKnock_APISource_AllowsForwarding(t *testing.T) {
	gin.SetMode(gin.TestMode)

	storage := NewMemoryStorage()
	hs := newForwardingTestServer(storage)

	fwdReq := buildKnockRequest(SourceAPI)
	w := callHandleInternalKnock(t, hs, fwdReq)

	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status %d, body: %s", w.Code, w.Body.String())
	}

	if storage.GetCallCount("GetACAssignment") == 0 {
		t.Error("Source=SourceAPI: expected httpForwarder to be called (GetACAssignment), but it was not — Forwarded was incorrectly set to true")
	}
}

// TestHandleInternalKnock_EmptySource_BlocksForwarding verifies that when
// Source is empty (server-to-server forwarding), the handler sets Forwarded=true,
// preventing the knock from being forwarded again. We verify this by checking
// that the httpForwarder's storage backend is NOT called.
func TestHandleInternalKnock_EmptySource_BlocksForwarding(t *testing.T) {
	gin.SetMode(gin.TestMode)

	storage := NewMemoryStorage()
	hs := newForwardingTestServer(storage)

	fwdReq := buildKnockRequest("") // empty source = server-to-server
	w := callHandleInternalKnock(t, hs, fwdReq)

	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status %d, body: %s", w.Code, w.Body.String())
	}

	var resp HttpKnockForwardResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.AckMsg == nil {
		t.Fatalf("AckMsg is nil, response: %s", w.Body.String())
	}
	if resp.AckMsg.OpenTime != 77 {
		t.Fatalf("AckMsg.OpenTime = %d, want storage-resolved OpenTime 77", resp.AckMsg.OpenTime)
	}

	if storage.GetCallCount("GetACAssignment") != 0 {
		t.Error("Source='': expected httpForwarder NOT to be called (Forwarded should be true), but GetACAssignment was called — loop prevention is broken")
	}
}

// TestHandleInternalKnock_UnknownSource_BlocksForwarding verifies that an
// unrecognized Source value is treated as server-to-server (Forwarded=true),
// preventing forwarding. This tests the defensive default behavior.
func TestHandleInternalKnock_UnknownSource_BlocksForwarding(t *testing.T) {
	gin.SetMode(gin.TestMode)

	storage := NewMemoryStorage()
	hs := newForwardingTestServer(storage)

	fwdReq := buildKnockRequest("unknown")
	w := callHandleInternalKnock(t, hs, fwdReq)

	if w.Code != http.StatusOK {
		t.Fatalf("unexpected status %d, body: %s", w.Code, w.Body.String())
	}

	if storage.GetCallCount("GetACAssignment") != 0 {
		t.Error("Source='unknown': expected httpForwarder NOT to be called (unknown source should block forwarding), but GetACAssignment was called")
	}
}

// TestForwardRequest_SourceOmittedFromJSON verifies that an empty Source field
// is omitted from JSON serialization (via the omitempty tag). This is a contract
// test ensuring that forwardToServer's constructed request (which never sets Source)
// produces JSON without the "source" key, so the receiving server treats it as a
// server-to-server forward and sets Forwarded=true.
func TestForwardRequest_SourceOmittedFromJSON(t *testing.T) {
	req := &HttpKnockForwardRequest{
		Request:  &common.HttpKnockRequest{},
		Resource: &common.ResourceData{},
		// Source intentionally omitted — matches forwardToServer behavior
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if _, exists := parsed["source"]; exists {
		t.Error("empty Source should be omitted from JSON (omitempty) — forwardToServer relies on this for loop prevention")
	}
}
