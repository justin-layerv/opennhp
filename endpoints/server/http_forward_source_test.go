package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
)

// newInternalKnockTestServer creates a minimal server that can exercise the
// authenticated pre-handler before the retired admission terminal.
func newInternalKnockTestServer() *HttpServer {
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
							// Inner Resources key is the resId on the catalog
							// path (resource_lookup.go) — key it that way here so
							// the fixture mirrors the production shape.
							Resources: map[string]*common.ResourceInfo{
								"r_test": {
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
	return &HttpServer{udpServer: udpSrv}
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

func TestHandleInternalKnock_ResourceLookupUsesLifecycleCtx(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const resourceID = "q_123456789ab"
	type ctxKey struct{}
	key := ctxKey{}
	q := newFakeResourcesQuerier()
	type seenGetItemCtx struct {
		marker any
		err    error
	}
	seenCtx := make(chan seenGetItemCtx, 1)
	q.beforeGetItemCtx = func(ctx context.Context) {
		seenCtx <- seenGetItemCtx{marker: ctx.Value(key), err: ctx.Err()}
	}
	q.putDynamicQURLWithTTL(resourceID, "qurl", "test-ac", "backend.example", "backend.example", 443, 77, time.Now().Add(time.Hour).Unix())
	lookup, err := NewResourceLookup(q, "nhp-resources-test", nhpSystemCustomerID, &captureApplier{})
	if err != nil {
		t.Fatalf("NewResourceLookup: %v", err)
	}

	lifecycleParent := context.WithValue(context.Background(), key, "lifecycle")
	lifecycleCtx, cancelLifecycle := context.WithCancel(lifecycleParent)
	defer cancelLifecycle()
	hs := &HttpServer{
		udpServer: &UdpServer{
			acConnectionMap: make(map[string][]*ACConn),
			resourceLookup:  lookup,
			lifecycleCtx:    lifecycleCtx,
			metrics:         metrics.NewPublisherForTest(t),
		},
	}
	fwdReq := HttpKnockForwardRequest{
		Request: &common.HttpKnockRequest{
			AuthServiceId: "qurl",
			ResourceId:    resourceID,
			SrcIp:         "10.0.1.50",
		},
		Resource: &common.ResourceData{
			ResourceGroup: common.ResourceGroup{
				AuthServiceId: "qurl",
				ResourceId:    resourceID,
				OpenTime:      300,
			},
		},
		Source: SourceAPI,
	}
	body, err := json.Marshal(fwdReq)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	reqParent := context.WithValue(context.Background(), key, "request")
	reqCtx, cancelReq := context.WithCancel(reqParent)
	cancelReq()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/nhp/internal/knock", bytes.NewReader(body)).WithContext(reqCtx)
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request.RemoteAddr = "10.0.1.100:12345"

	hs.handleInternalKnock(c)
	assertRetiredHTTPAdmissionResponse(t, w.Code, w.Body.Bytes())

	select {
	case got := <-seenCtx:
		if got.marker != "lifecycle" {
			t.Fatalf("resource lookup ctx marker = %v, want lifecycle marker", got.marker)
		}
		if got.err != nil {
			t.Fatalf("resource lookup ctx err = %v, want live lifecycle ctx", got.err)
		}
	default:
		t.Fatal("resource lookup GetItem was not called")
	}
}

// TestHandleInternalKnock_APISourceReachesRetiredAdmission verifies that an
// API origin clears the source gate and reaches the retired terminal without
// reviving cross-server application admission.
func TestHandleInternalKnock_APISourceReachesRetiredAdmission(t *testing.T) {
	gin.SetMode(gin.TestMode)

	hs := newInternalKnockTestServer()

	fwdReq := buildKnockRequest(SourceAPI)
	w := callHandleInternalKnock(t, hs, fwdReq)

	assertRetiredHTTPAdmissionResponse(t, w.Code, w.Body.Bytes())
}

// TestHandleInternalKnock_EmptySourceReachesRetiredAdmission verifies that a
// historical server-to-server source passes the retained pre-handler checks
// before the unsupported terminal.
func TestHandleInternalKnock_EmptySourceReachesRetiredAdmission(t *testing.T) {
	gin.SetMode(gin.TestMode)

	hs := newInternalKnockTestServer()

	fwdReq := buildKnockRequest("") // empty source = server-to-server
	w := callHandleInternalKnock(t, hs, fwdReq)

	assertRetiredHTTPAdmissionResponse(t, w.Code, w.Body.Bytes())
}

// TestHandleInternalKnock_UnknownSourceReachesRetiredAdmission verifies that an
// unrecognized source cannot revive admission behavior.
func TestHandleInternalKnock_UnknownSourceReachesRetiredAdmission(t *testing.T) {
	gin.SetMode(gin.TestMode)

	hs := newInternalKnockTestServer()

	fwdReq := buildKnockRequest("unknown")
	w := callHandleInternalKnock(t, hs, fwdReq)

	assertRetiredHTTPAdmissionResponse(t, w.Code, w.Body.Bytes())
}

// TestForwardRequest_SourceOmittedFromJSON verifies that an empty Source field
// is omitted from JSON serialization (via the omitempty tag). This is a contract
// test ensuring that a legacy server-to-server envelope remains distinguishable
// from SourceAPI while rolling versions overlap.
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
