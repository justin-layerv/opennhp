package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// TestHandleInternalKnock_RejectsResIdlessForward pins the receiver contract
// the sender must satisfy: a forward whose request omits resId is rejected
// 400 "missing aspId or resId". This is exactly the bare req the pre-fix
// sender shipped — so this test fails against the pre-fix forwarder shape.
func TestHandleInternalKnock_RejectsResIdlessForward(t *testing.T) {
	gin.SetMode(gin.TestMode)
	hs := newInternalKnockTestServer()

	bare := HttpKnockForwardRequest{
		Request: &common.HttpKnockRequest{AuthServiceId: "qurl"}, // resId empty
		// Source empty = server-to-server forward
	}
	w := callHandleInternalKnock(t, hs, bare)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("resId-less forward must be rejected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandleInternalKnock_SetsKnockProcessingDeadline preserves the bounded
// processing helper's contract and verifies that the headless HTTP pre-handler
// reaches the retired terminal after applying its validation stages.
func TestHandleInternalKnock_SetsKnockProcessingDeadline(t *testing.T) {
	gin.SetMode(gin.TestMode)
	hs := newInternalKnockTestServer()
	fwdReq := HttpKnockForwardRequest{
		Source:  SourceAPI,
		Request: &common.HttpKnockRequest{AuthServiceId: "qurl", ResourceId: "r_test", SrcIp: "10.0.1.50"},
	}

	before := time.Now()
	budgetCtx, cancel := withKnockProcessingBudget(context.Background())
	defer cancel()
	deadline, ok := budgetCtx.Deadline()
	if !ok {
		t.Fatal("withKnockProcessingBudget returned no deadline")
	}
	gotBudget := deadline.Sub(before)
	if gotBudget < HttpKnockProcessingBudget-2*time.Second || gotBudget > HttpKnockProcessingBudget+2*time.Second {
		t.Errorf("deadline budget = %v, want approximately %v", gotBudget, HttpKnockProcessingBudget)
	}

	w := callHandleInternalKnock(t, hs, fwdReq)
	assertRetiredHTTPAdmissionResponse(t, w.Code, w.Body.Bytes())
}
