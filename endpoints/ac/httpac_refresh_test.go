package ac

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// TestHandleHttpRefreshOperations_DeadlinePassedReturnsTokenExpired wires the
// /refresh handler's deadline-passed branch end-to-end (#1942). The unit
// tests pin the helper contracts (RemainingFirewallSeconds,
// VerifyAccessToken) but not the handler-level wiring between them; this
// test fences that gap.
//
// Specifically: an entry whose FirstKnockTime + OpenTime is in the past must
// produce a 200 OK with body `{"errMsg":"token expired"}` — NOT a fresh
// firewall extension via HandleAccessControl. A regression that drops the
// `remainingSec <= 0` check would silently re-open the ipset entry past the
// absolute deadline.
//
// Cannot exercise the HandleAccessControl success path here — that requires a
// fully-initialized AC with iptables/ipset (see msghandler_test.go:174
// rationale). Live-ipset coverage is tracked in #1950 (Tier 1 smoke).
func TestHandleHttpRefreshOperations_DeadlinePassedReturnsTokenExpired(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ua := &UdpAC{tokenStore: common.NewTokenStore[*AccessEntry]()}
	ha := &HttpAC{ua: ua}

	const openTime = 10
	entry := &AccessEntry{
		User:     &common.AgentUser{UserId: "u-deadline-passed"},
		SrcAddrs: []*common.NetAddress{{Ip: "1.2.3.4"}},
		DstAddrs: []*common.NetAddress{{Ip: "10.0.0.1", Port: 80}},
		OpenTime: openTime,
	}
	token := ua.GenerateAccessToken(entry)
	// Rewind FirstKnockTime so RemainingFirewallSeconds() returns 0 but
	// the token is still within the late-packet buffer window (so
	// VerifyAccessToken returns the entry rather than nil — exercising
	// the deadline-passed branch specifically, not the verify-failed branch).
	entry.FirstKnockTime = time.Now().Add(-time.Duration(openTime+1) * time.Second)
	ua.tokenStore.Store(token, entry)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	ha.HandleHttpRefreshOperations(c, &common.HttpRefreshRequest{
		Token: token,
		SrcIp: "1.2.3.4",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (handler writes 200 OK with errMsg body)", rec.Code, http.StatusOK)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not JSON: %v (body=%q)", err, rec.Body.String())
	}
	if got, want := body["errMsg"], "token expired"; got != want {
		t.Errorf("errMsg = %q, want %q — deadline-passed branch did not fire (raw body=%q)", got, want, rec.Body.String())
	}
}

// TestHandleHttpRefreshOperations_DeadlinePassedCancelsScheduledFlows fences
// #2172: when the firewall deadline has passed the handler now drops any
// L3 flush scheduler entries for the entry's tuples before responding.
// Without the Cancel, processEntry would fire a Flush on already-gone
// kernel state — ENOENT-noop, but inflates metricFlushTotal and exposes
// the breaker pointlessly.
//
// Test shape: build a real scheduler (NoOpFlusher so Flush is harmless),
// schedule a flow for the entry's tuple in the distant future, run the
// /refresh handler with a rewound FirstKnockTime so RemainingFirewallSeconds
// returns 0, then assert EntryCount drops to 0.
func TestHandleHttpRefreshOperations_DeadlinePassedCancelsScheduledFlows(t *testing.T) {
	gin.SetMode(gin.TestMode)

	sched := NewScheduler(&NoOpFlusher{}, WithTickInterval(5*time.Millisecond), WithWheelSize(100))
	sched.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := sched.Shutdown(ctx); err != nil {
			t.Errorf("scheduler shutdown: %v", err)
		}
	}()

	ua := &UdpAC{
		tokenStore:  common.NewTokenStore[*AccessEntry](),
		expirySched: sched,
	}
	ha := &HttpAC{ua: ua}

	const openTime = 10
	entry := &AccessEntry{
		User:     &common.AgentUser{UserId: "u-cancel-on-deadline"},
		SrcAddrs: []*common.NetAddress{{Ip: "1.2.3.4"}},
		DstAddrs: []*common.NetAddress{{Ip: "10.0.0.1", Port: 80, Protocol: "tcp"}},
		OpenTime: openTime,
	}
	token := ua.GenerateAccessToken(entry)
	// Schedule via the production wrapper so the FlowKey is recorded on
	// entry.scheduledKeys (#2201/#2205). Far-future deadline so the
	// scheduler keeps it in the wheel until Cancel.
	ua.scheduleFlushIfEnabled(entry, "1.2.3.4", "10.0.0.1", 80, FlowProtoTCP, time.Now().Add(1*time.Hour))
	if got := sched.EntryCount(); got != 1 {
		t.Fatalf("precondition: EntryCount = %d, want 1", got)
	}

	entry.FirstKnockTime = time.Now().Add(-time.Duration(openTime+1) * time.Second)
	ua.tokenStore.Store(token, entry)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	ha.HandleHttpRefreshOperations(c, &common.HttpRefreshRequest{
		Token: token,
		SrcIp: "1.2.3.4",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := sched.EntryCount(); got != 0 {
		t.Errorf("EntryCount after refresh-shorten = %d, want 0 (Cancel did not fire)", got)
	}
}

// TestHandleHttpRefreshOperations_TokenVerifyFailedReturnsErrMsg fences the
// other "deny without calling HandleAccessControl" branch — token verification
// failure. This is the case where VerifyAccessToken returns nil because either
// the token is unknown OR the absolute deadline (FirstKnockTime + OpenTime +
// buffer) has elapsed.
//
// Together with the deadline-passed test above, this pins the two "skip
// HandleAccessControl" paths the #1942 fix relies on.
//
// Post #1960 mitigation (cr round-17): the verify-failed branch and the
// firewall-deadline branch BOTH emit the same body — "token expired" — so
// a token-holder cannot use the response to fingerprint the buffer-window
// edge. Operator triage stays distinguishable via the distinct log lines.
func TestHandleHttpRefreshOperations_TokenVerifyFailedReturnsErrMsg(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ua := &UdpAC{tokenStore: common.NewTokenStore[*AccessEntry]()}
	ha := &HttpAC{ua: ua}

	// 32-byte base64-StdEncoding token that passes httpac.go's
	// `len(buf) != 32` wire-format check but is not in the store →
	// VerifyAccessToken returns nil.
	const fakeToken = "//////////////////////////////////////////8="

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	ha.HandleHttpRefreshOperations(c, &common.HttpRefreshRequest{
		Token: fakeToken,
		SrcIp: "1.2.3.4",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), "token expired") {
		t.Errorf("expected 'token expired' in body for unknown token (response collapsed per #1960); got %q", rec.Body.String())
	}
}

// TestHandleHttpRefreshOperations_PastAbsoluteDeadlineRejectsViaVerify pins
// the symmetric edge: when the token is past the ABSOLUTE deadline (not just
// the firewall deadline), VerifyAccessToken returns nil and the handler
// short-circuits before HandleAccessControl. Post #1960 mitigation (cr
// round-17), the response body is the same as the firewall-deadline branch
// — distinguishing the two paths from outside the AC is intentionally
// impossible. The internal distinction lives only in the log lines.
func TestHandleHttpRefreshOperations_PastAbsoluteDeadlineRejectsViaVerify(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ua := &UdpAC{tokenStore: common.NewTokenStore[*AccessEntry]()}
	ha := &HttpAC{ua: ua}

	const openTime = 10
	entry := &AccessEntry{
		User:     &common.AgentUser{UserId: "u-absolute-deadline"},
		SrcAddrs: []*common.NetAddress{{Ip: "1.2.3.4"}},
		DstAddrs: []*common.NetAddress{{Ip: "10.0.0.1", Port: 80}},
		OpenTime: openTime,
	}
	token := ua.GenerateAccessToken(entry)
	// Rewind past the ABSOLUTE deadline (OpenTime + buffer + 1).
	entry.FirstKnockTime = time.Now().Add(-time.Duration(openTime+accessTokenLatePacketBufferSeconds+1) * time.Second)
	ua.tokenStore.Store(token, entry)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	ha.HandleHttpRefreshOperations(c, &common.HttpRefreshRequest{
		Token: token,
		SrcIp: "1.2.3.4",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	// Past the absolute deadline VerifyAccessToken returns nil → handler
	// emits the collapsed "token expired" body (same shape as the firewall-
	// deadline branch, per #1960).
	if !strings.Contains(rec.Body.String(), "token expired") {
		t.Errorf("expected 'token expired' for past-absolute-deadline token; got %q", rec.Body.String())
	}
}

func TestHandleHttpRefreshOperations_CloseBetweenVerifyAndMutationCannotResurrectSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	scheduler := NewScheduler(&NoOpFlusher{}, WithTickInterval(time.Hour))
	scheduler.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = scheduler.Shutdown(ctx)
	})
	agent := testNHPAgentKey('A')
	ua := &UdpAC{
		config:      &Config{FilterMode: FilterMode_IPTABLES},
		tokenStore:  common.NewTokenStore[*AccessEntry](),
		revIndex:    newRevocationIndex(),
		nhpSessions: newNHPSessionIndex(),
		expirySched: scheduler,
	}
	ua.sessionFlushComplete.Store(true)
	ua.sessionControlLeaseHeld.Store(true)
	ua.sessionFlushGeneration.Store(1)
	entry := &AccessEntry{
		User:                     &common.AgentUser{UserId: "registered"},
		SrcAddrs:                 []*common.NetAddress{{Ip: "192.0.2.10"}},
		DstAddrs:                 []*common.NetAddress{{Ip: "192.0.2.20", Port: 443, Protocol: "tcp"}},
		OpenTime:                 60,
		NHPSessionId:             77,
		NHPServerPublicKey:       "server",
		NHPSessionOwnerId:        "00112233445566778899aabbccddeeff",
		NHPAgentPublicKey:        agent,
		NHPSessionIssuedAtMillis: 1000,
	}
	token := ua.GenerateAccessToken(entry)
	ha := &HttpAC{ua: ua}
	ha.beforeSessionControlRefreshFence = func() {
		ua.sessionControlFlushMu.Lock()
		defer ua.sessionControlFlushMu.Unlock()
		if err := ua.nhpSessions.beginExactCloseFence(agent, 77, 1000); err != nil {
			t.Fatalf("begin exact close fence: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if closed, err := ua.closeNHPExactSessionVerified(ctx, agent, 77, 1000); err != nil || closed != 1 {
			t.Fatalf("close during refresh = %d, %v, want 1", closed, err)
		}
		if err := ua.nhpSessions.commitExactCloseFence(agent, 77, 1000); err != nil {
			t.Fatalf("commit exact close fence: %v", err)
		}
	}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	ha.HandleHttpRefreshOperations(c, &common.HttpRefreshRequest{Token: token, SrcIp: "192.0.2.10"})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "token expired") {
		t.Fatalf("refresh response = %d %q, want collapsed expiry", rec.Code, rec.Body.String())
	}
	if _, ok := ua.tokenStore.Load(token); ok {
		t.Fatal("refresh restored a token removed by the converged close")
	}
	if got := len(entry.snapshotScheduledKeys()); got != 0 {
		t.Fatalf("refresh recorded %d post-close flow keys", got)
	}
}
