package ac

import (
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
