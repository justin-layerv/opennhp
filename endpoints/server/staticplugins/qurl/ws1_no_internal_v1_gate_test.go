package qurl

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

// WS1 completion gate: prove NO qURL v2 knock path calls a qURL v1 internal
// endpoint, while the legacy at_ path STILL does (the dual-path is by design,
// resolver.go:209/217). The unit routing tests in authnhpclaims_test.go already
// assert the in-process dispatch (re-knock -> authorize, never prepare; a qv2
// knock never reaches the legacy session path). This is the LITERAL end-to-end
// guard: a single fake qurl-service that records which internal HTTP paths
// actually receive requests when a knock is driven all the way through the
// plugin, so a regression that re-points a v2 path at v1 is caught by an HTTP
// observation, not just an in-memory routing assertion.
//
// Why a SEPARATE recorder from authnhpclaims_test.go's admissionRecorder: that
// one buckets requests on `r.URL.Path == admissionPreparePath` (the package
// CONSTANT). If a regression mutated admissionPreparePath to "/internal/v1/
// resolve", the constant would move WITH the mutation — the bucket would still
// match, still record "prepare", and a semantic-bucket assertion would stay
// GREEN even though prepare now POSTs to v1. That is exactly the worthless
// outcome the gate must not have. So this recorder is deliberately
// constant-independent: it records the RAW r.URL.Path of every request at the
// top of the handler (before any routing/response branch, so even a path that
// matches nothing is recorded), and every assertion below compares against a
// HARDCODED literal path string. Under the red-demo mutation
// (admissionPreparePath = "/internal/v1/resolve"; see the comment on
// TestWS1_NoQv2PathCallsInternalV1) the v2-prepare literal stops being hit and
// the v1-resolve literal starts being hit, so BOTH the v2-presence and the
// v1-absence assertions flip RED. A guard that could not go red is no guard.

// Hardcoded internal-path literals. These are intentionally NOT the package
// constants (admissionPreparePath, etc.): the whole point is to pin the wire
// paths independently so a constant that drifts toward v1 is caught.
const (
	// v1 paths that a qv2 knock must NEVER hit.
	wantV1ResolvePath      = "/internal/v1/resolve"
	wantV1BrowserRelayPath = "/internal/v1/browser-relay/resolve"

	// v2 admission paths. prepare/authorize are exact; commit/cancel carry an
	// admission-id segment (/internal/v2/qurl/admissions/{id}/commit) so they are
	// matched by suffix below.
	wantV2PreparePath   = "/internal/v2/qurl/admissions/prepare"
	wantV2AuthorizePath = "/internal/v2/qurl/admissions/authorize"
	wantV2CommitSuffix  = "/commit" // under /internal/v2/qurl/admissions/{id}
	wantV2CancelSuffix  = "/cancel" // under /internal/v2/qurl/admissions/{id}
)

// internalPathRecorder is a fake qurl-service internal server that records the
// RAW path of every request and serves the minimal valid response each knock
// path needs. It is the literal subject of the WS1 gate: tests drive a knock
// through the plugin and then read paths() to see which internal endpoints were
// actually contacted over HTTP.
type internalPathRecorder struct {
	server *httptest.Server

	mu    sync.Mutex
	calls []string // raw r.URL.Path of every request, in arrival order

	// authorize response, read by handle's authorize branch. Defaults to 403
	// access_denied (no live session) so a first knock falls through to prepare;
	// the re-knock case swaps in a live-session 200 via serveLiveAuthorize.
	// Guarded by mu alongside calls: the write (serveLiveAuthorize) happens-before
	// the knock that drives the read (handle), so the lock is not contended in
	// practice, but holding it makes the no-data-race invariant explicit rather
	// than resting on that ordering — see the mutex on every access below.
	authorizeStatus int
	authorizeBody   string
}

func newInternalPathRecorder(t *testing.T) *internalPathRecorder {
	t.Helper()
	rec := &internalPathRecorder{
		authorizeStatus: http.StatusForbidden,
		authorizeBody:   `{"success":false,"error":{"code":"access_denied"}}`,
	}
	rec.server = httptest.NewServer(http.HandlerFunc(rec.handle))
	t.Cleanup(rec.server.Close)
	return rec
}

// handle records the raw path FIRST (so a request to any path — even one that
// matches no branch below — is observed), then serves the minimal valid
// response. The response bodies mirror the success shapes the production
// handlers return so each knock path runs to completion rather than erroring out
// before it reaches the endpoint under test.
func (rec *internalPathRecorder) handle(w http.ResponseWriter, r *http.Request) {
	rec.mu.Lock()
	rec.calls = append(rec.calls, r.URL.Path)
	authorizeStatus, authorizeBody := rec.authorizeStatus, rec.authorizeBody
	rec.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")

	switch {
	// ---- qURL v2 admission contract ----
	case r.URL.Path == wantV2AuthorizePath:
		w.WriteHeader(authorizeStatus)
		_, _ = w.Write([]byte(authorizeBody))

	case r.URL.Path == wantV2PreparePath:
		body, _ := json.Marshal(internalAdmissionPrepareResponse{
			Success: true,
			Data: &AdmissionPrepareResponse{
				AdmissionID: "adm_ws1",
				QurlID:      "q_ws1abcdef0",
				OpenTime:    30,
				QurlSiteURL: "https://q.qurl.site/ws1",
				ACRouting:   defaultACRouting(),
			},
		})
		_, _ = w.Write(body)

	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, wantV2CommitSuffix):
		w.WriteHeader(http.StatusOK)

	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, wantV2CancelSuffix):
		w.WriteHeader(http.StatusOK)

	// ---- legacy qURL v1 (at_) browser-relay bootstrap ----
	case r.URL.Path == wantV1BrowserRelayPath:
		_ = json.NewEncoder(w).Encode(internalResolveResponse{
			Success: true,
			Data: &ResolveResponse{
				ResourceID:    "r_ws1legacy01",
				NHPResourceID: testNHPResourceID,
				QurlSiteURL:   "https://r_ws1legacy01.qurl.site",
				JWTSecret:     "ws1-jwt-secret",
				TokenExpire:   3600,
				OpenTime:      20,
				CookieDomain:  ".qurl.site",
			},
		})

	default:
		// Fail closed AND recorded: an unexpected path (e.g. a mutated v2 constant
		// pointing at /internal/v1/resolve) still appears in rec.calls above, so the
		// gate's v1-absence assertion catches it even though the response is a 404.
		w.WriteHeader(http.StatusNotFound)
	}
}

// serveLiveAuthorize flips the recorder's authorize response to a live-session
// 200 (the steady-state re-knock case): authorize returns remaining_seconds +
// the matched session id + the AC to refresh, so the flow refreshes via
// authorize alone and never touches prepare. It only sets the response fields
// handle() reads — the raw-path recording in handle() is untouched, so the
// re-knock's authorize hit is still recorded exactly like every other path.
// The fields are written under mu (the same lock handle() reads them under) so
// the recorder has a single, explicit synchronization point.
func (rec *internalPathRecorder) serveLiveAuthorize(sessionID string, remaining uint32) {
	body, _ := json.Marshal(internalAdmissionAuthorizeResponse{
		Success: true,
		Data: &AdmissionAuthorizeResponse{
			SessionID:        sessionID,
			RemainingSeconds: remaining,
			ACRouting:        defaultACRouting(),
		},
	})
	rec.mu.Lock()
	rec.authorizeStatus = http.StatusOK
	rec.authorizeBody = string(body)
	rec.mu.Unlock()
}

func (rec *internalPathRecorder) paths() []string {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	out := make([]string, len(rec.calls))
	copy(out, rec.calls)
	return out
}

// count returns how many recorded requests satisfy match.
func (rec *internalPathRecorder) count(match func(string) bool) int {
	n := 0
	for _, p := range rec.paths() {
		if match(p) {
			n++
		}
	}
	return n
}

func (rec *internalPathRecorder) countExact(path string) int {
	return rec.count(func(p string) bool { return p == path })
}

func (rec *internalPathRecorder) countSuffix(suffix string) int {
	return rec.count(func(p string) bool { return strings.HasSuffix(p, suffix) })
}

// pointResolverAt points the package-level resolver at the recorder's server and
// restores the previous resolver at test end. Like the other globals-mutating
// tests in this package (see metrics_test.go / main_test.go), the gate is NOT
// safe under t.Parallel(): it swaps the package-global resolver (and enableV2
// swaps v2AdmissionEnabled), so a future contributor adding t.Parallel() here or
// to a sibling test must serialize against these swaps.
func (rec *internalPathRecorder) pointResolverAt(t *testing.T) {
	t.Helper()
	prev := resolver
	resolver = &QurlResolver{
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		baseURL:      rec.server.URL,
		serviceToken: "ws1-token",
	}
	t.Cleanup(func() { resolver = prev })
}

// TestWS1_NoQv2PathCallsInternalV1 is the WS1 completion gate. Table-driven over
// the three flows that matter, each asserting which internal HTTP paths the fake
// qurl-service actually received:
//
//   - qv2 initial knock: authorize (>=1, falls through) + prepare(1) + commit(1),
//     NO v1 resolve, NO v1 browser-relay/resolve.
//   - qv2 re-knock (live session): authorize(1) only — NEVER prepare/commit, and
//     NO v1 endpoints.
//   - legacy at_ bootstrap knock: STILL hits /internal/v1/browser-relay/resolve
//     (the dual-path is intentional), and NO v2 admission endpoints.
//
// This gate asserts which endpoints are hit and how many times — NOT the call
// ORDER (e.g. authorize-before-prepare). Sequencing is intentionally delegated
// to the in-process routing tests in authnhpclaims_test.go (which assert
// authorize precedes prepare and commit precedes AC-open via an ordered call
// log); duplicating that here would couple this wire-level gate to dispatch
// order it does not need to pin.
//
// THE RED DEMO (proves this is a real regression guard, not a test that passes
// regardless of routing): change resolver_admission.go's
//
//	admissionPreparePath = "/internal/v1/resolve"
//
// and run this test. The qv2 initial-knock case goes RED two ways at once:
//   - wantV1ResolvePath count becomes 1 (was 0) -> "qv2 hit a v1 endpoint" fails;
//   - wantV2PreparePath count becomes 0 (was 1) -> "qv2 prepare hit" fails.
//
// (Verified empirically; see the PR description for the before/after output.) A
// recorder that bucketed on the package constant would NOT catch this, because
// the constant moves with the mutation — which is the whole reason this gate
// records raw r.URL.Path and asserts hardcoded literals.
func TestWS1_NoQv2PathCallsInternalV1(t *testing.T) {
	tests := []struct {
		name string
		// run drives one knock all the way through the plugin against rec and
		// returns the ack + error. It deliberately does NOT t.Fatal on a flow
		// error: the path-count assertions below must ALWAYS run, because they are
		// the whole point of this gate. Under the red-demo mutation the flow errors
		// AND the path counts flip — surfacing both makes the demonstration land on
		// the recorder (the apparatus under test), not on a runner's t.Fatal.
		run func(t *testing.T, rec *internalPathRecorder) (*common.ServerKnockAckMsg, error)

		// expected internal-path hit counts. Every flow here legitimately admits,
		// so the success check below is unconditional.
		wantV1Resolve      int
		wantV1BrowserRelay int
		wantV2Prepare      int
		wantV2Authorize    int
		wantV2Commit       int
	}{
		{
			name: "qv2 initial knock: authorize->prepare->commit, zero v1",
			run:  runQv2InitialKnock,
			// First knock: authorize 403s (no live session) then falls through to
			// prepare+commit. authorize is hit exactly once here.
			wantV1Resolve:      0,
			wantV1BrowserRelay: 0,
			wantV2Prepare:      1,
			wantV2Authorize:    1,
			wantV2Commit:       1,
		},
		{
			name: "qv2 re-knock (live session): authorize only, never prepare, zero v1",
			run:  runQv2ReKnock,
			// A live session refreshes via authorize alone: prepare/commit MUST be 0.
			wantV1Resolve:      0,
			wantV1BrowserRelay: 0,
			wantV2Prepare:      0,
			wantV2Authorize:    1,
			wantV2Commit:       0,
		},
		{
			name: "legacy at_ bootstrap knock: hits v1 browser-relay, zero v2",
			run:  runLegacyAtBootstrapKnock,
			// The dual-path is intentional: the legacy at_ knock STILL resolves via
			// the v1 browser-relay endpoint, and touches NO v2 admission endpoint.
			wantV1Resolve:      0,
			wantV1BrowserRelay: 1,
			wantV2Prepare:      0,
			wantV2Authorize:    0,
			wantV2Commit:       0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := newInternalPathRecorder(t)
			rec.pointResolverAt(t)

			ack, runErr := tt.run(t, rec)

			// Non-fatal so the path-count assertions still run and the red-demo
			// surfaces on the recorder. Every flow here legitimately admits; a flow
			// that errored early would also trip the path counts below.
			if runErr != nil {
				t.Errorf("flow returned error: %v (want a successful admit)", runErr)
			}
			if ack == nil || ack.ErrCode != common.ErrSuccess.ErrorCode() {
				t.Errorf("flow did not produce a success ack: ack=%+v", ack)
			}

			// ---- THE GATE: v1 absence on qv2, dual-path presence on legacy ----

			// /internal/v1/resolve == 0: no knock path calls resolver.Resolve() in
			// steady state (that is the HTTP/Traefik resolve at main.go:244), so this
			// reads vacuous — but it is load-bearing for exactly the mutation this
			// gate targets: under the red-demo (admissionPreparePath repointed at
			// /internal/v1/resolve) the qv2 initial knock DOES hit it and this == 0
			// flips red. The other load-bearing v1 endpoint is browser-relay/resolve
			// below, which the legacy at_ knock hits in steady state.
			if got := rec.countExact(wantV1ResolvePath); got != tt.wantV1Resolve {
				t.Errorf("%s hit %d times, want %d", wantV1ResolvePath, got, tt.wantV1Resolve)
			}
			if got := rec.countExact(wantV1BrowserRelayPath); got != tt.wantV1BrowserRelay {
				t.Errorf("%s hit %d times, want %d", wantV1BrowserRelayPath, got, tt.wantV1BrowserRelay)
			}

			// ---- v2 admission endpoint hits ----
			if got := rec.countExact(wantV2PreparePath); got != tt.wantV2Prepare {
				t.Errorf("%s hit %d times, want %d", wantV2PreparePath, got, tt.wantV2Prepare)
			}
			if got := rec.countExact(wantV2AuthorizePath); got != tt.wantV2Authorize {
				t.Errorf("%s hit %d times, want %d", wantV2AuthorizePath, got, tt.wantV2Authorize)
			}
			if got := rec.countSuffix(wantV2CommitSuffix); got != tt.wantV2Commit {
				t.Errorf("v2 commit (suffix %q) hit %d times, want %d", wantV2CommitSuffix, got, tt.wantV2Commit)
			}
			// No admission is ever canceled on a happy-path flow (commit succeeds,
			// re-knock has no lease, legacy never prepares).
			if got := rec.countSuffix(wantV2CancelSuffix); got != 0 {
				t.Errorf("v2 cancel (suffix %q) hit %d times, want 0 on a happy-path flow", wantV2CancelSuffix, got)
			}
		})
	}
}

// runQv2InitialKnock drives a fully-valid qv2 signed-claims knock with NO live
// session. It reuses the v2Fixture/enableV2 builders from authnhpclaims_test.go.
// It returns AuthWithNHP's (ack, err) verbatim — the caller decides what to
// assert — so a mutation that breaks the flow surfaces on the path counts, not
// on a t.Fatal here. rec is accepted for a uniform runner signature.
func runQv2InitialKnock(t *testing.T, _ *internalPathRecorder) (*common.ServerKnockAckMsg, error) {
	t.Helper()
	f := newV2Fixture(t, nil)
	enableV2(t, f.issuer.trustStore(t))
	return AuthWithNHP(f.req, f.helper(nil))
}

// runQv2ReKnock drives a qv2 signed-claims knock whose session is still live, so
// authorize 200s and the flow refreshes WITHOUT prepare/commit. The recorder's
// authorize handler is switched to a live-session 200 before the knock.
func runQv2ReKnock(t *testing.T, rec *internalPathRecorder) (*common.ServerKnockAckMsg, error) {
	t.Helper()
	f := newV2Fixture(t, nil)
	enableV2(t, f.issuer.trustStore(t))

	rec.serveLiveAuthorize("sess_ws1_live", 120)

	return AuthWithNHP(f.req, f.helper(nil))
}

// runLegacyAtBootstrapKnock drives a legacy qURL bootstrap knock: an at_ access
// token in the knock UserData and the bootstrap sentinel resource id. This is
// the path that POSTs /internal/v1/browser-relay/resolve, proving the dual-path
// is intact. It wires ResolveResourceFunc so the post-resolve catalog routing
// resolves and the AC opens. rec is accepted for a uniform runner signature.
func runLegacyAtBootstrapKnock(t *testing.T, _ *internalPathRecorder) (*common.ServerKnockAckMsg, error) {
	t.Helper()
	const (
		accessToken = "at_ws1legacy0123456789012"
		userAgent   = "Mozilla/5.0 ws1-gate-test"
		publicKey   = "mN5hEQiIhhwAhpiIxbgMsAqf6x9SZB8Z1Z4h6q67AD4="
	)

	req := testAuthReq(qurlBootstrapResourceID)
	req.PublicKey = publicKey
	req.Msg.AuthServiceId = PluginID
	req.Msg.UserData = map[string]any{
		qurlAccessTokenUserDataKey: accessToken,
		qurlUserAgentUserDataKey:   userAgent,
	}

	helper := &plugins.NhpServerPluginHelper{
		AspData: testAspData("unused-bootstrap-sentinel", 60),
		ResolveResourceFunc: func(aspID, resID, srcIP string) (*common.ResourceData, error) {
			return &common.ResourceData{
				ResourceGroup: common.ResourceGroup{
					AuthServiceId: aspID,
					ResourceId:    resID,
					OpenTime:      60,
					Resources: map[string]*common.ResourceInfo{
						"ac-1": {ACId: "ac-1", Addr: &common.NetAddress{Ip: "10.0.0.1", Port: 443}},
					},
				},
				SkipAuth: true,
			}, nil
		},
		AuthWithNhpCallbackFunc: func(req *common.NhpAuthRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			req.Ack.ErrCode = common.ErrSuccess.ErrorCode()
			return req.Ack, nil
		},
	}

	return AuthWithNHP(req, helper)
}
