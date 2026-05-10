package qurl

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	nhpserver "github.com/OpenNHP/opennhp/endpoints/server"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

// metricCapture records latency samples and counter increments emitted
// by AuthWithHttp through the helper's RecordLatency / IncrCounter
// callbacks. The shape (samples grouped by name) matches what the
// CloudWatch publisher does internally before flushing — the tests
// assert on intent (which metrics fired) rather than wire format.
type metricCapture struct {
	mu        sync.Mutex
	latencies map[string][]float64
	counters  map[string]int
}

func newMetricCapture() *metricCapture {
	return &metricCapture{
		latencies: map[string][]float64{},
		counters:  map[string]int{},
	}
}

func (m *metricCapture) recordLatency(name string, ms float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.latencies[name] = append(m.latencies[name], ms)
}

func (m *metricCapture) incrCounter(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counters[name]++
}

func (m *metricCapture) latencyCount(name string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.latencies[name])
}

// latencySamples returns a copy of the latency samples recorded under
// `name`. Returns a copy (not the underlying slice) so the caller can
// inspect samples without holding the mutex and without racing concurrent
// writes from a still-running goroutine. Always prefer this over direct
// access to m.latencies[...] in tests.
func (m *metricCapture) latencySamples(name string) []float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	src := m.latencies[name]
	out := make([]float64, len(src))
	copy(out, src)
	return out
}

func (m *metricCapture) counter(name string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counters[name]
}

// instrumentedHelper builds a plugin helper with metric captures wired
// in plus a knock callback. Mirrors the production NewHttpServerHelper
// shape; tests can swap the callback per scenario.
func instrumentedHelper(capture *metricCapture, knock plugins.HttpPluginPostAuthFunc) *plugins.HttpServerPluginHelper {
	return &plugins.HttpServerPluginHelper{
		AuthWithHttpCallbackFunc: knock,
		RecordLatency:            capture.recordLatency,
		IncrCounter:              capture.incrCounter,
	}
}

// startSuccessfulResolveServer returns an httptest server that mimics
// qurl-service /internal/v1/resolve answering with a fully-formed
// ResolveResponse. Caller is responsible for Close().
func startSuccessfulResolveServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(internalResolveResponse{
			Success: true,
			Data: &ResolveResponse{
				ResourceID:  "r_metrics_test",
				TargetURL:   "https://backend.example.com",
				QurlSiteURL: "https://r_metrics_test.qurl.site",
				Resources: map[string]*common.ResourceInfo{
					"default": {
						ACId:     "ac-001",
						Hostname: "backend.example.com",
						Addr:     &common.NetAddress{Ip: "10.0.0.1", Port: 443},
					},
				},
				JWTSecret:    "test-jwt-secret-key-for-signing",
				TokenExpire:  3600,
				OpenTime:     300,
				CookieDomain: ".qurl.site",
			},
		})
	}))
}

// withResolverPointingAt swaps the package-level resolver to talk to
// `baseURL` for the duration of the test. Restores the previous value
// via t.Cleanup so sequential tests don't leak state.
//
// NOT safe under t.Parallel(): the swap and the t.Cleanup restore
// race against any concurrent test that mutates the same package-level
// `resolver` (every Test* in this file does). Treat the package as
// serialized; a future contributor enabling t.Parallel() here must
// first hoist resolver into a per-test argument.
func withResolverPointingAt(t *testing.T, baseURL string) {
	t.Helper()
	old := resolver
	resolver = &QurlResolver{
		httpClient:            &http.Client{Timeout: 5 * time.Second},
		baseURL:               baseURL,
		serviceToken:          "test-service-token",
		allowedRedirectDomain: "qurl.site",
	}
	t.Cleanup(func() { resolver = old })
}

// formPostContext returns a gin context wired for a form-POST request
// to /plugins/qurl with the given token, ready for AuthWithHttp. Use
// formPostContextWithFields if extra form fields are needed alongside
// the token.
func formPostContext(token string) (*gin.Context, *httptest.ResponseRecorder) {
	return formPostContextWithFields(token, nil)
}

func TestAuthWithHttp_Metrics_SuccessPath(t *testing.T) {
	srv := startSuccessfulResolveServer(t)
	defer srv.Close()
	withResolverPointingAt(t, srv.URL)

	capture := newMetricCapture()
	helper := instrumentedHelper(capture, func(req *common.HttpKnockRequest, res *common.ResourceData) (*common.ServerKnockAckMsg, error) {
		return &common.ServerKnockAckMsg{
			ResourceHost: map[string]string{"default": "10.0.0.1:443"},
		}, nil
	})

	ctx, _ := formPostContext("valid_test_token_123")
	if _, err := AuthWithHttp(ctx, &common.HttpKnockRequest{}, helper); err != nil {
		t.Fatalf("AuthWithHttp: %v", err)
	}

	// Total + per-phase histograms each fire exactly once on the happy path.
	for _, name := range []string{
		nhpserver.MetricQurlResolveDurationMs,
		nhpserver.MetricQurlResolveTokenValidateMs,
		nhpserver.MetricQurlResolveKnockMs,
		nhpserver.MetricQurlResolveKnockAttemptMs,
	} {
		if got := capture.latencyCount(name); got != 1 {
			t.Errorf("%s: expected 1 sample, got %d", name, got)
		}
	}
	if got := capture.counter(nhpserver.MetricQurlResolveSuccess); got != 1 {
		t.Errorf("Success counter: want 1, got %d", got)
	}
	for _, name := range []string{
		nhpserver.MetricQurlResolveFailValidate,
		nhpserver.MetricQurlResolveFailKnock,
		nhpserver.MetricQurlResolveFailPostKnock,
		nhpserver.MetricQurlResolveFailCanceled,
		// FailUnknown is the sentinel default that catches return
		// paths missing an explicit outcome assignment. A non-zero
		// value on the success path would mean the success branch
		// regressed without this test noticing — exactly the
		// invariant this counter exists to fence.
		nhpserver.MetricQurlResolveFailUnknown,
		nhpserver.MetricQurlResolveKnockRetry,
	} {
		if got := capture.counter(name); got != 0 {
			t.Errorf("%s: want 0 (success path), got %d", name, got)
		}
	}
}

func TestAuthWithHttp_Metrics_TokenFormatRejected(t *testing.T) {
	// Invalid token format short-circuits before resolver.Resolve is
	// called, so the validate phase histogram MUST NOT fire — the
	// metric's purpose is to time the qurl-service RTT, not the
	// in-process character-class check.
	capture := newMetricCapture()
	helper := instrumentedHelper(capture, func(*common.HttpKnockRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) {
		t.Fatal("knock callback must not run when token format is rejected")
		return nil, nil
	})

	// '@' is outside ValidateAccessToken's permitted character class
	// (alphanumeric + - _ .), so format validation rejects this without
	// touching the package-level resolver.
	ctx, _ := formPostContext("invalid@token@chars")
	if _, err := AuthWithHttp(ctx, &common.HttpKnockRequest{}, helper); err == nil {
		t.Fatal("expected error from token format rejection")
	}

	if got := capture.latencyCount(nhpserver.MetricQurlResolveDurationMs); got != 1 {
		t.Errorf("Total duration: want 1, got %d", got)
	}
	if got := capture.latencyCount(nhpserver.MetricQurlResolveTokenValidateMs); got != 0 {
		t.Errorf("TokenValidateMs: want 0 (rejected before validate), got %d", got)
	}
	if got := capture.counter(nhpserver.MetricQurlResolveFailValidate); got != 1 {
		t.Errorf("FailValidate: want 1, got %d", got)
	}
	if got := capture.counter(nhpserver.MetricQurlResolveSuccess); got != 0 {
		t.Errorf("Success: want 0, got %d", got)
	}
}

func TestAuthWithHttp_Metrics_ResolverError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"success":false,"error":{"code":"INTERNAL_ERROR","message":"boom"}}`))
	}))
	defer srv.Close()
	withResolverPointingAt(t, srv.URL)

	capture := newMetricCapture()
	helper := instrumentedHelper(capture, func(*common.HttpKnockRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) {
		t.Fatal("knock callback must not run when resolver fails")
		return nil, nil
	})

	ctx, _ := formPostContext("valid_test_token_123")
	if _, err := AuthWithHttp(ctx, &common.HttpKnockRequest{}, helper); err == nil {
		t.Fatal("expected resolver error to propagate")
	}

	// Validate phase DID run (the RTT to qurl-service happened); it
	// just produced an error. The histogram must capture that — the
	// p99 panel is meaningless without the failure tail.
	if got := capture.latencyCount(nhpserver.MetricQurlResolveTokenValidateMs); got != 1 {
		t.Errorf("TokenValidateMs: want 1 (must record on resolver failure), got %d", got)
	}
	if got := capture.latencyCount(nhpserver.MetricQurlResolveKnockMs); got != 0 {
		t.Errorf("KnockMs: want 0 (knock never reached), got %d", got)
	}
	if got := capture.counter(nhpserver.MetricQurlResolveFailValidate); got != 1 {
		t.Errorf("FailValidate: want 1, got %d", got)
	}
}

func TestAuthWithHttp_Metrics_KnockRetryThenSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping retry test under -short (sleeps for knockRetryDelay)")
	}
	srv := startSuccessfulResolveServer(t)
	defer srv.Close()
	withResolverPointingAt(t, srv.URL)

	capture := newMetricCapture()
	var attempts int
	helper := instrumentedHelper(capture, func(*common.HttpKnockRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) {
		attempts++
		if attempts == 1 {
			return nil, errors.New("simulated AC connection closed")
		}
		return &common.ServerKnockAckMsg{ResourceHost: map[string]string{"default": "10.0.0.1:443"}}, nil
	})

	ctx, _ := formPostContext("valid_test_token_123")
	if _, err := AuthWithHttp(ctx, &common.HttpKnockRequest{}, helper); err != nil {
		t.Fatalf("expected success after one retry, got %v", err)
	}

	// Two attempts → two attempt-latency samples; one retry decision.
	if got := capture.latencyCount(nhpserver.MetricQurlResolveKnockAttemptMs); got != 2 {
		t.Errorf("KnockAttemptMs samples: want 2, got %d", got)
	}
	if got := capture.counter(nhpserver.MetricQurlResolveKnockRetry); got != 1 {
		t.Errorf("KnockRetry: want 1 (one retry decision before second attempt succeeded), got %d", got)
	}
	if got := capture.counter(nhpserver.MetricQurlResolveSuccess); got != 1 {
		t.Errorf("Success: want 1, got %d", got)
	}

	// Total knock time MUST include the 2-second retry sleep — that's
	// the operationally interesting figure (the user's wall-clock cost).
	// Stronger invariant: KnockMs >= Σ KnockAttemptMs + knockRetryDelay.
	// That's the *exact* shape the metric definition encodes — it's what
	// would break if a future "optimization" hoisted recordLatency(KnockMs,
	// ...) inside the for-loop, or skipped recording the retry sleep, or
	// double-counted attempts. Asserting the floor catches every one of
	// those regressions at the test, not in production.
	knockSamples := capture.latencySamples(nhpserver.MetricQurlResolveKnockMs)
	if len(knockSamples) != 1 {
		t.Fatalf("KnockMs: want 1 sample, got %d", len(knockSamples))
	}
	if knockSamples[0] < float64(knockRetryDelay.Milliseconds()) {
		t.Errorf("KnockMs (%v ms) must include the retry sleep (%v ms) — that's the whole point of the metric",
			knockSamples[0], knockRetryDelay.Milliseconds())
	}
	attemptSamples := capture.latencySamples(nhpserver.MetricQurlResolveKnockAttemptMs)
	var sumAttempts float64
	for _, s := range attemptSamples {
		sumAttempts += s
	}
	floor := sumAttempts + float64(knockRetryDelay.Milliseconds())
	if knockSamples[0] < floor {
		t.Errorf("KnockMs (%v ms) must be >= sum(KnockAttemptMs) (%v ms) + knockRetryDelay (%v ms) = %v ms — that invariant is the whole metric definition",
			knockSamples[0], sumAttempts, knockRetryDelay.Milliseconds(), floor)
	}
}

func TestAuthWithHttp_Metrics_KnockExhausted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping retry-exhaustion test under -short (sleeps for knockRetryDelay × 2)")
	}
	srv := startSuccessfulResolveServer(t)
	defer srv.Close()
	withResolverPointingAt(t, srv.URL)

	capture := newMetricCapture()
	helper := instrumentedHelper(capture, func(*common.HttpKnockRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) {
		return nil, errors.New("simulated permanent AC failure")
	})

	ctx, _ := formPostContext("valid_test_token_123")
	if _, err := AuthWithHttp(ctx, &common.HttpKnockRequest{}, helper); err == nil {
		t.Fatal("expected error after exhausting retries")
	}

	// 3 attempts, 2 retry decisions (after attempt 1 and 2; attempt 3
	// fails-and-falls-through, no retry decision).
	if got := capture.latencyCount(nhpserver.MetricQurlResolveKnockAttemptMs); got != knockMaxAttempts {
		t.Errorf("KnockAttemptMs samples: want %d, got %d", knockMaxAttempts, got)
	}
	if got := capture.counter(nhpserver.MetricQurlResolveKnockRetry); got != knockMaxAttempts-1 {
		t.Errorf("KnockRetry: want %d, got %d", knockMaxAttempts-1, got)
	}
	if got := capture.counter(nhpserver.MetricQurlResolveFailKnock); got != 1 {
		t.Errorf("FailKnock: want 1, got %d", got)
	}
	if got := capture.counter(nhpserver.MetricQurlResolveSuccess); got != 0 {
		t.Errorf("Success: want 0, got %d", got)
	}
}

func TestAuthWithHttp_Metrics_PostKnockRejected(t *testing.T) {
	// FailPostKnock has two branches in main.go: cookieErr and
	// redirectErr. Both must record FailPostKnock — a regression in
	// either ValidateCookieDomain or ValidateRedirectURL would slip
	// past a single-branch test, since both paths share the outcome
	// label. Parametric subtest covers both.
	makeResolveSrv := func(qurlSiteURL, cookieDomain string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(internalResolveResponse{
				Success: true,
				Data: &ResolveResponse{
					ResourceID:  "r_pk",
					TargetURL:   "https://backend.example.com",
					QurlSiteURL: qurlSiteURL,
					Resources: map[string]*common.ResourceInfo{
						"default": {ACId: "ac-001", Hostname: "h", Addr: &common.NetAddress{Ip: "10.0.0.1", Port: 443}},
					},
					JWTSecret:    "test-jwt-secret-key-for-signing",
					TokenExpire:  3600,
					OpenTime:     300,
					CookieDomain: cookieDomain,
				},
			})
		}))
	}
	cases := []struct {
		name         string
		qurlSiteURL  string
		cookieDomain string
	}{
		{
			name:         "redirect_url_rejected",
			qurlSiteURL:  "http://attacker.example.com", // refused: not HTTPS, wrong domain
			cookieDomain: ".qurl.site",
		},
		{
			name:         "cookie_domain_rejected",
			qurlSiteURL:  "https://r_ok.qurl.site",
			cookieDomain: ".attacker.example.com", // refused: not under allowedRedirectDomain
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := makeResolveSrv(tc.qurlSiteURL, tc.cookieDomain)
			defer srv.Close()
			withResolverPointingAt(t, srv.URL)

			capture := newMetricCapture()
			helper := instrumentedHelper(capture, func(*common.HttpKnockRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) {
				return &common.ServerKnockAckMsg{ResourceHost: map[string]string{"default": "10.0.0.1:443"}}, nil
			})

			ctx, _ := formPostContext("valid_test_token_123")
			if _, err := AuthWithHttp(ctx, &common.HttpKnockRequest{}, helper); err == nil {
				t.Fatal("expected validation to fail")
			}

			if got := capture.counter(nhpserver.MetricQurlResolveFailPostKnock); got != 1 {
				t.Errorf("FailPostKnock: want 1, got %d", got)
			}
			if got := capture.counter(nhpserver.MetricQurlResolveFailKnock); got != 0 {
				t.Errorf("FailKnock: want 0 (knock succeeded), got %d", got)
			}
			if got := capture.counter(nhpserver.MetricQurlResolveSuccess); got != 0 {
				t.Errorf("Success: want 0, got %d", got)
			}
			if got := capture.counter(nhpserver.MetricQurlResolveFailUnknown); got != 0 {
				t.Errorf("FailUnknown: want 0 (terminal outcome was set), got %d", got)
			}
			// The knock phase still fired — the firewall hole is open
			// even though the user can't be redirected. Operators need
			// that signal to know whether to also revoke the AC ipset
			// entry.
			if got := capture.latencyCount(nhpserver.MetricQurlResolveKnockMs); got != 1 {
				t.Errorf("KnockMs: want 1 (knock did succeed), got %d", got)
			}
		})
	}
}

func TestAuthWithHttp_Metrics_EmptyJWTSecretIsPostKnock(t *testing.T) {
	// Companion jwt.GenerateAll-error branch is structurally untestable
	// from outside (HS256 SignedString does not fail on any byte slice);
	// the FailUnknown sentinel fences regressions on that branch in prod.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(internalResolveResponse{
			Success: true,
			Data: &ResolveResponse{
				ResourceID:  "r_nojwt",
				TargetURL:   "https://backend.example.com",
				QurlSiteURL: "https://r_nojwt.qurl.site",
				Resources: map[string]*common.ResourceInfo{
					"default": {ACId: "ac-001", Hostname: "h", Addr: &common.NetAddress{Ip: "10.0.0.1", Port: 443}},
				},
				JWTSecret:    "", // ← triggers the configuration_error post-knock branch
				TokenExpire:  3600,
				OpenTime:     300,
				CookieDomain: ".qurl.site",
			},
		})
	}))
	defer srv.Close()
	withResolverPointingAt(t, srv.URL)

	capture := newMetricCapture()
	helper := instrumentedHelper(capture, func(*common.HttpKnockRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) {
		return &common.ServerKnockAckMsg{ResourceHost: map[string]string{"default": "10.0.0.1:443"}}, nil
	})

	ctx, _ := formPostContext("valid_test_token_123")
	if _, err := AuthWithHttp(ctx, &common.HttpKnockRequest{}, helper); err == nil {
		t.Fatal("expected error on empty JWT secret")
	}

	if got := capture.counter(nhpserver.MetricQurlResolveFailPostKnock); got != 1 {
		t.Errorf("FailPostKnock: want 1, got %d", got)
	}
	if got := capture.counter(nhpserver.MetricQurlResolveFailKnock); got != 0 {
		t.Errorf("FailKnock: want 0 (knock succeeded; this branch is post-knock), got %d", got)
	}
	if got := capture.counter(nhpserver.MetricQurlResolveFailUnknown); got != 0 {
		t.Errorf("FailUnknown: want 0 (terminal outcome was set), got %d", got)
	}
	// Knock succeeded → KnockMs sample must exist (the firewall hole
	// is open even though the user can't be redirected; operators need
	// the signal to know whether to revoke the AC ipset entry).
	if got := capture.latencyCount(nhpserver.MetricQurlResolveKnockMs); got != 1 {
		t.Errorf("KnockMs: want 1 (knock did succeed), got %d", got)
	}
}

func TestAuthWithHttp_Metrics_NoResourceHostsIsPostKnock(t *testing.T) {
	// "Knock returned no resource hosts" is operationally a post-knock
	// failure: helper.AuthWithHttpCallbackFunc returned err==nil, the
	// retry loop broke without exhausting attempts, and the AC opened
	// the firewall — but ackMsg.ResourceHost is empty so there's no
	// host to redirect to. Counting this as FailKnock would deflate the
	// retry-rate denominator (Success+FailKnock) by adding calls that
	// never exercised the retry policy. Belongs in FailPostKnock.
	srv := startSuccessfulResolveServer(t)
	defer srv.Close()
	withResolverPointingAt(t, srv.URL)

	capture := newMetricCapture()
	helper := instrumentedHelper(capture, func(*common.HttpKnockRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) {
		// Empty ResourceHost map → triggers the no-hosts post-knock
		// branch in main.go.
		return &common.ServerKnockAckMsg{ResourceHost: map[string]string{}}, nil
	})

	ctx, _ := formPostContext("valid_test_token_123")
	if _, err := AuthWithHttp(ctx, &common.HttpKnockRequest{}, helper); err == nil {
		t.Fatal("expected error on empty resource hosts")
	}

	if got := capture.counter(nhpserver.MetricQurlResolveFailPostKnock); got != 1 {
		t.Errorf("FailPostKnock: want 1, got %d", got)
	}
	if got := capture.counter(nhpserver.MetricQurlResolveFailKnock); got != 0 {
		t.Errorf("FailKnock: want 0 (knock loop succeeded; this branch is post-knock), got %d", got)
	}
	if got := capture.counter(nhpserver.MetricQurlResolveKnockRetry); got != 0 {
		t.Errorf("KnockRetry: want 0 (no retry decision was made), got %d", got)
	}
	// One attempt latency sample, one knock-total sample — the loop
	// broke on the first success, so the retry policy never ran.
	if got := capture.latencyCount(nhpserver.MetricQurlResolveKnockAttemptMs); got != 1 {
		t.Errorf("KnockAttemptMs samples: want 1, got %d", got)
	}
}

func TestAuthWithHttp_Metrics_KnockCanceledMidRetry(t *testing.T) {
	srv := startSuccessfulResolveServer(t)
	defer srv.Close()
	withResolverPointingAt(t, srv.URL)

	ctx, _ := formPostContext("valid_test_token_123")
	reqCtx, cancel := context.WithCancel(ctx.Request.Context())
	// defer cancel() satisfies go vet's lostcancel pass; in practice the
	// helper callback below fires it before AuthWithHttp returns, so
	// this defer is a no-op on the happy path.
	defer cancel()
	ctx.Request = ctx.Request.WithContext(reqCtx)

	// Synchronize the cancel call with the first knock attempt rather
	// than racing time.Sleep against the goroutine scheduler. Firing
	// cancel() from inside the callback guarantees:
	//   - resolver.Resolve has already completed (so the validate phase
	//     can't see a canceled context and short-circuit to FailValidate)
	//   - the loop is about to enter the retry-delay select, where
	//     reqCtx.Done() will deterministically win the race against
	//     time.After(knockRetryDelay)
	// Replaces a previous time.Sleep(150ms)-based version that flaked
	// on contended CI runners (GitHub Actions hosted runners can pause
	// goroutines for 200+ms under load, sometimes pushing the cancel
	// outside the retry-delay window).
	capture := newMetricCapture()
	var attempts int32
	helper := instrumentedHelper(capture, func(*common.HttpKnockRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) {
		if atomic.AddInt32(&attempts, 1) == 1 {
			cancel()
		}
		return nil, errors.New("simulated knock failure")
	})

	if _, err := AuthWithHttp(ctx, &common.HttpKnockRequest{}, helper); err == nil {
		t.Fatal("expected error after cancel")
	}

	if got := capture.counter(nhpserver.MetricQurlResolveFailCanceled); got != 1 {
		t.Errorf("FailCanceled: want 1, got %d", got)
	}
	if got := capture.counter(nhpserver.MetricQurlResolveFailKnock); got != 0 {
		t.Errorf("FailKnock: want 0 (cancel is downstream of user, not server fault), got %d", got)
	}
	if got := capture.counter(nhpserver.MetricQurlResolveFailUnknown); got != 0 {
		t.Errorf("FailUnknown: want 0 (terminal outcome was set), got %d", got)
	}
	// KnockRetry must still fire on the retry decision before cancel
	// landed — the server DID decide to retry; the user just gave up
	// before the retry could run. Without this, FailCanceled would
	// disappear from the operational picture entirely.
	if got := capture.counter(nhpserver.MetricQurlResolveKnockRetry); got < 1 {
		t.Errorf("KnockRetry: want ≥1 (retry decision happened before cancel), got %d", got)
	}
}

func TestAuthWithHttp_Metrics_NilCallbacksDoNotPanic(t *testing.T) {
	// When the host server is started without a metrics publisher
	// (tests, dev), NewHttpServerHelper leaves RecordLatency and
	// IncrCounter nil. AuthWithHttp must remain functional — observability
	// is best-effort.
	srv := startSuccessfulResolveServer(t)
	defer srv.Close()
	withResolverPointingAt(t, srv.URL)

	helper := &plugins.HttpServerPluginHelper{
		AuthWithHttpCallbackFunc: func(*common.HttpKnockRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) {
			return &common.ServerKnockAckMsg{ResourceHost: map[string]string{"default": "10.0.0.1:443"}}, nil
		},
		// RecordLatency and IncrCounter intentionally nil.
	}

	ctx, _ := formPostContext("valid_test_token_123")
	if _, err := AuthWithHttp(ctx, &common.HttpKnockRequest{}, helper); err != nil {
		t.Fatalf("AuthWithHttp must not depend on metric callbacks: %v", err)
	}
}

// formPostContextWithFields is a sibling of formPostContext that lets a
// browser-timing test attach extra hidden form fields alongside the
// token. Keys and values are URL-encoded so any future test value can
// include '&', '=', '+', '%', or non-ASCII bytes without corrupting
// the wire form.
func formPostContextWithFields(token string, extras map[string]string) (*gin.Context, *httptest.ResponseRecorder) {
	v := url.Values{"token": {token}}
	for k, val := range extras {
		v.Set(k, val)
	}
	body := v.Encode()
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/plugins/qurl", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return ctx, w
}

func TestAuthWithHttp_BrowserTimings_AllFieldsValid(t *testing.T) {
	srv := startSuccessfulResolveServer(t)
	defer srv.Close()
	withResolverPointingAt(t, srv.URL)

	capture := newMetricCapture()
	helper := instrumentedHelper(capture, func(*common.HttpKnockRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) {
		return &common.ServerKnockAckMsg{ResourceHost: map[string]string{"default": "10.0.0.1:443"}}, nil
	})

	ctx, _ := formPostContextWithFields("valid_test_token_123", map[string]string{
		"t_dns_ms":             "12.5",
		"t_tcp_ms":             "45",
		"t_tls_ms":             "90",
		"t_ttfb_ms":            "250",
		"t_dom_interactive_ms": "480",
		"t_to_submit_ms":       "1100",
	})
	if _, err := AuthWithHttp(ctx, &common.HttpKnockRequest{}, helper); err != nil {
		t.Fatalf("AuthWithHttp: %v", err)
	}

	for _, name := range []string{
		nhpserver.MetricQurlResolveBrowserDNSMs,
		nhpserver.MetricQurlResolveBrowserTCPMs,
		nhpserver.MetricQurlResolveBrowserTLSMs,
		nhpserver.MetricQurlResolveBrowserTTFBMs,
		nhpserver.MetricQurlResolveBrowserDOMInteractiveMs,
		nhpserver.MetricQurlResolveBrowserTimeToSubmitMs,
	} {
		if got := capture.latencyCount(name); got != 1 {
			t.Errorf("%s: want 1 sample, got %d", name, got)
		}
	}
	for _, name := range []string{
		nhpserver.MetricQurlResolveBrowserRejectedMalformed,
		nhpserver.MetricQurlResolveBrowserRejectedOutOfRange,
	} {
		if got := capture.counter(name); got != 0 {
			t.Errorf("%s: want 0 (all values valid), got %d", name, got)
		}
	}
}

func TestAuthWithHttp_BrowserTimings_AbsentFieldsSkipped(t *testing.T) {
	// Older browsers may not surface every PerformanceNavigationTiming
	// entry. Absent fields must be skipped silently — no rejected
	// counter, no histogram observation. Only 0 ms observations would
	// distort the p* tail, and we have no signal to send.
	srv := startSuccessfulResolveServer(t)
	defer srv.Close()
	withResolverPointingAt(t, srv.URL)

	capture := newMetricCapture()
	helper := instrumentedHelper(capture, func(*common.HttpKnockRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) {
		return &common.ServerKnockAckMsg{ResourceHost: map[string]string{"default": "10.0.0.1:443"}}, nil
	})

	// Send only DNS and TTFB; the rest are absent.
	ctx, _ := formPostContextWithFields("valid_test_token_123", map[string]string{
		"t_dns_ms":  "15",
		"t_ttfb_ms": "200",
	})
	if _, err := AuthWithHttp(ctx, &common.HttpKnockRequest{}, helper); err != nil {
		t.Fatalf("AuthWithHttp: %v", err)
	}

	if got := capture.latencyCount(nhpserver.MetricQurlResolveBrowserDNSMs); got != 1 {
		t.Errorf("DNS: want 1, got %d", got)
	}
	if got := capture.latencyCount(nhpserver.MetricQurlResolveBrowserTTFBMs); got != 1 {
		t.Errorf("TTFB: want 1, got %d", got)
	}
	for _, name := range []string{
		nhpserver.MetricQurlResolveBrowserTCPMs,
		nhpserver.MetricQurlResolveBrowserTLSMs,
		nhpserver.MetricQurlResolveBrowserDOMInteractiveMs,
		nhpserver.MetricQurlResolveBrowserTimeToSubmitMs,
	} {
		if got := capture.latencyCount(name); got != 0 {
			t.Errorf("%s: want 0 (absent → no observation), got %d", name, got)
		}
	}
	if got := capture.counter(nhpserver.MetricQurlResolveBrowserRejectedMalformed); got != 0 {
		t.Errorf("RejectedMalformed: want 0 (absent != malformed), got %d", got)
	}
}

func TestAuthWithHttp_BrowserTimings_RejectsMalformedAndOutOfRange(t *testing.T) {
	// Adversarial / corrupted browsers must NOT contaminate the
	// histogram tail. Out-of-range and unparseable values are dropped
	// AND counted on the corresponding rejected counter so the pattern
	// is observable in dashboards.
	srv := startSuccessfulResolveServer(t)
	defer srv.Close()
	withResolverPointingAt(t, srv.URL)

	capture := newMetricCapture()
	helper := instrumentedHelper(capture, func(*common.HttpKnockRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) {
		return &common.ServerKnockAckMsg{ResourceHost: map[string]string{"default": "10.0.0.1:443"}}, nil
	})

	ctx, _ := formPostContextWithFields("valid_test_token_123", map[string]string{
		"t_dns_ms":             "NaN",      // → malformed (ParseFloat succeeds; explicit NaN guard catches it)
		"t_tcp_ms":             "-1",       // → out of range (negative)
		"t_tls_ms":             "120000",   // → out of range (above 60s cap)
		"t_ttfb_ms":            "250",      // ✓ valid; should still emit
		"t_dom_interactive_ms": "Infinity", // → out of range (+Inf > 60000)
		"t_to_submit_ms":       "1100",     // ✓ valid; should still emit
	})
	if _, err := AuthWithHttp(ctx, &common.HttpKnockRequest{}, helper); err != nil {
		t.Fatalf("AuthWithHttp: %v", err)
	}

	// Only the two valid fields produce histogram observations.
	if got := capture.latencyCount(nhpserver.MetricQurlResolveBrowserTTFBMs); got != 1 {
		t.Errorf("TTFB (valid): want 1, got %d", got)
	}
	if got := capture.latencyCount(nhpserver.MetricQurlResolveBrowserTimeToSubmitMs); got != 1 {
		t.Errorf("TimeToSubmit (valid): want 1, got %d", got)
	}
	for _, name := range []string{
		nhpserver.MetricQurlResolveBrowserDNSMs,
		nhpserver.MetricQurlResolveBrowserTCPMs,
		nhpserver.MetricQurlResolveBrowserTLSMs,
		nhpserver.MetricQurlResolveBrowserDOMInteractiveMs,
	} {
		if got := capture.latencyCount(name); got != 0 {
			t.Errorf("%s: want 0 (rejected), got %d", name, got)
		}
	}

	// Rejected counters: NaN takes the malformed bucket via the explicit
	// NaN guard in recordBrowserTimings — without that guard, NaN would
	// slip both range gates (every NaN comparison is false in IEEE 754)
	// and contaminate the histogram. Negative, above-cap, and +Inf all
	// trip the range gate; +Inf is permitted by ParseFloat ("Infinity"
	// parses to +math.Inf(1)) so it lands in out_of_range.
	// Direct equality on each bucket — pins the routing decision
	// (NaN → malformed; negative / over-cap / +Inf → out-of-range)
	// rather than the totals. A future change that misroutes one
	// bucket would silently pass a sum-only assertion.
	if got := capture.counter(nhpserver.MetricQurlResolveBrowserRejectedMalformed); got != 1 {
		t.Errorf("RejectedMalformed: want 1 (NaN guard), got %d", got)
	}
	if got := capture.counter(nhpserver.MetricQurlResolveBrowserRejectedOutOfRange); got != 3 {
		t.Errorf("RejectedOutOfRange: want 3 (-1, 120000, +Inf), got %d", got)
	}
}

func TestAuthWithHttp_BrowserTimings_NotRecordedWhenTokenFormatRejected(t *testing.T) {
	// Token-format-invalid is rejected before timing parse; this fences
	// the trust-model property that random scanners hitting /plugins/qurl
	// can't poison the histograms. ValidateAccessToken's character class
	// rejects '@', so this token never reaches recordBrowserTimings.
	capture := newMetricCapture()
	helper := instrumentedHelper(capture, func(*common.HttpKnockRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) {
		t.Fatal("knock callback must not run when token format is rejected")
		return nil, nil
	})

	ctx, _ := formPostContextWithFields("invalid@token@chars", map[string]string{
		"t_dns_ms": "12",
	})
	if _, err := AuthWithHttp(ctx, &common.HttpKnockRequest{}, helper); err == nil {
		t.Fatal("expected error from token format rejection")
	}

	if got := capture.latencyCount(nhpserver.MetricQurlResolveBrowserDNSMs); got != 0 {
		t.Errorf("BrowserDNSMs: want 0 (parse runs only after token format gate), got %d", got)
	}
	// Stronger fence: the rejected counters must also stay at 0. A
	// non-zero value would mean recordBrowserTimings ran (and rejected
	// fields), which would mean the token-format gate failed to short-
	// circuit — exactly the regression this test exists to fence.
	for _, name := range []string{
		nhpserver.MetricQurlResolveBrowserRejectedMalformed,
		nhpserver.MetricQurlResolveBrowserRejectedOutOfRange,
	} {
		if got := capture.counter(name); got != 0 {
			t.Errorf("%s: want 0 (recordBrowserTimings must not run before format gate), got %d", name, got)
		}
	}
}

func TestAuthWithHttp_BrowserTimings_ZeroIsRecorded(t *testing.T) {
	// Pin the server-side permissive zero behavior. The frontend
	// contract (msghandler.go::QurlResolveBrowser*) requires omitting
	// absent phases rather than sending 0 — but the server treats
	// an explicit "0" as a structurally valid measurement. A future
	// change adding a server-side `ms <= 0` reject would silently
	// distort the cohort distinction (cache-hit honest=0 vs
	// frontend-bug-emitted 0) by collapsing both into the rejected
	// counter; this test fences against that.
	srv := startSuccessfulResolveServer(t)
	defer srv.Close()
	withResolverPointingAt(t, srv.URL)

	capture := newMetricCapture()
	helper := instrumentedHelper(capture, func(*common.HttpKnockRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) {
		return &common.ServerKnockAckMsg{ResourceHost: map[string]string{"default": "10.0.0.1:443"}}, nil
	})

	ctx, _ := formPostContextWithFields("valid_test_token_123", map[string]string{
		"t_dns_ms": "0",
	})
	if _, err := AuthWithHttp(ctx, &common.HttpKnockRequest{}, helper); err != nil {
		t.Fatalf("AuthWithHttp: %v", err)
	}

	samples := capture.latencySamples(nhpserver.MetricQurlResolveBrowserDNSMs)
	if len(samples) != 1 || samples[0] != 0 {
		t.Errorf("DNS sample: want [0], got %v (server is intentionally permissive on 0)", samples)
	}
	for _, name := range []string{
		nhpserver.MetricQurlResolveBrowserRejectedMalformed,
		nhpserver.MetricQurlResolveBrowserRejectedOutOfRange,
	} {
		if got := capture.counter(name); got != 0 {
			t.Errorf("%s: want 0 (0 is structurally allowed), got %d", name, got)
		}
	}
}

func TestAuthWithHttp_BrowserTimings_OverlongFieldRejected(t *testing.T) {
	// Defense-in-depth: a raw form value longer than
	// browserTimingMaxFieldLen (32) is rejected as malformed before
	// reaching strconv.ParseFloat. Bounds ParseFloat's digit-grinding
	// cost on adversarial input independent of the request-level body
	// cap (#1839). 100 digits of "9" parses cleanly to a finite float
	// today, so this test fences the *length* check, not a parse-error
	// fallback.
	srv := startSuccessfulResolveServer(t)
	defer srv.Close()
	withResolverPointingAt(t, srv.URL)

	capture := newMetricCapture()
	helper := instrumentedHelper(capture, func(*common.HttpKnockRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) {
		return &common.ServerKnockAckMsg{ResourceHost: map[string]string{"default": "10.0.0.1:443"}}, nil
	})

	overlong := strings.Repeat("9", 100)
	ctx, _ := formPostContextWithFields("valid_test_token_123", map[string]string{
		"t_dns_ms": overlong,
	})
	if _, err := AuthWithHttp(ctx, &common.HttpKnockRequest{}, helper); err != nil {
		t.Fatalf("AuthWithHttp: %v", err)
	}

	if got := capture.latencyCount(nhpserver.MetricQurlResolveBrowserDNSMs); got != 0 {
		t.Errorf("DNS samples: want 0 (overlong rejected pre-parse), got %d", got)
	}
	if got := capture.counter(nhpserver.MetricQurlResolveBrowserRejectedMalformed); got != 1 {
		t.Errorf("RejectedMalformed: want 1 (overlong field), got %d", got)
	}
	if got := capture.counter(nhpserver.MetricQurlResolveBrowserRejectedOutOfRange); got != 0 {
		t.Errorf("RejectedOutOfRange: want 0 (length check fires before range check), got %d", got)
	}
}

func TestAuthWithHttp_BrowserTimings_DuplicateKeys_FirstValueWins(t *testing.T) {
	// Pin gin.Context.PostForm's "first value wins" behavior on
	// duplicate keys. A buggy / adversarial client sending
	// t_dns_ms=10&t_dns_ms=NaN must record 10 (valid sample) and
	// silently drop the NaN. The attacker gains nothing — sending NaN
	// alone would have been caught by the NaN guard — but documenting
	// the deduplication behavior in code prevents a future gin upgrade
	// or framework swap from silently flipping the semantics.
	srv := startSuccessfulResolveServer(t)
	defer srv.Close()
	withResolverPointingAt(t, srv.URL)

	capture := newMetricCapture()
	helper := instrumentedHelper(capture, func(*common.HttpKnockRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) {
		return &common.ServerKnockAckMsg{ResourceHost: map[string]string{"default": "10.0.0.1:443"}}, nil
	})

	// url.Values is the wire-correct way to build a multi-value field.
	// formPostContextWithFields takes a map[string]string which can't
	// express duplicates, so build the body inline here.
	body := "token=valid_test_token_123&t_dns_ms=10&t_dns_ms=NaN"
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/plugins/qurl", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if _, err := AuthWithHttp(ctx, &common.HttpKnockRequest{}, helper); err != nil {
		t.Fatalf("AuthWithHttp: %v", err)
	}

	// First value (10) emitted; NaN second value silently dropped.
	if got := capture.latencyCount(nhpserver.MetricQurlResolveBrowserDNSMs); got != 1 {
		t.Errorf("DNSMs: want 1 (first value=10 wins), got %d", got)
	}
	samples := capture.latencySamples(nhpserver.MetricQurlResolveBrowserDNSMs)
	if len(samples) != 1 || samples[0] != 10 {
		t.Errorf("DNSMs sample: want [10], got %v", samples)
	}
	// The NaN second value never reached the parse path, so the
	// rejected counter must stay at 0. A non-zero value would indicate
	// gin started enumerating duplicate keys (semantic change).
	if got := capture.counter(nhpserver.MetricQurlResolveBrowserRejectedMalformed); got != 0 {
		t.Errorf("RejectedMalformed: want 0 (duplicate-key NaN never parsed), got %d", got)
	}
}

func TestAuthWithHttp_BrowserTimings_BoundaryAtCap(t *testing.T) {
	// Pin the inclusive/exclusive choice at the 60s cap. The current
	// gate is `ms > browserTimingMaxMs` (exclusive), so 60000 must
	// emit and 60000.001 must reject. A future refactor flipping `>`
	// to `>=` would silently shift behavior at the boundary; this test
	// fences against that.
	srv := startSuccessfulResolveServer(t)
	defer srv.Close()
	withResolverPointingAt(t, srv.URL)

	cases := []struct {
		name             string
		value            string
		expectAccepted   bool
		expectOutOfRange int
	}{
		{name: "exactly_zero", value: "0", expectAccepted: true, expectOutOfRange: 0},
		{name: "just_below_zero", value: "-0.001", expectAccepted: false, expectOutOfRange: 1},
		{name: "exactly_at_cap", value: "60000", expectAccepted: true, expectOutOfRange: 0},
		{name: "one_us_over_cap", value: "60000.001", expectAccepted: false, expectOutOfRange: 1},
		// ±Inf routing pins the deliberate decision: ParseFloat parses
		// "Infinity" / "-Infinity" cleanly, and we route them to
		// out_of_range (not malformed) because the value is a parsed
		// number, just outside the cap. A future change routing Inf
		// to malformed would fail these rows.
		{name: "positive_infinity", value: "Infinity", expectAccepted: false, expectOutOfRange: 1},
		{name: "negative_infinity", value: "-Infinity", expectAccepted: false, expectOutOfRange: 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			capture := newMetricCapture()
			helper := instrumentedHelper(capture, func(*common.HttpKnockRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error) {
				return &common.ServerKnockAckMsg{ResourceHost: map[string]string{"default": "10.0.0.1:443"}}, nil
			})

			ctx, _ := formPostContextWithFields("valid_test_token_123", map[string]string{
				"t_dns_ms": tc.value,
			})
			if _, err := AuthWithHttp(ctx, &common.HttpKnockRequest{}, helper); err != nil {
				t.Fatalf("AuthWithHttp: %v", err)
			}

			wantSamples := 0
			if tc.expectAccepted {
				wantSamples = 1
			}
			if got := capture.latencyCount(nhpserver.MetricQurlResolveBrowserDNSMs); got != wantSamples {
				t.Errorf("DNSMs samples: want %d, got %d", wantSamples, got)
			}
			if got := capture.counter(nhpserver.MetricQurlResolveBrowserRejectedOutOfRange); got != tc.expectOutOfRange {
				t.Errorf("RejectedOutOfRange: want %d, got %d", tc.expectOutOfRange, got)
			}
		})
	}
}
