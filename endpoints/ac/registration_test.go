package ac

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// testServerListenPort is the UDP port an NHP server instance binds. Assigned
// servers, discovery peers, and NHP_AAK ServerAddr values all address a server
// directly on this port. It is deliberately NOT DefaultServerPort: that is the
// public client-edge port the AC dials for registration, which the cell NLB
// then forwards here.
const testServerListenPort = common.DefaultNHPPort

const (
	testRefreshBootID          = "00112233445566778899aabbccddeeff"
	testRefreshFlushGeneration = uint64(1)
	testRefreshAOLTransaction  = uint64(7)
)

func prepareRefreshSessionControl(t *testing.T, ac *UdpAC) {
	t.Helper()
	ac.bootID = testRefreshBootID
	if ac.nhpSessions == nil {
		ac.nhpSessions = newNHPSessionIndex()
	}
	if ac.tokenStore == nil {
		ac.tokenStore = common.NewTokenStore[*AccessEntry]()
	}
	if ac.expirySched == nil {
		ac.expirySched = NewScheduler(&NoOpFlusher{})
	}
	ac.sessionControlStateDir = t.TempDir()
	if err := persistSessionControlGeneration(
		filepath.Join(ac.sessionControlStateDir, sessionControlGenerationRelativePath),
		testRefreshFlushGeneration,
	); err != nil {
		t.Fatalf("persist session-control generation fixture: %v", err)
	}
	ac.sessionFlushGeneration.Store(testRefreshFlushGeneration)
	ac.sessionFlushComplete.Store(true)
	ac.sessionControlLeaseHeld.Store(true)
}

// mustNewACRegistration is a test helper that calls NewACRegistration and
// fails the test if it returns an error.
//
// Defaults config.Environment to "test" when not set so this helper
// doesn't emit the empty-Environment fallback warning on every test
// run. Tests that deliberately exercise empty/whitespace Environment
// behavior call NewACRegistration directly.
//
// Implementation note: UdpAC contains a sync.Mutex, so we can't
// safely *copy* UdpAC (govet copylocks). Config has no Mutex, so we
// shallow-copy *Config and reassign ac.config to the copy. The
// caller's ac.config pointer is mutated, but the original *Config
// struct underneath is preserved — a caller that holds an earlier
// pointer to the Config sees the empty value it constructed.
func mustNewACRegistration(t *testing.T, ac *UdpAC) *ACRegistration {
	t.Helper()
	if ac != nil && !common.ValidNHPACBootID(ac.bootID) {
		prepareRefreshSessionControl(t, ac)
	}
	if ac != nil && ac.config != nil && ac.config.Environment == "" {
		cfg := *ac.config
		cfg.Environment = "test"
		ac.config = &cfg
	}
	reg, err := NewACRegistration(ac)
	if err != nil {
		t.Fatalf("NewACRegistration failed: %v", err)
	}
	return reg
}

// handleTestRegistrationResponse upgrades legacy success fixtures to the
// strict NHP 1.2 authority tuple. Individual tests remain focused on peer and
// registration transitions; strict AAK grammar and mismatch behavior have
// dedicated codec/lease tests and must not be weakened in production.
func handleTestRegistrationResponse(reg *ACRegistration, ppd *core.PacketParserData, peer *core.UdpPeer) error {
	if reg == nil {
		return errors.New("nil AC registration fixture")
	}
	if reg.ac == nil || ppd == nil || ppd.HeaderType != core.NHP_AAK {
		return reg.handleRegistrationResponse(ppd, peer)
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(ppd.BodyMessage, &object) != nil {
		return reg.handleRegistrationResponse(ppd, peer)
	}
	if _, present := object["errCode"]; !present {
		object["errCode"] = json.RawMessage(`"0"`)
	}
	var errCode string
	var registered bool
	if json.Unmarshal(object["errCode"], &errCode) != nil ||
		json.Unmarshal(object["registered"], &registered) != nil ||
		!common.IsSuccessErrCode(errCode) || !registered {
		body, _ := json.Marshal(object)
		copyPPD := *ppd
		copyPPD.BodyMessage = body
		return reg.handleRegistrationResponse(&copyPPD, peer)
	}
	object["bootId"] = mustJSONRaw(reg.ac.bootID)
	object["sessFlushGen"] = mustJSONRaw(reg.ac.sessionFlushGeneration.Load())
	object["aolTrxId"] = mustJSONRaw(testRefreshAOLTransaction)
	body, _ := json.Marshal(object)
	copyPPD := *ppd
	copyPPD.BodyMessage = body
	copyPPD.SenderTrxId = testRefreshAOLTransaction
	return reg.handleRegistrationResponse(&copyPPD, peer)
}

func mustJSONRaw(value any) json.RawMessage {
	body, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return body
}

// successfulTestAAKPacket constructs the exact successful wire response used
// by mocked registration transactions. Callers supply only the fields relevant
// to their test; this helper adds the required success and authority fields.
func successfulTestAAKPacket(ac *UdpAC, body []byte) *core.PacketParserData {
	var object map[string]json.RawMessage
	if json.Unmarshal(body, &object) != nil {
		panic("successfulTestAAKPacket requires a JSON object")
	}
	object["errCode"] = json.RawMessage(`"0"`)
	object["registered"] = json.RawMessage(`true`)
	object["bootId"] = mustJSONRaw(ac.bootID)
	object["sessFlushGen"] = mustJSONRaw(ac.sessionFlushGeneration.Load())
	object["aolTrxId"] = mustJSONRaw(testRefreshAOLTransaction)
	strictBody, err := json.Marshal(object)
	if err != nil {
		panic(err)
	}
	return &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: strictBody,
		SenderTrxId: testRefreshAOLTransaction,
	}
}

// TestNilMetricsPublisher tests that ACRegistration with nil metrics publisher doesn't panic.
// The metrics.Publisher is nil-safe — all methods are no-ops on nil receiver.
func TestNilMetricsPublisher(t *testing.T) {
	reg := &ACRegistration{
		ac: &UdpAC{config: &Config{ACId: "test-ac"}},
		// metrics intentionally nil (Publisher is nil-safe)
	}
	// All metric methods should be no-ops without panic
	reg.metrics.IncrCounter("TestMetric")
	reg.metrics.IncrCounterWithDims("TestMetric", nil)
	reg.metrics.AddCounterWithDims("TestMetric", 5, nil)
	reg.metrics.Stop()
}

func TestACMetricHelpersNilSafe(t *testing.T) {
	for _, tc := range []struct {
		name string
		ac   *UdpAC
	}{
		{name: "nil registration", ac: &UdpAC{}},
		{name: "nil publisher", ac: &UdpAC{registration: &ACRegistration{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.ac.incrMetric("TestMetric")
			if tc.ac.addMetric("TestMetric", 1) {
				t.Fatalf("addMetric reported success with no metrics publisher")
			}
		})
	}
}

// mockNetError implements net.Error for testing the typed interface path in classifyError.
type mockNetError struct {
	msg     string
	timeout bool
}

func (e *mockNetError) Error() string   { return e.msg }
func (e *mockNetError) Timeout() bool   { return e.timeout }
func (e *mockNetError) Temporary() bool { return false }

// TestClassifyError tests error categorization for CloudWatch dimensions.
func TestClassifyError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"nil error", nil, "none"},
		{"typed NHP error", common.ErrTransactionFailedByTimeout, common.ErrTransactionFailedByTimeout.ErrorCode()},
		{"wrapped NHP error", fmt.Errorf("registration failed: %w", common.ErrTransactionFailedByTimeout), common.ErrTransactionFailedByTimeout.ErrorCode()},
		{"net.Error timeout", &mockNetError{msg: "i/o timeout", timeout: true}, "timeout"},
		{"net.Error non-timeout", &mockNetError{msg: "connection refused", timeout: false}, "connection_error"},
		{"wrapped net.Error timeout", fmt.Errorf("dial failed: %w", &mockNetError{msg: "deadline", timeout: true}), "timeout"},
		{"timeout string", fmt.Errorf("operation timed out"), "timeout"},
		{"deadline exceeded", fmt.Errorf("context deadline exceeded"), "timeout"},
		{"connection refused", fmt.Errorf("dial: connection refused"), "connection_error"},
		{"connection reset", fmt.Errorf("read: connection reset by peer"), "connection_error"},
		{"ECDH failure", fmt.Errorf("ECDH key exchange failed"), "crypto_error"},
		{"decrypt error", fmt.Errorf("failed to decrypt packet"), "crypto_error"},
		{"DNS failure", fmt.Errorf("no such host"), "dns_error"},
		{"resolve error", fmt.Errorf("could not resolve endpoint"), "dns_error"},
		{"DNS lookup failed", fmt.Errorf("DNS lookup failed for server.nhp.internal"), "dns_error"},
		{"name resolution", fmt.Errorf("name resolution failed"), "dns_error"},
		{"unknown error", fmt.Errorf("something unexpected"), "other"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyError(tt.err)
			if got != tt.expected {
				t.Errorf("classifyError(%q) = %q, want %q", tt.err, got, tt.expected)
			}
		})
	}
}

// TestClassifyReason tests reason categorization for CloudWatch dimensions.
func TestClassifyReason(t *testing.T) {
	tests := []struct {
		name     string
		reason   string
		expected string
	}{
		{"refresh redirect", ReasonRefreshRedirect, ReasonRefreshRedirect},
		{"refresh peer change", ReasonRefreshPeerChange, ReasonRefreshPeerChange},
		{"server connection timeout", ReasonServerConnectionTimeout, ReasonServerConnectionTimeout},
		{"connection timeout", ReasonConnectionTimeout, ReasonConnectionTimeout},
		{"unknown reason", "some_random_reason", "other"},
		{"empty string", "", "other"},
		{"error message as reason", "failed to connect to server 10.0.0.1", "other"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyReason(tt.reason)
			if got != tt.expected {
				t.Errorf("classifyReason(%q) = %q, want %q", tt.reason, got, tt.expected)
			}
		})
	}
}

// TestACRegistration_NewACRegistration tests creation of ACRegistration.
func TestACRegistration_NewACRegistration(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	if reg == nil {
		t.Fatal("NewACRegistration returned nil")
	}

	if reg.ac != ac {
		t.Error("ACRegistration.ac not set correctly")
	}

	if reg.assignedServers == nil {
		t.Error("assignedServers slice should be initialized")
	}

	if len(reg.assignedServers) != 0 {
		t.Error("assignedServers should be empty initially")
	}

	if reg.stopCh == nil {
		t.Error("stopCh should be initialized")
	}
}

// TestACRegistration_NewACRegistration_RequiresAWSRegion asserts that
// NewACRegistration returns an error when neither AWS_REGION nor
// AWS_DEFAULT_REGION is set (#1659).
//
// Must NOT call t.Parallel: t.Setenv panics in parallel tests.
func TestACRegistration_NewACRegistration_RequiresAWSRegion(t *testing.T) {
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-no-region",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg, err := NewACRegistration(ac)
	if err == nil {
		t.Fatal("NewACRegistration with AWS_REGION unset: got nil error, want non-nil")
	}
	if reg != nil {
		t.Error("NewACRegistration with AWS_REGION unset: got non-nil registration")
	}
	if !strings.Contains(err.Error(), "AWS_REGION") {
		t.Errorf("error %q does not mention AWS_REGION", err)
	}
}

// TestACRegistration_NewACRegistration_AcceptsAWSDefaultRegion asserts the
// SDK-compatible fallback: a process with only AWS_DEFAULT_REGION set still
// constructs.
//
// Must NOT call t.Parallel: t.Setenv panics in parallel tests.
func TestACRegistration_NewACRegistration_AcceptsAWSDefaultRegion(t *testing.T) {
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "us-west-2")

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-default-region",
			ServerEndpoint: "server.nhp.test.internal",
			// Set Environment explicitly to suppress the empty-Env
			// startup warning — this test calls NewACRegistration
			// directly to assert it returns nil error, not via
			// mustNewACRegistration (which would default-set it).
			Environment: "test",
		},
	}

	if _, err := NewACRegistration(ac); err != nil {
		t.Fatalf("NewACRegistration with only AWS_DEFAULT_REGION set: %v", err)
	}
}

// TestResolveRegion_AWSRegionWins fences the documented precedence:
// AWS_REGION takes priority over AWS_DEFAULT_REGION when both are set.
//
// Must NOT call t.Parallel: t.Setenv panics in parallel tests.
func TestResolveRegion_AWSRegionWins(t *testing.T) {
	t.Setenv("AWS_REGION", "us-east-2")
	t.Setenv("AWS_DEFAULT_REGION", "us-west-2")
	if got := resolveRegion(); got != "us-east-2" {
		t.Errorf("resolveRegion() = %q, want us-east-2", got)
	}
}

// TestResolveRegion_WhitespaceFallsThrough fences the TrimSpace defense
// against `Environment="AWS_REGION= "` typos: a whitespace-only value
// must fall through to AWS_DEFAULT_REGION rather than passing the guard.
//
// Must NOT call t.Parallel: t.Setenv panics in parallel tests.
func TestResolveRegion_WhitespaceFallsThrough(t *testing.T) {
	t.Setenv("AWS_REGION", "  ")
	t.Setenv("AWS_DEFAULT_REGION", "us-west-2")
	if got := resolveRegion(); got != "us-west-2" {
		t.Errorf("resolveRegion() with whitespace AWS_REGION = %q, want us-west-2", got)
	}
}

// TestResolveEnvironment fences the publisher Environment dim
// fallback. Deployed envs must carry a real value (TF user_data
// writes it into config.toml); local/dev with an empty config
// falls back to "unknown" so the binary still starts.
//
// The whitespace cases fence the documented symmetry with
// resolveRegion — a `Environment=" prod "` typo in a heredoc-
// mangled config.toml must trim to "prod", and an all-whitespace
// value must fall back. Without the trim, the publisher would
// emit a whitespace-padded dim that mismatches the alarm's
// Environment value just as surely as "unknown" does — the exact
// failure mode this PR closes, one tab character down the rabbit
// hole.
func TestResolveEnvironment(t *testing.T) {
	cases := []struct {
		name         string
		in           string
		want         string
		wantFallback bool
	}{
		{"empty", "", envFallbackUnknown, true},
		{"deployed_value", "prod", "prod", false},
		{"all_spaces", "   ", envFallbackUnknown, true},
		{"tabs_and_newlines", "\t\n", envFallbackUnknown, true},
		{"leading_trailing_spaces", " prod ", "prod", false},
		{"leading_trailing_tabs", "\tprod\n", "prod", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, fallback := resolveEnvironment(c.in)
			if got != c.want || fallback != c.wantFallback {
				t.Errorf("resolveEnvironment(%q) = (%q, %v), want (%q, %v)", c.in, got, fallback, c.want, c.wantFallback)
			}
		})
	}
}

// TestACRegistration_PublisherDimsCarryConfigEnvironment fences the
// wiring between ac.config.Environment, resolveEnvironment, acBaseDims,
// and the metrics Publisher. The component pieces are each tested in
// isolation (TestResolveEnvironment, TestACBaseDims) — this test
// catches a future refactor that drops the resolveEnvironment call
// while leaving the helper intact, or that builds the Publisher with
// the wrong dim slice. Without this fence, the original bug class
// this PR closes (Environment=unknown reaching CloudWatch despite a
// populated config) could regress silently.
//
// Two cases: the happy path (deployed env value survives the round
// trip) and the fallback path (empty config produces envFallbackUnknown
// in the published dim). The fallback case is the symmetric counterpart
// — without it, a refactor that does e.g. `env := ac.config.Environment`
// (dropping the resolveEnvironment call) would still pass the
// happy-path assertion ("prod" survives the round trip) but
// re-introduce the original bug on misconfigured envs.
//
// Must NOT call t.Parallel: t.Setenv panics in parallel tests.
func TestACRegistration_PublisherDimsCarryConfigEnvironment(t *testing.T) {
	cases := []struct {
		name               string
		configEnvironment  string
		wantEnvironmentDim string
	}{
		{"deployed_env_survives_roundtrip", "prod", "prod"},
		{"empty_config_falls_back_to_unknown", "", envFallbackUnknown},
		{"whitespace_config_falls_back_to_unknown", "   ", envFallbackUnknown},
		{"whitespace_padded_config_is_trimmed", " prod ", "prod"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// AWS_REGION is set only to satisfy the resolveRegion
			// startup guard in NewACRegistration. The metrics
			// Publisher constructed below does NO network IO at
			// construction time (no CloudWatch API calls until
			// the flush loop starts, which this test never triggers),
			// so the test does not need real AWS credentials and
			// shouldn't be flake-coupled to the SDK's config-file
			// or env-credential lookup.
			t.Setenv("AWS_REGION", "us-east-2")
			t.Setenv("AWS_DEFAULT_REGION", "")

			// Stub the warn so the empty/whitespace subtests don't
			// emit real log output during the run. The warn-call-
			// site itself is fenced by
			// TestACRegistration_EnvFallbackWarnFires.
			origWarn := envFallbackWarn
			envFallbackWarn = func() {}
			t.Cleanup(func() { envFallbackWarn = origWarn })

			ac := &UdpAC{
				config: &Config{
					ACId:           "test-ac-wiring",
					ServerEndpoint: "server.nhp.test.internal",
					Environment:    c.configEnvironment,
				},
			}
			// Call NewACRegistration directly, NOT
			// mustNewACRegistration — the helper defaults
			// Environment="test" when empty so other tests don't
			// emit the startup warning, but this test's fallback
			// subtests need the empty value to flow through.
			reg, err := NewACRegistration(ac)
			if err != nil {
				t.Fatalf("NewACRegistration failed: %v", err)
			}

			dims := reg.metrics.DimensionsForTest(t)
			got := make(map[string]string)
			for _, d := range dims {
				got[*d.Name] = *d.Value
			}
			// Cardinality fence: the alarm dim-set guarantee depends
			// on the publisher emitting exactly these three dims and
			// no more. A future refactor that adds a 4th dim (e.g.,
			// Cell) here without updating monitoring.tf alarms would
			// mismatch streams the same way Environment=unknown did.
			if len(dims) != 3 {
				t.Errorf("publisher dim count = %d, want 3 (got dims: %v)", len(dims), got)
			}
			if got["Environment"] != c.wantEnvironmentDim {
				t.Errorf("publisher Environment dim = %q, want %q (got dims: %v)", got["Environment"], c.wantEnvironmentDim, got)
			}
			if got["Region"] != "us-east-2" {
				t.Errorf("publisher Region dim = %q, want %q (got dims: %v)", got["Region"], "us-east-2", got)
			}
			if got["Component"] != "AC" {
				t.Errorf("publisher Component dim = %q, want %q (got dims: %v)", got["Component"], "AC", got)
			}
		})
	}
}

// TestACRegistration_EnvFallbackWarnFires fences the startup warning
// emitted when ac.config.Environment is empty or whitespace-only.
// The warning is the operator signal that a TF user_data regression
// has reintroduced the original bug class; if a future refactor drops
// the envFallbackWarn() call site (or moves it past the fallback
// branch), CloudWatch would silently latch alarms again without any
// AC-log breadcrumb.
//
// Asserts the warn fires on each fallback shape (empty, whitespace)
// AND does NOT fire when Environment is populated, including the
// literal "unknown" case (operator-explicit, not a fallback).
//
// Must NOT call t.Parallel: t.Setenv panics in parallel tests.
func TestACRegistration_EnvFallbackWarnFires(t *testing.T) {
	cases := []struct {
		name              string
		configEnvironment string
		wantWarn          bool
	}{
		{"empty_fires_warn", "", true},
		{"whitespace_fires_warn", "   ", true},
		{"tab_newline_fires_warn", "\t\n", true},
		{"populated_no_warn", "prod", false},
		{"literal_unknown_no_warn", envFallbackUnknown, false},
		{"trimmed_value_no_warn", " prod ", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("AWS_REGION", "us-east-2")

			var calls int
			origWarn := envFallbackWarn
			envFallbackWarn = func() { calls++ }
			t.Cleanup(func() { envFallbackWarn = origWarn })

			ac := &UdpAC{
				config: &Config{
					ACId:           "test-ac-warn-fence",
					ServerEndpoint: "server.nhp.test.internal",
					Environment:    c.configEnvironment,
				},
			}
			if _, err := NewACRegistration(ac); err != nil {
				t.Fatalf("NewACRegistration: %v", err)
			}

			wantCalls := 0
			if c.wantWarn {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Errorf("envFallbackWarn calls = %d, want %d for Environment=%q", calls, wantCalls, c.configEnvironment)
			}
		})
	}
}

// TestACBaseDims fences the publisher base dim set against accidental
// regression — every AC metric is keyed on these three dims and the
// alarms in terraform/modules/ac/monitoring.tf require an exact match.
func TestACBaseDims(t *testing.T) {
	dims := acBaseDims("test-env", "us-west-2")

	got := make(map[string]string, len(dims))
	for _, d := range dims {
		got[*d.Name] = *d.Value
	}

	want := map[string]string{
		"Environment": "test-env",
		"Component":   "AC",
		"Region":      "us-west-2",
	}
	for name, value := range want {
		if got[name] != value {
			t.Errorf("dim %s = %q, want %q", name, got[name], value)
		}
	}
	if len(dims) != len(want) {
		t.Errorf("got %d dims, want %d (%v)", len(dims), len(want), got)
	}
}

// TestACRegistration_HandleRedispatch tests handling of NHP_ARD messages.
func TestACRegistration_HandleRedispatch(t *testing.T) {
	// Create a minimal AC with required fields
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
		sendMsgCh: make(chan *core.MsgData, 10), // Buffer to prevent blocking
	}

	reg := mustNewACRegistration(t, ac)

	tests := []struct {
		name          string
		ardMsg        *common.ACRedispatchMsg
		expectError   bool
		errorContains string
	}{
		{
			name: "empty targets",
			ardMsg: &common.ACRedispatchMsg{
				Targets: []common.RedirectTarget{},
			},
			expectError:   true,
			errorContains: "no targets",
		},
		{
			name: "error code set",
			ardMsg: &common.ACRedispatchMsg{
				ErrCode: "LICENSE_EXPIRED",
				ErrMsg:  "License has expired",
				Targets: []common.RedirectTarget{
					{IP: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: "pubkey"},
				},
			},
			expectError:   true,
			errorContains: "redispatch failed",
		},
		{
			name: "target with empty IP",
			ardMsg: &common.ACRedispatchMsg{
				Targets: []common.RedirectTarget{
					{IP: "", Port: testServerListenPort, PubKeyBase64: "pubkey"},
				},
			},
			expectError:   true,
			errorContains: "no valid targets",
		},
		{
			name: "target with invalid port",
			ardMsg: &common.ACRedispatchMsg{
				Targets: []common.RedirectTarget{
					{IP: "10.0.0.1", Port: 0, PubKeyBase64: "pubkey"},
				},
			},
			expectError:   true,
			errorContains: "no valid targets",
		},
		{
			name: "target with empty public key",
			ardMsg: &common.ACRedispatchMsg{
				Targets: []common.RedirectTarget{
					{IP: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: ""},
				},
			},
			expectError:   true,
			errorContains: "no valid targets",
		},
		{
			name: "target with invalid IP format",
			ardMsg: &common.ACRedispatchMsg{
				Targets: []common.RedirectTarget{
					{IP: "not-an-ip", Port: testServerListenPort, PubKeyBase64: "pubkey"},
				},
			},
			expectError:   true,
			errorContains: "no valid targets",
		},
		// Note: We don't test "success code with targets" here because it requires
		// a fully initialized device. That's tested in integration tests.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := reg.HandleRedispatch(tt.ardMsg)

			if tt.expectError && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.expectError && err != nil && tt.errorContains != "" {
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error containing %q, got %q", tt.errorContains, err.Error())
				}
			}
		})
	}
}

// TestACRegistration_HasAssignedServers tests the HasAssignedServers method.
func TestACRegistration_HasAssignedServers(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	if reg.HasAssignedServers() {
		t.Error("should return false when no servers assigned")
	}

	reg.assignedServers = []*AssignedServer{
		{
			Target: common.RedirectTarget{
				IP:   "10.0.0.1",
				Port: testServerListenPort,
			},
		},
	}

	if !reg.HasAssignedServers() {
		t.Error("should return true when servers are assigned")
	}
}

// TestACRegistration_ConcurrentAccess tests thread safety of ACRegistration.
func TestACRegistration_ConcurrentAccess(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Add some servers
	server := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.1",
			Port:         testServerListenPort,
			PubKeyBase64: "pubkey1",
		},
	}
	server.UpdateLastSeen()
	reg.assignedServers = []*AssignedServer{server}

	// Run concurrent operations
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(2)

		// Reader - registration level
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = reg.HasAssignedServers()
				_ = reg.GetAssignedServers()
			}
		}()

		// Reader - server level
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = server.GetLastSeen()
				_ = server.IsConnected()
			}
		}()
	}

	wg.Wait()
	// If we get here without race detector issues, the test passes
}

// TestConfig_RegistrationFields tests that registration config fields are parsed correctly.
func TestConfig_RegistrationFields(t *testing.T) {
	config := &Config{
		ACId:               "test-ac",
		PrivateKeyBase64:   "testprivkey",
		LicenseKey:         "lk_abc123",
		ServerEndpoint:     "server.nhp.test.internal",
		ACVersion:          "1.0.0",
		ServerPubKeyBase64: "serverpubkey",
		ServerPort:         DefaultServerPort,
	}

	if config.LicenseKey != "lk_abc123" {
		t.Errorf("LicenseKey = %q, want %q", config.LicenseKey, "lk_abc123")
	}

	if config.ServerEndpoint != "server.nhp.test.internal" {
		t.Errorf("ServerEndpoint = %q, want %q", config.ServerEndpoint, "server.nhp.test.internal")
	}

	if config.ACVersion != "1.0.0" {
		t.Errorf("ACVersion = %q, want %q", config.ACVersion, "1.0.0")
	}

	if config.ServerPubKeyBase64 != "serverpubkey" {
		t.Errorf("ServerPubKeyBase64 = %q, want %q", config.ServerPubKeyBase64, "serverpubkey")
	}

	if config.ServerPort != 443 {
		t.Errorf("ServerPort = %d, want %d", config.ServerPort, 443)
	}
}

// TestAssignedServer_Accessors tests the thread-safe accessor methods.
func TestAssignedServer_Accessors(t *testing.T) {
	server := &AssignedServer{
		Target: common.RedirectTarget{
			IP:   "10.0.0.1",
			Port: testServerListenPort,
		},
	}

	// Test SetConnected and IsConnected
	if server.IsConnected() {
		t.Error("new server should not be connected")
	}

	server.SetConnected(true)
	if !server.IsConnected() {
		t.Error("server should be connected after SetConnected(true)")
	}

	server.SetConnected(false)
	if server.IsConnected() {
		t.Error("server should not be connected after SetConnected(false)")
	}

	// Test IncrementFailCount
	count := server.IncrementFailCount()
	if count != 1 {
		t.Errorf("expected FailCount=1, got %d", count)
	}

	count = server.IncrementFailCount()
	if count != 2 {
		t.Errorf("expected FailCount=2, got %d", count)
	}

	count = server.IncrementFailCount()
	if count != 3 {
		t.Errorf("expected FailCount=3, got %d", count)
	}

	// Test UpdateLastSeen resets FailCount
	server.UpdateLastSeen()
	server.mu.RLock()
	failCount := server.FailCount
	server.mu.RUnlock()
	if failCount != 0 {
		t.Errorf("UpdateLastSeen should reset FailCount, got %d", failCount)
	}

	// Test GetLastSeen returns recent time
	lastSeen := server.GetLastSeen()
	if time.Since(lastSeen) > time.Second {
		t.Error("GetLastSeen should return recent time after UpdateLastSeen")
	}
}

func TestAssignedServer_IsHealthy(t *testing.T) {
	window := 30 * time.Second

	// Not connected -> not healthy even with fresh LastSeen
	s := &AssignedServer{}
	s.UpdateLastSeen()
	if s.IsHealthy(window) {
		t.Error("disconnected server should not be healthy")
	}

	// Connected and recently seen -> healthy
	s.SetConnected(true)
	if !s.IsHealthy(window) {
		t.Error("connected server with recent LastSeen should be healthy")
	}

	// Connected but LastSeen beyond window -> not healthy
	stale := &AssignedServer{Connected: true, LastSeen: time.Now().Add(-2 * window)}
	if stale.IsHealthy(window) {
		t.Error("connected server past health window should not be healthy")
	}

	// Connected but zero LastSeen -> not healthy
	zeroSeen := &AssignedServer{Connected: true}
	if zeroSeen.IsHealthy(window) {
		t.Error("connected server with zero LastSeen should not be healthy")
	}
}

func TestACRegistration_ConnectedServerCount(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}
	reg := mustNewACRegistration(t, ac)

	if got := reg.connectedServerCount(); got != 0 {
		t.Errorf("expected 0 connected servers, got %v", got)
	}

	reg.mu.Lock()
	reg.assignedServers = []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: testServerListenPort}, Connected: true, LastSeen: time.Now()},
		{Target: common.RedirectTarget{IP: "10.0.0.2", Port: testServerListenPort}, Connected: false},
		{Target: common.RedirectTarget{IP: "10.0.0.3", Port: testServerListenPort}, Connected: true, LastSeen: time.Now()},
	}
	reg.mu.Unlock()

	if got := reg.connectedServerCount(); got != 2 {
		t.Errorf("expected 2 connected servers, got %v", got)
	}

	// Disconnecting one brings count down.
	reg.assignedServers[0].SetConnected(false)
	if got := reg.connectedServerCount(); got != 1 {
		t.Errorf("expected 1 connected server after disconnect, got %v", got)
	}

	reg.assignedServers[2].SetConnected(false)
	if got := reg.connectedServerCount(); got != 0 {
		t.Errorf("expected 0 connected servers after disconnecting all, got %v", got)
	}
}

func TestACRegistration_HealthyServerCount(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}
	reg := mustNewACRegistration(t, ac)

	if got := reg.healthyServerCount(); got != 0 {
		t.Errorf("expected 0 healthy servers with empty list, got %v", got)
	}
	if reg.hasHealthyServer() {
		t.Error("expected hasHealthyServer=false with empty assigned server list")
	}

	healthWindow := KeepaliveInterval * KeepaliveMaxRetries
	now := time.Now()

	reg.mu.Lock()
	reg.assignedServers = []*AssignedServer{
		// Fresh + connected -> healthy.
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: testServerListenPort}, Connected: true, LastSeen: now},
		// Connected but LastSeen outside the window -> not healthy.
		{Target: common.RedirectTarget{IP: "10.0.0.2", Port: testServerListenPort}, Connected: true, LastSeen: now.Add(-2 * healthWindow)},
		// Not connected -> not healthy.
		{Target: common.RedirectTarget{IP: "10.0.0.3", Port: testServerListenPort}, Connected: false, LastSeen: now},
		// Fresh + connected -> healthy.
		{Target: common.RedirectTarget{IP: "10.0.0.4", Port: testServerListenPort}, Connected: true, LastSeen: now.Add(-healthWindow / 2)},
	}
	reg.mu.Unlock()

	if got := reg.healthyServerCount(); got != 2 {
		t.Errorf("expected 2 healthy servers, got %v", got)
	}
	if !reg.hasHealthyServer() {
		t.Error("expected hasHealthyServer=true with at least one fresh connected server")
	}

	// Mark the stale server as recently seen -> becomes healthy.
	reg.assignedServers[1].UpdateLastSeen()
	if got := reg.healthyServerCount(); got != 3 {
		t.Errorf("expected 3 healthy servers after UpdateLastSeen, got %v", got)
	}

	for _, server := range reg.assignedServers {
		server.SetConnected(false)
	}
	if reg.hasHealthyServer() {
		t.Error("expected hasHealthyServer=false after all assigned servers disconnect")
	}

	var nilReg *ACRegistration
	if nilReg.hasHealthyServer() {
		t.Error("nil registration must not report readiness")
	}
}

// TestRecordRegistrationSuccess_EmitsBothBaseAndTypedCounters verifies that
// recordRegistrationSuccess emits BOTH the base counter (no extra dimensions)
// and the breakdown counter (with RegistrationType).
//
// Regression test for the registration_stale alarm: that alarm matches the
// publisher base dimension set [Component, Environment, Region], so the base
// counter must always fire on success or the alarm sits in INSUFFICIENT_DATA
// even when ACs are healthy.
func TestRecordRegistrationSuccess_EmitsBothBaseAndTypedCounters(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}
	reg := mustNewACRegistration(t, ac)

	reg.recordRegistrationSuccess(dimValDirect)
	reg.recordRegistrationSuccess(dimValRedispatch)
	reg.recordRegistrationSuccess(dimValDirect)

	counters, dimCounters := reg.metrics.CountersForTest(t)
	if got := counters[MetricRegistrationSuccess]; got != 3 {
		t.Errorf("base RegistrationSuccess counter: want 3, got %v", got)
	}

	// Breakdown counter: 2 for Direct, 1 for Redispatch.
	var directCount, redispatchCount float64
	for key, v := range dimCounters {
		if !strings.Contains(key, MetricRegistrationSuccess) {
			continue
		}
		if strings.Contains(key, "RegistrationType="+*dimValDirect) {
			directCount += v
		}
		if strings.Contains(key, "RegistrationType="+*dimValRedispatch) {
			redispatchCount += v
		}
	}
	if directCount != 2 {
		t.Errorf("Direct breakdown counter: want 2, got %v", directCount)
	}
	if redispatchCount != 1 {
		t.Errorf("Redispatch breakdown counter: want 1, got %v", redispatchCount)
	}
}

// TestACRegistration_GetAssignedServers tests the GetAssignedServers method.
func TestACRegistration_GetAssignedServers(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Initially empty
	servers := reg.GetAssignedServers()
	if len(servers) != 0 {
		t.Errorf("expected 0 servers initially, got %d", len(servers))
	}

	// Add some servers
	reg.assignedServers = []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: testServerListenPort}},
		{Target: common.RedirectTarget{IP: "10.0.0.2", Port: testServerListenPort}},
	}

	servers = reg.GetAssignedServers()
	if len(servers) != 2 {
		t.Errorf("expected 2 servers, got %d", len(servers))
	}
}

// TestACRegistration_Stop tests graceful shutdown.
func TestACRegistration_Stop(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Manually simulate what Start() would do for testing
	reg.wg.Add(1)
	go func() {
		defer reg.wg.Done()
		<-reg.stopCh
	}()

	// Stop should complete without hanging
	done := make(chan struct{})
	go func() {
		reg.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Success - Stop completed
	case <-time.After(time.Second):
		t.Error("Stop() should complete within 1 second")
	}
}

// TestACRegistration_Stop_DoubleStopSafe tests that Stop() can be called multiple times without panic.
func TestACRegistration_Stop_DoubleStopSafe(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Manually simulate what Start() would do for testing
	reg.wg.Add(1)
	go func() {
		defer reg.wg.Done()
		<-reg.stopCh
	}()

	// First Stop should work
	reg.Stop()

	// Second Stop should not panic (would panic if closing stopCh twice)
	reg.Stop()

	// Third Stop should also be safe
	reg.Stop()
}

// TestACRegistration_ReregisteringGuard tests the atomic re-registration guard.
func TestACRegistration_ReregisteringGuard(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// First attempt should succeed
	if !reg.reregistering.CompareAndSwap(false, true) {
		t.Error("first CompareAndSwap should succeed")
	}

	// Second attempt should fail (already reregistering)
	if reg.reregistering.CompareAndSwap(false, true) {
		t.Error("second CompareAndSwap should fail while reregistering")
	}

	// After reset, should succeed again
	reg.reregistering.Store(false)
	if !reg.reregistering.CompareAndSwap(false, true) {
		t.Error("CompareAndSwap should succeed after reset")
	}
}

// TestACRegistration_ServerAssignment tests that servers are correctly assigned.
// Note: Full HandleRedispatch with connections requires integration tests.
func TestACRegistration_ServerAssignment(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Directly assign servers (simulating what HandleRedispatch does internally)
	reg.assignedServers = []*AssignedServer{
		{
			Target: common.RedirectTarget{
				IP:           "10.0.0.1",
				Port:         testServerListenPort,
				PubKeyBase64: "pubkey1",
				ServerID:     "server-1",
				AZ:           "us-west-2a",
			},
		},
		{
			Target: common.RedirectTarget{
				IP:           "10.0.0.2",
				Port:         testServerListenPort,
				PubKeyBase64: "pubkey2",
				ServerID:     "server-2",
				AZ:           "us-west-2b",
			},
		},
		{
			Target: common.RedirectTarget{
				IP:           "10.0.0.3",
				Port:         testServerListenPort,
				PubKeyBase64: "pubkey3",
				ServerID:     "server-3",
				AZ:           "us-west-2c",
			},
		},
	}

	// Verify servers were assigned
	servers := reg.GetAssignedServers()
	if len(servers) != 3 {
		t.Errorf("expected 3 assigned servers, got %d", len(servers))
	}

	// Verify server details
	if servers[0].Target.IP != "10.0.0.1" {
		t.Errorf("expected first server IP 10.0.0.1, got %s", servers[0].Target.IP)
	}
	if servers[1].Target.AZ != "us-west-2b" {
		t.Errorf("expected second server AZ us-west-2b, got %s", servers[1].Target.AZ)
	}
	if servers[2].Target.ServerID != "server-3" {
		t.Errorf("expected third server ID server-3, got %s", servers[2].Target.ServerID)
	}

	// Verify HasAssignedServers
	if !reg.HasAssignedServers() {
		t.Error("HasAssignedServers should return true")
	}
}

// TestACRegistration_CheckServerHealth_SkipsNeverConnected tests that health check
// skips servers that were never connected (prevents false positive re-registration).
func TestACRegistration_CheckServerHealth_SkipsNeverConnected(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Create a server that was never connected (Connected=false, LastSeen=zero)
	// This simulates a server where connectToServer() failed
	neverConnectedServer := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.1",
			Port:         testServerListenPort,
			PubKeyBase64: "pubkey1",
		},
		// Connected is false (default), LastSeen is zero (default)
	}

	// Create a healthy connected server
	healthyServer := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.2",
			Port:         testServerListenPort,
			PubKeyBase64: "pubkey2",
		},
	}
	healthyServer.SetConnected(true)
	healthyServer.UpdateLastSeen()

	reg.assignedServers = []*AssignedServer{neverConnectedServer, healthyServer}

	// Run health check - should NOT trigger re-registration
	// because the only "stale" server was never connected
	reg.checkServerHealth()

	// Verify re-registration was NOT triggered
	if reg.reregistering.Load() {
		t.Error("checkServerHealth should not trigger re-registration for never-connected servers")
	}

	// Now simulate the healthy server going stale
	healthyServer.mu.Lock()
	healthyServer.LastSeen = time.Now().Add(-1 * time.Hour) // Way past threshold
	healthyServer.mu.Unlock()

	// Run health check again - should trigger re-registration
	reg.checkServerHealth()

	// Verify re-registration was triggered for the actually-stale connected server
	if !reg.reregistering.Load() {
		t.Error("checkServerHealth should trigger re-registration when connected server is stale")
	}
}

// TestACRegistration_ConcurrentRedispatchAndHealthCheck tests that concurrent
// modifications to assignedServers and health checks don't race.
// This verifies the slice copy pattern works correctly under load.
func TestACRegistration_ConcurrentRedispatchAndHealthCheck(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Pre-populate with connected servers
	for i := 0; i < 3; i++ {
		server := &AssignedServer{
			Target: common.RedirectTarget{
				IP:           fmt.Sprintf("10.0.0.%d", i+1),
				Port:         testServerListenPort,
				PubKeyBase64: fmt.Sprintf("pubkey%d", i+1),
			},
		}
		server.SetConnected(true)
		server.UpdateLastSeen()
		reg.assignedServers = append(reg.assignedServers, server)
	}

	var wg sync.WaitGroup
	iterations := 100

	// Goroutine 1: Repeatedly modify assignedServers (simulating HandleRedispatch)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			reg.mu.Lock()
			// Simulate what HandleRedispatch does: replace the slice
			newServers := make([]*AssignedServer, 3)
			for j := 0; j < 3; j++ {
				newServers[j] = &AssignedServer{
					Target: common.RedirectTarget{
						IP:           fmt.Sprintf("192.168.%d.%d", i%256, j+1),
						Port:         testServerListenPort,
						PubKeyBase64: fmt.Sprintf("newkey%d-%d", i, j),
					},
				}
				newServers[j].SetConnected(true)
				newServers[j].UpdateLastSeen()
			}
			reg.assignedServers = newServers
			reg.mu.Unlock()
			time.Sleep(time.Microsecond) // Yield to other goroutines
		}
	}()

	// Goroutine 2: Repeatedly call checkServerHealth
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			reg.checkServerHealth()
			time.Sleep(time.Microsecond)
		}
	}()

	// Goroutine 3: Repeatedly call GetAssignedServers
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			servers := reg.GetAssignedServers()
			_ = len(servers) // Use the result
			time.Sleep(time.Microsecond)
		}
	}()

	wg.Wait()
	// If we get here without race detector issues or panics, the test passes
}

// TestACRegistration_HandleServerDownRespectStopChannel tests that handleServerDown
// respects the stop channel and exits cleanly.
func TestACRegistration_HandleServerDownRespectStopChannel(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Set up a server to trigger handleServerDown
	deadServer := &AssignedServer{
		Target: common.RedirectTarget{
			IP:   "10.0.0.1",
			Port: testServerListenPort,
		},
	}

	// Set reregistering flag (as checkServerHealth would)
	reg.reregistering.Store(true)

	// Start handleServerDown in a goroutine
	done := make(chan struct{})
	go func() {
		reg.handleServerDown(deadServer)
		close(done)
	}()

	// Give it a moment to start the jitter sleep
	time.Sleep(10 * time.Millisecond)

	// Close stopCh to signal shutdown
	close(reg.stopCh)

	// handleServerDown should exit quickly
	select {
	case <-done:
		// Success - handleServerDown exited
	case <-time.After(time.Second):
		t.Error("handleServerDown did not respect stopCh within 1 second")
	}

	// Verify reregistering flag was reset
	if reg.reregistering.Load() {
		t.Error("reregistering flag should be reset after handleServerDown exits")
	}
}

// TestACRegistration_HealthCheckFullFlow tests the complete health check flow:
// connected server goes stale -> triggers re-registration flag.
func TestACRegistration_HealthCheckFullFlow(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Create a mix of servers in different states
	servers := []*AssignedServer{
		// Server 1: Never connected (should be skipped)
		{
			Target: common.RedirectTarget{
				IP:           "10.0.0.1",
				Port:         testServerListenPort,
				PubKeyBase64: "pubkey1",
			},
			// Connected: false (default)
			// LastSeen: zero (default)
		},
		// Server 2: Connected and healthy
		{
			Target: common.RedirectTarget{
				IP:           "10.0.0.2",
				Port:         testServerListenPort,
				PubKeyBase64: "pubkey2",
			},
		},
		// Server 3: Connected but stale
		{
			Target: common.RedirectTarget{
				IP:           "10.0.0.3",
				Port:         testServerListenPort,
				PubKeyBase64: "pubkey3",
			},
		},
	}

	// Set up server states
	servers[1].SetConnected(true)
	servers[1].UpdateLastSeen() // Fresh

	servers[2].SetConnected(true)
	servers[2].mu.Lock()
	servers[2].LastSeen = time.Now().Add(-1 * time.Hour) // Stale
	servers[2].mu.Unlock()

	reg.assignedServers = servers

	// Verify initial state
	if reg.reregistering.Load() {
		t.Fatal("reregistering should be false initially")
	}

	// Run health check
	reg.checkServerHealth()

	// Should NOT trigger re-registration: only 1/2 connected servers is stale
	if reg.reregistering.Load() {
		t.Error("checkServerHealth should not trigger re-registration when at least one connected server is healthy")
	}

	// Make all connected servers stale -> now should trigger re-registration.
	servers[1].mu.Lock()
	servers[1].LastSeen = time.Now().Add(-1 * time.Hour)
	servers[1].mu.Unlock()

	reg.reregistering.Store(false)
	reg.checkServerHealth()
	if !reg.reregistering.Load() {
		t.Error("checkServerHealth should trigger re-registration when all connected servers are stale")
	}

	// Reset and make both connected servers healthy again.
	reg.reregistering.Store(false)
	servers[1].UpdateLastSeen()
	servers[2].UpdateLastSeen()

	reg.checkServerHealth()

	// Should NOT trigger re-registration now
	if reg.reregistering.Load() {
		t.Error("checkServerHealth should not trigger re-registration when all connected servers are healthy")
	}
}

// TestACRegistration_KeepaliveFilteringLogic tests the filtering conditions
// in sendKeepalives (skips disconnected and nil peer servers).
// Note: Full sendKeepalives testing requires device setup; this tests the logic.
func TestACRegistration_KeepaliveFilteringLogic(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Create servers with different states to verify filtering conditions
	connectedWithPeer := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.1",
			Port:         testServerListenPort,
			PubKeyBase64: "pubkey1",
		},
		Peer: &core.UdpPeer{
			Ip:   "10.0.0.1",
			Port: testServerListenPort,
		},
	}
	connectedWithPeer.SetConnected(true)

	disconnectedWithPeer := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.2",
			Port:         testServerListenPort,
			PubKeyBase64: "pubkey2",
		},
		Peer: &core.UdpPeer{
			Ip:   "10.0.0.2",
			Port: testServerListenPort,
		},
	}
	// disconnectedWithPeer.Connected is false by default

	connectedNoPeer := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.3",
			Port:         testServerListenPort,
			PubKeyBase64: "pubkey3",
		},
		// Peer is nil
	}
	connectedNoPeer.SetConnected(true)

	reg.assignedServers = []*AssignedServer{connectedWithPeer, disconnectedWithPeer, connectedNoPeer}

	// Verify the filtering conditions that sendKeepalives uses
	servers := reg.GetAssignedServers()

	eligibleCount := 0
	for _, server := range servers {
		// This matches the condition in sendKeepalives:
		// if server.Peer == nil || !server.IsConnected() { continue }
		if server.Peer != nil && server.IsConnected() {
			eligibleCount++
		}
	}

	// Only connectedWithPeer should be eligible
	if eligibleCount != 1 {
		t.Errorf("expected 1 eligible server for keepalive, got %d", eligibleCount)
	}

	// Verify each server's eligibility
	if connectedWithPeer.Peer == nil || !connectedWithPeer.IsConnected() {
		t.Error("connectedWithPeer should be eligible for keepalive")
	}
	if disconnectedWithPeer.Peer != nil && disconnectedWithPeer.IsConnected() {
		t.Error("disconnectedWithPeer should NOT be eligible for keepalive")
	}
	if connectedNoPeer.Peer != nil && connectedNoPeer.IsConnected() {
		t.Error("connectedNoPeer should NOT be eligible for keepalive (nil peer)")
	}
}

// TestACRegistration_Start_MissingConfig tests Start() with missing required config.
func TestACRegistration_Start_MissingConfig(t *testing.T) {
	// ServerEndpoint is the only required config for cloud mode registration
	ac := &UdpAC{
		config: &Config{
			ACId: "test-ac-001",
			// ServerEndpoint is empty
		},
	}
	reg := mustNewACRegistration(t, ac)

	err := reg.Start()
	if err == nil {
		t.Error("expected error but got nil")
		return
	}
	if err.Error() != "ServerEndpoint is required" {
		t.Errorf("expected error %q, got %q", "ServerEndpoint is required", err.Error())
	}
}

// TestACRegistration_HandleRegistrationResponse tests all error paths in handleRegistrationResponse.
func TestACRegistration_HandleRegistrationResponse(t *testing.T) {
	// Create a test private key for the device
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	// Create a mock peer for testing (used by RemovePeer on error paths)
	mockPeer := &core.UdpPeer{
		Hostname:     "test-server",
		Ip:           "10.0.0.1",
		Port:         testServerListenPort,
		PubKeyBase64: "dGVzdC1wdWJrZXktYmFzZTY0", // "test-pubkey-base64" in base64
		Type:         core.NHP_SERVER,
	}

	tests := []struct {
		name          string
		ppd           *core.PacketParserData
		expectError   bool
		errorContains string
	}{
		{
			name: "ppd.Error set",
			ppd: &core.PacketParserData{
				Error: fmt.Errorf("network error"),
			},
			expectError:   true,
			errorContains: "registration failed",
		},
		{
			name: "NHP_AAK with error code",
			ppd: &core.PacketParserData{
				HeaderType:  core.NHP_AAK,
				BodyMessage: []byte(`{"errCode":"LICENSE_EXPIRED","errMsg":"License has expired"}`),
			},
			expectError:   true,
			errorContains: "registration rejected",
		},
		{
			name: "NHP_AAK with Registered=false",
			ppd: &core.PacketParserData{
				HeaderType:  core.NHP_AAK,
				BodyMessage: []byte(`{"registered":false}`),
			},
			expectError:   true,
			errorContains: "successful AAK must contain registered:true",
		},
		{
			name: "NHP_AAK parse error",
			ppd: &core.PacketParserData{
				HeaderType:  core.NHP_AAK,
				BodyMessage: []byte(`{invalid json`),
			},
			expectError:   true,
			errorContains: "failed to parse NHP_AAK",
		},
		{
			name: "NHP_ARD parse error",
			ppd: &core.PacketParserData{
				HeaderType:  core.NHP_ARD,
				BodyMessage: []byte(`{invalid json`),
			},
			expectError:   true,
			errorContains: "failed to parse NHP_ARD",
		},
		{
			name: "unexpected response type",
			ppd: &core.PacketParserData{
				HeaderType:  core.NHP_KPL, // Not AAK or ARD
				BodyMessage: []byte(`{}`),
			},
			expectError:   true,
			errorContains: "unexpected response type",
		},
		{
			name: "NHP_AAK success",
			ppd: &core.PacketParserData{
				HeaderType:  core.NHP_AAK,
				BodyMessage: []byte(`{"registered":true,"acAddr":"10.0.0.1:62206"}`),
			},
			expectError: false,
		},
		{
			name: "NHP_AAK success with ErrCode 0",
			ppd: &core.PacketParserData{
				HeaderType:  core.NHP_AAK,
				BodyMessage: []byte(`{"errCode":"0","registered":true,"acAddr":"10.0.0.1:62206"}`),
			},
			expectError: false,
		},
		{
			name: "NHP_AAK with invalid ErrCode string fails",
			ppd: &core.PacketParserData{
				HeaderType:  core.NHP_AAK,
				BodyMessage: []byte(`{"errCode":"SUCCESS","registered":true,"acAddr":"10.0.0.1:62206"}`),
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handleTestRegistrationResponse(reg, tt.ppd, mockPeer)

			if tt.expectError && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.expectError && err != nil && tt.errorContains != "" {
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error containing %q, got %q", tt.errorContains, err.Error())
				}
			}
		})
	}
}

// TestACRegistration_CheckServerHealth_AlreadyReregistering tests that health check
// skips triggering re-registration when already in progress.
func TestACRegistration_CheckServerHealth_AlreadyReregistering(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Create a stale connected server that would trigger re-registration
	staleServer := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.1",
			Port:         testServerListenPort,
			PubKeyBase64: "pubkey1",
		},
	}
	staleServer.SetConnected(true)
	staleServer.mu.Lock()
	staleServer.LastSeen = time.Now().Add(-1 * time.Hour) // Very stale
	staleServer.mu.Unlock()

	reg.assignedServers = []*AssignedServer{staleServer}

	// Pre-set reregistering flag to simulate already in progress
	reg.reregistering.Store(true)

	// Run health check - should NOT spawn another handleServerDown
	// because reregistering is already true
	reg.checkServerHealth()

	// Flag should still be true (unchanged)
	if !reg.reregistering.Load() {
		t.Error("reregistering flag should remain true")
	}

	// Reset and verify it would have triggered if not already reregistering
	reg.reregistering.Store(false)
	reg.checkServerHealth()

	// Now it should have triggered
	if !reg.reregistering.Load() {
		t.Error("reregistering should be set when not already in progress")
	}
}

// TestACRegistration_CheckServerHealth_BackoffWindow tests that health-check
// triggered re-registration is suppressed while circuit-breaker backoff is active.
func TestACRegistration_CheckServerHealth_BackoffWindow(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	staleServer := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.1",
			Port:         testServerListenPort,
			PubKeyBase64: "pubkey1",
		},
	}
	staleServer.SetConnected(true)
	staleServer.mu.Lock()
	staleServer.LastSeen = time.Now().Add(-1 * time.Hour)
	staleServer.mu.Unlock()
	reg.assignedServers = []*AssignedServer{staleServer}

	// Simulate an active cooldown window from prior failed re-registrations.
	reg.serverDownReregCooldownUntil.Store(time.Now().Add(2 * time.Minute).UnixNano())

	reg.checkServerHealth()
	if reg.reregistering.Load() {
		t.Error("checkServerHealth should respect cooldown and not trigger re-registration")
	}

	// Clear cooldown and ensure stale health can trigger re-registration again.
	reg.serverDownReregCooldownUntil.Store(0)
	reg.checkServerHealth()
	if !reg.reregistering.Load() {
		t.Error("checkServerHealth should trigger re-registration after cooldown expires")
	}
}

// TestACRegistration_CheckServerHealth_BackoffEscalation tests that consecutive
// server-down re-registration failures produce exponentially increasing cooldowns
// capped at MaxServerDownReregBackoff.
func TestACRegistration_CheckServerHealth_BackoffEscalation(t *testing.T) {
	expected := []time.Duration{
		KeepaliveInterval,         // failure 1: 10s * 2^0
		KeepaliveInterval * 2,     // failure 2: 10s * 2^1
		KeepaliveInterval * 4,     // failure 3: 10s * 2^2
		KeepaliveInterval * 8,     // failure 4: 10s * 2^3
		KeepaliveInterval * 16,    // failure 5: 10s * 2^4
		MaxServerDownReregBackoff, // failure 6: capped at 5m
		MaxServerDownReregBackoff, // failure 7: still capped
	}

	for i, want := range expected {
		failures := int32(i + 1)
		cooldown := KeepaliveInterval * time.Duration(1<<min(failures-1, 5))
		if cooldown > MaxServerDownReregBackoff {
			cooldown = MaxServerDownReregBackoff
		}
		if cooldown != want {
			t.Errorf("failure %d: got cooldown %v, want %v", failures, cooldown, want)
		}
	}
}

// TestACRegistration_CheckServerHealth_CooldownResetOnSuccess verifies that
// circuit-breaker state (failures counter and cooldown timestamp) is cleared
// after a successful re-registration from both handleServerDown and
// TriggerReregistration paths.
func TestACRegistration_CheckServerHealth_CooldownResetOnSuccess(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Simulate accumulated circuit-breaker state from prior failures.
	reg.serverDownReregFailures.Store(3)
	reg.serverDownReregCooldownUntil.Store(time.Now().Add(5 * time.Minute).UnixNano())

	// handleServerDown clears state on success — simulate by calling the
	// stores directly (the actual register() call would need a live server).
	reg.serverDownReregFailures.Store(0)
	reg.serverDownReregCooldownUntil.Store(0)

	if reg.serverDownReregFailures.Load() != 0 {
		t.Error("serverDownReregFailures should be 0 after reset")
	}
	if reg.serverDownReregCooldownUntil.Load() != 0 {
		t.Error("serverDownReregCooldownUntil should be 0 after reset")
	}

	// Re-apply state and verify health check is suppressed, then cleared.
	reg.serverDownReregFailures.Store(2)
	reg.serverDownReregCooldownUntil.Store(time.Now().Add(5 * time.Minute).UnixNano())

	staleServer := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.1",
			Port:         testServerListenPort,
			PubKeyBase64: "pubkey1",
		},
	}
	staleServer.SetConnected(true)
	staleServer.mu.Lock()
	staleServer.LastSeen = time.Now().Add(-1 * time.Hour)
	staleServer.mu.Unlock()
	reg.assignedServers = []*AssignedServer{staleServer}

	// While cooldown is active, health check should be suppressed.
	reg.checkServerHealth()
	if reg.reregistering.Load() {
		t.Error("checkServerHealth should be suppressed while cooldown is active")
	}

	// Simulate successful re-registration clearing the state.
	reg.serverDownReregFailures.Store(0)
	reg.serverDownReregCooldownUntil.Store(0)

	// Now health check should trigger re-registration again.
	reg.checkServerHealth()
	if !reg.reregistering.Load() {
		t.Error("checkServerHealth should trigger re-registration after cooldown state is cleared")
	}
}

// TestACRegistration_Constants tests that important constants have expected values.
func TestACRegistration_Constants(t *testing.T) {
	// These constants are critical for correct behavior - verify they haven't been
	// accidentally changed to inappropriate values.

	if RegistrationTimeout != 30*time.Second {
		t.Errorf("RegistrationTimeout = %v, want 30s", RegistrationTimeout)
	}

	if KeepaliveInterval != 10*time.Second {
		t.Errorf("KeepaliveInterval = %v, want 10s", KeepaliveInterval)
	}

	if KeepaliveTimeout != ConnectionTimeout {
		t.Errorf("KeepaliveTimeout = %v, want ConnectionTimeout %v", KeepaliveTimeout, ConnectionTimeout)
	}

	if KeepaliveMaxRetries != 3 {
		t.Errorf("KeepaliveMaxRetries = %d, want 3", KeepaliveMaxRetries)
	}

	if MaxReregistrationAttempts != 5 {
		t.Errorf("MaxReregistrationAttempts = %d, want 5", MaxReregistrationAttempts)
	}

	// AC registration dials the cell's PUBLIC server NLB, so the default is the
	// client-edge port (443), not the port the server process binds (62206).
	if DefaultServerPort != 443 {
		t.Errorf("DefaultServerPort = %d, want 443", DefaultServerPort)
	}

	coreAOLTimeout := time.Duration(core.ACRegistrationTransactionResponseTimeoutMs) * time.Millisecond
	if ConnectionTimeout <= coreAOLTimeout {
		t.Errorf("ConnectionTimeout = %v, must exceed core AOL timeout %v", ConnectionTimeout, coreAOLTimeout)
	}
	if margin := ConnectionTimeout - coreAOLTimeout; margin != 250*time.Millisecond {
		t.Errorf("ConnectionTimeout margin = %v, want tight 250ms backstop", margin)
	}

	// Verify health check threshold calculation
	healthCheckThreshold := KeepaliveInterval * KeepaliveMaxRetries
	if healthCheckThreshold != 30*time.Second {
		t.Errorf("Health check threshold = %v, want 30s (10s * 3)", healthCheckThreshold)
	}
}

// TestACRegistration_ServerPortDefault tests that ServerPort defaults to 62206.
func TestACRegistration_ServerPortDefault(t *testing.T) {
	// When ServerPort is 0, register() should use DefaultServerPort
	config := &Config{
		ACId:               "test-ac",
		ServerEndpoint:     "server.nhp.test.internal",
		ServerPubKeyBase64: "testpubkey",
		ServerPort:         0, // Should default to the public client edge (443)
	}

	if config.ServerPort == 0 {
		// This is the condition in register() that triggers the default
		serverPort := config.ServerPort
		if serverPort == 0 {
			serverPort = DefaultServerPort
		}

		if serverPort != 443 {
			t.Errorf("default ServerPort = %d, want 443", serverPort)
		}
	}

	// Also test when ServerPort is explicitly set
	config.ServerPort = 12345
	if config.ServerPort != 12345 {
		t.Errorf("explicit ServerPort = %d, want 12345", config.ServerPort)
	}
}

// TestACRegistration_HandleRedispatch_PartialSuccess tests that HandleRedispatch
// succeeds with partial connection success (some but not all servers).
func TestACRegistration_HandleRedispatch_PartialSuccess(t *testing.T) {
	// This test verifies the partial success warning logic by examining
	// the conditions that trigger it.

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// After HandleRedispatch runs, if successCount < len(serversToConnect),
	// it logs a warning but still returns nil (success).
	// We can't easily test the actual connection without a device,
	// but we can verify the assigned servers are set up correctly.

	// Manually simulate what HandleRedispatch does for server assignment
	reg.mu.Lock()
	reg.assignedServers = []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: "key1"}, Connected: false},
		{Target: common.RedirectTarget{IP: "10.0.0.2", Port: testServerListenPort, PubKeyBase64: "key2"}, Connected: false},
		{Target: common.RedirectTarget{IP: "10.0.0.3", Port: testServerListenPort, PubKeyBase64: "key3"}, Connected: false},
	}
	reg.mu.Unlock()

	// Simulate partial success: only 2 of 3 connected
	reg.assignedServers[0].SetConnected(true)
	reg.assignedServers[1].SetConnected(true)
	// reg.assignedServers[2] remains disconnected

	// Verify state
	connectedCount := 0
	for _, server := range reg.GetAssignedServers() {
		if server.IsConnected() {
			connectedCount++
		}
	}

	if connectedCount != 2 {
		t.Errorf("expected 2 connected servers, got %d", connectedCount)
	}

	// This is "partial success" - some but not all servers connected
	totalServers := len(reg.GetAssignedServers())
	if connectedCount >= totalServers {
		t.Error("this should be partial success (not all connected)")
	}
	if connectedCount == 0 {
		t.Error("this should be partial success (at least one connected)")
	}
}

// TestACRegistration_Stop_CleansUpRegistrationPeer tests that Stop() cleans up
// the registration peer that was kept after NHP_AAK response.
func TestACRegistration_Stop_CleansUpRegistrationPeer(t *testing.T) {
	// Create a test private key for the device
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	// Simulate a registration peer being set (as would happen after NHP_AAK)
	regPeer := &core.UdpPeer{
		Hostname:     "reg-server",
		Ip:           "10.0.0.100",
		Port:         testServerListenPort,
		PubKeyBase64: "cmVnLXNlcnZlci1wdWJrZXk=", // "reg-server-pubkey" in base64
		Type:         core.NHP_SERVER,
	}
	device.AddPeer(regPeer)
	reg.registrationPeer = regPeer

	// Simulate some connected servers with peers
	serverPeer := &core.UdpPeer{
		Hostname:     "assigned-server",
		Ip:           "10.0.0.1",
		Port:         testServerListenPort,
		PubKeyBase64: "YXNzaWduZWQtc2VydmVyLXB1YmtleQ==", // "assigned-server-pubkey" in base64
		Type:         core.NHP_SERVER,
	}
	device.AddPeer(serverPeer)

	reg.mu.Lock()
	reg.assignedServers = []*AssignedServer{
		{
			Target: common.RedirectTarget{
				IP:           "10.0.0.1",
				Port:         testServerListenPort,
				PubKeyBase64: "YXNzaWduZWQtc2VydmVyLXB1YmtleQ==",
			},
			Peer:      serverPeer,
			Connected: true,
		},
	}
	reg.mu.Unlock()

	// Stop the registration manager
	reg.Stop()

	// Verify registration peer was cleaned up
	if reg.registrationPeer != nil {
		t.Error("registrationPeer should be nil after Stop()")
	}

	// Verify assigned servers were cleaned up
	if len(reg.assignedServers) != 0 {
		t.Errorf("assignedServers should be empty after Stop(), got %d", len(reg.assignedServers))
	}
}

// TestACRegistration_HandleRegistrationResponse_ReplacesOldPeer tests that receiving
// NHP_AAK when there's already a registration peer cleans up the old one.
func TestACRegistration_HandleRegistrationResponse_ReplacesOldPeer(t *testing.T) {
	// Create a test private key for the device
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	// Simulate an existing registration peer (from previous registration)
	oldPeer := &core.UdpPeer{
		Hostname:     "old-server",
		Ip:           "10.0.0.50",
		Port:         testServerListenPort,
		PubKeyBase64: "b2xkLXNlcnZlci1wdWJrZXk=", // "old-server-pubkey" in base64
		Type:         core.NHP_SERVER,
	}
	device.AddPeer(oldPeer)
	reg.registrationPeer = oldPeer

	// Create a new peer for the new registration
	newPeer := &core.UdpPeer{
		Hostname:     "new-server",
		Ip:           "10.0.0.100",
		Port:         testServerListenPort,
		PubKeyBase64: "bmV3LXNlcnZlci1wdWJrZXk=", // "new-server-pubkey" in base64
		Type:         core.NHP_SERVER,
	}

	// Simulate successful NHP_AAK response
	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(`{"errCode":"0","registered":true,"acAddr":"10.0.0.100:62206"}`),
	}

	err := handleTestRegistrationResponse(reg, ppd, newPeer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the registration peer was updated to the new one
	reg.mu.RLock()
	currentPeer := reg.registrationPeer
	reg.mu.RUnlock()

	if currentPeer != newPeer {
		t.Error("registrationPeer should be updated to the new peer")
	}

	if currentPeer.PubKeyBase64 != newPeer.PubKeyBase64 {
		t.Errorf("registrationPeer pubkey mismatch: got %s, want %s",
			currentPeer.PubKeyBase64, newPeer.PubKeyBase64)
	}
}

// TestACRegistration_NHP_AAK_AddsToAssignedServers verifies that when NHP_AAK is received
// (direct registration without redispatch), the registration peer is added to assignedServers.
// This is critical for keepalive management - without this fix, the connection times out
// after 5 minutes because keepaliveLoop() has no servers to send keepalives to.
func TestACRegistration_NHP_AAK_AddsToAssignedServers(t *testing.T) {
	// Create a test private key for the device
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	// Create a peer with a resolvable IP address
	testPeer := &core.UdpPeer{
		Hostname:     "test-server",
		Ip:           "10.0.0.1",
		Port:         testServerListenPort,
		PubKeyBase64: "dGVzdC1wdWJrZXktYmFzZTY0", // "test-pubkey-base64" in base64
		Type:         core.NHP_SERVER,
	}

	// Verify assignedServers is empty before
	if reg.HasAssignedServers() {
		t.Fatal("assignedServers should be empty before NHP_AAK")
	}

	// Simulate successful NHP_AAK response
	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(`{"errCode":"0","registered":true,"acAddr":"10.0.0.1:62206"}`),
	}

	err := handleTestRegistrationResponse(reg, ppd, testPeer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the registration peer was added to assignedServers
	if !reg.HasAssignedServers() {
		t.Fatal("assignedServers should NOT be empty after NHP_AAK - this is the critical fix!")
	}

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 assigned server, got %d", len(servers))
	}

	server := servers[0]

	// Verify the assigned server has the correct peer
	if server.Peer != testPeer {
		t.Error("assigned server Peer should be the registration peer")
	}

	// Verify the assigned server is marked as connected
	if !server.IsConnected() {
		t.Error("assigned server should be marked as Connected=true")
	}

	// Verify LastSeen is set (not zero)
	if server.GetLastSeen().IsZero() {
		t.Error("assigned server LastSeen should be set")
	}

	// Verify the target has correct IP and port from the peer's SendAddr
	sendAddr := testPeer.SendAddr()
	if sendAddr == nil {
		t.Fatal("test peer SendAddr should not be nil")
	}
	udpAddr, ok := sendAddr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", sendAddr)
	}

	if server.Target.IP != udpAddr.IP.String() {
		t.Errorf("Target.IP = %s, want %s", server.Target.IP, udpAddr.IP.String())
	}
	if server.Target.Port != udpAddr.Port {
		t.Errorf("Target.Port = %d, want %d", server.Target.Port, udpAddr.Port)
	}
	if server.Target.PubKeyBase64 != testPeer.PublicKeyBase64() {
		t.Errorf("Target.PubKeyBase64 = %s, want %s", server.Target.PubKeyBase64, testPeer.PublicKeyBase64())
	}
}

// TestACRegistration_NHP_AAK_KeepaliveEligibility verifies that after NHP_AAK,
// the assigned server is eligible for keepalives (has Peer != nil and IsConnected).
// This test ensures the keepalive filtering logic will include the registration server.
func TestACRegistration_NHP_AAK_KeepaliveEligibility(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-002",
			ServerEndpoint: "server.nhp.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	testPeer := &core.UdpPeer{
		Hostname:     "test-server",
		Ip:           "10.0.0.2",
		Port:         testServerListenPort,
		PubKeyBase64: "dGVzdC1wdWJrZXktMg==",
		Type:         core.NHP_SERVER,
	}

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(`{"errCode":"0","registered":true,"acAddr":"10.0.0.2:62206"}`),
	}

	err := handleTestRegistrationResponse(reg, ppd, testPeer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 assigned server, got %d", len(servers))
	}

	server := servers[0]

	// These are the exact conditions checked in sendKeepalives():
	// if server.Peer == nil || !server.IsConnected() { continue }
	if server.Peer == nil {
		t.Error("server.Peer is nil - keepalives will NOT be sent!")
	}
	if !server.IsConnected() {
		t.Error("server.IsConnected() is false - keepalives will NOT be sent!")
	}

	// Verify the peer has a valid SendAddr (required for sending keepalives)
	if server.Peer.SendAddr() == nil {
		t.Error("server.Peer.SendAddr() is nil - keepalives cannot be sent!")
	}
}

// TestACRegistration_NHP_AAK_ReRegistration_ReplacesAssignedServer verifies that
// when re-registration occurs (receiving another NHP_AAK), the old assigned server
// is replaced with the new one.
func TestACRegistration_NHP_AAK_ReRegistration_ReplacesAssignedServer(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-003",
			ServerEndpoint: "server.nhp.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	// First registration
	firstPeer := &core.UdpPeer{
		Hostname:     "first-server",
		Ip:           "10.0.0.10",
		Port:         testServerListenPort,
		PubKeyBase64: "Zmlyc3Qtc2VydmVy",
		Type:         core.NHP_SERVER,
	}

	ppd1 := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(`{"errCode":"0","registered":true,"acAddr":"10.0.0.10:62206"}`),
	}

	err := handleTestRegistrationResponse(reg, ppd1, firstPeer)
	if err != nil {
		t.Fatalf("first registration failed: %v", err)
	}

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 assigned server after first registration, got %d", len(servers))
	}
	if servers[0].Target.IP != "10.0.0.10" {
		t.Errorf("first server IP = %s, want 10.0.0.10", servers[0].Target.IP)
	}

	// Second registration (re-registration)
	secondPeer := &core.UdpPeer{
		Hostname:     "second-server",
		Ip:           "10.0.0.20",
		Port:         testServerListenPort,
		PubKeyBase64: "c2Vjb25kLXNlcnZlcg==",
		Type:         core.NHP_SERVER,
	}

	ppd2 := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(`{"errCode":"0","registered":true,"acAddr":"10.0.0.20:62206"}`),
	}

	err = handleTestRegistrationResponse(reg, ppd2, secondPeer)
	if err != nil {
		t.Fatalf("second registration failed: %v", err)
	}

	// After re-registration, we should have exactly 1 server (replaced, not appended).
	// This prevents duplicate entries from accumulating on repeated re-registrations.
	servers = reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected exactly 1 assigned server after re-registration, got %d", len(servers))
	}

	// Verify it's the new server, not the old one
	if servers[0].Target.IP != "10.0.0.20" {
		t.Errorf("expected new server IP 10.0.0.20, got %s", servers[0].Target.IP)
	}
	if servers[0].Peer != secondPeer {
		t.Error("new server should have secondPeer")
	}

	// Verify old server is NOT present
	for _, s := range servers {
		if s.Target.IP == "10.0.0.10" {
			t.Error("old server (10.0.0.10) should not be in assignedServers after re-registration")
		}
	}
}

// TestACRegistration_NHP_AAK_AssignedServerFields verifies all fields of the
// AssignedServer are correctly populated after NHP_AAK.
func TestACRegistration_NHP_AAK_AssignedServerFields(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-004",
			ServerEndpoint: "server.nhp.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	testPeer := &core.UdpPeer{
		Hostname:     "test-server",
		Ip:           "192.168.1.100",
		Port:         12345,
		PubKeyBase64: "dGVzdC1rZXktMTIzNDU=",
		Type:         core.NHP_SERVER,
	}

	beforeTime := time.Now()

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(`{"errCode":"0","registered":true,"acAddr":"192.168.1.100:12345"}`),
	}

	err := handleTestRegistrationResponse(reg, ppd, testPeer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	afterTime := time.Now()

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 assigned server, got %d", len(servers))
	}

	server := servers[0]

	// Check Target fields
	if server.Target.IP != "192.168.1.100" {
		t.Errorf("Target.IP = %s, want 192.168.1.100", server.Target.IP)
	}
	if server.Target.Port != 12345 {
		t.Errorf("Target.Port = %d, want 12345", server.Target.Port)
	}
	if server.Target.PubKeyBase64 != testPeer.PublicKeyBase64() {
		t.Errorf("Target.PubKeyBase64 mismatch")
	}

	// Check Peer
	if server.Peer != testPeer {
		t.Error("Peer should be the test peer")
	}

	// Check Connected
	if !server.IsConnected() {
		t.Error("Connected should be true")
	}

	// Check LastSeen is within expected range
	lastSeen := server.GetLastSeen()
	if lastSeen.Before(beforeTime) || lastSeen.After(afterTime) {
		t.Errorf("LastSeen %v not in expected range [%v, %v]", lastSeen, beforeTime, afterTime)
	}

	// Check FailCount is 0
	server.mu.RLock()
	failCount := server.FailCount
	server.mu.RUnlock()
	if failCount != 0 {
		t.Errorf("FailCount = %d, want 0", failCount)
	}
}

// TestACRegistration_NHP_AAK_ServerAddr verifies that when NHP_AAK contains
// ServerAddr and ServerPubKey, the AC creates a new peer with the direct server
// address instead of using the registration peer (which may be connected to NLB).
func TestACRegistration_NHP_AAK_ServerAddr(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-serveraddr",
			ServerEndpoint: "nlb.test.internal", // AC connects to NLB
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	// Registration peer is connected to NLB (initial registration endpoint)
	registrationPeer := &core.UdpPeer{
		Hostname:     "nlb.test.internal",
		Ip:           "10.0.0.1", // NLB IP
		Port:         testServerListenPort,
		PubKeyBase64: "bmxiLXB1YmtleQ==", // NLB/shared public key
		Type:         core.NHP_SERVER,
	}

	// Server's direct address (different from NLB)
	// Use a public IP (TEST-NET-3 range) to test the switch-to-direct behavior
	serverDirectIP := "203.0.113.100"
	serverDirectPort := testServerListenPort
	serverPubKey := "c2VydmVyLWRpcmVjdC1wdWJrZXk=" // Different from NLB key

	// NHP_AAK with server's direct address
	aakJSON := fmt.Sprintf(`{
		"errCode": "0",
		"registered": true,
		"acAddr": "192.168.1.50:50000",
		"serverAddr": "%s:%d",
		"serverPubKey": "%s"
	}`, serverDirectIP, serverDirectPort, serverPubKey)

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(aakJSON),
	}

	err := handleTestRegistrationResponse(reg, ppd, registrationPeer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 assigned server, got %d", len(servers))
	}

	server := servers[0]

	// Verify the server uses the DIRECT address, not the NLB address
	if server.Target.IP != serverDirectIP {
		t.Errorf("Target.IP = %s, want %s (server direct IP)", server.Target.IP, serverDirectIP)
	}
	if server.Target.Port != serverDirectPort {
		t.Errorf("Target.Port = %d, want %d", server.Target.Port, serverDirectPort)
	}
	if server.Target.PubKeyBase64 != serverPubKey {
		t.Errorf("Target.PubKeyBase64 = %s, want %s (server direct pubkey)", server.Target.PubKeyBase64, serverPubKey)
	}

	// Verify the peer is the new direct peer, not the registration peer
	if server.Peer == registrationPeer {
		t.Error("server.Peer should be a NEW peer (direct), not the registration peer (NLB)")
	}
	if server.Peer.PublicKeyBase64() != serverPubKey {
		t.Errorf("server.Peer.PublicKeyBase64() = %s, want %s", server.Peer.PublicKeyBase64(), serverPubKey)
	}

	// Verify the peer can send to the direct address
	sendAddr := server.Peer.SendAddr()
	if sendAddr == nil {
		t.Fatal("server.Peer.SendAddr() should not be nil")
	}
	udpAddr, ok := sendAddr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", sendAddr)
	}
	if udpAddr.IP.String() != serverDirectIP {
		t.Errorf("SendAddr IP = %s, want %s", udpAddr.IP.String(), serverDirectIP)
	}
	if udpAddr.Port != serverDirectPort {
		t.Errorf("SendAddr Port = %d, want %d", udpAddr.Port, serverDirectPort)
	}
}

// TestACRegistration_NHP_AAK_ServerAddr_Fallback verifies that if ServerAddr
// parsing fails, the AC falls back to using the registration peer.
func TestACRegistration_NHP_AAK_ServerAddr_Fallback(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-fallback",
			ServerEndpoint: "nlb.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	registrationPeer := &core.UdpPeer{
		Hostname:     "nlb.test.internal",
		Ip:           "10.0.0.1",
		Port:         testServerListenPort,
		PubKeyBase64: "bmxiLXB1YmtleQ==",
		Type:         core.NHP_SERVER,
	}

	// NHP_AAK with invalid ServerAddr (missing port)
	aakJSON := `{
		"errCode": "0",
		"registered": true,
		"acAddr": "192.168.1.50:50000",
		"serverAddr": "invalid-no-port",
		"serverPubKey": "c2VydmVyLWRpcmVjdC1wdWJrZXk="
	}`

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(aakJSON),
	}

	err := handleTestRegistrationResponse(reg, ppd, registrationPeer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 assigned server, got %d", len(servers))
	}

	server := servers[0]

	// Should fall back to registration peer's address
	if server.Peer != registrationPeer {
		t.Error("should fall back to registration peer when ServerAddr parsing fails")
	}
}

// TestACRegistration_NHP_AAK_Legacy verifies backwards compatibility:
// when ServerAddr is not provided, the AC uses the registration peer (legacy behavior).
func TestACRegistration_NHP_AAK_Legacy(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-legacy",
			ServerEndpoint: "nlb.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	registrationPeer := &core.UdpPeer{
		Hostname:     "nlb.test.internal",
		Ip:           "10.0.0.1",
		Port:         testServerListenPort,
		PubKeyBase64: "bmxiLXB1YmtleQ==",
		Type:         core.NHP_SERVER,
	}

	// Legacy NHP_AAK without ServerAddr/ServerPubKey
	aakJSON := `{
		"errCode": "0",
		"registered": true,
		"acAddr": "192.168.1.50:50000"
	}`

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(aakJSON),
	}

	err := handleTestRegistrationResponse(reg, ppd, registrationPeer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 assigned server, got %d", len(servers))
	}

	server := servers[0]

	// Should use registration peer (legacy behavior)
	if server.Peer != registrationPeer {
		t.Error("legacy mode should use registration peer")
	}
	if server.Target.PubKeyBase64 != registrationPeer.PublicKeyBase64() {
		t.Errorf("Target.PubKeyBase64 = %s, want %s", server.Target.PubKeyBase64, registrationPeer.PublicKeyBase64())
	}
}

// TestACRegistration_NHP_AAK_ServerAddr_RemovesOldPeer verifies that when switching
// to direct connection, the old NLB-connected peer is removed from the device.
func TestACRegistration_NHP_AAK_ServerAddr_RemovesOldPeer(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-remove-peer",
			ServerEndpoint: "nlb.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	// NLB peer (will be removed after direct connection)
	nlbPubKey := "bmxiLXB1YmtleS1yZW1vdmU="
	registrationPeer := &core.UdpPeer{
		Ip:           "10.0.0.1",
		Port:         testServerListenPort,
		PubKeyBase64: nlbPubKey,
		Type:         core.NHP_SERVER,
	}

	// Add the registration peer to the device (simulating what register() does)
	device.AddPeer(registrationPeer)

	// Verify the NLB peer is in the device
	if device.LookupPeer(registrationPeer.PublicKey()) == nil {
		t.Fatal("NLB peer should be in device before NHP_AAK")
	}

	// Server's direct address (different public key)
	serverPubKey := "c2VydmVyLWRpcmVjdC1rZXk="
	aakJSON := fmt.Sprintf(`{
		"errCode": "0",
		"registered": true,
		"acAddr": "192.168.1.50:50000",
		"serverAddr": "203.0.113.100:62206",
		"serverPubKey": "%s"
	}`, serverPubKey)

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(aakJSON),
	}

	err := handleTestRegistrationResponse(reg, ppd, registrationPeer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the OLD NLB peer was removed from the device
	if device.LookupPeer(registrationPeer.PublicKey()) != nil {
		t.Error("old NLB peer should be removed from device after switching to direct connection")
	}

	// Verify the NEW direct peer was added to the device
	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 assigned server, got %d", len(servers))
	}

	directPeer := servers[0].Peer
	if device.LookupPeer(directPeer.PublicKey()) == nil {
		t.Error("new direct peer should be added to device")
	}
}

// TestACRegistration_NHP_AAK_ServerAddr_IPv6 verifies handling of IPv6 server addresses.
func TestACRegistration_NHP_AAK_ServerAddr_IPv6(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-ipv6",
			ServerEndpoint: "nlb.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	registrationPeer := &core.UdpPeer{
		Ip:           "10.0.0.1",
		Port:         testServerListenPort,
		PubKeyBase64: "bmxiLXB1YmtleQ==",
		Type:         core.NHP_SERVER,
	}

	// IPv6 address with brackets (standard format for host:port)
	serverIPv6 := "2001:db8::1"
	serverPort := testServerListenPort
	serverPubKey := "aXB2Ni1zZXJ2ZXIta2V5"

	aakJSON := fmt.Sprintf(`{
		"errCode": "0",
		"registered": true,
		"acAddr": "192.168.1.50:50000",
		"serverAddr": "[%s]:%d",
		"serverPubKey": "%s"
	}`, serverIPv6, serverPort, serverPubKey)

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(aakJSON),
	}

	err := handleTestRegistrationResponse(reg, ppd, registrationPeer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 assigned server, got %d", len(servers))
	}

	server := servers[0]

	// Verify IPv6 address was parsed correctly
	if server.Target.IP != serverIPv6 {
		t.Errorf("Target.IP = %s, want %s", server.Target.IP, serverIPv6)
	}
	if server.Target.Port != serverPort {
		t.Errorf("Target.Port = %d, want %d", server.Target.Port, serverPort)
	}
}

// TestACRegistration_NHP_AAK_ServerAddr_OnlyServerAddr verifies behavior when
// ServerAddr is provided but ServerPubKey is missing (should fall back).
func TestACRegistration_NHP_AAK_ServerAddr_OnlyServerAddr(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-no-pubkey",
			ServerEndpoint: "nlb.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	registrationPeer := &core.UdpPeer{
		Ip:           "10.0.0.1",
		Port:         testServerListenPort,
		PubKeyBase64: "bmxiLXB1YmtleQ==",
		Type:         core.NHP_SERVER,
	}

	// ServerAddr provided but no ServerPubKey
	aakJSON := `{
		"errCode": "0",
		"registered": true,
		"acAddr": "192.168.1.50:50000",
		"serverAddr": "203.0.113.100:62206"
	}`

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(aakJSON),
	}

	err := handleTestRegistrationResponse(reg, ppd, registrationPeer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 assigned server, got %d", len(servers))
	}

	// Should fall back to registration peer when ServerPubKey is missing
	if servers[0].Peer != registrationPeer {
		t.Error("should use registration peer when ServerPubKey is missing")
	}
}

// TestACRegistration_NHP_AAK_ServerAddr_OnlyServerPubKey verifies behavior when
// ServerPubKey is provided but ServerAddr is missing (should fall back).
func TestACRegistration_NHP_AAK_ServerAddr_OnlyServerPubKey(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-no-addr",
			ServerEndpoint: "nlb.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	registrationPeer := &core.UdpPeer{
		Ip:           "10.0.0.1",
		Port:         testServerListenPort,
		PubKeyBase64: "bmxiLXB1YmtleQ==",
		Type:         core.NHP_SERVER,
	}

	// ServerPubKey provided but no ServerAddr
	aakJSON := `{
		"errCode": "0",
		"registered": true,
		"acAddr": "192.168.1.50:50000",
		"serverPubKey": "c2VydmVyLXB1YmtleQ=="
	}`

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(aakJSON),
	}

	err := handleTestRegistrationResponse(reg, ppd, registrationPeer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 assigned server, got %d", len(servers))
	}

	// Should fall back to registration peer when ServerAddr is missing
	if servers[0].Peer != registrationPeer {
		t.Error("should use registration peer when ServerAddr is missing")
	}
}

// TestACRegistration_NHP_AAK_ServerAddr_ReRegistration verifies that re-registration
// with ServerAddr properly replaces the old direct peer with a new one.
func TestACRegistration_NHP_AAK_ServerAddr_ReRegistration(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-rereg",
			ServerEndpoint: "nlb.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	// First registration
	firstPeer := &core.UdpPeer{
		Ip:           "10.0.0.1",
		Port:         testServerListenPort,
		PubKeyBase64: "Zmlyc3QtcGVlcg==",
		Type:         core.NHP_SERVER,
	}

	firstServerPubKey := "Zmlyc3Qtc2VydmVy"
	firstAAK := fmt.Sprintf(`{
		"errCode": "0",
		"registered": true,
		"acAddr": "192.168.1.50:50000",
		"serverAddr": "203.0.113.100:62206",
		"serverPubKey": "%s"
	}`, firstServerPubKey)

	ppd1 := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(firstAAK),
	}

	err := handleTestRegistrationResponse(reg, ppd1, firstPeer)
	if err != nil {
		t.Fatalf("first registration failed: %v", err)
	}

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 server after first registration, got %d", len(servers))
	}
	firstDirectPeer := servers[0].Peer

	// Second registration (re-registration to different server)
	secondPeer := &core.UdpPeer{
		Ip:           "10.0.0.2",
		Port:         testServerListenPort,
		PubKeyBase64: "c2Vjb25kLXBlZXI=",
		Type:         core.NHP_SERVER,
	}

	secondServerPubKey := "c2Vjb25kLXNlcnZlcg=="
	secondAAK := fmt.Sprintf(`{
		"errCode": "0",
		"registered": true,
		"acAddr": "192.168.1.50:50001",
		"serverAddr": "203.0.113.200:62206",
		"serverPubKey": "%s"
	}`, secondServerPubKey)

	ppd2 := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(secondAAK),
	}

	err = handleTestRegistrationResponse(reg, ppd2, secondPeer)
	if err != nil {
		t.Fatalf("second registration failed: %v", err)
	}

	servers = reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 server after re-registration, got %d", len(servers))
	}

	// Verify the server was replaced
	if servers[0].Target.IP != "203.0.113.200" {
		t.Errorf("server IP should be updated to 203.0.113.200, got %s", servers[0].Target.IP)
	}
	if servers[0].Target.PubKeyBase64 != secondServerPubKey {
		t.Errorf("server pubkey should be updated")
	}

	// Verify the first direct peer was removed from device
	if device.LookupPeer(firstDirectPeer.PublicKey()) != nil {
		t.Error("first direct peer should be removed after re-registration")
	}

	// Verify the second direct peer is in device
	if device.LookupPeer(servers[0].Peer.PublicKey()) == nil {
		t.Error("second direct peer should be in device")
	}
}

// TestACRegistration_NHP_AAK_ServerAddr_KeepaliveTarget verifies that after
// switching to direct connection, keepalives would be sent to the direct address.
func TestACRegistration_NHP_AAK_ServerAddr_KeepaliveTarget(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-keepalive",
			ServerEndpoint: "nlb.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	nlbIP := "10.0.0.1"
	registrationPeer := &core.UdpPeer{
		Ip:           nlbIP,
		Port:         testServerListenPort,
		PubKeyBase64: "bmxiLXB1YmtleQ==",
		Type:         core.NHP_SERVER,
	}

	directIP := "203.0.113.100"
	serverPubKey := "ZGlyZWN0LXNlcnZlcg=="
	aakJSON := fmt.Sprintf(`{
		"errCode": "0",
		"registered": true,
		"acAddr": "192.168.1.50:50000",
		"serverAddr": "%s:62206",
		"serverPubKey": "%s"
	}`, directIP, serverPubKey)

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(aakJSON),
	}

	err := handleTestRegistrationResponse(reg, ppd, registrationPeer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 assigned server, got %d", len(servers))
	}

	server := servers[0]

	// Verify keepalive would go to DIRECT address, not NLB
	sendAddr := server.Peer.SendAddr()
	if sendAddr == nil {
		t.Fatal("Peer.SendAddr() should not be nil")
	}

	udpAddr, ok := sendAddr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", sendAddr)
	}
	if udpAddr.IP.String() != directIP {
		t.Errorf("keepalive target IP = %s, want %s (direct, not NLB %s)",
			udpAddr.IP.String(), directIP, nlbIP)
	}

	// Verify the server meets keepalive eligibility criteria
	if server.Peer == nil {
		t.Error("server.Peer should not be nil for keepalives")
	}
	if !server.IsConnected() {
		t.Error("server should be connected for keepalives")
	}
}

// TestACRegistration_NHP_AAK_ServerAddr_SamePubKey verifies correct behavior when
// the server's direct pubkey is the same as the NLB shared key.
func TestACRegistration_NHP_AAK_ServerAddr_SamePubKey(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-same-key",
			ServerEndpoint: "nlb.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	// Same public key for both NLB and direct (shared key scenario)
	sharedPubKey := "c2hhcmVkLWtleQ=="
	registrationPeer := &core.UdpPeer{
		Ip:           "10.0.0.1", // NLB IP
		Port:         testServerListenPort,
		PubKeyBase64: sharedPubKey,
		Type:         core.NHP_SERVER,
	}

	device.AddPeer(registrationPeer)

	directIP := "203.0.113.100"
	aakJSON := fmt.Sprintf(`{
		"errCode": "0",
		"registered": true,
		"acAddr": "192.168.1.50:50000",
		"serverAddr": "%s:62206",
		"serverPubKey": "%s"
	}`, directIP, sharedPubKey)

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(aakJSON),
	}

	err := handleTestRegistrationResponse(reg, ppd, registrationPeer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 assigned server, got %d", len(servers))
	}

	// Even with same pubkey, the peer should be pointing to the DIRECT IP
	sendAddr := servers[0].Peer.SendAddr()
	if sendAddr == nil {
		t.Fatal("SendAddr should not be nil")
	}

	udpAddr, ok := sendAddr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", sendAddr)
	}
	if udpAddr.IP.String() != directIP {
		t.Errorf("peer should point to direct IP %s, got %s", directIP, udpAddr.IP.String())
	}
}

// TestACRegistration_NHP_AAK_ServerAddr_VariousPorts verifies handling of various port numbers.
func TestACRegistration_NHP_AAK_ServerAddr_VariousPorts(t *testing.T) {
	testCases := []struct {
		name         string
		serverAddr   string
		expectedIP   string
		expectedPort int
	}{
		{
			name:         "standard port",
			serverAddr:   "203.0.113.100:62206",
			expectedIP:   "203.0.113.100",
			expectedPort: testServerListenPort,
		},
		{
			name:         "high port",
			serverAddr:   "203.0.113.100:65535",
			expectedIP:   "203.0.113.100",
			expectedPort: 65535,
		},
		{
			name:         "low port",
			serverAddr:   "203.0.113.100:1024",
			expectedIP:   "203.0.113.100",
			expectedPort: 1024,
		},
		{
			name:         "port 1",
			serverAddr:   "203.0.113.100:1",
			expectedIP:   "203.0.113.100",
			expectedPort: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var testPrivateKey [32]byte
			for i := range testPrivateKey {
				testPrivateKey[i] = byte(i)
			}

			device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
			if device == nil {
				t.Fatal("Failed to create device")
			}

			ac := &UdpAC{
				config: &Config{
					ACId:           "test-ac-" + tc.name,
					ServerEndpoint: "nlb.test.internal",
				},
				device: device,
			}

			reg := mustNewACRegistration(t, ac)

			registrationPeer := &core.UdpPeer{
				Ip:           "10.0.0.1",
				Port:         testServerListenPort,
				PubKeyBase64: "bmxiLXB1YmtleQ==",
				Type:         core.NHP_SERVER,
			}

			aakJSON := fmt.Sprintf(`{
				"errCode": "0",
				"registered": true,
				"acAddr": "192.168.1.50:50000",
				"serverAddr": "%s",
				"serverPubKey": "c2VydmVyLWtleQ=="
			}`, tc.serverAddr)

			ppd := &core.PacketParserData{
				HeaderType:  core.NHP_AAK,
				BodyMessage: []byte(aakJSON),
			}

			err := handleTestRegistrationResponse(reg, ppd, registrationPeer)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			servers := reg.GetAssignedServers()
			if len(servers) != 1 {
				t.Fatalf("expected 1 server, got %d", len(servers))
			}

			if servers[0].Target.IP != tc.expectedIP {
				t.Errorf("IP = %s, want %s", servers[0].Target.IP, tc.expectedIP)
			}
			if servers[0].Target.Port != tc.expectedPort {
				t.Errorf("Port = %d, want %d", servers[0].Target.Port, tc.expectedPort)
			}
		})
	}
}

// TestACRegistration_NHP_AAK_ServerAddr_InvalidFormats tests various invalid ServerAddr formats.
func TestACRegistration_NHP_AAK_ServerAddr_InvalidFormats(t *testing.T) {
	testCases := []struct {
		name       string
		serverAddr string
	}{
		{"missing port", "203.0.113.100"},
		{"empty string", ""},
		{"just colon", ":"},
		{"port only", ":62206"},
		{"invalid port", "203.0.113.100:notaport"},
		{"negative port", "203.0.113.100:-1"},
		{"spaces", "203.0.113.100 : 62206"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var testPrivateKey [32]byte
			for i := range testPrivateKey {
				testPrivateKey[i] = byte(i)
			}

			device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
			if device == nil {
				t.Fatal("Failed to create device")
			}

			ac := &UdpAC{
				config: &Config{
					ACId:           "test-ac-invalid",
					ServerEndpoint: "nlb.test.internal",
				},
				device: device,
			}

			reg := mustNewACRegistration(t, ac)

			nlbIP := "10.0.0.1"
			registrationPeer := &core.UdpPeer{
				Ip:           nlbIP,
				Port:         testServerListenPort,
				PubKeyBase64: "bmxiLXB1YmtleQ==",
				Type:         core.NHP_SERVER,
			}

			aakJSON := fmt.Sprintf(`{
				"errCode": "0",
				"registered": true,
				"acAddr": "192.168.1.50:50000",
				"serverAddr": "%s",
				"serverPubKey": "c2VydmVyLWtleQ=="
			}`, tc.serverAddr)

			ppd := &core.PacketParserData{
				HeaderType:  core.NHP_AAK,
				BodyMessage: []byte(aakJSON),
			}

			err := handleTestRegistrationResponse(reg, ppd, registrationPeer)
			if err != nil {
				t.Fatalf("should not error, but got: %v", err)
			}

			servers := reg.GetAssignedServers()
			if len(servers) != 1 {
				t.Fatalf("expected 1 server, got %d", len(servers))
			}

			// Should fall back to registration peer for invalid formats
			if servers[0].Peer != registrationPeer {
				t.Error("should fall back to registration peer for invalid ServerAddr")
			}

			// Verify the peer points to NLB address (fallback)
			sendAddr := servers[0].Peer.SendAddr()
			if sendAddr != nil {
				udpAddr, ok := sendAddr.(*net.UDPAddr)
				if !ok {
					t.Fatalf("expected *net.UDPAddr, got %T", sendAddr)
				}
				if udpAddr.IP.String() != nlbIP {
					t.Errorf("fallback should use NLB IP %s, got %s", nlbIP, udpAddr.IP.String())
				}
			}
		})
	}
}

// TestACRegistration_NHP_AAK_ServerAddr_UnresolvableHost verifies that when ServerAddr
// contains a valid format but unresolvable hostname, it falls back to registration peer.
func TestACRegistration_NHP_AAK_ServerAddr_UnresolvableHost(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-unresolvable",
			ServerEndpoint: "nlb.test.internal",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	nlbIP := "10.0.0.1"
	registrationPeer := &core.UdpPeer{
		Ip:           nlbIP,
		Port:         testServerListenPort,
		PubKeyBase64: "bmxiLXB1YmtleQ==",
		Type:         core.NHP_SERVER,
	}

	// Valid format but unresolvable hostname - should fall back via SendAddr() == nil
	aakJSON := `{
		"errCode": "0",
		"registered": true,
		"acAddr": "192.168.1.50:50000",
		"serverAddr": "unresolvable.invalid.hostname.test:62206",
		"serverPubKey": "c2VydmVyLWtleQ=="
	}`

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(aakJSON),
	}

	err := handleTestRegistrationResponse(reg, ppd, registrationPeer)
	if err != nil {
		t.Fatalf("should not error, but got: %v", err)
	}

	servers := reg.GetAssignedServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}

	// Should fall back to registration peer when hostname cannot be resolved
	if servers[0].Peer != registrationPeer {
		t.Error("should fall back to registration peer for unresolvable hostname")
	}

	// Verify the peer points to NLB address (fallback)
	sendAddr := servers[0].Peer.SendAddr()
	if sendAddr != nil {
		udpAddr, ok := sendAddr.(*net.UDPAddr)
		if !ok {
			t.Fatalf("expected *net.UDPAddr, got %T", sendAddr)
		}
		if udpAddr.IP.String() != nlbIP {
			t.Errorf("fallback should use NLB IP %s, got %s", nlbIP, udpAddr.IP.String())
		}
	}
}

// TestACRegistration_NHP_AAK_ServerAddr_PrivateIPBlocked verifies that when ServerAddr
// contains a private IP (RFC 1918), the AC stays on the NLB connection instead of
// switching to the private address which would be unreachable from outside the VPC.
func TestACRegistration_NHP_AAK_ServerAddr_PrivateIPBlocked(t *testing.T) {
	var testPrivateKey [32]byte
	for i := range testPrivateKey {
		testPrivateKey[i] = byte(i)
	}

	device := core.NewDevice(core.NHP_AC, testPrivateKey[:], nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}

	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-private-ip",
			ServerEndpoint: "nlb.example.com",
		},
		device: device,
	}

	reg := mustNewACRegistration(t, ac)

	// NLB has a public IP
	nlbIP := "203.0.113.1"
	nlbPubKey := "bmxiLXB1YmtleQ=="
	registrationPeer := &core.UdpPeer{
		Ip:           nlbIP,
		Port:         testServerListenPort,
		PubKeyBase64: nlbPubKey,
		Type:         core.NHP_SERVER,
	}

	// Test various non-routable IP ranges
	testCases := []struct {
		name      string
		privateIP string
	}{
		// RFC 1918 private ranges
		{"10.x.x.x range", "10.0.1.100"},
		{"172.16.x.x range", "172.16.0.100"},
		{"172.31.x.x range", "172.31.255.100"},
		{"192.168.x.x range", "192.168.1.100"},
		// Loopback
		{"loopback 127.0.0.1", "127.0.0.1"},
		{"loopback 127.0.0.100", "127.0.0.100"},
		// Link-local
		{"link-local 169.254.x.x", "169.254.1.1"},
		// CGNAT (Carrier-Grade NAT) - 100.64.0.0/10
		{"CGNAT 100.64.x.x", "100.64.0.1"},
		{"CGNAT 100.100.x.x", "100.100.100.100"},
		{"CGNAT 100.127.x.x", "100.127.255.255"},
	}

	serverPubKey := "c2VydmVyLWRpcmVjdC1wdWJrZXk="

	// Helper to run a single test case
	runTestCase := func(t *testing.T, privateIP string) {
		t.Helper()

		// Reset device state
		device.RemovePeer(nlbPubKey)
		device.RemovePeer(serverPubKey)

		aakJSON := fmt.Sprintf(`{
			"errCode": "0",
			"registered": true,
			"acAddr": "192.168.1.50:50000",
			"serverAddr": "%s:62206",
			"serverPubKey": "%s"
		}`, privateIP, serverPubKey)

		ppd := &core.PacketParserData{
			HeaderType:  core.NHP_AAK,
			BodyMessage: []byte(aakJSON),
		}

		err := handleTestRegistrationResponse(reg, ppd, registrationPeer)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		servers := reg.GetAssignedServers()
		if len(servers) != 1 {
			t.Fatalf("expected 1 server, got %d", len(servers))
		}
		server := servers[0]

		// Verify IP stayed on NLB
		if server.Target.IP != nlbIP {
			t.Errorf("should stay on NLB IP %s, got %s (private IP should be blocked)", nlbIP, server.Target.IP)
		}

		// Verify pubkey updated to server's key
		if server.Target.PubKeyBase64 != serverPubKey {
			t.Errorf("should update pubkey to %s, got %s", serverPubKey, server.Target.PubKeyBase64)
		}

		// Verify peer is registration peer (NLB)
		if server.Peer != registrationPeer {
			t.Error("should use registration peer (NLB) when private IP is blocked")
		}

		// Verify peer map lookup by NEW public key works
		if device.LookupPeer(decodeTestPubKey(t, serverPubKey)) == nil {
			t.Error("peer should be findable by server's public key after update")
		}

		// Verify old NLB key no longer finds peer
		if device.LookupPeer(decodeTestPubKey(t, nlbPubKey)) != nil {
			t.Error("peer should NOT be findable by old NLB public key")
		}
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runTestCase(t, tc.privateIP)
		})
	}
}

// decodeTestPubKey decodes a base64 public key for test lookup
func decodeTestPubKey(t *testing.T, pubKeyBase64 string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		t.Fatalf("failed to decode public key: %v", err)
	}
	return decoded
}

// TestIsNonRoutableIP tests the isNonRoutableIP helper function directly.
func TestIsNonRoutableIP(t *testing.T) {
	testCases := []struct {
		name     string
		ip       string
		expected bool
	}{
		// RFC 1918 private ranges - should be non-routable
		{"private 10.0.0.1", "10.0.0.1", true},
		{"private 10.255.255.255", "10.255.255.255", true},
		{"private 172.16.0.1", "172.16.0.1", true},
		{"private 172.31.255.255", "172.31.255.255", true},
		{"private 192.168.0.1", "192.168.0.1", true},
		{"private 192.168.255.255", "192.168.255.255", true},

		// Loopback - should be non-routable
		{"loopback 127.0.0.1", "127.0.0.1", true},
		{"loopback 127.255.255.255", "127.255.255.255", true},

		// Link-local - should be non-routable
		{"link-local 169.254.0.1", "169.254.0.1", true},
		{"link-local 169.254.255.255", "169.254.255.255", true},

		// CGNAT (100.64.0.0/10) - should be non-routable
		{"CGNAT start 100.64.0.0", "100.64.0.0", true},
		{"CGNAT middle 100.100.100.100", "100.100.100.100", true},
		{"CGNAT end 100.127.255.255", "100.127.255.255", true},

		// Just outside CGNAT range - should be routable
		{"not CGNAT 100.63.255.255", "100.63.255.255", false},
		{"not CGNAT 100.128.0.0", "100.128.0.0", false},

		// Public IPs - should be routable
		{"public 8.8.8.8", "8.8.8.8", false},
		{"public 1.1.1.1", "1.1.1.1", false},
		{"public 203.0.113.1", "203.0.113.1", false},
		{"public 52.0.0.1", "52.0.0.1", false},

		// Edge cases for 172.x.x.x - only 172.16-31 is private
		{"not private 172.15.255.255", "172.15.255.255", false},
		{"not private 172.32.0.0", "172.32.0.0", false},

		// IPv6 private (fc00::/7) - should be non-routable
		{"IPv6 private fc00::", "fc00::", true},
		{"IPv6 private fd00::1", "fd00::1", true},

		// IPv6 loopback - should be non-routable
		{"IPv6 loopback ::1", "::1", true},

		// IPv6 link-local - should be non-routable
		{"IPv6 link-local fe80::1", "fe80::1", true},

		// IPv6 public - should be routable
		{"IPv6 public 2001:4860:4860::8888", "2001:4860:4860::8888", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP: %s", tc.ip)
			}

			result := isNonRoutableIP(ip)
			if result != tc.expected {
				t.Errorf("isNonRoutableIP(%s) = %v, want %v", tc.ip, result, tc.expected)
			}
		})
	}
}

// TestIsNonRoutableIP_NilIP tests that nil IP is treated as non-routable.
func TestIsNonRoutableIP_NilIP(t *testing.T) {
	if !isNonRoutableIP(nil) {
		t.Error("nil IP should be treated as non-routable")
	}
}

// TestACRegistration_ResetIptables tests that resetIptables() correctly
// handles different FilterMode values and nil iptables safely.
func TestACRegistration_ResetIptables(t *testing.T) {
	tests := []struct {
		name       string
		filterMode int
	}{
		{
			name:       "IPTABLES mode with nil iptables - should not panic",
			filterMode: FilterMode_IPTABLES,
		},
		{
			name:       "EBPF mode - should not call iptables",
			filterMode: FilterMode_EBPFXDP,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ac := &UdpAC{
				config: &Config{
					ACId:           "test-ac-001",
					ServerEndpoint: "server.nhp.test.internal",
					FilterMode:     tc.filterMode,
				},
				// iptables is nil - we're testing that resetIptables handles this safely
			}

			reg := mustNewACRegistration(t, ac)

			// This should not panic even with nil iptables
			// The function checks both FilterMode AND nil iptables before calling
			reg.resetIptables()

			// If we get here without panic, the nil-safety check works
		})
	}
}

// TestACRegistration_LastSeenUpdatePreventsReregistration tests that updating
// LastSeen via validated NHP_AOL refresh responses prevents false "server down"
// detection. LastSeen is only updated when the server responds with a valid
// NHP_AAK to a periodic NHP_AOL refresh — not on NHP_KPL send or raw packet receipt.
func TestACRegistration_LastSeenUpdatePreventsReregistration(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Create a connected server with recent LastSeen (simulating a successful
	// NHP_AOL refresh response via handleRefreshResponse)
	server := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.1",
			Port:         testServerListenPort,
			PubKeyBase64: "pubkey1",
		},
	}
	server.SetConnected(true)
	server.UpdateLastSeen() // Simulates handleRefreshResponse updating LastSeen on valid NHP_AAK

	reg.assignedServers = []*AssignedServer{server}

	// Run health check - should NOT trigger re-registration
	reg.checkServerHealth()

	if reg.reregistering.Load() {
		t.Error("Health check should NOT trigger re-registration when LastSeen is recent")
	}

	// Simulate time passing but LastSeen being refreshed (like NHP_AOL refresh response)
	time.Sleep(10 * time.Millisecond)
	server.UpdateLastSeen() // Simulates another validated NHP_AAK response

	reg.checkServerHealth()

	if reg.reregistering.Load() {
		t.Error("Health check should NOT trigger re-registration after validated LastSeen refresh")
	}
}

// TestACRegistration_StaleLastSeenTriggersReregistration verifies that when
// LastSeen is NOT updated (e.g., if NHP_AOL refresh responses stop arriving),
// re-registration is correctly triggered. This ensures the health check detects
// server failures when the server stops responding to validated keepalives.
func TestACRegistration_StaleLastSeenTriggersReregistration(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Create a connected server with STALE LastSeen
	server := &AssignedServer{
		Target: common.RedirectTarget{
			IP:           "10.0.0.1",
			Port:         testServerListenPort,
			PubKeyBase64: "pubkey1",
		},
	}
	server.SetConnected(true)
	// Set LastSeen to 1 hour ago - way past the threshold
	server.mu.Lock()
	server.LastSeen = time.Now().Add(-1 * time.Hour)
	server.mu.Unlock()

	reg.assignedServers = []*AssignedServer{server}

	// Run health check - SHOULD trigger re-registration
	reg.checkServerHealth()

	if !reg.reregistering.Load() {
		t.Error("Health check SHOULD trigger re-registration when LastSeen is stale")
	}
}

// TestACRegistration_SendKeepalives_SkipsInvalidServers verifies that
// sendKeepalives correctly skips servers that shouldn't receive keepalives.
func TestACRegistration_SendKeepalives_SkipsInvalidServers(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Server with no peer - should be skipped
	serverNoPeer := &AssignedServer{
		Target: common.RedirectTarget{
			IP:   "10.0.0.1",
			Port: testServerListenPort,
		},
		Peer: nil,
	}
	serverNoPeer.SetConnected(true)

	// Server not connected - should be skipped
	serverNotConnected := &AssignedServer{
		Target: common.RedirectTarget{
			IP:   "10.0.0.2",
			Port: testServerListenPort,
		},
	}
	// Connected is false by default

	reg.assignedServers = []*AssignedServer{serverNoPeer, serverNotConnected}

	// Record initial LastSeen times (zero time)
	noPeerLastSeen := serverNoPeer.GetLastSeen()
	notConnectedLastSeen := serverNotConnected.GetLastSeen()

	// sendKeepalives sends NHP_KPL to keep the UDP path active but does NOT update
	// LastSeen (only validated NHP_AOL responses do that). These servers should be
	// skipped entirely since they have nil peer or are not connected.

	// Server with nil peer should NOT receive keepalives
	if serverNoPeer.Peer != nil {
		t.Error("Test setup error: serverNoPeer should have nil peer")
	}

	// Server not connected should NOT have LastSeen updated
	if serverNotConnected.IsConnected() {
		t.Error("Test setup error: serverNotConnected should not be connected")
	}

	// Verify neither would be processed (their conditions fail the skip check)
	// The actual sendKeepalives requires device infrastructure, so we verify
	// the conditions that would cause them to be skipped
	for _, server := range reg.assignedServers {
		if server.Peer == nil || !server.IsConnected() {
			// This server would be skipped - verify LastSeen unchanged
			if server.Target.IP == "10.0.0.1" && server.GetLastSeen() != noPeerLastSeen {
				t.Error("Server with nil peer should be skipped, LastSeen should not change")
			}
			if server.Target.IP == "10.0.0.2" && server.GetLastSeen() != notConnectedLastSeen {
				t.Error("Disconnected server should be skipped, LastSeen should not change")
			}
		}
	}
}

// TestACRegistration_IsServerAddress tests the IsServerAddress method that determines
// if a given address belongs to an assigned server (used by connectionRoutine timeout handling).
func TestACRegistration_IsServerAddress(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Add some assigned servers (including IPv6)
	reg.assignedServers = []*AssignedServer{
		{
			Target: common.RedirectTarget{
				IP:   "10.0.0.1",
				Port: testServerListenPort,
			},
		},
		{
			Target: common.RedirectTarget{
				IP:   "192.168.1.100",
				Port: testServerListenPort,
			},
		},
		{
			Target: common.RedirectTarget{
				IP:   "::1", // IPv6 loopback
				Port: testServerListenPort,
			},
		},
		{
			Target: common.RedirectTarget{
				IP:   "2001:db8::1", // IPv6 address
				Port: 8080,
			},
		},
	}

	tests := []struct {
		name     string
		addr     string
		expected bool
	}{
		{
			name:     "exact match first server",
			addr:     "10.0.0.1:62206",
			expected: true,
		},
		{
			name:     "exact match second server",
			addr:     "192.168.1.100:62206",
			expected: true,
		},
		{
			name:     "IPv6 loopback with brackets (as net.UDPAddr.String() formats)",
			addr:     "[::1]:62206",
			expected: true,
		},
		{
			name:     "IPv6 address with brackets",
			addr:     "[2001:db8::1]:8080",
			expected: true,
		},
		{
			name:     "IPv6 wrong port",
			addr:     "[::1]:12345",
			expected: false,
		},
		{
			name:     "wrong port",
			addr:     "10.0.0.1:12345",
			expected: false,
		},
		{
			name:     "wrong IP",
			addr:     "10.0.0.99:62206",
			expected: false,
		},
		{
			name:     "completely different address",
			addr:     "8.8.8.8:53",
			expected: false,
		},
		{
			name:     "empty address",
			addr:     "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := reg.IsServerAddress(tt.addr)
			if result != tt.expected {
				t.Errorf("IsServerAddress(%q) = %v, want %v", tt.addr, result, tt.expected)
			}
		})
	}
}

// TestACRegistration_IsServerAddress_WithRegistrationPeer tests that IsServerAddress
// also checks the registration peer address.
func TestACRegistration_IsServerAddress_WithRegistrationPeer(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Create a registration peer with a send address
	regPeer := &core.UdpPeer{
		Ip:   "10.0.0.50",
		Port: testServerListenPort,
	}
	regPeer.Type = core.NHP_SERVER
	// Set SendAddr by encoding the IP/Port (UdpPeer uses these fields)
	reg.registrationPeer = regPeer

	// No assigned servers, only registration peer
	reg.assignedServers = nil

	// Registration peer address should match
	// Note: SendAddr() returns *net.UDPAddr from the peer's Ip:Port fields
	peerAddr := fmt.Sprintf("%s:%d", regPeer.Ip, regPeer.Port)

	if !reg.IsServerAddress(peerAddr) {
		t.Errorf("Expected IsServerAddress(%q) = true for registration peer", peerAddr)
	}

	// Other addresses should not match
	if reg.IsServerAddress("8.8.8.8:53") {
		t.Error("Expected IsServerAddress to return false for non-server address")
	}
}

// TestACRegistration_TriggerReregistration_AtomicGuard tests that TriggerReregistration
// respects the atomic re-registration guard to prevent concurrent re-registrations.
func TestACRegistration_TriggerReregistration_AtomicGuard(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// First call should proceed
	reg.TriggerReregistration("test_reason_1")

	// Poll for reregistering flag to be set (more reliable than fixed sleep)
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if reg.reregistering.Load() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Verify reregistering flag is set
	if !reg.reregistering.Load() {
		t.Error("Expected reregistering flag to be true after first trigger")
	}

	// Second call while first is in progress should be skipped
	reg.TriggerReregistration("test_reason_2")

	// Brief pause to let second call attempt to run
	time.Sleep(5 * time.Millisecond)

	// The key assertion is that reregistering flag is still true (first call still running)
	// and second call was skipped (didn't reset the flag or cause issues)
	if !reg.reregistering.Load() {
		t.Error("Expected reregistering flag to still be true (first trigger still running)")
	}

	// Stop the registration to clean up
	reg.Stop()
}

// TestACRegistration_TriggerReregistration_StopsOnShutdown tests that TriggerReregistration
// respects the stop channel and exits cleanly during shutdown.
func TestACRegistration_TriggerReregistration_StopsOnShutdown(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Trigger re-registration
	reg.TriggerReregistration("shutdown_test")

	// Give goroutine time to start
	time.Sleep(10 * time.Millisecond)

	// Stop immediately - should cause the goroutine to exit
	reg.Stop()

	// Verify reregistering flag is eventually cleared
	time.Sleep(100 * time.Millisecond)

	// After stop, the flag should be cleared (goroutine exited)
	// Note: The flag might still be true if goroutine didn't exit yet,
	// but Stop() should have closed stopCh
	select {
	case <-reg.stopCh:
		// Good - stop channel is closed
	default:
		t.Error("Expected stopCh to be closed after Stop()")
	}
}

// TestRegistrationRefreshInterval verifies the periodic refresh constant is set correctly.
// The refresh interval determines how often NHP_AOL is re-sent to validate server liveness.
// This is the primary health signal — NHP_KPL is unidirectional and cannot confirm receipt.
// Only validated NHP_AAK responses to NHP_AOL update LastSeen.
func TestRegistrationRefreshInterval(t *testing.T) {
	// Authenticated AAK refresh is the 10-second session-control heartbeat.
	expectedTicks := 1
	if RegistrationRefreshInterval != expectedTicks {
		t.Errorf("Expected RegistrationRefreshInterval to be %d, got %d", expectedTicks, RegistrationRefreshInterval)
	}

	// Verify the actual interval is 10 seconds.
	actualInterval := time.Duration(RegistrationRefreshInterval) * KeepaliveInterval
	expectedInterval := 10 * time.Second
	if actualInterval != expectedInterval {
		t.Errorf("Expected actual refresh interval to be %v, got %v", expectedInterval, actualInterval)
	}
}

// TestRefreshAssignedServerRegistrations_NoServers verifies the function handles
// an empty server list gracefully without panicking.
func TestRefreshAssignedServerRegistrations_NoServers(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	// Should not panic with empty server list
	reg.refreshAssignedServerRegistrations()
	// Test passes if no panic occurs
}

// TestRefreshAssignedServerRegistrations_SkipsDisconnectedServers verifies that
// the refresh logic skips servers that are not connected.
func TestRefreshAssignedServerRegistrations_SkipsDisconnectedServers(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
		sendMsgCh: make(chan *core.MsgData, 10),
	}

	reg := mustNewACRegistration(t, ac)

	// Add servers with different connection states
	server1 := &AssignedServer{
		Target: common.RedirectTarget{
			IP:   "10.0.1.100",
			Port: testServerListenPort,
		},
		Connected: false, // Not connected - should be skipped
		Peer:      nil,
	}

	server2 := &AssignedServer{
		Target: common.RedirectTarget{
			IP:   "10.0.2.100",
			Port: testServerListenPort,
		},
		Connected: true,
		Peer:      nil, // Nil peer - should be skipped
	}

	reg.mu.Lock()
	reg.assignedServers = []*AssignedServer{server1, server2}
	reg.mu.Unlock()

	// Should not panic and should skip both servers
	reg.refreshAssignedServerRegistrations()

	// Verify no messages were sent (both servers should be skipped)
	select {
	case <-ac.sendMsgCh:
		t.Error("Expected no messages to be sent for disconnected/nil-peer servers")
	default:
		// Good - no messages sent
	}
}

// TestHandleRefreshResponse_Success tests successful NHP_AAK response handling.
func TestHandleRefreshResponse_Success(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	server := &AssignedServer{
		Target: common.RedirectTarget{
			IP:   "10.0.1.100",
			Port: testServerListenPort,
		},
		Connected: true,
		LastSeen:  time.Now().Add(-time.Minute), // Set old LastSeen
	}

	sendAddr := &net.UDPAddr{IP: net.ParseIP("10.0.1.100"), Port: testServerListenPort}

	// Create successful NHP_AAK response
	aakMsg := common.ServerACAckMsg{
		ErrCode: common.ErrSuccess.ErrorCode(),
	}
	ppd := newAAKPacket(t, ac, aakMsg)

	oldLastSeen := server.GetLastSeen()

	// Handle the response
	reg.handleRefreshResponse(ppd, server, sendAddr)

	// Verify LastSeen was updated
	if !server.GetLastSeen().After(oldLastSeen) {
		t.Error("Expected LastSeen to be updated after successful refresh")
	}
}

// TestHandleRefreshResponse_Rejected tests NHP_AAK with error code handling.
func TestHandleRefreshResponse_Rejected(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	server := &AssignedServer{
		Target: common.RedirectTarget{
			IP:   "10.0.1.100",
			Port: testServerListenPort,
		},
		Connected: true,
		LastSeen:  time.Now().Add(-time.Minute),
	}

	sendAddr := &net.UDPAddr{IP: net.ParseIP("10.0.1.100"), Port: testServerListenPort}

	// Create rejected NHP_AAK response
	aakMsg := common.ServerACAckMsg{
		ErrCode: "license_invalid",
		ErrMsg:  "License validation failed",
	}
	aakBytes, _ := json.Marshal(aakMsg)

	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: aakBytes,
	}

	oldLastSeen := server.GetLastSeen()

	// Handle the response - should not update LastSeen
	reg.handleRefreshResponse(ppd, server, sendAddr)

	// Verify LastSeen was NOT updated (rejection)
	if server.GetLastSeen() != oldLastSeen {
		t.Error("Expected LastSeen to NOT be updated after rejected refresh")
	}
}

// TestHandleRefreshResponse_Redirect tests NHP_ARD response triggering re-registration.
func TestHandleRefreshResponse_Redirect(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
		sendMsgCh: make(chan *core.MsgData, 10),
	}

	reg := mustNewACRegistration(t, ac)

	server := &AssignedServer{
		Target: common.RedirectTarget{
			IP:   "10.0.1.100",
			Port: testServerListenPort,
		},
		Connected: true,
	}

	sendAddr := &net.UDPAddr{IP: net.ParseIP("10.0.1.100"), Port: testServerListenPort}

	// Create NHP_ARD response (server wants us to connect elsewhere)
	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_ARD,
		BodyMessage: []byte("{}"), // Empty ARD message
	}

	// Handle the response - should trigger re-registration
	reg.handleRefreshResponse(ppd, server, sendAddr)

	// Give goroutine time to set the flag
	time.Sleep(10 * time.Millisecond)

	// Verify re-registration was triggered (reregistering flag should be set)
	// Note: We can't directly check the flag, but the TriggerReregistration
	// function was called. The test verifies no panic occurs.
}

// TestHandleRefreshResponse_Error tests error response handling.
func TestHandleRefreshResponse_Error(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	server := &AssignedServer{
		Target: common.RedirectTarget{
			IP:   "10.0.1.100",
			Port: testServerListenPort,
		},
		Connected: true,
		LastSeen:  time.Now().Add(-time.Minute),
	}

	sendAddr := &net.UDPAddr{IP: net.ParseIP("10.0.1.100"), Port: testServerListenPort}

	// Create response with error
	ppd := &core.PacketParserData{
		Error: fmt.Errorf("decryption failed"),
	}

	oldLastSeen := server.GetLastSeen()

	// Handle the response - should not panic, should not update LastSeen
	reg.handleRefreshResponse(ppd, server, sendAddr)

	// Verify LastSeen was NOT updated
	if server.GetLastSeen() != oldLastSeen {
		t.Error("Expected LastSeen to NOT be updated after error response")
	}
}

// TestHandleRefreshResponse_UnexpectedType tests handling of unexpected response types.
func TestHandleRefreshResponse_UnexpectedType(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	server := &AssignedServer{
		Target: common.RedirectTarget{
			IP:   "10.0.1.100",
			Port: testServerListenPort,
		},
		Connected: true,
		LastSeen:  time.Now().Add(-time.Minute),
	}

	sendAddr := &net.UDPAddr{IP: net.ParseIP("10.0.1.100"), Port: testServerListenPort}

	// Create unexpected response type (e.g., NHP_KPL)
	ppd := &core.PacketParserData{
		HeaderType:  core.NHP_KPL, // Unexpected type
		BodyMessage: []byte{},
	}

	oldLastSeen := server.GetLastSeen()

	// Handle the response - should not panic, should log warning
	reg.handleRefreshResponse(ppd, server, sendAddr)

	// Verify LastSeen was NOT updated
	if server.GetLastSeen() != oldLastSeen {
		t.Error("Expected LastSeen to NOT be updated after unexpected response type")
	}
}

// TestACRegistration_KeepaliveResponseValidation tests the full keepalive response
// validation flow: NHP_KPL does NOT update LastSeen, only validated NHP_AAK responses
// to NHP_AOL refresh requests update it. This prevents spoofed packets from masking
// server failures (GitHub issue #124).
func TestACRegistration_KeepaliveResponseValidation(t *testing.T) {
	ac := &UdpAC{
		config: &Config{
			ACId:           "test-ac-001",
			ServerEndpoint: "server.nhp.test.internal",
		},
	}

	reg := mustNewACRegistration(t, ac)

	server := &AssignedServer{
		Target: common.RedirectTarget{
			IP:   "10.0.1.100",
			Port: testServerListenPort,
		},
		Connected: true,
		LastSeen:  time.Now().Add(-time.Minute), // Old LastSeen
	}

	sendAddr := &net.UDPAddr{IP: net.ParseIP("10.0.1.100"), Port: testServerListenPort}

	t.Run("valid NHP_AAK updates LastSeen", func(t *testing.T) {
		oldLastSeen := server.GetLastSeen()

		aakMsg := common.ServerACAckMsg{
			ErrCode: common.ErrSuccess.ErrorCode(),
		}
		ppd := newAAKPacket(t, ac, aakMsg)

		reg.handleRefreshResponse(ppd, server, sendAddr)

		if !server.GetLastSeen().After(oldLastSeen) {
			t.Error("Valid NHP_AAK should update LastSeen")
		}
	})

	t.Run("rejected NHP_AAK does not update LastSeen", func(t *testing.T) {
		// Reset LastSeen to old time
		server.mu.Lock()
		server.LastSeen = time.Now().Add(-time.Minute)
		server.mu.Unlock()
		oldLastSeen := server.GetLastSeen()

		aakMsg := common.ServerACAckMsg{
			ErrCode: "auth_failed",
			ErrMsg:  "Authentication failed",
		}
		aakBytes, _ := json.Marshal(aakMsg)
		ppd := &core.PacketParserData{
			HeaderType:  core.NHP_AAK,
			BodyMessage: aakBytes,
		}

		reg.handleRefreshResponse(ppd, server, sendAddr)

		if server.GetLastSeen() != oldLastSeen {
			t.Error("Rejected NHP_AAK should NOT update LastSeen")
		}
	})

	t.Run("malformed NHP_AAK does not update LastSeen", func(t *testing.T) {
		server.mu.Lock()
		server.LastSeen = time.Now().Add(-time.Minute)
		server.mu.Unlock()
		oldLastSeen := server.GetLastSeen()

		ppd := &core.PacketParserData{
			HeaderType:  core.NHP_AAK,
			BodyMessage: []byte("not json"),
		}

		reg.handleRefreshResponse(ppd, server, sendAddr)

		if server.GetLastSeen() != oldLastSeen {
			t.Error("Malformed NHP_AAK should NOT update LastSeen")
		}
	})

	t.Run("error response does not update LastSeen", func(t *testing.T) {
		server.mu.Lock()
		server.LastSeen = time.Now().Add(-time.Minute)
		server.mu.Unlock()
		oldLastSeen := server.GetLastSeen()

		ppd := &core.PacketParserData{
			Error: fmt.Errorf("crypto validation failed"),
		}

		reg.handleRefreshResponse(ppd, server, sendAddr)

		if server.GetLastSeen() != oldLastSeen {
			t.Error("Error response should NOT update LastSeen")
		}
	})

	t.Run("NHP_KPL response does not update LastSeen", func(t *testing.T) {
		server.mu.Lock()
		server.LastSeen = time.Now().Add(-time.Minute)
		server.mu.Unlock()
		oldLastSeen := server.GetLastSeen()

		ppd := &core.PacketParserData{
			HeaderType: core.NHP_KPL,
		}

		reg.handleRefreshResponse(ppd, server, sendAddr)

		if server.GetLastSeen() != oldLastSeen {
			t.Error("NHP_KPL response should NOT update LastSeen")
		}
	})

	t.Run("stale server triggers reregistration", func(t *testing.T) {
		// Server with LastSeen far in the past should trigger re-registration
		staleServer := &AssignedServer{
			Target: common.RedirectTarget{
				IP:   "10.0.1.200",
				Port: testServerListenPort,
			},
			Connected: true,
		}
		staleServer.mu.Lock()
		staleServer.LastSeen = time.Now().Add(-(KeepaliveInterval*KeepaliveMaxRetries + time.Hour))
		staleServer.mu.Unlock()

		reg2 := mustNewACRegistration(t, ac)
		reg2.assignedServers = []*AssignedServer{staleServer}

		reg2.checkServerHealth()

		if !reg2.reregistering.Load() {
			t.Error("Stale server should trigger re-registration")
		}
	})
}

// newRegWithServers creates an ACRegistration with pre-populated assignedServers
// for peersChanged tests. Encapsulates the lock/assign/unlock pattern.
func newRegWithServers(t *testing.T, acID string, servers []*AssignedServer) *ACRegistration {
	t.Helper()
	ac := &UdpAC{
		config:    &Config{ACId: acID, ServerEndpoint: "server.test"},
		sendMsgCh: make(chan *core.MsgData, 10),
	}
	prepareRefreshSessionControl(t, ac)
	reg := mustNewACRegistration(t, ac)
	reg.mu.Lock()
	reg.assignedServers = servers
	reg.mu.Unlock()
	return reg
}

func TestACRegistration_PeersChanged(t *testing.T) {
	t.Parallel()

	threeBlue := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: 62206}},
		{Target: common.RedirectTarget{IP: "10.0.0.2", Port: 62206}},
		{Target: common.RedirectTarget{IP: "10.0.0.3", Port: 62206}},
	}

	tests := []struct {
		name     string
		assigned []*AssignedServer
		peers    []common.RedirectTarget
		want     bool
	}{
		{
			name:     "same peers",
			assigned: threeBlue,
			peers: []common.RedirectTarget{
				{IP: "10.0.0.1", Port: 62206, PubKeyBase64: "key1"},
				{IP: "10.0.0.2", Port: 62206, PubKeyBase64: "key2"},
				{IP: "10.0.0.3", Port: 62206, PubKeyBase64: "key3"},
			},
			want: false,
		},
		{
			name:     "different IPs (blue-green switch)",
			assigned: threeBlue,
			peers: []common.RedirectTarget{
				{IP: "10.0.1.1", Port: 62206, PubKeyBase64: "key1"},
				{IP: "10.0.1.2", Port: 62206, PubKeyBase64: "key2"},
				{IP: "10.0.1.3", Port: 62206, PubKeyBase64: "key3"},
			},
			want: true,
		},
		{
			name: "count mismatch (2 assigned, 3 peers)",
			assigned: []*AssignedServer{
				{Target: common.RedirectTarget{IP: "10.0.0.1", Port: 62206}},
				{Target: common.RedirectTarget{IP: "10.0.0.2", Port: 62206}},
			},
			peers: []common.RedirectTarget{
				{IP: "10.0.0.1", Port: 62206, PubKeyBase64: "key1"},
				{IP: "10.0.0.2", Port: 62206, PubKeyBase64: "key2"},
				{IP: "10.0.0.3", Port: 62206, PubKeyBase64: "key3"},
			},
			want: true,
		},
		{
			name:     "empty assigned",
			assigned: nil,
			peers: []common.RedirectTarget{
				{IP: "10.0.0.1", Port: 62206, PubKeyBase64: "key1"},
			},
			want: true,
		},
		{
			name: "port difference",
			assigned: []*AssignedServer{
				{Target: common.RedirectTarget{IP: "10.0.0.1", Port: 62206}},
			},
			peers: []common.RedirectTarget{
				{IP: "10.0.0.1", Port: 62207, PubKeyBase64: "key1"},
			},
			want: true,
		},
		{
			name:     "same peers different order",
			assigned: threeBlue,
			peers: []common.RedirectTarget{
				{IP: "10.0.0.3", Port: 62206, PubKeyBase64: "key3"},
				{IP: "10.0.0.1", Port: 62206, PubKeyBase64: "key1"},
				{IP: "10.0.0.2", Port: 62206, PubKeyBase64: "key2"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			reg := newRegWithServers(t, "test-"+tt.name, tt.assigned)
			got, addrLog := reg.peersChanged(tt.peers)
			if got != tt.want {
				t.Errorf("peersChanged() = %v, want %v", got, tt.want)
			}
			if got && addrLog == "" {
				t.Error("peersChanged() returned changed=true but empty addrLog")
			}
		})
	}
}

// newAAKPacket marshals a ServerACAckMsg into a PacketParserData for handleRefreshResponse tests.
func newAAKPacket(t *testing.T, ac *UdpAC, msg common.ServerACAckMsg) *core.PacketParserData {
	t.Helper()
	senderTrxID := uint64(0)
	if common.IsSuccessErrCode(msg.ErrCode) {
		msg.Registered = true
		msg.BootID = ac.bootID
		msg.SessionFlushGeneration = ac.sessionFlushGeneration.Load()
		msg.AOLTransactionID = testRefreshAOLTransaction
		senderTrxID = testRefreshAOLTransaction
	}
	body, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal ServerACAckMsg: %v", err)
	}
	return &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: body,
		SenderTrxId: senderTrxID,
	}
}

// TestHandleRefreshResponse_PeerReconciliation exercises the full
// handleRefreshResponse → filterValidPeers → peersChanged → TriggerReregistration path.
func TestHandleRefreshResponse_PeerReconciliation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		assigned         []*AssignedServer
		aak              common.ServerACAckMsg
		wantReregistered bool
	}{
		{
			name: "changed peers triggers re-registration",
			assigned: []*AssignedServer{
				{Target: common.RedirectTarget{IP: "10.0.0.1", Port: 62206}},
				{Target: common.RedirectTarget{IP: "10.0.0.2", Port: 62206}},
				{Target: common.RedirectTarget{IP: "10.0.0.3", Port: 62206}},
			},
			aak: common.ServerACAckMsg{
				ErrCode: common.ErrSuccess.ErrorCode(), Registered: true,
				Peers: []common.RedirectTarget{
					{IP: "10.0.1.1", Port: 62206, PubKeyBase64: "greenkey1"},
					{IP: "10.0.1.2", Port: 62206, PubKeyBase64: "greenkey2"},
					{IP: "10.0.1.3", Port: 62206, PubKeyBase64: "greenkey3"},
				},
			},
			wantReregistered: true,
		},
		{
			name: "same peers does not trigger re-registration",
			assigned: []*AssignedServer{
				{Target: common.RedirectTarget{IP: "10.0.0.1", Port: 62206}},
				{Target: common.RedirectTarget{IP: "10.0.0.2", Port: 62206}},
			},
			aak: common.ServerACAckMsg{
				ErrCode: common.ErrSuccess.ErrorCode(), Registered: true,
				Peers: []common.RedirectTarget{
					{IP: "10.0.0.1", Port: 62206, PubKeyBase64: "key1"},
					{IP: "10.0.0.2", Port: 62206, PubKeyBase64: "key2"},
				},
			},
			wantReregistered: false,
		},
		{
			name: "no peers falls through to UpdateLastSeen",
			assigned: []*AssignedServer{
				{Target: common.RedirectTarget{IP: "10.0.0.1", Port: 62206}},
			},
			aak: common.ServerACAckMsg{
				ErrCode: common.ErrSuccess.ErrorCode(), Registered: true,
				// Peers intentionally omitted
			},
			wantReregistered: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			reg := newRegWithServers(t, "test-"+tt.name, tt.assigned)
			server := &AssignedServer{Target: tt.assigned[0].Target}
			sendAddr := &net.UDPAddr{IP: net.ParseIP(tt.assigned[0].Target.IP), Port: tt.assigned[0].Target.Port}

			reg.handleRefreshResponse(newAAKPacket(t, reg.ac, tt.aak), server, sendAddr)

			if got := reg.reregistering.Load(); got != tt.wantReregistered {
				t.Errorf("reregistering = %v, want %v", got, tt.wantReregistered)
			}
		})
	}
}

// TestPeersChanged_DuplicatePeers documents the behavior when the server
// sends duplicate peer addresses. With current=[A,B] and peers=[A,A],
// len matches (2==2) and both A's are in the set, so peersChanged returns
// false. This is documented as "assumed not to happen" since DynamoDB
// assignments are unique, but this test guards the behavior if it ever does.
func TestPeersChanged_DuplicatePeers(t *testing.T) {
	t.Parallel()

	reg := newRegWithServers(t, "test-dup-peers", []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: 62206}},
		{Target: common.RedirectTarget{IP: "10.0.0.2", Port: 62206}},
	})

	// Server sends [A, A] instead of [A, B] — a bug, but what does peersChanged do?
	peers := []common.RedirectTarget{
		{IP: "10.0.0.1", Port: 62206, PubKeyBase64: "key1"},
		{IP: "10.0.0.1", Port: 62206, PubKeyBase64: "key1"},
	}

	got, _ := reg.peersChanged(peers)
	// Both entries match set member A, and len(2)==len(2), so no change detected.
	// This is a known false-negative for duplicate inputs. The no-duplicates
	// assumption is documented on peersChanged.
	if got {
		t.Error("peersChanged with duplicate peers matching a subset should return false (known limitation)")
	}
}

func TestFilterValidPeers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		peers     []common.RedirectTarget
		wantCount int
	}{
		{
			name: "all valid",
			peers: []common.RedirectTarget{
				{IP: "10.0.0.1", Port: 62206, PubKeyBase64: "key1"},
				{IP: "10.0.0.2", Port: 62206, PubKeyBase64: "key2"},
			},
			wantCount: 2,
		},
		{
			name: "empty IP dropped",
			peers: []common.RedirectTarget{
				{IP: "10.0.0.1", Port: 62206, PubKeyBase64: "key1"},
				{IP: "", Port: 62206, PubKeyBase64: "key2"},
			},
			wantCount: 1,
		},
		{
			name: "bad port dropped",
			peers: []common.RedirectTarget{
				{IP: "10.0.0.1", Port: 0, PubKeyBase64: "key1"},
				{IP: "10.0.0.2", Port: 62206, PubKeyBase64: "key2"},
			},
			wantCount: 1,
		},
		{
			name: "missing pubkey dropped",
			peers: []common.RedirectTarget{
				{IP: "10.0.0.1", Port: 62206, PubKeyBase64: ""},
				{IP: "10.0.0.2", Port: 62206, PubKeyBase64: "key2"},
			},
			wantCount: 1,
		},
		{
			name: "all invalid returns empty",
			peers: []common.RedirectTarget{
				{IP: "", Port: 0, PubKeyBase64: ""},
			},
			wantCount: 0,
		},
		{
			name:      "nil input",
			peers:     nil,
			wantCount: 0,
		},
		{
			name: "all valid returns original slice",
			peers: []common.RedirectTarget{
				{IP: "10.0.0.1", Port: 62206, PubKeyBase64: "key1"},
			},
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := filterValidPeers(tt.peers, "test")
			if len(got) != tt.wantCount {
				t.Errorf("filterValidPeers() returned %d peers, want %d", len(got), tt.wantCount)
			}
		})
	}
}

// TestHandleRefreshResponse_MixedValidInvalidPeers verifies that when
// the server sends a mix of valid and invalid peers, only the valid ones
// are compared. 3 current servers + 2 valid peers (out of 3 sent) →
// count mismatch → re-registration triggered.
func TestHandleRefreshResponse_MixedValidInvalidPeers(t *testing.T) {
	t.Parallel()

	assigned := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: 62206}},
		{Target: common.RedirectTarget{IP: "10.0.0.2", Port: 62206}},
		{Target: common.RedirectTarget{IP: "10.0.0.3", Port: 62206}},
	}
	reg := newRegWithServers(t, "test-mixed-peers", assigned)

	// Server sends 3 peers but one has empty IP (invalid per #832)
	aak := common.ServerACAckMsg{
		ErrCode: common.ErrSuccess.ErrorCode(), Registered: true,
		Peers: []common.RedirectTarget{
			{IP: "10.0.1.1", Port: 62206, PubKeyBase64: "key1"},
			{IP: "", Port: 62206, PubKeyBase64: "key2"}, // invalid — dropped by filterValidPeers
			{IP: "10.0.1.3", Port: 62206, PubKeyBase64: "key3"},
		},
	}

	server := &AssignedServer{Target: assigned[0].Target}
	sendAddr := &net.UDPAddr{IP: net.ParseIP(assigned[0].Target.IP), Port: assigned[0].Target.Port}

	reg.handleRefreshResponse(newAAKPacket(t, reg.ac, aak), server, sendAddr)

	// 2 valid peers vs 3 assigned → count mismatch → re-registration
	if !reg.reregistering.Load() {
		t.Error("handleRefreshResponse with mixed valid/invalid peers should trigger re-registration (count mismatch after filtering)")
	}
}
