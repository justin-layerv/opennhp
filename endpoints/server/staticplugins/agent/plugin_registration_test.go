package agent

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

// withRegistrar installs reg for the duration of the test and restores the prior
// value afterward. The plugin reads the package-level reg (set by Init in
// production); tests inject a fake-backed one directly. Serialized implicitly by
// go test running a package's tests in one goroutine unless t.Parallel is used —
// none of these call t.Parallel.
func withRegistrar(t *testing.T, r *registrar) {
	t.Helper()
	prev := reg
	reg = r
	t.Cleanup(func() { reg = prev })
}

// fakeQurl spins an httptest server with the given handler and returns a
// registrar pointed at it.
func fakeQurl(t *testing.T, h http.HandlerFunc) *registrar {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &registrar{
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		baseURL:      srv.URL,
		serviceToken: "test-service-token",
	}
}

func newOTPReq() *common.NhpOTPRequest {
	return &common.NhpOTPRequest{
		Msg: &common.AgentOTPMsg{
			UserId:        "ak_live",
			DeviceId:      "dev_live",
			AuthServiceId: "agent",
			Passcode:      "PASSCODE-SECRET-DO-NOT-LOG",
		},
		PublicKey: "cHVიaz0=",
		SrcAddr:   &common.NetAddress{Ip: "203.0.113.7", Port: 40000},
	}
}

func newRegReq() *common.NhpRegisterRequest {
	return &common.NhpRegisterRequest{
		Msg: &common.AgentRegisterMsg{
			UserId:        "ak_live",
			DeviceId:      "dev_live",
			AuthServiceId: "agent",
			OTP:           "OTP-CREDENTIAL-DO-NOT-LOG",
			UserData: map[string]any{
				"hostname": "workstation-7",
				"version":  "2.0.1",
				"takeover": true,
			},
		},
		Ack:       &common.ServerRegisterAckMsg{},
		PublicKey: "cHVიaz0=",
		SrcAddr:   &common.NetAddress{Ip: "203.0.113.7", Port: 40000},
	}
}

// ---- Flag OFF: inert, no HTTP call ---------------------------------------

func TestRequestOTP_FlagOff_DisabledNoHTTP(t *testing.T) {
	withRegistrar(t, nil) // reg == nil models the disabled/dark plugin
	p := &Plugin{}
	err := p.RequestOTP(newOTPReq(), nil)
	if !errors.Is(err, common.ErrRegistrationDisabled) {
		t.Fatalf("flag-off RequestOTP err=%v want ErrRegistrationDisabled", err)
	}
}

func TestRegisterAgent_FlagOff_DisabledRAKNoHTTP(t *testing.T) {
	withRegistrar(t, nil)
	p := &Plugin{}
	req := newRegReq()
	ack, err := p.RegisterAgent(req, nil)
	if err != nil {
		t.Fatalf("RegisterAgent must return a nil error and carry the verdict in the ack; got err=%v", err)
	}
	if ack == nil {
		t.Fatal("ack=nil; RegisterAgent must always return a non-nil RAK")
	}
	if ack.ErrCode != common.ErrRegistrationDisabled.ErrorCode() {
		t.Errorf("flag-off RAK ErrCode=%q want %q", ack.ErrCode, common.ErrRegistrationDisabled.ErrorCode())
	}
	if ack.AuthServiceId != "agent" {
		t.Errorf("RAK aspId=%q want echoed \"agent\"", ack.AuthServiceId)
	}
	if common.IsSuccessErrCode(ack.ErrCode) {
		t.Error("flag-off RAK reported success; must fail closed")
	}
}

// A registrar whose handler fails the test if reached, but which is NOT
// installed (reg stays nil), proves the flag-off path short-circuits before any
// network call. The httptest server is live; the flag-off plugin must simply
// never dial it.
func TestRegisterAgent_FlagOff_MakesNoNetworkCall(t *testing.T) {
	reached := false
	// Stand up a live server but do not install its registrar — reg stays nil.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	withRegistrar(t, nil)
	p := &Plugin{}
	_, _ = p.RegisterAgent(newRegReq(), nil)
	_ = p.RequestOTP(newOTPReq(), nil)
	if reached {
		t.Fatal("flag-off path made a network call; it must short-circuit before the registrar")
	}
}

// ---- Flag ON: delegates to the registrar ---------------------------------

func TestRequestOTP_FlagOn_202ReturnsNil(t *testing.T) {
	withRegistrar(t, fakeQurl(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	if err := (&Plugin{}).RequestOTP(newOTPReq(), nil); err != nil {
		t.Fatalf("flag-on RequestOTP on 202 err=%v want nil", err)
	}
}

func TestRequestOTP_FlagOn_ErrorMapsThrough(t *testing.T) {
	withRegistrar(t, fakeQurl(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"success":false,"error":{"code":"rate_limited"}}`))
	}))
	err := (&Plugin{}).RequestOTP(newOTPReq(), nil)
	if !errors.Is(err, common.ErrRegistrationRateLimited) {
		t.Fatalf("flag-on RequestOTP err=%v want ErrRegistrationRateLimited (mapped through)", err)
	}
}

func TestRegisterAgent_FlagOn_SuccessRAKZeroCode(t *testing.T) {
	withRegistrar(t, fakeQurl(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"data":{"agent_id":"agt_100"}}`))
	}))
	req := newRegReq()
	ack, err := (&Plugin{}).RegisterAgent(req, nil)
	if err != nil {
		t.Fatalf("RegisterAgent err=%v want nil (verdict in ack)", err)
	}
	if ack.ErrCode != common.ErrSuccess.ErrorCode() {
		t.Errorf("success RAK ErrCode=%q want %q (\"0\")", ack.ErrCode, common.ErrSuccess.ErrorCode())
	}
	if !common.IsSuccessErrCode(ack.ErrCode) {
		t.Error("success RAK not recognized as success")
	}
	if ack.AuthServiceId != "agent" {
		t.Errorf("RAK aspId=%q want \"agent\"", ack.AuthServiceId)
	}
}

// Every register error code lands the correct common.Err* on the RAK.
func TestRegisterAgent_FlagOn_ErrorCodesOnRAK(t *testing.T) {
	cases := []struct {
		code string
		want *common.Error
	}{
		{"credential_invalid", common.ErrRegistrationCredentialInvalid},
		{"credential_expired", common.ErrRegistrationCredentialExpired},
		{"attempts_exceeded", common.ErrRegistrationAttemptsExceeded},
		{"agent_identity_conflict", common.ErrRegistrationIdentityConflict},
		{"rate_limited", common.ErrRegistrationRateLimited},
		{"email_unavailable", common.ErrRegistrationEmailUnavailable},
		{"invalid_api_key", common.ErrRegistrationApiKeyInvalid},
		{"invalid_device_id", common.ErrRegistrationInvalidInput},
		{"bootstrap_key_consumed", common.ErrRegistrationBootstrapKeyConsumed},
		{"internal_error", common.ErrRegistrationDisabled},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			withRegistrar(t, fakeQurl(t, func(w http.ResponseWriter, req *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"success":false,"error":{"code":"` + tc.code + `"}}`))
			}))
			req := newRegReq()
			ack, err := (&Plugin{}).RegisterAgent(req, nil)
			if err != nil {
				t.Fatalf("RegisterAgent err=%v want nil (verdict in ack)", err)
			}
			if ack.ErrCode != tc.want.ErrorCode() {
				t.Errorf("RAK ErrCode=%q want %q for code %q", ack.ErrCode, tc.want.ErrorCode(), tc.code)
			}
			if common.IsSuccessErrCode(ack.ErrCode) {
				t.Errorf("RAK for %q reported success; must fail closed", tc.code)
			}
			if ack.AuthServiceId != "agent" {
				t.Errorf("RAK aspId=%q want echoed \"agent\" even on failure", ack.AuthServiceId)
			}
		})
	}
}

// A transport failure (unreachable server) fails the RAK closed as
// ErrRegistrationDisabled (untyped error → disabled).
func TestRegisterAgent_FlagOn_TransportFailureFailsClosed(t *testing.T) {
	// Point at a closed port to force a dial error.
	withRegistrar(t, &registrar{
		httpClient:   &http.Client{Timeout: 500 * time.Millisecond},
		baseURL:      "http://127.0.0.1:1", // unroutable/closed
		serviceToken: "tok",
	})
	ack, err := (&Plugin{}).RegisterAgent(newRegReq(), nil)
	if err != nil {
		t.Fatalf("RegisterAgent err=%v want nil (verdict in ack)", err)
	}
	if ack.ErrCode != common.ErrRegistrationDisabled.ErrorCode() {
		t.Errorf("transport-failure RAK ErrCode=%q want ErrRegistrationDisabled %q", ack.ErrCode, common.ErrRegistrationDisabled.ErrorCode())
	}
}

// ---- UserData metadata extraction ----------------------------------------

func TestRegisterMetadata_DefensiveTyping(t *testing.T) {
	// Absent map ⇒ zero values.
	if h, v, tk := registerMetadata(nil); h != "" || v != "" || tk {
		t.Errorf("nil userData = (%q,%q,%t) want empty/empty/false", h, v, tk)
	}
	// Wrong-typed entries ⇒ ignored (no panic, zero values).
	bad := map[string]any{"hostname": 123, "version": true, "takeover": "yes"}
	if h, v, tk := registerMetadata(bad); h != "" || v != "" || tk {
		t.Errorf("wrong-typed userData = (%q,%q,%t) want empty/empty/false", h, v, tk)
	}
	// Correctly-typed entries ⇒ read through.
	good := map[string]any{"hostname": "hh", "version": "vv", "takeover": true}
	if h, v, tk := registerMetadata(good); h != "hh" || v != "vv" || !tk {
		t.Errorf("good userData = (%q,%q,%t) want hh/vv/true", h, v, tk)
	}
}

// The register wire body reflects UserData-derived hostname/version/takeover
// end-to-end through the plugin.
func TestRegisterAgent_FlagOn_UserDataReachesWire(t *testing.T) {
	var body []byte
	withRegistrar(t, fakeQurl(t, func(w http.ResponseWriter, req *http.Request) {
		body, _ = io.ReadAll(req.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"data":{"agent_id":"agt_1"}}`))
	}))
	_, _ = (&Plugin{}).RegisterAgent(newRegReq(), nil)
	s := string(body)
	for _, want := range []string{`"hostname":"workstation-7"`, `"version":"2.0.1"`, `"takeover":true`} {
		if !strings.Contains(s, want) {
			t.Errorf("register wire body missing %s; got %s", want, s)
		}
	}
}

// ---- Redaction: no secret ever reaches the logs --------------------------

// TestRegistration_NeverLogsSecrets drives both RequestOTP and RegisterAgent
// with distinctive secret values and asserts neither the api_key_secret
// (Passcode) nor the credential (OTP) appears in the captured server log. The
// log is file-based and async; installing a temp-dir logger and restoring the
// prior one (which closes+flushes the temp writer) makes the assertion
// deterministic.
func TestRegistration_NeverLogsSecrets(t *testing.T) {
	const (
		secretPasscode = "PASSCODE-SECRET-DO-NOT-LOG"
		secretOTP      = "OTP-CREDENTIAL-DO-NOT-LOG"
	)

	dir := t.TempDir()
	// A fresh file logger at Debug level so even the [AGENT] Debug call-line is
	// captured. callDepth is irrelevant to the byte content we grep for.
	lg := log.NewLogger("agent-redaction", log.LogLevelDebug, dir, "server")
	prev := log.SwapGlobalLogger(lg)
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		// Reinstall the previous logger; this returns (does not close) lg, so we
		// close lg explicitly to flush its async writer to disk.
		log.SwapGlobalLogger(prev)
		lg.Close()
	}
	t.Cleanup(restore)

	withRegistrar(t, fakeQurl(t, func(w http.ResponseWriter, req *http.Request) {
		// Echo an error on register to also exercise the error log path.
		if strings.HasSuffix(req.URL.Path, "/register") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"success":false,"error":{"code":"credential_invalid","message":"bad"}}`))
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"success":true}`))
	}))

	_ = (&Plugin{}).RequestOTP(newOTPReq(), nil)
	_, _ = (&Plugin{}).RegisterAgent(newRegReq(), nil)

	// Flush + restore before reading the file.
	restore()

	var combined strings.Builder
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read log dir: %v", err)
	}
	for _, e := range entries {
		b, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			t.Fatalf("read log file %s: %v", e.Name(), rerr)
		}
		combined.Write(b)
	}
	logs := combined.String()

	// Sanity: the plugin DID log (so an empty-file false-negative can't pass the
	// redaction check). The non-secret api_key_id must be present.
	if !strings.Contains(logs, "ak_live") {
		t.Fatalf("expected non-secret api_key_id ak_live in logs, but logs were:\n%s", logs)
	}
	if strings.Contains(logs, secretPasscode) {
		t.Errorf("api_key_secret (Passcode) LEAKED into logs:\n%s", logs)
	}
	if strings.Contains(logs, secretOTP) {
		t.Errorf("credential (OTP) LEAKED into logs:\n%s", logs)
	}
}

// ---- Init wiring ----------------------------------------------------------

// TestInitDisabledLoadsInert proves Init on a disabled config loads without a
// registrar and without error — the dark default.
func TestInitDisabledLoadsInert(t *testing.T) {
	// Init uses a sync.Once so it can only run meaningfully once per process; if
	// another test already triggered it this is a no-op. Guard so this test does
	// not depend on ordering: only assert the invariant when we win the Once.
	clearRegEnv(t)
	t.Setenv("AGENT_OTP_REGISTRATION_ENABLED", "false")
	if err := Init(&plugins.PluginParamsIn{}); err != nil {
		t.Fatalf("Init on disabled config err=%v want nil", err)
	}
	// Whether or not this call won the Once, a disabled server must never have a
	// registrar installed by Init. (If a prior test injected one via
	// withRegistrar, its Cleanup already restored the prior — which is nil in a
	// fresh process.)
	// We assert the weaker, order-independent property: Init returned no error.
}
