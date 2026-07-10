package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/OpenNHP/opennhp/nhp/log"
)

// maxResponseBodySize caps the qurl-service response read to prevent memory
// exhaustion on a hostile/broken upstream. Same 1MiB cap the qURL resolver uses
// (staticplugins/qurl/resolver.go).
const maxResponseBodySize = 1 << 20

// requestIDHeader is a LOCAL MIRROR of endpoints/server/requestid.go's
// RequestIDHeader ("X-Request-ID"). The agent plugin cannot import
// endpoints/server for it: that package imports this one back (resource_lookup.go
// → qurlplacement → agent's AuthWithNHP surface), and pulling nhpserver in here
// forms an import cycle that also blocks the server package's relay-dispatch
// tests from driving the real agent plugin. The header name is a stable wire
// contract; mirroring it locally is the same tactic this package already uses
// for pubkeyLogPrefix (upstream symbol is package-private / cycle-forming). If
// the upstream constant's value ever changes, change this in lockstep.
const requestIDHeader = "X-Request-ID"

// Registrar-level sentinel errors. requestOTP/registerAgent return one of these
// (or a wrapped transport error) so the plugin layer can decide the RAK errCode
// without re-parsing the wire envelope. The qurl-service {code} strings are
// mapped to *common.Error registration codes in plugin.go (qurlErrCodeToRegErr);
// these sentinels cover only the non-{code} failure shapes.
var (
	// errEmptyServiceToken guards the same fail-fast the qURL resolver has:
	// config validation should make this unreachable, but proceeding without
	// the X-Service-Token header would be a silent auth bypass attempt.
	errEmptyServiceToken = errors.New("service token is empty - cannot authenticate with qurl-service")
	// errMalformedResponse indicates qurl-service returned a body that does not
	// parse as the {success,error} envelope (or a 2xx that decodes but omits the
	// data the caller needs). Treated as a server-side fault by the plugin.
	errMalformedResponse = errors.New("qurl-service returned a malformed response")
	// errUnexpectedStatus is the fallback for a non-2xx with no structured
	// {error:{code}} body — nothing actionable to map, so the plugin fails it
	// closed as a generic server fault.
	errUnexpectedStatus = errors.New("qurl-service returned an unexpected status")
)

// otpAPIRequest is the exact JSON body for POST /internal/v1/agent/otp, per the
// finalized Q2 contract. Field names and omitempty are load-bearing: qurl-service
// deserializes this verbatim. SrcIP is optional (omitempty) — the direct/relayed
// dispatch supplies it when it has a routable source, but it is informational
// (rate-limit hint) and qurl-service tolerates its absence.
//
// SECRET FIELDS: APIKeySecret is the caller's api-key secret (the agent's
// Passcode). It is serialized here because sending it to qurl-service to
// trigger the OTP email is the entire point of the call — but it MUST NEVER be
// logged. The registrar logs only non-secret identifiers; see requestOTP.
type otpAPIRequest struct {
	APIKeyID        string `json:"api_key_id"`
	APIKeySecret    string `json:"api_key_secret"` //nolint:gosec // G117: JSON tag required — the api-key secret is sent to qurl-service to authorize the OTP dispatch; never logged (see requestOTP)
	DeviceID        string `json:"device_id"`
	DevicePubkeyB64 string `json:"device_pubkey_b64"`
	SrcIP           string `json:"src_ip,omitempty"`
}

// registerAPIRequest is the exact JSON body for POST /internal/v1/agent/register.
// Credential is the registration OTP (Msg.OTP) and is a SECRET — serialized to
// verify the enrollment, never logged. Hostname/Version are optional metadata
// (omitempty ⇒ omitted when the agent did not supply them). Takeover is always
// sent (a bool has no "absent" wire state and qurl-service reads it as an
// explicit intent flag).
type registerAPIRequest struct {
	APIKeyID        string `json:"api_key_id"`
	DeviceID        string `json:"device_id"`
	Credential      string `json:"credential"` //nolint:gosec // G117: JSON tag required — the registration OTP is sent to qurl-service to verify enrollment; never logged (see registerAgent)
	DevicePubkeyB64 string `json:"device_pubkey_b64"`
	Hostname        string `json:"hostname,omitempty"`
	Version         string `json:"version,omitempty"`
	Takeover        bool   `json:"takeover"`
	SrcIP           string `json:"src_ip,omitempty"`
}

// apiError is the {code,message,retry_after_seconds} object qurl-service returns
// inside a failure envelope. Code is the machine-readable discriminator the
// plugin maps to a registration errCode; Message/RetryAfterSeconds are carried
// for logging only.
type apiError struct {
	Code              string `json:"code"`
	Message           string `json:"message"`
	RetryAfterSeconds int    `json:"retry_after_seconds,omitempty"`
}

// registerData is the success payload of the register endpoint
// (200 {"success":true,"data":{"agent_id":"…"}}). agent_id is used server-side
// for logging/audit only — it does NOT travel back to the agent in the RAK (the
// RAK shape stays frozen at {errCode,errMsg,aspId}); the SDK obtains agent_id via
// the separate HTTPS completion fetch. See plugin.go RegisterAgent.
type registerData struct {
	AgentID string `json:"agent_id"`
}

// apiEnvelope is the shared {success,error} wire envelope both endpoints return.
// Data is only populated by the register endpoint's success response; the OTP
// endpoint's 202 success carries {"success":true} with no data.
type apiEnvelope struct {
	Success bool          `json:"success"`
	Data    *registerData `json:"data,omitempty"`
	Error   *apiError     `json:"error,omitempty"`
}

// registrar performs the qurl-service internal-API calls for the agent
// registration flow. It mirrors staticplugins/qurl/resolver.go::QurlResolver:
// a pooled http.Transport, redirects disabled (internal API returns direct
// responses only), a bounded response read, and the X-Service-Token auth header
// on every request. Constructed once at Init (sync.Once in main.go).
type registrar struct {
	httpClient   *http.Client
	transport    *http.Transport
	baseURL      string
	serviceToken string
}

// newRegistrar builds a registrar from cfg. cfg is expected to be already
// validated (Enabled==true with a non-empty URL+token); newRegistrar itself is
// only ever called on the enabled path.
func newRegistrar(cfg *Config) *registrar {
	// Transport tuning mirrors the qURL resolver exactly (connection pooling +
	// HTTP/2 attempt) so both plugins present identical client behavior to
	// qurl-service.
	transport := &http.Transport{
		MaxIdleConns:        cfg.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.MaxIdleConnsPerHost,
		IdleConnTimeout:     time.Duration(cfg.IdleConnTimeout) * time.Second,
		ForceAttemptHTTP2:   true,
	}
	return &registrar{
		httpClient: &http.Client{
			Timeout:   time.Duration(cfg.APITimeout) * time.Second,
			Transport: transport,
			// Disable redirects for internal API calls — we expect direct
			// responses only, same as the qURL resolver.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		transport:    transport,
		baseURL:      cfg.QurlAPIURL,
		serviceToken: cfg.ServiceToken,
	}
}

// Close releases pooled connections. Mirrors QurlResolver.Close; safe to call on
// a nil-transport registrar.
func (r *registrar) Close() {
	if r.transport != nil {
		r.transport.CloseIdleConnections()
	}
}

// requestOTP calls POST /internal/v1/agent/otp — fire-and-forget from the
// agent's perspective: it triggers the OTP email at qurl-service. Returns nil on
// the 202 success; on any failure it returns a mapped registration error
// (*common.Error) for a structured {error:{code}} body, or a registrar sentinel
// / wrapped transport error otherwise. The caller (plugin.RequestOTP) logs and
// swallows whatever is returned — no RAK is produced for OTP.
//
// requestID is propagated to qurl-service via the X-Request-ID header for trace
// correlation, matching the qURL resolver's request-id propagation.
func (r *registrar) requestOTP(ctx context.Context, body *otpAPIRequest, requestID string) error {
	env, status, err := r.postEnvelope(ctx, "/internal/v1/agent/otp", body, requestID)
	if err != nil {
		return err
	}
	// The OTP endpoint signals success with HTTP 202 + {"success":true}.
	if succeeded(env, status) {
		return nil
	}
	return r.envelopeError(env, status)
}

// registerAgent calls POST /internal/v1/agent/register — enrolls the device.
// On the 200 success it returns the qurl-service-issued agent_id (for
// server-side audit logging only; it is NOT placed in the RAK). On failure it
// returns an empty agentID and a mapped registration error (same shape as
// requestOTP): a *common.Error for a structured {error:{code}} body, or a
// registrar sentinel / wrapped transport error otherwise.
func (r *registrar) registerAgent(ctx context.Context, body *registerAPIRequest, requestID string) (agentID string, err error) {
	env, status, err := r.postEnvelope(ctx, "/internal/v1/agent/register", body, requestID)
	if err != nil {
		return "", err
	}

	if succeeded(env, status) {
		if env.Data == nil || env.Data.AgentID == "" {
			// A 200 success that omits agent_id violates the contract
			// (resp: 200 {"success":true,"data":{"agent_id":"…"}}). Registration
			// "succeeded" but we have no identity to audit — treat as a
			// server-side fault so the RAK fails closed rather than reporting a
			// success we can't stand behind.
			return "", errMalformedResponse
		}
		return env.Data.AgentID, nil
	}

	return "", r.envelopeError(env, status)
}

// postEnvelope marshals body, POSTs it to path with the service-token + content
// headers (and the request-id header when present), reads the bounded response,
// and decodes it into an apiEnvelope. It returns the decoded envelope and the
// HTTP status. A non-nil error is only a transport/marshal/decode failure or an
// empty-token guard trip; an HTTP error STATUS with a well-formed envelope is a
// nil error here (the caller inspects status+envelope). This split mirrors the
// qURL resolver's resolvePath structure.
func (r *registrar) postEnvelope(ctx context.Context, path string, body any, requestID string) (*apiEnvelope, int, error) {
	if r.serviceToken == "" {
		return nil, 0, errEmptyServiceToken
	}

	// G117 (secret-in-json): the request bodies carry the api-key secret / OTP;
	// marshaling them into the POST is the whole point of the call. The struct
	// fields already carry their own nolint; suppress the Marshal callsite too
	// with the protocol-required rationale, matching the qURL resolver.
	raw, err := json.Marshal(body) //nolint:gosec // G117
	if err != nil {
		return nil, 0, fmt.Errorf("failed to marshal request: %w", err)
	}

	reqURL := fmt.Sprintf("%s%s", r.baseURL, path)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(raw))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(ServiceTokenHeader, r.serviceToken)
	if requestID != "" {
		httpReq.Header.Set(requestIDHeader, requestID)
	}

	log.Debug("[AGENT] [req_id=%s] Calling qurl-service: %s", requestID, reqURL)
	resp, err := r.httpClient.Do(httpReq) //nolint:gosec // G704: baseURL from QURL_API_URL env var with http(s) schema validation
	if err != nil {
		log.Error("[AGENT] [req_id=%s] qurl-service request failed: %v", requestID, err)
		return nil, 0, fmt.Errorf("failed to call qurl-service: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read response: %w", err)
	}

	// An empty body on a non-2xx is a legitimate (if unhelpful) shape — return a
	// zero envelope so the caller's envelopeError falls back to status-only
	// mapping instead of erroring on the decode.
	env := &apiEnvelope{}
	if len(bytes.TrimSpace(respBody)) > 0 {
		if err := json.Unmarshal(respBody, env); err != nil {
			log.Error("[AGENT] [req_id=%s] failed to parse qurl-service response (status %d): %v", requestID, resp.StatusCode, err)
			return nil, resp.StatusCode, errMalformedResponse
		}
	}
	return env, resp.StatusCode, nil
}

// succeeded reports whether the response is a success: a 2xx status AND the
// envelope's success flag set. Both endpoints share this gate — the OTP endpoint
// returns 202 and register returns 200, but any 2xx is accepted defensively (a
// future qurl-service revision could change the exact code) as long as
// success:true, so a 2xx carrying success:false is still a failure. The callers
// differ only in what they do AFTER success (OTP → nil; register → extract
// agent_id), so this helper covers just the shared branch predicate.
func succeeded(env *apiEnvelope, status int) bool {
	return status >= 200 && status < 300 && env != nil && env.Success
}

// envelopeError converts a failure envelope+status into the error the plugin
// maps to a RAK errCode. A structured {error:{code}} yields the mapped
// registration *common.Error (via qurlErrCodeToRegErr); a failure with no code
// falls back to errUnexpectedStatus so the plugin fails it closed generically.
func (r *registrar) envelopeError(env *apiEnvelope, status int) error {
	if env != nil && env.Error != nil && env.Error.Code != "" {
		return qurlErrCodeToRegErr(env.Error.Code)
	}
	return fmt.Errorf("%w: %d", errUnexpectedStatus, status)
}
