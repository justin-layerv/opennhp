package qurl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	nhpserver "github.com/OpenNHP/opennhp/endpoints/server"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// qURL v2 admission client for the NHP Server Contract two-phase admission flow:
//
//	POST /internal/v2/qurl/admissions/prepare
//	POST /internal/v2/qurl/admissions/{admission_id}/commit
//	POST /internal/v2/qurl/admissions/{admission_id}/cancel
//
// (docs/design/QURL_V2_KEYED_IDENTITY.md → "NHP Server Contract"). Prepare
// reserves the qURL with a short lease and selects an AC; commit finalizes the
// one-time-use consume / max-session counter and records the selected ac_id
// durably (the recorded id matches the AC NHP then opens); cancel releases the
// lease ONLY on the pre-commit path. NHP opens AC LAST, after commit — so AC
// open failing after commit is a fail-closed reliability tradeoff that must not
// un-consume a one-time-use qURL (the caller does not cancel after commit).
//
// These methods build to the contract's documented request/response shapes
// (P3c implements the qurl-service side in parallel; the DOC is the contract).

// Admission-flow paths and prepare-error codes.
const (
	admissionPreparePath = "/internal/v2/qurl/admissions/prepare"

	// admissionCommitPathFmt / admissionCancelPathFmt take the admission id.
	admissionCommitPathFmt = "/internal/v2/qurl/admissions/%s/commit"
	admissionCancelPathFmt = "/internal/v2/qurl/admissions/%s/cancel"
)

// Admission errors. Terminal denials (the qURL is not admissible) are distinct
// from transient/transport failures so the knock handler can map them to a
// fail-closed deny vs a retryable error ACK, mirroring the qv1 resolve split.
var (
	// ErrAdmissionDenied is a terminal admission denial from qurl-service prepare
	// (expired/revoked/consumed/over-policy/unknown qURL). The agent must
	// re-resolve via a fresh qURL to be admitted; a re-knock will not help.
	ErrAdmissionDenied = errors.New("qurl v2 admission denied")
	// ErrAdmissionService is a transient/transport failure talking to
	// qurl-service prepare/commit/cancel (5xx, network, malformed body).
	ErrAdmissionService = errors.New("qurl v2 admission service error")
	// ErrAdmissionInvalidResponse is a structurally invalid prepare 200 body
	// (missing admission_id / ac_routing). Distinct from a clean denial.
	ErrAdmissionInvalidResponse = errors.New("qurl v2 admission invalid response")
)

// AdmissionPrepareRequest is the NHP Server Contract prepare request body.
//
// Per the contract, NHP sends ONLY the signed claims blobs plus the
// independently-authenticated facts — qurl-service derives resource/cell/user
// keys, expiry, and jti FROM the verified signed claims and must NOT receive
// unsigned duplicate copies of them. AuthenticatedQurlPublicKeyB64 is the Noise
// IK-recovered agent key NHP authenticated; it is the proof-of-possession fact,
// not browser-submitted JSON. (A future debug field would be named observed_*,
// ignored for authorization, and compared only after signature verification.)
type AdmissionPrepareRequest struct {
	QurlClaimsB64                 string `json:"qurl_claims_b64"`
	QurlIssuerSigB64              string `json:"qurl_issuer_sig_b64"`
	AuthenticatedQurlPublicKeyB64 string `json:"authenticated_qurl_public_key_b64"`
	SrcIP                         string `json:"src_ip"`
	UserAgent                     string `json:"user_agent,omitempty"`
	// RequestID rides in the request-id HTTP header, not the JSON body.
	RequestID string `json:"-"`
}

// ACRouting is the AC the prepare step selected. NHP opens THIS AC after commit
// (the contract: "NHP opens the AC named in that ac_routing"), so the opened AC
// matches the ac_id commit records into admitted_ac_ids — keeping a targeted
// revoke's target set complete by construction.
type ACRouting struct {
	ACId     string `json:"ac_id"`
	DestHost string `json:"dest_host"`
	DestPort int    `json:"dest_port"`
}

// AdmissionPrepareResponse is the NHP Server Contract prepare response. Only the
// fields NHP acts on are modeled; unmodeled fields (resource_key_id,
// qurl_user_public_key_hash, session_duration, remaining_seconds, etc.) are
// ignored by the JSON decoder. resource_key_id is deliberately NOT used for
// routing/admission keys — it is a DNS/API alias only. NHP clamps the AC pinhole
// to the prepare OpenTime; the session lifetime is qurl-service's to enforce, so
// NHP does not act on session_duration/remaining_seconds on the first knock.
type AdmissionPrepareResponse struct {
	AdmissionID string     `json:"admission_id"`
	QurlID      string     `json:"qurl_id"`
	OpenTime    uint32     `json:"open_time"`
	QurlSiteURL string     `json:"qurl_site_url"`
	ACRouting   *ACRouting `json:"ac_routing"`
}

// internalAdmissionPrepareResponse is the success/error envelope qurl-service
// wraps prepare in, matching the qv1 internalResolveResponse shape so the error
// classification stays consistent across the two internal endpoints.
type internalAdmissionPrepareResponse struct {
	Success bool                      `json:"success"`
	Data    *AdmissionPrepareResponse `json:"data,omitempty"`
	Error   *resolveError             `json:"error,omitempty"`
}

// PrepareAdmission calls the NHP Server Contract prepare endpoint. It reserves
// the qURL lease and returns the selected AC routing + lease metadata. The
// caller MUST commit or cancel the returned admission_id (commit on success,
// cancel only before a successful commit).
func (r *QurlResolver) PrepareAdmission(ctx context.Context, req *AdmissionPrepareRequest) (*AdmissionPrepareResponse, error) {
	if r.serviceToken == "" {
		return nil, fmt.Errorf("%w: service token is empty", ErrAdmissionService)
	}
	if req == nil {
		return nil, fmt.Errorf("%w: nil prepare request", ErrAdmissionService)
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal prepare request: %w", ErrAdmissionService, err)
	}

	respBody, status, err := r.doAdmissionRequest(ctx, http.MethodPost, admissionPreparePath, body, req.RequestID)
	if err != nil {
		return nil, err
	}

	if status != http.StatusOK {
		return nil, classifyAdmissionStatus(status, respBody)
	}

	var env internalAdmissionPrepareResponse
	if err := json.Unmarshal(respBody, &env); err != nil {
		return nil, fmt.Errorf("%w: parse prepare response: %w", ErrAdmissionInvalidResponse, err)
	}
	if !env.Success || env.Error != nil {
		if env.Error != nil {
			return nil, classifyAdmissionErrorCode(env.Error.Code)
		}
		return nil, ErrAdmissionService
	}
	if env.Data == nil {
		return nil, fmt.Errorf("%w: prepare success with no data", ErrAdmissionInvalidResponse)
	}
	if err := validateAdmissionPrepareResponse(env.Data); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrAdmissionInvalidResponse, err.Error())
	}
	return env.Data, nil
}

// CommitAdmission finalizes the admission identified by admissionID (one-time-use
// consume / max-session counter, durable session write recording the selected
// ac_id). It is called AFTER all crypto checks and a successful prepare, and
// BEFORE NHP opens the AC. A non-200 is a hard failure: the caller must NOT open
// the AC. Because a failed commit leaves prepare's lease still pending, the
// caller releases it via CancelAdmission (the TTL is only the backstop for a
// vanished client).
func (r *QurlResolver) CommitAdmission(ctx context.Context, admissionID, requestID string) error {
	return r.admissionLifecycleCall(ctx, admissionCommitPathFmt, admissionID, requestID, "commit")
}

// CancelAdmission releases the pending prepare lease for admissionID. It is valid
// ONLY before a successful commit. After commit succeeds, consume/session state
// is durable and must not be silently undone, so the caller never cancels then.
func (r *QurlResolver) CancelAdmission(ctx context.Context, admissionID, requestID string) error {
	return r.admissionLifecycleCall(ctx, admissionCancelPathFmt, admissionID, requestID, "cancel")
}

// admissionLifecycleCall is the shared commit/cancel POST. Both take the
// admission id in the path, no body, and a 2xx means success.
func (r *QurlResolver) admissionLifecycleCall(ctx context.Context, pathFmt, admissionID, requestID, op string) error {
	if r.serviceToken == "" {
		return fmt.Errorf("%w: service token is empty", ErrAdmissionService)
	}
	if admissionID == "" {
		return fmt.Errorf("%w: empty admission id for %s", ErrAdmissionService, op)
	}

	path := fmt.Sprintf(pathFmt, url.PathEscape(admissionID))
	respBody, status, err := r.doAdmissionRequest(ctx, http.MethodPost, path, nil, requestID)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		log.Error("[QURL] admission %s failed: status=%d body=%s", op, status, string(respBody))
		// A terminal 4xx on commit/cancel is still an admission failure for the
		// caller; we do not split it further because the caller's response to a
		// failed commit (deny, no AC, no cancel) is the same regardless of class.
		return fmt.Errorf("%w: %s returned status %d", ErrAdmissionService, op, status)
	}
	return nil
}

// doAdmissionRequest performs the HTTP round-trip for an admission call and
// returns the (size-limited) body and status. Network/transport failures are
// wrapped as ErrAdmissionService; the caller classifies the status.
func (r *QurlResolver) doAdmissionRequest(ctx context.Context, method, path string, body []byte, requestID string) ([]byte, int, error) {
	reqURL := fmt.Sprintf("%s%s", r.baseURL, path)
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: build request: %w", ErrAdmissionService, err)
	}
	if body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	httpReq.Header.Set(ServiceTokenHeader, r.serviceToken)
	if requestID != "" {
		httpReq.Header.Set(nhpserver.RequestIDHeader, requestID)
	}

	resp, err := r.httpClient.Do(httpReq) //nolint:gosec // G704: baseURL from QURL_API_URL env var with schema validation
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrAdmissionService, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return nil, 0, fmt.Errorf("%w: read response: %w", ErrAdmissionService, err)
	}
	return respBody, resp.StatusCode, nil
}

// classifyAdmissionStatus maps a non-200 prepare status to terminal-deny vs
// transient. It first tries the structured error body (qurl-service always sends
// one), falling back to status-code mapping for a bodiless response. (Free
// function — it needs no resolver state; contrast the qv1 parseErrorResponse,
// which calls r.mapErrorCode.)
func classifyAdmissionStatus(status int, body []byte) error {
	var env internalAdmissionPrepareResponse
	if err := json.Unmarshal(body, &env); err == nil && env.Error != nil {
		return classifyAdmissionErrorCode(env.Error.Code)
	}
	switch status {
	case http.StatusForbidden, http.StatusNotFound, http.StatusGone, http.StatusConflict:
		// 403 policy/over-limit; 404 unknown qURL; 410 expired/consumed/revoked;
		// 409 lease conflict (a concurrent first-knock holds the lease) — all
		// terminal for THIS knock (the agent re-resolves or the other knock wins).
		return ErrAdmissionDenied
	default:
		return ErrAdmissionService
	}
}

// classifyAdmissionErrorCode maps a qurl-service error code to a terminal deny or
// a transient service error. Codes mirror the qv1 resolve error vocabulary plus
// the v2 lease-conflict code.
func classifyAdmissionErrorCode(code string) error {
	switch code {
	case "qurl_not_found", "resource_not_found", "qurl_revoked", "resource_revoked",
		"qurl_consumed", "qurl_expired", "resource_expired",
		"policy_violation", "max_sessions_reached", "admission_lease_conflict":
		return ErrAdmissionDenied
	default:
		return ErrAdmissionService
	}
}

// validateAdmissionPrepareResponse checks the prepare 200 body carries the fields
// NHP must have to commit and open the AC: an admission id (to commit/cancel),
// a positive open_time, and AC routing with an ac_id and a destination (to open
// the pinhole).
//
// open_time MUST be > 0. authWithNHPClaims stamps ackMsg.OpenTime (and the AC
// pinhole) straight from prepResp.OpenTime; a zero open_time would reset the
// agent's open-timer to 0 and hammer the server — the exact failure the qv1 path
// guards against. Unlike qv1, v2 has NO catalog lookup, so there is no second
// server-side ceiling to clamp against: prepare's open_time is authoritative by
// design (the contract makes qurl-service the session-lifetime authority), and we
// reject only the degenerate zero rather than re-deriving a ceiling here.
func validateAdmissionPrepareResponse(resp *AdmissionPrepareResponse) error {
	if resp.AdmissionID == "" {
		return errors.New("prepare returned empty admission_id")
	}
	if resp.OpenTime == 0 {
		return errors.New("prepare returned open_time=0 (would reset the agent open-timer)")
	}
	if resp.ACRouting == nil {
		return errors.New("prepare returned no ac_routing")
	}
	if resp.ACRouting.ACId == "" {
		return errors.New("prepare ac_routing has empty ac_id")
	}
	if resp.ACRouting.DestHost == "" {
		return errors.New("prepare ac_routing has empty dest_host")
	}
	if resp.ACRouting.DestPort <= 0 || resp.ACRouting.DestPort > 65535 {
		return fmt.Errorf("prepare ac_routing has invalid dest_port %d", resp.ACRouting.DestPort)
	}
	return nil
}
