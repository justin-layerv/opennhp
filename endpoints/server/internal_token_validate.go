package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/layervai/nhp/internalauth"
)

// maxInternalTokenValidateRequestSize caps the POST body
// /nhp/internal/token/validate accepts. The endpoint reads
// {token, agent_run_id?} — both fields are short opaque strings —
// so 4 KiB is more than 4× the largest plausible request and
// trips a 413 well before the HMAC compute on a malformed/oversize
// caller. Sibling of maxInternalKnockRequestSize (64 KiB); kept
// smaller because this endpoint's contract is much tighter.
const maxInternalTokenValidateRequestSize int64 = 4 << 10 // 4 KiB

const (
	// internalTokenValidateResponseNonceHeader carries the downstream
	// caller's response-auth nonce. Wire format is exactly 32
	// lowercase hex characters. When present on a successfully
	// request-authenticated /token/validate call, the handler signs
	// the exact response bytes into X-Nhp-Auth.
	internalTokenValidateResponseNonceHeader = "X-Nhp-Nonce"
	internalTokenValidateResponseNonceHexLen = 32
	// internalTokenValidateResponseAuthPathPrefix is a signature
	// context string, not an HTTP route. It reuses internalauth.Signer
	// without making response HMACs replayable as request HMACs.
	internalTokenValidateResponseAuthPathPrefix = "/nhp/internal/token/validate/response/"
)

// internalTokenValidateRequest is the JSON body of
// POST /nhp/internal/token/validate.
//
// Token is the opaque AC token issued via the ACK path
// (ackMsg.ACTokens[resourceId]) — the same value the agent will
// attach to its FRP login Metas as `qurl_knock_token`.
//
// AgentRunID is optional only while the live token entry has no stored RunID,
// which is intentional for legacy auth services. Once
// an entry has a non-empty RunID, the request must supply the same value;
// omission or inequality is rejected as run_id_mismatch. The response `run_id`
// always echoes AgentRunID and carries `omitempty`, so a rejection for omission
// does not expose the stored run identifier.
type internalTokenValidateRequest struct {
	Token      string `json:"token"`
	AgentRunID string `json:"agent_run_id,omitempty"`
}

// maxAgentRunIDBytes caps the size of req.AgentRunID. The handler
// echoes AgentRunID verbatim into the response `run_id` field on
// every validation-result path; without a cap, a (HMAC-authed)
// caller could amplify any future tunnel-server response-by-hash
// cache by inflating agent_run_id up to the 4 KiB body limit. 256 bytes
// is well above any plausible legitimate run identifier (UUIDs,
// ULIDs, hex SHAs are all under 64 bytes) while keeping the
// echoed wire shape bounded. Oversize is rejected (not truncated)
// so the response run_id remains a faithful correlation key for
// the caller's logs.
const maxAgentRunIDBytes = 256

// internalTokenValidateResponse is the JSON body returned by
// POST /nhp/internal/token/validate.
//
// Idempotency contract: the handler reads tokenStore.Load and
// does not mutate ExpireTime — repeated validations within the
// entry's TTL return identical bodies byte-for-byte. The
// idempotency test in internal_token_validate_test.go pins this.
//
// Error vocabulary (Error field, populated only when Valid=false):
//
//	"not_found"      — token absent from the local tokenStore and the
//	                    configured fleet-visible fallback. This
//	                    collapses cases the consumer cannot distinguish
//	                    from the wire shape alone: the token was never
//	                    issued, was already swept, or was minted on a
//	                    different server while the shared fallback was
//	                    disabled. Operators should pair a spike with
//	                    issuing-server and shared-store telemetry.
//	"expired"        — entry present but ExpireTime <= now. The
//	                    sweeper runs every TokenStoreRefreshInterval
//	                    seconds, so an entry can linger past its
//	                    ExpireTime briefly — the handler must
//	                    re-check rather than trust the absence-
//	                    of-not-found as proof of validity.
//	"run_id_mismatch" — a live entry carries a non-empty RunID and
//	                    the request omits agent_run_id or supplies a
//	                    different value. The response echoes only the
//	                    request value and omits all stored metadata.
//	"invalid_format"  — reserved for future shape checks (e.g. a
//	                    length floor) once the AC token shape is
//	                    fenced; not emitted today. Empty tokens
//	                    are rejected pre-handler with HTTP 400
//	                    `missing token` rather than a Valid=false
//	                    body with this code.
//
// Consumer contract on omitempty: KnockSrcIP, KnockUser, and
// ResourceId, SessionId, SessionExpiresAt, and ExpiresAt use `omitempty`
// so they are absent on negative results (the no-metadata-leak property).
// Every Valid=true response requires all four: ResourceId binds the token to
// one NHP resource; SessionId is the server-assigned AOP/ART/ACK identity;
// SessionExpiresAt is the exact serving deadline; ExpiresAt is the later
// token-resolution deadline that includes the late-packet buffer. Consumers
// must never use ExpiresAt to extend serving. KnockSrcIP and KnockUser may be absent
// even on Valid=true: TestInternalTokenValidate_HappyNoUserGuard
// exercises the entry.User == nil branch (an ACK-path entry built
// before the agent identity was captured) and tokenstore.go marks
// UserAddr as trusted-transitive (not from-wire-verified), so an
// empty KnockSrcIP is also reachable. Consumers (tunnel-server's
// knock_validator) MUST treat a missing knock_src_ip / knock_user
// on a Valid=true response as "unknown, not captured" — annotate
// the audit trail accordingly and do NOT treat it as a server
// bug. The alternative — dropping omitempty so the empty string
// is always on the wire — was rejected to keep the wire shape
// minimal on negative-result bodies that tunnel-server may cache
// by hash.
type internalTokenValidateResponse struct {
	Valid            bool   `json:"valid"`
	ResourceId       string `json:"resource_id,omitempty"`
	SessionId        uint64 `json:"session_id,omitempty"`
	SessionExpiresAt int64  `json:"session_expires_at,omitempty"`
	KnockSrcIP       string `json:"knock_src_ip,omitempty"`
	KnockUser        string `json:"knock_user,omitempty"`
	// OwnerId is the server-resolved tenant identity stamped at
	// knock-validation time from the pubkey-bound agent registry
	// (see `endpoints/server/agent_peer_lookup.go::CachedOwnerID`
	// and `endpoints/server/tokenstore.go::NewACKTokenEntry`).
	//
	// Consumers (e.g. qurl-reverse-tunnel-server's tunnel-auth
	// plugin) MAY use this as the authoritative identity for
	// application-layer authorization, avoiding a re-resolution
	// roundtrip on every protected-service action. Per CSA Stealth
	// Mode SDP §"NHP Workflow", the pubkey-based
	// authentication at the NHP-Server IS the trust root for the
	// agent's identity; propagating that resolution through the
	// ACK-path lets downstream services trust it without re-
	// validating client-supplied labels.
	//
	// omitempty: empty for a legacy entry without pubkey-resolved identity OR
	// when the agentPeerLookup cache was evicted between
	// resolve and ACK-publish (best-effort surfacing). Consumers
	// MUST treat empty as "identity not resolved at this hop" and
	// either fall back to other identity signals or reject per
	// their own policy.
	OwnerId string `json:"owner_id,omitempty"`
	// RunID echoes only the caller-supplied agent_run_id. Field-name
	// asymmetry (request agent_run_id vs response run_id) is
	// intentional: the response confirms the caller's asserted
	// identifier, while entry.RunID remains a server-side binding
	// used to reject a non-empty mismatch.
	RunID string `json:"run_id,omitempty"`
	// ExpiresAt is the entry's ExpireTime, RFC3339Nano in UTC.
	//
	// IMPORTANT for consumers: for ACK-path tokens, the value INCLUDES
	// the late-packet buffer (common.AccessTokenLatePacketBufferSeconds,
	// 5s today) on top of the agent-requested OpenTime — see
	// NewACKTokenEntry in tokenstore.go. The AC's pinhole tear-down
	// happens at OpenTime, not at ExpireTime; the extra ~5s exists so
	// the server can still resolve in-flight late packets, NOT so the
	// pinhole stays open longer. A tunnel-server consumer that treats
	// expires_at as "AC pinhole is still open until T" will over-admit
	// by the buffer; treat it as "validation will still resolve until
	// T" and pair with the agent's own OpenTime for routing decisions.
	ExpiresAt string `json:"expires_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

// internalTokenValidateResponseAuthPath builds the response-auth
// signature-context path for a caller-supplied nonce, or returns ""
// if the nonce is malformed (not exactly 32 lowercase hex chars). The
// empty string is the same "do not sign" sentinel that responseAuthPath
// and writeInternalTokenValidateJSON's authPath parameter use, so the
// builder and the field it feeds share one convention. A valid result
// is always non-empty (non-empty prefix + nonce).
func internalTokenValidateResponseAuthPath(nonce string) string {
	if len(nonce) != internalTokenValidateResponseNonceHexLen {
		return ""
	}
	for _, r := range nonce {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			continue
		}
		return ""
	}
	return internalTokenValidateResponseAuthPathPrefix + nonce
}

// writeInternalTokenValidateJSON marshals payload and writes it as the
// response body. authPath selects response signing: empty means write
// the legacy unsigned body; a non-empty authPath is a pre-validated
// signature-context path (built by internalTokenValidateResponseAuthPath
// in handleInternalTokenValidate, only after request HMAC verification
// and nonce-shape validation both pass) over which the exact response
// bytes are signed into X-Nhp-Auth.
func (hs *HttpServer) writeInternalTokenValidateJSON(ctx *gin.Context, status int, payload any, authPath string) {
	body, err := json.Marshal(payload)
	if err != nil {
		log.Error("internal token validate: marshal response failed reqID=%s err=%v", GetRequestID(ctx), err)
		// Marshal failures are intentionally unsigned even on a signed
		// response path. Current payload structs cannot fail to marshal
		// in practice; if a future payload can, the verifier must reject
		// this unsigned 500 rather than trust a body we could not sign.
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to marshal response"})
		return
	}
	if authPath != "" {
		// A non-empty authPath is a signing request. The handler only
		// builds one when the signer is non-nil, so this guard is
		// defensive depth for future direct callers of the writer helper
		// (only the direct-call unit test reaches the nil branch today).
		if hs.internalAuthSigner == nil {
			log.Error("internal token validate: response signing requested without signer reqID=%s", GetRequestID(ctx))
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "response signer unavailable"})
			return
		}
		ctx.Header(internalauth.Header, hs.internalAuthSigner.Sign(http.MethodPost, authPath, body))
	}
	ctx.Data(status, "application/json; charset=utf-8", body)
}

// handleInternalTokenValidate verifies an AC-issued knock token
// for tunnel-server PR-2c. The endpoint mirrors handleInternalKnock's
// auth posture exactly:
//
//  1. RFC-1918 / loopback source-IP check (defense in depth).
//  2. HMAC verification of the X-Nhp-Auth header. Permit/strict
//     mode per NHP_INTERNAL_AUTH_REQUIRE; reuses the same signer +
//     emit + require state as handleInternalKnock so a single
//     rollout flip toggles both endpoints in lockstep.
//
// On success the handler looks up the token in the server
// tokenStore via tokenStore.Load (not VerifyAccessToken — see the
// comment at the call site) and returns a structured response
// describing the entry's ownership + TTL.
//
// Response auth: callers that send an X-Nhp-Nonce of exactly 32
// lowercase hex characters receive X-Nhp-Auth over (nonce, exact
// response bytes) after request HMAC verification succeeds. Legacy
// callers that omit the nonce keep receiving the unsigned response
// body so nhp-server can roll out before qurl-reverse-tunnel-server
// starts requiring signed responses. The server validates nonce
// format, not uniqueness; replay protection depends on the verifier
// generating a fresh single-use nonce per request and accepting only
// the signature bound to that in-flight nonce. The response signature
// uses the same shared internal-auth secret as the request, so it
// defends against a path-positioned tamper point that lacks the
// secret, not against a compromised authenticated caller.
// The HTTP status is intentionally outside the signature; consumers
// must make trust decisions from the signed JSON fields, not from
// status alone. A status rewrite can deny service, but cannot forge
// valid=true / owner_id without also forging the body signature.
// Once responseAuthPath is set (after request HMAC verification and
// nonce-shape validation both pass), downstream validation/store
// errors are signed too; a verifier that opted in must verify any
// signed non-200 response before classifying the status as failure.
// The durable cross-repo contract lives in:
// docs/design/TOKEN_VALIDATE_RESPONSE_AUTH.md.
//
// Idempotency: the handler does not extend ExpireTime on lookup —
// multiple validations within the entry's TTL return identical
// bodies.
//
// Replay within the HMAC skew window: a captured (body, header) pair
// can be replayed against this endpoint within the skew window and
// will succeed. That's fine — the validate operation is non-mutating
// and the AC token itself is the secret (anyone replaying already
// holds it), so the replay adds no leverage. The skew defense lives
// in internalauth.Signer; this handler defers to it.
func (hs *HttpServer) handleInternalTokenValidate(ctx *gin.Context) {
	responseNonce := ctx.GetHeader(internalTokenValidateResponseNonceHeader)
	// responseAuthPath stays empty (legacy unsigned response) until request
	// HMAC verification succeeds AND the opt-in nonce is well formed — see
	// the success branch below. Keeping it empty here is what leaves pre-auth
	// rejects, permit-mode unverified responses, and malformed-nonce 400s
	// unsigned, per docs/design/TOKEN_VALIDATE_RESPONSE_AUTH.md.
	responseAuthPath := ""
	// Closure intentionally reads responseAuthPath at call time: early
	// returns see "", while post-auth branches see the assigned signing path.
	respond := func(status int, payload any) {
		hs.writeInternalTokenValidateJSON(ctx, status, payload, responseAuthPath)
	}

	// Source IP check: reject non-RFC-1918 IPs.
	//
	// Mirror handleInternalKnock — RemoteAddr (not ctx.ClientIP())
	// because a permissive NHP_TRUSTED_PROXY_CIDRS would let a
	// public workload spoof a private IP via X-Forwarded-For.
	srcIP := extractIP(ctx.Request.RemoteAddr)
	if !isPrivateIP(srcIP) {
		log.Warning("internal token validate rejected: non-private source IP %s", srcIP)
		respond(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}

	// Reject query and fragment for the same reason as
	// handleInternalKnock — neither is part of the signed string,
	// so accepting them would let a future endpoint silently leave
	// a parameter unsigned.
	if ctx.Request.URL.RawQuery != "" || ctx.Request.URL.Fragment != "" {
		log.Warning("internal token validate rejected: URL must have no query or fragment (got query=%q fragment=%q)", redactSensitiveQuery(ctx.Request.URL.RawQuery), ctx.Request.URL.Fragment)
		respond(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	// Buffer the body so the HMAC verify and the JSON bind see the
	// same bytes. Same shape as handleInternalKnock.
	//
	// Response-code asymmetry between the two branches is
	// intentional: legacy mode (signer == nil) surfaces oversize
	// bodies as 400 via the subsequent Decode failure, while
	// signer-set mode runs an explicit length check and returns
	// 413. TestInternalTokenValidate_LegacyMode_NoSigner pins both
	// codes against drift.
	//
	// Caveat on the legacy branch: http.MaxBytesReader closes the
	// underlying connection when the limit fires mid-read, so the
	// 400 body may not reach a real client (the test uses
	// httptest.ResponseRecorder which doesn't model the close).
	// Acceptable because the rollout ends with signer != nil for
	// everyone — legacy is a transitional posture, not a steady state.
	if hs.internalAuthSigner == nil {
		ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, maxInternalTokenValidateRequestSize)
	} else {
		origBody := ctx.Request.Body
		defer origBody.Close()
		body, err := io.ReadAll(io.LimitReader(origBody, maxInternalTokenValidateRequestSize+1))
		if err != nil {
			log.Warning("internal token validate: read body failed src=%s reqID=%s err=%v",
				srcIP, GetRequestID(ctx), err)
			respond(http.StatusBadRequest, gin.H{"error": "failed to read body"})
			return
		}
		if int64(len(body)) > maxInternalTokenValidateRequestSize {
			log.Warning("internal token validate rejected: body over limit src=%s reqID=%s size=%d limit=%d",
				srcIP, GetRequestID(ctx), len(body), maxInternalTokenValidateRequestSize)
			respond(http.StatusRequestEntityTooLarge, gin.H{"error": "body too large"})
			return
		}
		ctx.Request.Body = io.NopCloser(bytes.NewReader(body))
		ctx.Request.ContentLength = int64(len(body))

		authErr := hs.internalAuthSigner.Verify(
			ctx.GetHeader(internalauth.Header),
			ctx.Request.Method,
			ctx.Request.URL.Path,
			body,
			0, // use default skew window
		)
		if authErr != nil {
			stage := internalauth.ClassifyAuthFailure(authErr)
			reqID := GetRequestID(ctx)
			// NEVER add req.Token (or the raw body) to ANY log line
			// in this handler — the AC token is bearer-token-equivalent
			// (anyone who holds it can validate against the issuing
			// server), so leaking it via logs would compromise the
			// pinhole it gates. The src/stage/reqID triple is
			// sufficient for triage. Rule applies to strict-reject,
			// permit-allow, and read-body-fail log lines below.
			if hs.internalAuthRequire {
				log.Warning("internal token validate rejected (strict): src=%s stage=%s reqID=%s", srcIP, stage, reqID)
				if hs.internalAuthEmit != nil {
					hs.internalAuthEmit(MetricInternalAuthFailStrict)
				}
				respond(http.StatusUnauthorized, gin.H{"error": internalauth.ErrInternalAuth.Error()})
				return
			}
			// Permit-mode: log + count, allow through. Same rollout
			// posture as handleInternalKnock. Token omitted per the
			// rule above.
			log.Info("internal token validate permit-mode unverified (allowing through): src=%s stage=%s reqID=%s", srcIP, stage, reqID)
			if hs.internalAuthEmit != nil {
				hs.internalAuthEmit(MetricInternalAuthFailPermit)
			}
		} else {
			if hs.internalAuthEmit != nil {
				// Success path means request HMAC verification
				// succeeded. Emit before response-nonce validation so
				// an authenticated caller with a malformed opt-in nonce
				// is still counted as request-auth success, while
				// remaining mutually exclusive with FailStrict /
				// FailPermit above.
				// (Legacy-mode no-emit is enforced by the outer
				// `if hs.internalAuthSigner == nil` short-circuit,
				// not this branch.)
				hs.internalAuthEmit(MetricInternalAuthSuccess)
			}
			if responseNonce != "" {
				authPath := internalTokenValidateResponseAuthPath(responseNonce)
				if authPath == "" {
					log.Warning("internal token validate rejected: malformed response nonce reqID=%s", GetRequestID(ctx))
					if hs.internalAuthEmit != nil {
						hs.internalAuthEmit(MetricInternalTokenValidateBadNonce)
					}
					respond(http.StatusBadRequest, gin.H{"error": "bad nonce"})
					return
				}
				responseAuthPath = authPath
			}
		}
	}

	// Decode the body. Unknown fields are tolerated so callers
	// running ahead of this server's schema (a tunnel-server
	// bumped to a future PR's body shape) don't get rejected on
	// every probe — the field set is purposely small and any
	// addition will land coordinated with a server-side handler
	// update anyway.
	//
	// Plain json.NewDecoder (not ctx.ShouldBindJSON) is deliberate.
	// ShouldBindJSON wraps the decoder with gin's error formatter,
	// which surfaces "Field validation for 'X' failed on the 'required'
	// tag" — useful for a public API, noisy for an internal endpoint
	// that already runs custom field-by-field validation below.
	//
	// dec.More() rejects trailing garbage after the JSON object
	// (e.g., `{"token":"x"}{"y":1}`) so two distinct bodies can't
	// parse identically — matters if a future tunnel-server caches
	// validation responses by request-body hash.
	var req internalTokenValidateRequest
	dec := json.NewDecoder(ctx.Request.Body)
	if err := dec.Decode(&req); err != nil || dec.More() {
		respond(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if req.Token == "" {
		// invalid_format is reserved for shape errors on the token
		// itself. An entirely missing token field is treated as a
		// 400 (the request is malformed at the API layer), not as
		// valid=false — a tunnel-server caller that omits the
		// token should get a loud failure, not an authoritative
		// "the token is invalid" response that could be cached.
		respond(http.StatusBadRequest, gin.H{"error": "missing token"})
		return
	}

	// Cap AgentRunID. The field is echoed verbatim into every
	// response path's run_id (happy, expired, not_found), so an
	// oversize value would inflate any downstream response-by-hash
	// cache. Reject loudly rather than silently truncate — the
	// caller treats run_id as a correlation key, and a truncated
	// echo would degrade log-correlation without flagging the bug
	// at the source.
	if len(req.AgentRunID) > maxAgentRunIDBytes {
		respond(http.StatusBadRequest, gin.H{"error": "agent_run_id too long"})
		return
	}

	// Use tokenStore.Load directly (not VerifyAccessToken) so we can
	// distinguish "not in store" from "in store but expired". The
	// latter feeds the "expired" error vocabulary the tunnel-server
	// uses to decide whether to retry routing vs. surface an explicit
	// TTL-exceeded result to the agent. VerifyAccessToken collapses
	// both into a single nil return — fine for its own callers, but
	// loses information this handler needs.
	//
	// Contract this endpoint advertises is "this server has a live,
	// server-bound token entry for X". tokenStore remains a flat keyspace
	// shared with server-issued tokens from GenerateAccessToken, but the
	// positive path below requires an immutable protected-resource subject,
	// nonzero NHP session identity, and exact serving deadline. Entries that do
	// not carry those server-owned bindings fail closed.
	entry, found := hs.udpServer.tokenStore.Load(req.Token)
	sharedStoreHit := false
	if !found {
		if hs.udpServer.ackTokenStore != nil {
			var loadErr error
			// Use the request context so tunnel-server cancellation
			// also cancels the DDB read; shared-store hits are not
			// cached locally, so detached lookups would only amplify
			// load during validator retry storms.
			entry, found, loadErr = hs.udpServer.ackTokenStore.LoadACToken(ctx.Request.Context(), req.Token)
			if loadErr != nil {
				hs.udpServer.metrics.IncrCounter(MetricACKTokenSharedStoreReadFailure)
				log.Warning("internal token validate shared-store lookup failed: src=%s reqID=%s err=%v", srcIP, GetRequestID(ctx), loadErr)
				respond(http.StatusServiceUnavailable, gin.H{"error": "token store unavailable"})
				return
			}
			if found {
				sharedStoreHit = true
			}
		}
		if !found {
			// Not in this server's tokenStore and not in the
			// fleet-visible fallback. Echo the supplied run_id so the
			// caller can correlate request/response without keeping
			// per-call state.
			hs.recordInternalTokenValidateFailure(srcIP, "not_found")
			respond(http.StatusOK, internalTokenValidateResponse{
				Valid: false,
				RunID: req.AgentRunID,
				Error: "not_found",
			})
			return
		}
	}

	// Entry is present in the store. The raw Load above does NOT
	// consult ExpireTime — that's CleanExpired's job, which runs
	// on a TokenStoreRefreshInterval cadence. Re-check expiry here
	// so a token whose entry hasn't been swept yet still surfaces
	// as expired. ExpireTime semantics: the entry is valid up to
	// AND INCLUDING ExpireTime; strictly after that it's expired.
	//
	// A zero ExpireTime is treated as expired (fail-closed) so a
	// future construction path that forgets to set it can't grant
	// immortal validation. IsZero() is redundant with After (zero is
	// year 1, before any real now) but kept as an explicit assertion
	// — readers don't have to puzzle out the After-vs-zero case.
	if entry.ExpireTime.IsZero() || time.Now().After(entry.ExpireTime) {
		// Echo req.AgentRunID rather than entry.RunID even though the
		// entry is present here. The expired branch has no live
		// pinhole, so the echoed run_id is purely a request/response
		// correlation key; the live-entry binding check below does not
		// apply.
		hs.recordInternalTokenValidateFailure(srcIP, "expired")
		respond(http.StatusOK, internalTokenValidateResponse{
			Valid: false,
			RunID: req.AgentRunID,
			Error: "expired",
		})
		return
	}
	if sharedStoreHit {
		// Do not warm shared-store hits into tokenStore. Shared-store
		// entries intentionally omit ACTokens, while locally minted
		// entries keep that snapshot; caching here would make future
		// VerifyAccessToken callers see shape differences based only on
		// whether this validate request landed on the issuing process.
		hs.udpServer.metrics.IncrCounter(MetricACKTokenSharedStoreHit)
	}
	// Generic/HTTP bookkeeping entries and pre-producer rows can have an empty
	// RunID, so there is no stored value to compare at this step. They still fail
	// the protected-resource/session gates below and can never produce a signed
	// Valid=true serving response. A registered-agent entry always carries a
	// binding, and the caller must assert its exact value: omission is a mismatch.
	if entry.RunID != "" && entry.RunID != req.AgentRunID {
		// Echo only the request value so every negative result remains
		// correlatable without leaking the stored binding or any other
		// token metadata. On omission, omitempty keeps run_id off the wire.
		hs.recordInternalTokenValidateFailure(srcIP, "run_id_mismatch")
		respond(http.StatusOK, internalTokenValidateResponse{
			Valid: false,
			RunID: req.AgentRunID,
			Error: "run_id_mismatch",
		})
		return
	}
	if !validProtectedResourceID(entry.ProtectedResourceId) || entry.ProtectedResourceId == entry.ResourceId {
		hs.recordInternalTokenValidateFailure(srcIP, "invalid_resource")
		respond(http.StatusOK, internalTokenValidateResponse{Valid: false, RunID: req.AgentRunID, Error: "invalid_resource"})
		return
	}
	if entry.SessionId == 0 || entry.SessionExpireTime.IsZero() {
		hs.recordInternalTokenValidateFailure(srcIP, "invalid_session")
		respond(http.StatusOK, internalTokenValidateResponse{Valid: false, RunID: req.AgentRunID, Error: "invalid_session"})
		return
	}
	if !time.Now().Before(entry.SessionExpireTime) {
		hs.recordInternalTokenValidateFailure(srcIP, "session_expired")
		respond(http.StatusOK, internalTokenValidateResponse{Valid: false, RunID: req.AgentRunID, Error: "session_expired"})
		return
	}

	// Happy path. Populate everything the tunnel-server's
	// knock_validator expects:
	//   - resource_id:  the canonical public P-256 resource subject copied from
	//     the resolved catalog row. This is not the wire KnockResourceID or the
	//     ACK-token catalog key stored as entry.ResourceId.
	//     The tunnel server must match it against each FRP proxy resource;
	//     owner identity alone is not resource authorization.
	//   - session_id:   the nonzero server-assigned NHP session echoed through
	//     AOP, ART, and ACK.
	//   - session_expires_at: Unix seconds for the serving deadline derived
	//     from the server issuance time plus OpenTime. It is deliberately
	//     earlier than expires_at and does not include the late-packet buffer.
	//   - knock_src_ip: the IP the agent knocked from. The
	//     tunnel-server uses this response-authenticated source for
	//     connector fairness; it must not compare it to FRP's
	//     ClientAddress, which is the shared AC/Traefik peer in the
	//     supported topology.
	//   - knock_user:   the AgentUser.UserId (omits DeviceId /
	//     OrgId / AuthServiceId; the tunnel-server only uses the
	//     UserId for audit-log annotation today).
	//   - run_id:       echoes the caller-supplied agent_run_id after the exact
	//     registered-agent stored-binding check above.
	//   - expires_at:   RFC3339Nano to keep the response self-
	//     describing across language clients AND preserve the
	//     sub-second precision the in-memory ExpireTime carries.
	//     Production ACK-path entries set ExpireTime via
	//     time.Now().Add(...) (nanosecond precision); plain
	//     RFC3339 would silently advertise an expiry up to ~1s
	//     earlier than truth, which would later bite a consumer
	//     interleaving expires_at with its own monotonic clock.
	//
	user := ""
	ownerId := ""
	if entry.User != nil {
		user = entry.User.UserId
		ownerId = entry.User.OwnerId
	}
	respond(http.StatusOK, internalTokenValidateResponse{
		Valid:            true,
		ResourceId:       entry.ProtectedResourceId,
		SessionId:        entry.SessionId,
		SessionExpiresAt: entry.SessionExpireTime.UTC().Unix(),
		KnockSrcIP:       entry.KnockSrcIP,
		KnockUser:        user,
		OwnerId:          ownerId,
		RunID:            req.AgentRunID,
		ExpiresAt:        entry.ExpireTime.UTC().Format(time.RFC3339Nano),
	})
}
