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

// internalTokenValidateRequest is the JSON body of
// POST /nhp/internal/token/validate.
//
// Token is the opaque AC token issued via the ACK path
// (ackMsg.ACTokens[resourceId]) — the same value the agent will
// attach to its FRP login Metas as `qurl_knock_token`.
//
// AgentRunID is optional. Plan PR-2c populates it once the agent
// registration path threads RunID through the ACK construction
// sites; until then, callers omit the field. The response's
// `run_id` also carries `omitempty`, so when neither the entry's
// stored RunID nor the request's AgentRunID is set the field is
// absent from the response body rather than serialized as an
// empty string. Callers using `run_id` as a correlation key
// should treat its absence as "no run identifier on either side"
// and not key off an empty string.
type internalTokenValidateRequest struct {
	Token      string `json:"token"`
	AgentRunID string `json:"agent_run_id,omitempty"`
}

// maxAgentRunIDBytes caps the size of req.AgentRunID. The handler
// echoes AgentRunID verbatim into the response `run_id` field on
// every code path; without a cap, a (HMAC-authed) caller could
// amplify any future tunnel-server response-by-hash cache by
// inflating agent_run_id up to the 4 KiB body limit. 256 bytes
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
//	"not_found"      — token absent from tokenStore. This collapses
//	                    two operationally distinct cases the consumer
//	                    cannot distinguish from the wire shape alone:
//	                    (a) the token was never issued by any server,
//	                    or (b) it was issued by a different server in
//	                    a multi-server fleet and this one never saw
//	                    it, or (c) it was issued here but already
//	                    swept by CleanExpired. A spike in not_found
//	                    can mean any of the three; operators triaging
//	                    should pair with the issuing-server's emit
//	                    counter to disambiguate.
//	"expired"        — entry present but ExpireTime <= now. The
//	                    sweeper runs every TokenStoreRefreshInterval
//	                    seconds, so an entry can linger past its
//	                    ExpireTime briefly — the handler must
//	                    re-check rather than trust the absence-
//	                    of-not-found as proof of validity.
//	"invalid_format" — reserved for future shape checks (e.g. a
//	                    length floor) once the AC token shape is
//	                    fenced; not emitted today. Empty tokens
//	                    are rejected pre-handler with HTTP 400
//	                    `missing token` rather than a Valid=false
//	                    body with this code.
//
// Consumer contract on omitempty: KnockSrcIP, KnockUser, and
// ExpiresAt use `omitempty` so they're absent on negative results
// (the no-metadata-leak property). On a Valid=true response
// ExpiresAt is always populated (every construction path sets
// ExpireTime, and a zero value is fail-closed to expired before
// this branch). KnockSrcIP and KnockUser, however, may be absent
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
	Valid      bool   `json:"valid"`
	KnockSrcIP string `json:"knock_src_ip,omitempty"`
	KnockUser  string `json:"knock_user,omitempty"`
	// RunID echoes the entry's stored RunID when set, otherwise
	// the caller-supplied agent_run_id. Field-name asymmetry
	// (request agent_run_id vs response run_id) is intentional —
	// the request labels the field as the agent's identifier; the
	// response carries it as a correlation key the tunnel-server
	// may also merge with its own run_id sources.
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
	// Source IP check: reject non-RFC-1918 IPs.
	//
	// Mirror handleInternalKnock — RemoteAddr (not ctx.ClientIP())
	// because a permissive NHP_TRUSTED_PROXY_CIDRS would let a
	// public workload spoof a private IP via X-Forwarded-For.
	srcIP := extractIP(ctx.Request.RemoteAddr)
	if !isPrivateIP(srcIP) {
		log.Warning("internal token validate rejected: non-private source IP %s", srcIP)
		ctx.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}

	// Reject query and fragment for the same reason as
	// handleInternalKnock — neither is part of the signed string,
	// so accepting them would let a future endpoint silently leave
	// a parameter unsigned.
	if ctx.Request.URL.RawQuery != "" || ctx.Request.URL.Fragment != "" {
		log.Warning("internal token validate rejected: URL must have no query or fragment (got query=%q fragment=%q)", ctx.Request.URL.RawQuery, ctx.Request.URL.Fragment)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
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
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
			return
		}
		if int64(len(body)) > maxInternalTokenValidateRequestSize {
			log.Warning("internal token validate rejected: body over limit src=%s reqID=%s size=%d limit=%d",
				srcIP, GetRequestID(ctx), len(body), maxInternalTokenValidateRequestSize)
			ctx.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "body too large"})
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
				ctx.JSON(http.StatusUnauthorized, gin.H{"error": internalauth.ErrInternalAuth.Error()})
				return
			}
			// Permit-mode: log + count, allow through. Same rollout
			// posture as handleInternalKnock. Token omitted per the
			// rule above.
			log.Info("internal token validate permit-mode unverified (allowing through): src=%s stage=%s reqID=%s", srcIP, stage, reqID)
			if hs.internalAuthEmit != nil {
				hs.internalAuthEmit(MetricInternalAuthFailPermit)
			}
		} else if hs.internalAuthEmit != nil {
			// Success path — mutually exclusive with the FailStrict /
			// FailPermit emits above. The `else if` shape MUST stay
			// or the Success/Fail mutual-exclusion invariant breaks.
			// (Legacy-mode no-emit is enforced by the outer
			// `if hs.internalAuthSigner == nil` short-circuit, not
			// this branch.)
			hs.internalAuthEmit(MetricInternalAuthSuccess)
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
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if req.Token == "" {
		// invalid_format is reserved for shape errors on the token
		// itself. An entirely missing token field is treated as a
		// 400 (the request is malformed at the API layer), not as
		// valid=false — a tunnel-server caller that omits the
		// token should get a loud failure, not an authoritative
		// "the token is invalid" response that could be cached.
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "missing token"})
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
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "agent_run_id too long"})
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
	// Contract this endpoint advertises is "this server has a live
	// token entry for X", not "this is specifically an AC-issued
	// knock token" — tokenStore is a flat keyspace shared with
	// server-issued tokens from GenerateAccessToken. The resource_id
	// follow-up (see PR description) is the natural seam for any
	// future tightening of the AC-only contract.
	entry, found := hs.udpServer.tokenStore.Load(req.Token)
	if !found {
		// Not in this server's tokenStore. In a multi-server fleet
		// the issuing server may differ from the validating
		// server; the caller (tunnel-server) is responsible for
		// the routing decision. Echo the supplied run_id so the
		// caller can correlate request/response without keeping
		// per-call state.
		ctx.JSON(http.StatusOK, internalTokenValidateResponse{
			Valid: false,
			RunID: req.AgentRunID,
			Error: "not_found",
		})
		return
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
		// Echo req.AgentRunID rather than entry.RunID even though
		// the entry is present here. The "entry wins over caller"
		// rule on the happy path is about ownership of the live
		// pinhole; the expired branch has no live pinhole, so the
		// echoed run_id is purely a request/response correlation
		// key and the caller's value is the safer default.
		ctx.JSON(http.StatusOK, internalTokenValidateResponse{
			Valid: false,
			RunID: req.AgentRunID,
			Error: "expired",
		})
		return
	}

	// Happy path. Populate everything the tunnel-server's
	// knock_validator expects:
	//   - knock_src_ip: the IP the agent knocked from. The
	//     tunnel-server may compare to ClientAddress on the FRP
	//     login (logs a warn on mismatch but does not reject —
	//     GCP Cloud NAT egress varies, see plan PR-2c).
	//   - knock_user:   the AgentUser.UserId (omits DeviceId /
	//     OrgId / AuthServiceId; the tunnel-server only uses the
	//     UserId for audit-log annotation today).
	//   - run_id:       entry.RunID wins when set; otherwise the
	//     handler echoes the caller-supplied agent_run_id. "Trust
	//     the entry over the caller" so a misbehaving caller can't
	//     claim ownership of a different run's pinhole. Plan PR-2c
	//     populates entry.RunID once the agent-registration thread
	//     is wired; until then ACK-path entries hold the empty
	//     string and the request's agent_run_id is echoed so a
	//     caller-side correlation key works regardless of which
	//     side is ahead in the rollout. See the precedence rule on
	//     internalTokenValidateResponse.RunID for the canonical
	//     statement.
	//   - expires_at:   RFC3339Nano to keep the response self-
	//     describing across language clients AND preserve the
	//     sub-second precision the in-memory ExpireTime carries.
	//     Production ACK-path entries set ExpireTime via
	//     time.Now().Add(...) (nanosecond precision); plain
	//     RFC3339 would silently advertise an expiry up to ~1s
	//     earlier than truth, which would later bite a consumer
	//     interleaving expires_at with its own monotonic clock.
	//
	// entry.ResourceId is intentionally omitted from the response.
	// PR-2c's knock_validator does not consume it today, and
	// adding it without a matching consumer would publish a
	// half-bound contract. Adding resource_id later (so the
	// tunnel-server can reject a token issued for resource A
	// presented against an FRP login for resource B) is tracked
	// as a follow-up — see PR description.
	user := ""
	if entry.User != nil {
		user = entry.User.UserId
	}
	runID := entry.RunID
	if runID == "" {
		runID = req.AgentRunID
	}
	ctx.JSON(http.StatusOK, internalTokenValidateResponse{
		Valid:      true,
		KnockSrcIP: entry.KnockSrcIP,
		KnockUser:  user,
		RunID:      runID,
		ExpiresAt:  entry.ExpireTime.UTC().Format(time.RFC3339Nano),
	})
}
