package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/layervai/nhp/internalauth"
)

// maxInternalRevocationRequestSize caps the POST body on
// /nhp/internal/revocation. A revocation Event is small (a scope, a prefixed
// scope_key, an epoch, an event id, and — when targeted — a list of AC ids);
// the targeted list is the only unbounded field, and a cell's admitted-AC set
// is far below this ceiling. Sized to match maxInternalKnockRequestSize (64 KiB)
// so the internal surface has one body cap, not a per-endpoint zoo.
const maxInternalRevocationRequestSize int64 = 64 << 10

// revocationEvent is the nhp-side parse target for the qurl-service revocation
// Event JSON (CROSS-REPO contract). nhp and qurl-service are SEPARATE Go
// modules — nhp cannot import qurl-service — so this struct re-declares only
// the fields the server send side consumes, with json tags that match
// qurl-service's `internal/revocation/event.go` Event byte-for-byte. Keep these
// tags stable; they are the wire contract.
//
// Field-by-field correspondence with qurl-service Event (P4d):
//   - Scope            ← event.Scope            (string: "qurl"|"resource"|"session"|"cell")
//   - ScopeKey         ← event.ScopeKey         (scope-PREFIXED "<scope>:<identity>")
//   - RevocationEpoch  ← event.RevocationEpoch  (int64, must be >= 0)
//   - EventID          ← event.EventID          ("evt_...", log-correlation only)
//   - FanoutMode       ← event.FanoutMode       ("targeted"|"cell-wide")
//   - TargetSetComplete← event.TargetSetComplete(targeted is honored only when true)
//   - TargetACIDs      ← event.TargetACIDs      (admitted-AC ids for targeted fanout)
//
// The qurl-service Event carries additional fields (event_type, the per-scope
// identity hashes, cell_public_key_hash, effective_at, reason) that the server
// does not consume; they are intentionally omitted here and ignored on decode.
// ScopeKey is forwarded to the AC VERBATIM (still prefixed). The AC handler
// strips the "<scope>:" prefix (Slice 1 bareScopeKey); the server must NOT strip
// it.
type revocationEvent struct {
	Scope             string   `json:"scope"`
	ScopeKey          string   `json:"scope_key"`
	RevocationEpoch   int64    `json:"revocation_epoch"`
	EventID           string   `json:"event_id"`
	FanoutMode        string   `json:"fanout_mode"`
	TargetSetComplete bool     `json:"target_set_complete"`
	TargetACIDs       []string `json:"target_ac_ids"`
}

// revocationWireScopes is the set of scopes the server accepts on the wire. It
// mirrors qurl-service's Scope constants (internal/revocation/event.go) and the
// AC's wireRevocationScope allowlist (endpoints/ac/msghandler.go). "cell" is a
// server-side fanout selector with no AC-local index — it is a valid wire scope
// (the AC drops it), so the server accepts it here; the AC's own allowlist
// no-ops it. "admission" is an AC-internal index dimension and is NOT a wire
// scope (neither end accepts it). The server does not act on the scope itself
// beyond this gate; it field-copies scope + scope_key into the NHP_REV message
// for the AC to resolve.
var revocationWireScopes = map[string]struct{}{
	"qurl":     {},
	"resource": {},
	"session":  {},
	"cell":     {},
}

// handleInternalRevocation receives a qURL v2 revocation Event from
// qurl-service over POST /nhp/internal/revocation and fans it out to the
// matching connected ACs as NHP_REV (server→AC, fire-and-forget).
//
// Auth mirrors handleInternalKnock (NOT the no-body sweep helper, since this
// endpoint has a body): RFC-1918 source-IP gate, then the rollout-gated HMAC
// tri-mode (legacy: no signer configured → source-IP only; permit: signer set
// but NHP_INTERNAL_AUTH_REQUIRE=false → verify, warn-and-allow on failure;
// strict: require=true → 401 on failure). The shared authorizeInternalSignedBodyRequest
// helper buffers the body so the HMAC verify sees exactly the bytes the JSON
// decode will.
//
// Delivery semantics: qurl-service's Publisher provides at-least-once to nhp
// via retry (it maps this endpoint's 5xx → transient → retry, 4xx → permanent).
// The nhp→AC hop is best-effort: a lost NHP_REV is not retried at this layer, so
// the corresponding AC entry simply lives to its natural expiry (documented
// fail-open). Backpressure is the one exception that is fail-closed — see
// fanoutRevocation: a full send queue returns 503 so the event is retried rather
// than dropped.
func (hs *HttpServer) handleInternalRevocation(ctx *gin.Context) {
	body, ok := hs.authorizeInternalSignedBodyRequest(ctx, "internal revocation", maxInternalRevocationRequestSize)
	if !ok {
		return
	}

	if hs.udpServer == nil {
		ctx.JSON(http.StatusServiceUnavailable, gin.H{"error": "udp server unavailable"})
		return
	}

	var evt revocationEvent
	// Decode from the buffered body (authorizeInternalSignedBodyRequest already
	// reset ctx.Request.Body to it, but decode the bytes directly so the parse
	// is independent of any downstream body re-read).
	if err := json.Unmarshal(body, &evt); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// Validation. The server validates only what it consumes/forwards; it does
	// NOT re-implement qurl-service's scope-specific identity-field checks
	// (resource_public_key_hash etc.) because it does not read those fields.
	if _, valid := revocationWireScopes[evt.Scope]; !valid {
		log.Warning("internal revocation rejected: unknown scope %q (eventId=%q)", evt.Scope, evt.EventID)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid scope"})
		return
	}
	if evt.ScopeKey == "" {
		log.Warning("internal revocation rejected: empty scope_key (scope=%q eventId=%q)", evt.Scope, evt.EventID)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "empty scope_key"})
		return
	}
	// RevocationEpoch must be non-negative: a negative int64 would convert to a
	// near-max uint64 on the AC and poison the per-(scope, scope_key) epoch
	// watermark (Slice 1 rejects it AC-side too; this is belt-and-suspenders).
	if evt.RevocationEpoch < 0 {
		log.Warning("internal revocation rejected: negative revocation_epoch %d (scope=%q eventId=%q)", evt.RevocationEpoch, evt.Scope, evt.EventID)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "negative revocation_epoch"})
		return
	}

	// Fanout-mode gate. Only the two known modes are accepted; an unknown mode
	// is malformed.
	switch evt.FanoutMode {
	case revocationFanoutCellWide, revocationFanoutTargeted:
	default:
		log.Warning("internal revocation rejected: unknown fanout_mode %q (scope=%q eventId=%q)", evt.FanoutMode, evt.Scope, evt.EventID)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid fanout_mode"})
		return
	}
	// Incomplete-targeted gate (belt-and-suspenders vs qurl-service's
	// Event.Validate, which already rejects this with ErrIncompleteTargeted).
	// A targeted event whose target set is not provably complete must NOT be
	// honored as targeted — doing so could miss an admitting AC and fail open.
	// qurl-service is expected to send cell-wide in that case; if a targeted +
	// incomplete event reaches here it is a producer bug, so reject hard (400)
	// rather than silently widening to cell-wide.
	if evt.FanoutMode == revocationFanoutTargeted && !evt.TargetSetComplete {
		log.Warning("internal revocation rejected: targeted fanout without target_set_complete (scope=%q eventId=%q)", evt.Scope, evt.EventID)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "targeted fanout requires target_set_complete"})
		return
	}

	// metrics is nil-safe (Publisher.IncrCounter / AddCounterWithDims guard a
	// nil receiver), so no explicit nil check is needed here.
	hs.udpServer.metrics.IncrCounter(MetricRevocationReceived)

	// Field-copy into the AC-facing message. scope_key is forwarded VERBATIM
	// (still scope-prefixed); the AC strips the prefix (Slice 1 bareScopeKey).
	revMsg := &common.ACRevocationMsg{
		Scope:           evt.Scope,
		ScopeKey:        evt.ScopeKey,
		RevocationEpoch: evt.RevocationEpoch,
		EventId:         evt.EventID,
	}
	revBytes, err := json.Marshal(revMsg)
	if err != nil {
		// Marshaling a fixed-shape struct of plain fields cannot realistically
		// fail; treat it as an internal error rather than asking the producer
		// to retry an identical (still-unmarshalable) payload.
		log.Error("internal revocation: failed to marshal ACRevocationMsg (scope=%q eventId=%q): %v", evt.Scope, evt.EventID, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	conns := hs.udpServer.findACConnectionsForRevocation(evt.FanoutMode, evt.TargetACIDs)
	sent, ok := hs.udpServer.fanoutRevocation(conns, revBytes)
	if !ok {
		// Backpressure: the send queue filled mid-fanout. Fail closed so
		// qurl-service retries the whole event (NHP_REV apply is epoch-
		// idempotent on the AC, so re-delivery to already-served ACs is safe).
		ctx.JSON(http.StatusServiceUnavailable, gin.H{"error": "send queue full, retry"})
		return
	}

	// Record how many ACs this event was enqueued for (0 on a no-matching-AC
	// no-op). AddCounterWithDims is nil-safe.
	hs.udpServer.metrics.AddCounterWithDims(MetricRevocationFanoutSent, float64(sent), nil)

	// At-least-once: ack 200 only AFTER the fanout has been enqueued for every
	// matched AC. An empty match set (cell-wide with no connected ACs / targeted
	// with no matching ACId here) is a legitimate success — nothing to flush on
	// this server.
	log.Info("internal revocation applied: scope=%q fanout=%q acs_targeted=%d eventId=%q epoch=%d",
		evt.Scope, evt.FanoutMode, sent, evt.EventID, evt.RevocationEpoch)
	ctx.JSON(http.StatusOK, gin.H{"status": "accepted", "acs_targeted": sent})
}

// authorizeInternalSignedBodyRequest runs the /nhp/internal request-auth gate
// for a handler that HAS a body, mirroring handleInternalKnock's auth surface,
// and returns the buffered body on success. It is the body-carrying sibling of
// authorizeInternalSignedNoBodyRequest (used by the sweep endpoint), factored
// out so a third body-carrying internal endpoint does not re-copy the ~80-line
// buffer-and-verify block.
//
// On any rejection it writes the response and returns ok=false; callers must
// return immediately. The returned body is the exact bytes the HMAC verify ran
// over, so the caller's JSON decode and the signature see identical input.
//
// handleInternalKnock is intentionally NOT migrated onto this helper in this
// change: its legacy-mode path streams the body via http.MaxBytesReader (no
// full buffer) and unifying that arm risks a behavior change to a live endpoint
// during the auth rollout. This helper always buffers (correct for a small
// revocation Event); converging knock onto it is a separate, test-guarded
// refactor.
//
// Gate order (matches handleInternalKnock):
//  1. RFC-1918 / loopback source-IP check on RemoteAddr (NOT ctx.ClientIP — the
//     internal surface must not trust X-Forwarded-For).
//  2. Reject any URL query or fragment (not part of the signing string).
//  3. Buffer the body under a size cap (413 over the cap).
//  4. HMAC verify in the configured mode: legacy (no signer) → source-IP only;
//     permit (signer, require=false) → warn+allow on failure; strict
//     (require=true) → 401 on failure.
func (hs *HttpServer) authorizeInternalSignedBodyRequest(ctx *gin.Context, operation string, maxBodySize int64) (body []byte, ok bool) {
	srcIP := extractIP(ctx.Request.RemoteAddr)
	if !isPrivateIP(srcIP) {
		log.Warning("%s rejected: non-private source IP %s", operation, srcIP)
		ctx.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return nil, false
	}
	if ctx.Request.URL.RawQuery != "" || ctx.Request.URL.Fragment != "" {
		log.Warning("%s rejected: URL must have no query or fragment (got query=%q fragment=%q)",
			operation, redactSensitiveQuery(ctx.Request.URL.RawQuery), ctx.Request.URL.Fragment)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return nil, false
	}

	// Always buffer (unlike knock's legacy streaming arm) so the verify and the
	// JSON decode see identical bytes regardless of mode. The +1 lets us
	// distinguish "exactly at cap" from "over cap".
	origBody := ctx.Request.Body
	defer origBody.Close()
	buf, err := io.ReadAll(io.LimitReader(origBody, maxBodySize+1))
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return nil, false
	}
	if int64(len(buf)) > maxBodySize {
		log.Warning("%s rejected: body over limit src=%s reqID=%s size=%d limit=%d",
			operation, srcIP, GetRequestID(ctx), len(buf), maxBodySize)
		ctx.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "body too large"})
		return nil, false
	}
	// Reset the body + ContentLength so any downstream consumer that re-reads
	// the request sees the buffered bytes.
	ctx.Request.Body = io.NopCloser(bytes.NewReader(buf))
	ctx.Request.ContentLength = int64(len(buf))

	// Legacy mode: no signer configured (initial rollout). Source-IP gate only.
	if hs.internalAuthSigner == nil {
		return buf, true
	}

	authErr := hs.internalAuthSigner.Verify(
		ctx.GetHeader(internalauth.Header),
		ctx.Request.Method,
		ctx.Request.URL.Path,
		buf,
		0, // default skew window
	)
	if authErr != nil {
		stage := internalauth.ClassifyAuthFailure(authErr)
		reqID := GetRequestID(ctx)
		if hs.internalAuthRequire {
			log.Warning("%s rejected (strict): src=%s stage=%s reqID=%s", operation, srcIP, stage, reqID)
			if hs.internalAuthEmit != nil {
				hs.internalAuthEmit(MetricInternalAuthFailStrict)
			}
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": internalauth.ErrInternalAuth.Error()})
			return nil, false
		}
		// Permit mode: warn + allow during the signing rollout. Info (not
		// Warning) for the same reason as knock — every pre-upgrade caller
		// emits one per request; the alarm signal is the Permit counter.
		log.Info("%s permit-mode unverified (allowing through): src=%s stage=%s reqID=%s", operation, srcIP, stage, reqID)
		if hs.internalAuthEmit != nil {
			hs.internalAuthEmit(MetricInternalAuthFailPermit)
		}
		return buf, true
	}
	if hs.internalAuthEmit != nil {
		hs.internalAuthEmit(MetricInternalAuthSuccess)
	}
	return buf, true
}
