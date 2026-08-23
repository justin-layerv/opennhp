package qurl

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	nhpserver "github.com/OpenNHP/opennhp/endpoints/server"
	"github.com/OpenNHP/opennhp/endpoints/server/internal/qurlv2"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

// qURL v2 knock UserData blob keys, sourced from the server package so the
// HandleKnockRequest skip-DDB predicate (isQurlV2ClaimsKnock) and this plugin's
// qv2 dispatch cannot drift on the wire field names. These also match the NHP
// Server Contract prepare-request field names.
const (
	qurlV2ClaimsUserDataKey    = nhpserver.QurlV2ClaimsUserDataKey
	qurlV2IssuerSigUserDataKey = nhpserver.QurlV2IssuerSigUserDataKey
)

// authWithNHPClaims is the qURL v2 signed-claims admission path. It is the
// integrity boundary for v2: it verifies the issuer signature INDEPENDENTLY
// (not trusting qurl-service to have done so) and binds the signed claims to the
// authenticated NHP identity, the cell, and the knock resource BEFORE it asks
// qurl-service to prepare anything or opens any AC. No AC is opened if ANY crypto
// check (signature / cell / proof-of-possession / resource identity / liveness)
// fails, even if qurl-service state would say the qURL is active.
//
// Order (the contract's "prepare, commit durable state, then open AC"):
//
//  1. VerifyClaims — independent issuer-signature verify + strict parse.
//  2. Liveness — reject expired / not-yet-valid claims (skew-tolerant).
//  3. Cell binding — claims.cell_public_key_b64 == THIS server's cell key.
//  4. Proof-of-possession — claims.qurl_user_public_key_b64 == the Noise
//     IK-authenticated agent key (req.PublicKey).
//  5. Resource binding — claims.resource_public_key_b64 == the knock resource id.
//  6. prepare → reserve lease + select AC.
//  7. commit → finalize consume/session durably (BEFORE opening AC).
//  8. open AC named in the prepare ac_routing.
//
// cancel releases the lease ONLY on a pre-commit failure (prepare succeeded but
// we abort before commit). After a successful commit, an AC-open failure is
// fail-closed: deny + loud log, and NEVER cancel (the contract forbids silently
// un-consuming a one-time-use qURL).
func authWithNHPClaims(req *common.NhpAuthRequest, helper *plugins.NhpServerPluginHelper, claimsB64, sigB64, clientIP string) (*common.ServerKnockAckMsg, error) {
	ackMsg := req.Ack

	// Feature wiring guards. v2AdmissionEnabled gates entry, but the trust store
	// and callback must be present too; fail closed if Init did not wire them.
	if v2TrustStore == nil {
		log.Error("[QURL] authWithNHPClaims: v2 trust store not initialized; failing closed")
		return failAck(ackMsg, common.ErrAuthServiceProviderNotFound, "qurl v2 admission not initialized")
	}
	if resolver == nil {
		return failAck(ackMsg, common.ErrAuthServiceProviderNotFound, "qurl.authWithNHPClaims: plugin not initialized (nil resolver)")
	}

	// ---- Integrity boundary: checks 1-5 ----

	// 1. Independent issuer-signature verify + strict parse over the EXACT wire
	//    claims bytes. We do NOT trust qurl-service to have verified them.
	claims, err := qurlv2.VerifyClaims(claimsB64, sigB64, v2TrustStore)
	if err != nil {
		log.Info("[QURL] authWithNHPClaims: claims verification failed client=%s: %v", clientIP, err)
		return failAck(ackMsg, common.ErrInvalidInput, "qurl v2 claims verification failed")
	}

	// 2. Liveness (clock-dependent; VerifyClaims is clock-free). Fail-fast on a
	//    stale link before the qurl-service round-trip. qurl-service DDB state
	//    remains the authoritative liveness/revocation gate.
	if err := qurlv2.CheckLiveness(claims, time.Now(), v2ClockSkewAllowance); err != nil {
		log.Info("[QURL] authWithNHPClaims: claims not live client=%s: %v", clientIP, err)
		return failAck(ackMsg, common.ErrQurlSessionExpired, "qurl v2 claims expired or not yet valid")
	}

	// 3. Cell binding: the qURL must be minted for THIS cell. Compared by decoded
	//    bytes (claim is base64url, server cell key is std-base64).
	if helper.ServerCellPublicKeyB64 == "" {
		log.Error("[QURL] authWithNHPClaims: server cell public key not plumbed; failing closed")
		return failAck(ackMsg, common.ErrAuthServiceProviderNotFound, "qurl v2 admission: server cell key unavailable")
	}
	if err := qurlv2.ClaimKeyMatchesStdB64(claims.CellPublicKeyB64, helper.ServerCellPublicKeyB64); err != nil {
		log.Warning("[QURL] authWithNHPClaims: cell key mismatch client=%s: %v", clientIP, err)
		return failAck(ackMsg, common.ErrInvalidInput, "qurl v2 claims target a different cell")
	}

	// 4. Proof-of-possession: the Noise IK handshake authenticated req.PublicKey
	//    as the agent static key; it must equal the signed per-qURL public key.
	//    This is what makes the unsigned secret safe — swapping it for an
	//    attacker key makes this check fail.
	if err := qurlv2.ClaimKeyMatchesStdB64(claims.QurlUserPublicKeyB64, req.PublicKey); err != nil {
		log.Warning("[QURL] authWithNHPClaims: proof-of-possession mismatch client=%s: %v", clientIP, err)
		return failAck(ackMsg, common.ErrInvalidInput, "qurl v2 authenticated key does not match claims")
	}

	// 5. Resource binding: the knock resource identity IS the protected-resource
	//    public key, and must equal the signed resource key (both base64url).
	if err := qurlv2.ClaimResourceKeyMatches(claims.ResourcePublicKeyB64, req.Msg.ResourceId); err != nil {
		log.Warning("[QURL] authWithNHPClaims: resource identity mismatch client=%s: %v", clientIP, err)
		return failAck(ackMsg, common.ErrResourceNotFound, "qurl v2 knock resource does not match claims")
	}

	// claims.RelayURL is intentionally NOT consumed on the NHP server side. Relay
	// selection is a client-side concern (the browser/headless agent acts on
	// relay_url to choose where to POST before any server sees the knock); the NHP
	// server just receives the (possibly relay-forwarded) knock. The field is a
	// required, issuer-signed claim — so it is part of the signed anti-tamper
	// envelope and is verified — but there is nothing for admission to act on here.
	// qurlv2.ValidateRelayURL exists for the client/issuer side, not this path.

	// ---- Steady-state re-knock gate: authorize-first, prepare-fallback ----
	//
	// The integrity boundary (checks 1-5) has passed, so the inner identity is
	// proven. Now ask qurl-service's idempotent, SESSION-keyed authorize endpoint
	// whether this is a steady-state re-knock with a still-live session
	// (QURL_V2_KEYED_IDENTITY.md L643: "Steady-state re-knocks should call an
	// idempotent authorize endpoint"). This is what closes the admission-audit
	// MAJOR: a CONSUMED one-time-use qURL whose session is still live must REFRESH
	// here instead of being re-denied by prepare's status-gated IsAdmissibleAt.
	//
	// The switch below maps the four authorize outcomes; two of those branches turn
	// on non-obvious safety arguments worth stating once here:
	//
	//   - ONLY ErrNoLiveSession (403 access_denied) falls through to prepare. That
	//     403 conflates a genuine FIRST knock with a revoked/expired session, but
	//     the conflation is SAFE: a revoked/expired qURL that 403s here is then
	//     re-denied by prepare (a strictly stronger gate on qURL state), while a
	//     still-admissible first knock is correctly admitted by prepare.
	//   - A transient/transport authorize failure (ErrAdmissionService) must NOT
	//     fall through. Routing a transient blip to prepare would re-deny a
	//     CONSUMED-but-live one-time-use session at the status gate — reopening the
	//     exact MAJOR this path closes. A re-knock retries cleanly instead.
	//
	// authorize gets its own bounded context (the knock path has no inheritable
	// request context); the fall-through prepare/commit each get a fresh one too.
	requestID := uuid.NewString()

	// qurl-service's qv2 admission endpoints decode AuthenticatedQurlPublicKeyB64
	// as UNPADDED base64url (RawURLEncoding), per the qURL v2 contract that every
	// key field is base64url, never standard base64 (QURL_V2_KEYED_IDENTITY.md).
	// req.PublicKey is STANDARD base64 (nhp/core PublicKeyBase64 — padded, +/
	// alphabet), which that decoder rejects with HTTP 400, turning every qv2 knock
	// into ErrKnockApiRequestFailed. Send claims.QurlUserPublicKeyB64 instead: PoP
	// (check 4 above) proved it equals req.PublicKey, and it is already the same key
	// in the canonical base64url encoding the admission API expects.
	authedQurlUserKeyB64 := claims.QurlUserPublicKeyB64

	authzCtx, authzDone := context.WithTimeout(context.Background(), qurlAuthorizeTimeout)
	authzResp, authzErr := resolver.AuthorizeAdmission(authzCtx, &AdmissionAuthorizeRequest{
		AuthenticatedQurlPublicKeyB64: authedQurlUserKeyB64,
		ClientIP:                      clientIP,
		// VisitorSessionID and ACID are intentionally empty: the browser knock path
		// has no visitor-session id to present (authorize falls back to ClientIP
		// matching), and we let authorize re-open the AC it already recorded for the
		// winning session (ACID empty), which keeps the session's admitted-AC set
		// complete without NHP picking a possibly-different AC here.
		RequestID: requestID,
	})
	authzDone()
	switch {
	case authzErr == nil:
		// Live session matched -> refresh the AC for its remaining lifetime.
		return refreshV2Admission(req, helper, claims, authzResp, clientIP)
	case errors.Is(authzErr, ErrNoLiveSession):
		// Not a steady-state re-knock (no live session, OR no state row at all).
		// Fall through to the first-knock prepare path. A revoked/expired qURL that
		// lands here is correctly re-denied by prepare's stronger qURL-state gate.
		log.Info("[QURL] authWithNHPClaims: no live session for re-knock client=%s; falling through to prepare", clientIP)
	case errors.Is(authzErr, ErrAdmissionDenied):
		log.Info("[QURL] authWithNHPClaims: authorize terminally denied client=%s: %v", clientIP, authzErr)
		return failAck(ackMsg, common.ErrQurlSessionExpired, "qurl v2 admission denied")
	default:
		// Transient/transport authorize failure. Do NOT fall through to prepare —
		// prepare's status gate would wrongly re-deny a consumed-but-live session.
		log.Error("[QURL] authWithNHPClaims: authorize failed client=%s: %v", clientIP, authzErr)
		return failAck(ackMsg, common.ErrKnockApiRequestFailed, common.ErrKnockApiRequestFailed.Error())
	}

	// ---- First-knock admission: prepare → commit → open AC ----
	//
	// prepare and commit each get their OWN bounded context (not one shared
	// budget) so a slow prepare cannot starve commit's deadline — which would turn
	// a healthy admission into a failed commit → cancel, and a re-knock into a
	// lease-conflict deny. The cancel-on-commit-failure path uses its own fresh
	// context too (see cancelPendingAdmission).

	prepCtx, prepDone := context.WithTimeout(context.Background(), qurlAuthorizeTimeout)
	prepResp, prepErr := resolver.PrepareAdmission(prepCtx, &AdmissionPrepareRequest{
		QurlClaimsB64:                 claimsB64,
		QurlIssuerSigB64:              sigB64,
		AuthenticatedQurlPublicKeyB64: authedQurlUserKeyB64,
		SrcIP:                         clientIP,
		// Reuse the qv1 bootstrap user-agent extractor (same UserData key + length
		// cap) so attribution is consistent across the two qURL flows.
		UserAgent: qurlBootstrapUserAgent(req.Msg),
		RequestID: requestID,
	})
	prepDone()
	if prepErr != nil {
		if errors.Is(prepErr, ErrAdmissionDenied) {
			log.Info("[QURL] authWithNHPClaims: admission denied client=%s: %v", clientIP, prepErr)
			return failAck(ackMsg, common.ErrQurlSessionExpired, "qurl v2 admission denied")
		}
		log.Error("[QURL] authWithNHPClaims: prepare failed client=%s: %v", clientIP, prepErr)
		return failAck(ackMsg, common.ErrKnockApiRequestFailed, common.ErrKnockApiRequestFailed.Error())
	}

	// Commit BEFORE opening AC. If commit fails, prepare's lease is still PENDING
	// (consume did not durably land), so release it promptly with cancel rather
	// than wedging a one-time-use / max-session slot until the lease TTL reclaims
	// it. (TTL is the backstop for a client that prepares and then vanishes — NHP
	// has not vanished on a transient commit failure; it knows the lease is
	// pending.) We do NOT open the AC.
	// #3032 drift guard: qurl-service echoed qurl_user_public_key_hash in the
	// prepare response (commit uses it to locate the admission state row), while
	// NHP recomputes the same hash locally for the AC revocation index
	// (revocationHashesFromClaims). Both are hex(sha256(base64url key)) by contract,
	// so they MUST be equal. If a future hash-format drift makes them differ, commit
	// still succeeds (the echoed value locates the row) but the revocation index
	// would key by a different value and targeted user-key revocation would silently
	// miss — so make the drift observable here instead of latent.
	if localHash, hErr := qurlv2.PublicKeyHashFromB64(claims.QurlUserPublicKeyB64); hErr == nil && localHash != prepResp.QurlUserPublicKeyHash {
		log.Warning("[QURL] authWithNHPClaims: qurl_user_public_key_hash DRIFT admission=%s: qurl-service=%s nhp-local=%s (revocation index may silently miss; contract requires the same preimage)",
			prepResp.AdmissionID, prepResp.QurlUserPublicKeyHash, localHash)
		// Metric (not just the log) so this security-relevant drift is alertable
		// rather than reliant on someone reading logs.
		if helper.IncrCounter != nil {
			helper.IncrCounter(nhpserver.MetricQurlV2CommitHashDrift)
		}
	}

	commitCtx, commitDone := context.WithTimeout(context.Background(), qurlAuthorizeTimeout)
	commitErr := resolver.CommitAdmission(commitCtx, admissionFinalizeParams{
		admissionID:           prepResp.AdmissionID,
		qurlUserPublicKeyHash: prepResp.QurlUserPublicKeyHash,
		srcIP:                 clientIP,
		requestID:             requestID,
	})
	commitDone()
	if commitErr != nil {
		log.Error("[QURL] authWithNHPClaims: commit failed admission=%s client=%s: %v", prepResp.AdmissionID, clientIP, commitErr)
		cancelPendingAdmission(admissionFinalizeParams{
			admissionID:           prepResp.AdmissionID,
			qurlUserPublicKeyHash: prepResp.QurlUserPublicKeyHash,
			srcIP:                 clientIP,
			requestID:             requestID,
		})
		return failAck(ackMsg, common.ErrKnockApiRequestFailed, "qurl v2 admission commit failed")
	}

	// Commit succeeded → consume/session state is durable. From here we MUST NOT
	// cancel: an AC-open failure is fail-closed (deny + loud log), never a silent
	// un-consume of a one-time-use qURL.
	//
	// Stamp OpenTime before the callback (handleNhpOpenResource serializes it onto
	// the wire ack so the agent paces its re-knock cadence). RedirectUrl is stamped
	// only on the SUCCESS path below, so a failed-open ack does not carry it.
	//
	// QurlSiteURL is taken from the prepare response as-is, NOT validated against
	// AllowedRedirectDomain. It comes from a service-token-authenticated
	// qurl-service response (qurl-service builds it for both qurl.site and
	// customer custom domains), the same trust basis on which the qv1 browser
	// bootstrap path (authnhp.go) already forwards QurlSiteURL unvalidated. The
	// prepare response carries no is_custom_domain flag, so validating against
	// AllowedRedirectDomain here would reject every custom-domain qURL; that gate
	// belongs with a custom-domain signal in the contract (tracked for the
	// flag-flip rollout), not as a blanket reject that breaks custom domains.
	// incrCounter mirrors the nil-guarded helper.IncrCounter idiom used across
	// the qURL plugin (see main.go): a no-op when the helper did not bind a
	// metric emitter (e.g. unit tests), live on the knock path where
	// NewNhpServerHelper binds udpServer.metrics.IncrCounter.
	incrCounter := func(name string) {
		if helper.IncrCounter != nil {
			helper.IncrCounter(name)
		}
	}
	openRes := buildV2ResourceData(prepResp, claims, incrCounter)
	ackMsg.OpenTime = openRes.OpenTime

	openedAck, openErr := helper.AuthWithNhpCallbackFunc(req, openRes)
	if openErr != nil {
		// AC open failed AFTER a durable commit. The qURL may now be consumed even
		// though the user never reached the resource — an explicit fail-closed
		// reliability tradeoff (product may offer reissue UX). We do NOT cancel.
		log.Error("[QURL] authWithNHPClaims: AC open failed AFTER commit admission=%s client=%s (NOT canceling; fail-closed): %v",
			prepResp.AdmissionID, clientIP, openErr)
		// Prefer the callback's ack (it may carry a specific AC error code the agent
		// can act on). Only if the callback returned no ack do we stamp our own, so
		// the agent gets a readable error ack on this branch rather than a null body.
		if openedAck != nil {
			return openedAck, openErr
		}
		return failAck(ackMsg, common.ErrKnockApiRequestFailed, "qurl v2 AC open failed after commit")
	}
	if openedAck != nil {
		openedAck.RedirectUrl = prepResp.QurlSiteURL
	}

	log.Info("[QURL] authWithNHPClaims: admitted admission=%s qurl=%s client=%s ac=%s open_time=%d",
		prepResp.AdmissionID, prepResp.QurlID, clientIP, prepResp.ACRouting.ACId, openRes.OpenTime)
	return openedAck, nil
}

// refreshV2Admission is the steady-state re-knock path: a live session matched
// authorize, so we re-open (refresh) the AC pinhole for the session's REMAINING
// lifetime instead of re-minting via prepare/commit. There is NO prepare lease
// and NO commit to undo here — authorize is idempotent and already recorded the
// landing AC into the session's admitted set — so an AC-open failure is simply a
// retryable error ack (the next re-knock refreshes again); there is nothing to
// cancel. This is what keeps a CONSUMED one-time-use qURL's still-live session
// alive across OpenTime expiries, closing the admission-audit MAJOR.
//
// authorize's response carries no OpenTime/QurlSiteURL (those are first-knock
// concepts): the pinhole duration is remaining_seconds (validated > 0 by the
// authorize client), and — exactly like the v1 tokenless re-knock — no
// RedirectUrl is stamped (the browser already has the page; re-knocks only
// refresh the pinhole). session_id (which prepare cannot return) flows from the
// authorize response into the AOP revocation metadata here.
func refreshV2Admission(req *common.NhpAuthRequest, helper *plugins.NhpServerPluginHelper, claims *qurlv2.Claims, authzResp *AdmissionAuthorizeResponse, clientIP string) (*common.ServerKnockAckMsg, error) {
	ackMsg := req.Ack

	incrCounter := func(name string) {
		if helper.IncrCounter != nil {
			helper.IncrCounter(name)
		}
	}
	openRes := buildV2RefreshResourceData(authzResp, claims, incrCounter)
	ackMsg.OpenTime = openRes.OpenTime

	openedAck, openErr := helper.AuthWithNhpCallbackFunc(req, openRes)
	if openErr != nil {
		// Refresh AC-open failure. Unlike the first-knock commit path there is no
		// durable lease/consume to reconcile (authorize did not consume anything), so
		// this is a plain retryable error ack — the agent's next re-knock refreshes
		// again. We prefer the callback's ack if it carries a specific AC error code.
		log.Error("[QURL] refreshV2Admission: AC refresh open failed session=%s client=%s ac=%s: %v",
			authzResp.SessionID, clientIP, authzResp.ACRouting.ACId, openErr)
		if openedAck != nil {
			return openedAck, openErr
		}
		return failAck(ackMsg, common.ErrKnockApiRequestFailed, "qurl v2 AC refresh open failed")
	}

	// Re-knock refresh: no RedirectUrl (the browser already navigated at bootstrap;
	// this only refreshes the pinhole), mirroring the v1 tokenless re-knock path.
	log.Info("[QURL] refreshV2Admission: refreshed session=%s client=%s ac=%s open_time=%d",
		authzResp.SessionID, clientIP, authzResp.ACRouting.ACId, openRes.OpenTime)
	return openedAck, nil
}

// buildV2RefreshResourceData maps an authorize (re-knock) response's ac_routing
// into the ResourceData the AC-open callback consumes, mirroring
// buildV2ResourceData but for the refresh path. Differences from the first-knock
// builder:
//
//   - OpenTime is the session's remaining_seconds (authorize is the session-
//     lifetime authority; there is no catalog ceiling in v2). The authorize client
//     already rejects a 200 with remaining_seconds == 0, so OpenTime is > 0 here.
//   - ResourceId is the authorize ac_routing's ac_id is NOT a qURL id; we have no
//     qurl_id on the refresh response, so the pinhole ResourceGroup is keyed by the
//     AC's ac_id. (The qURL/resource identity that matters for revocation rides the
//     hashes below, not this group id.)
//   - QurlSessionId is set from the authorize response (the first slice where a
//     session id exists); AdmissionId is empty (authorize records no new admission).
//   - There is no RedirectUrl (re-knocks do not re-navigate).
//
// The two revocation key hashes are recomputed from the VERIFIED claim key bytes
// via the shared revocationHashesFromClaims helper (same fail-open-but-observable
// nil-claims / hash-error behavior as the first-knock buildV2ResourceData), so a
// hash anomaly degrades targeted revocation to timer-wheel expiry rather than
// tearing down a live session over revocation-INDEX metadata.
func buildV2RefreshResourceData(resp *AdmissionAuthorizeResponse, claims *qurlv2.Claims, incrCounter func(string)) *common.ResourceData {
	qurlUserKeyHash, resourceKeyHash, deadline := revocationHashesFromClaims(
		claims, "session="+resp.SessionID, incrCounter)

	return &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			// No qurl_id on the refresh response; key the pinhole group by the AC id.
			// The revocation identity rides the hashes + session_id below.
			ResourceId:    resp.ACRouting.ACId,
			AuthServiceId: PluginID,
			OpenTime:      resp.RemainingSeconds,
			Resources: map[string]*common.ResourceInfo{
				resp.ACRouting.ACId: acRoutingToResourceInfo(resp.ACRouting),
			},
		},
		// No RedirectUrl on a re-knock refresh.

		// P4a revocation metadata. session_id is carried here (and ONLY here) — the
		// authorize response is the first place it exists. admission_id stays empty
		// (no new admission decision on a refresh).
		QurlUserPublicKeyHash: qurlUserKeyHash,
		ResourcePublicKeyHash: resourceKeyHash,
		QurlSessionId:         resp.SessionID,
		Deadline:              deadline,
	}
}

// revocationHashesFromClaims recomputes the two P4a revocation key hashes (and the
// claim-exp deadline) from the VERIFIED claim key bytes, via the single canonical
// hasher qurlv2.PublicKeyHashFromB64 — so the AC's P4b indexes key off exactly the
// same digest. It is the shared core of buildV2ResourceData (first knock) and
// buildV2RefreshResourceData (re-knock); logCtx is the caller's id label
// ("admission=..." or "session=...") so the fail-open log lines stay attributable.
//
// Fail-open, but observable: claims is the post-VerifyClaims value at both call
// sites, so claims == nil (or a key that no longer decodes after passing
// proof-of-possession / resource-binding) is a documented invariant violation, not
// an expected input. Rather than panic at this now-test-reachable seam or fail an
// already-committed / already-authorized admission over revocation-INDEX metadata,
// we return an EMPTY hash for the offending key and bump
// MetricQurlV2RevocationHashError so the regression is alertable in aggregate. An
// empty hash means the flow is invisible to P4b's targeted revocation (it degrades
// to scheduled timer-wheel expiry only) — a security-relevant degradation, but a
// strictly better outcome than tearing the flow down. incrCounter is the plugin's
// nil-guarded helper.IncrCounter (no-op when unset, e.g. in unit tests); the
// knock-path helper (NewNhpServerHelper) binds it, so this is live on the real v2
// admission path.
func revocationHashesFromClaims(claims *qurlv2.Claims, logCtx string, incrCounter func(string)) (qurlUserKeyHash, resourceKeyHash string, deadline int64) {
	if claims == nil {
		log.Error("[QURL] revocationHashesFromClaims: nil claims (invariant violation) %s; proceeding with empty revocation hashes", logCtx)
		incrCounter(nhpserver.MetricQurlV2RevocationHashError)
		return "", "", 0
	}
	var err error
	qurlUserKeyHash, err = qurlv2.PublicKeyHashFromB64(claims.QurlUserPublicKeyB64)
	if err != nil {
		log.Error("[QURL] revocationHashesFromClaims: hashing qurl-user public key failed %s: %v", logCtx, err)
		incrCounter(nhpserver.MetricQurlV2RevocationHashError)
	}
	resourceKeyHash, err = qurlv2.PublicKeyHashFromB64(claims.ResourcePublicKeyB64)
	if err != nil {
		log.Error("[QURL] revocationHashesFromClaims: hashing resource public key failed %s: %v", logCtx, err)
		incrCounter(nhpserver.MetricQurlV2RevocationHashError)
	}
	return qurlUserKeyHash, resourceKeyHash, claims.Exp
}

// acRoutingToResourceInfo maps a qurl-service ac_routing into the ResourceInfo
// the AC-open callback consumes. It is the single source of truth shared by the
// first-knock (buildV2ResourceData) and re-knock (buildV2RefreshResourceData)
// builders, and it deliberately mirrors the qv1 catalog shape in
// endpoints/server/resource_lookup.go (resourceDataFromRow) so the two qURL
// flows produce byte-identical AOP destinations:
//
//   - Addr.Ip is left EMPTY — NOT dest_host. The customer always terminates at the
//     AC's own ingress (portal domain → AC NLB → Traefik-on-AC → upstream resource),
//     so the pinhole must key on the AC-local IP, not the resource's — regardless of
//     whether the upstream is an FRPS backend or an arbitrary URL. The AC's
//     applyDefaultIpSubstitution (endpoints/ac/msghandler.go) rewrites an empty (or
//     0.0.0.0) Ip to its DefaultIp (= LOCAL_IP) at rule-write time. Feeding dest_host
//     here breaks the datapath two ways: a hostname fails the AC's parseIP ("invalid
//     IP address" → ErrServerACOpsFailed/52005), and a real resource IP keys the rule
//     on the WRONG dst (silent datapath deny). This is the load-bearing empty-Ip
//     sentinel the qv1 DDB bridge already documents (terraform/resources.tf), and it
//     is a DISTINCT field from the NHP-ACK "Resource Address" (carried on Hostname
//     below) — the pre-fix bug conflated the two.
//   - Hostname carries dest_host so the ack's ResourceHost stays populated
//     (ResourceInfo.DestHost() prefers Hostname over Addr.Ip) — same field/shape as
//     qv1 (qv1 puts the customer FQDN there; here it is the upstream host, but the
//     value is ack-informational only) and preserves pre-fix qv2 ack behavior.
//   - Addr.Port is ac_routing.dest_port UNCHANGED (no substitution): per the contract
//     (QURL_V2_KEYED_IDENTITY.md example shows dest_port=443) it is the AC ingress /
//     customer-facing port (the Traefik-on-AC listener), NOT the upstream resource
//     port — so the pinhole (LOCAL_IP, dest_port) matches the customer's connection.
//     Same as qv1, where terraform maps dest_port = customer_facing_port → Addr.Port.
//   - PortSuffix is intentionally false (the one divergence from qv1's row.PortSuffix):
//     it only shapes the ack ResourceHost (bare host vs "host:port"), never the
//     datapath, and qv2 clients navigate via the redirect qurl_site_url, not by
//     dialing ResourceHost:port.
//   - Protocol is "tcp" (matching qv1): every NHP-gated qURL resource is TCP (HTTPS).
//     This also narrows the AC rule from port-agnostic (pre-fix qv2 left Protocol
//     empty → the AC adds a no-port rule) to port-specific TCP on Addr.Port — strictly
//     tighter and the proven qv1 shape, and it is why the dest_port = AC-ingress-port
//     invariant above is load-bearing (a wrong port would now silently not match).
//
// ac is non-nil at both call sites: prepare/authorize responses are validated
// (validateAdmission{Prepare,Authorize}Response reject a nil ac_routing) before
// these builders run.
func acRoutingToResourceInfo(ac *ACRouting) *common.ResourceInfo {
	return &common.ResourceInfo{
		ACId:     ac.ACId,
		Hostname: ac.DestHost, // informational (ack ResourceHost); NOT the datapath dst
		Addr: &common.NetAddress{
			// Ip intentionally empty → AC applyDefaultIpSubstitution writes LOCAL_IP.
			Port:     ac.DestPort,
			Protocol: "tcp",
		},
	}
}

// buildV2ResourceData maps the prepare response's selected ac_routing into the
// ResourceData the AC-open callback consumes. NHP opens the AC named in
// ac_routing (the contract: "NHP opens the AC named in that ac_routing"), so the
// opened AC matches the ac_id commit recorded into admitted_ac_ids — keeping a
// targeted revoke's target set complete by construction. handleNhpOpenResource
// resolves the live AC connection by ACId; the pinhole destination is built by
// acRoutingToResourceInfo (see it for why dest_host does NOT become the datapath
// dst IP).
//
// It also stamps the P4a revocation metadata onto the ResourceData so it flows
// down to the AOP builder and on to the AC, via the shared
// revocationHashesFromClaims helper (recompute from the VERIFIED claim bytes;
// fail-open-but-observable on a nil-claims / hash anomaly — see that helper).
//
// session_id and revocation_epoch are intentionally left unset: the prepare
// contract (AdmissionPrepareResponse) does not return them. The re-knock refresh
// path (buildV2RefreshResourceData) carries session_id; revocation_epoch awaits a
// contract field and a later slice. The AOP fields exist already and stay omitted
// until then.
func buildV2ResourceData(resp *AdmissionPrepareResponse, claims *qurlv2.Claims, incrCounter func(string)) *common.ResourceData {
	qurlUserKeyHash, resourceKeyHash, deadline := revocationHashesFromClaims(
		claims, "admission="+resp.AdmissionID, incrCounter)

	return &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			ResourceId:    resp.QurlID,
			AuthServiceId: PluginID,
			OpenTime:      resp.OpenTime,
			Resources: map[string]*common.ResourceInfo{
				resp.ACRouting.ACId: acRoutingToResourceInfo(resp.ACRouting),
			},
		},
		RedirectUrl: resp.QurlSiteURL,

		// P4a revocation metadata (see ResourceData field docs).
		QurlUserPublicKeyHash: qurlUserKeyHash,
		ResourcePublicKeyHash: resourceKeyHash,
		AdmissionId:           resp.AdmissionID,
		Deadline:              deadline,
	}
}

// cancelPendingAdmission best-effort releases a still-pending prepare lease after
// a failed commit. It uses a FRESH context (not the admission ctx): the shared
// context may already be expired — often the very reason commit failed — and
// reusing it would make the cancel a guaranteed no-op. A cancel against an
// already-committed admission is a safe no-op on the qurl-service side (cancel
// only releases a pending lease), so this is safe even in the unlikely
// commit-landed-but-response-lost case. Cancel failure is logged, not fatal: the
// lease TTL is the ultimate backstop.
func cancelPendingAdmission(in admissionFinalizeParams) {
	ctx, cancel := context.WithTimeout(context.Background(), qurlAuthorizeTimeout)
	defer cancel()
	if err := resolver.CancelAdmission(ctx, in); err != nil {
		log.Warning("[QURL] authWithNHPClaims: cancel after failed commit did not confirm admission=%s client=%s (lease TTL will reclaim): %v",
			in.admissionID, in.srcIP, err)
	}
}

// qurlV2ClaimsBlobs extracts the qv2 signed-claims and issuer-signature blobs
// from the encrypted knock UserData. It returns ok=false unless BOTH are present
// non-empty strings — mirroring the HandleKnockRequest predicate so the dispatch
// and the skip-DDB gate agree on what a qv2 knock is.
func qurlV2ClaimsBlobs(msg *common.AgentKnockMsg) (claimsB64, sigB64 string, ok bool) {
	if msg == nil || msg.UserData == nil {
		return "", "", false
	}
	claimsB64, ok = nhpserver.TrimmedStringUserData(msg.UserData, qurlV2ClaimsUserDataKey)
	if !ok {
		return "", "", false
	}
	sigB64, ok = nhpserver.TrimmedStringUserData(msg.UserData, qurlV2IssuerSigUserDataKey)
	if !ok {
		return "", "", false
	}
	return claimsB64, sigB64, true
}
