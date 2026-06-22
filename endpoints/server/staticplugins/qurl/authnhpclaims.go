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

	// ---- Liveness/policy admission: prepare → commit → open AC ----
	//
	// prepare and commit each get their OWN bounded context (not one shared
	// budget) so a slow prepare cannot starve commit's deadline — which would turn
	// a healthy admission into a failed commit → cancel, and a re-knock into a
	// lease-conflict deny. The cancel-on-commit-failure path uses its own fresh
	// context too (see cancelPendingAdmission).

	requestID := uuid.NewString()

	prepCtx, prepDone := context.WithTimeout(context.Background(), qurlAuthorizeTimeout)
	prepResp, prepErr := resolver.PrepareAdmission(prepCtx, &AdmissionPrepareRequest{
		QurlClaimsB64:                 claimsB64,
		QurlIssuerSigB64:              sigB64,
		AuthenticatedQurlPublicKeyB64: req.PublicKey,
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
	commitCtx, commitDone := context.WithTimeout(context.Background(), qurlAuthorizeTimeout)
	commitErr := resolver.CommitAdmission(commitCtx, prepResp.AdmissionID, requestID)
	commitDone()
	if commitErr != nil {
		log.Error("[QURL] authWithNHPClaims: commit failed admission=%s client=%s: %v", prepResp.AdmissionID, clientIP, commitErr)
		cancelPendingAdmission(prepResp.AdmissionID, requestID, clientIP)
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
	openRes := buildV2ResourceData(prepResp)
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

// buildV2ResourceData maps the prepare response's selected ac_routing into the
// ResourceData the AC-open callback consumes. NHP opens the AC named in
// ac_routing (the contract: "NHP opens the AC named in that ac_routing"), so the
// opened AC matches the ac_id commit recorded into admitted_ac_ids — keeping a
// targeted revoke's target set complete by construction. handleNhpOpenResource
// resolves the live AC connection by ACId; dest host/port come from ac_routing.
func buildV2ResourceData(resp *AdmissionPrepareResponse) *common.ResourceData {
	return &common.ResourceData{
		ResourceGroup: common.ResourceGroup{
			ResourceId:    resp.QurlID,
			AuthServiceId: PluginID,
			OpenTime:      resp.OpenTime,
			Resources: map[string]*common.ResourceInfo{
				resp.ACRouting.ACId: {
					ACId: resp.ACRouting.ACId,
					Addr: &common.NetAddress{
						Ip:   resp.ACRouting.DestHost,
						Port: resp.ACRouting.DestPort,
					},
				},
			},
		},
		RedirectUrl: resp.QurlSiteURL,
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
func cancelPendingAdmission(admissionID, requestID, clientIP string) {
	ctx, cancel := context.WithTimeout(context.Background(), qurlAuthorizeTimeout)
	defer cancel()
	if err := resolver.CancelAdmission(ctx, admissionID, requestID); err != nil {
		log.Warning("[QURL] authWithNHPClaims: cancel after failed commit did not confirm admission=%s client=%s (lease TTL will reclaim): %v",
			admissionID, clientIP, err)
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
