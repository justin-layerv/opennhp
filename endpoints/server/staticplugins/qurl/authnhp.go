package qurl

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	nhpserver "github.com/OpenNHP/opennhp/endpoints/server"
	"github.com/OpenNHP/opennhp/endpoints/server/internal/qurlplacement"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

const (
	// qurlAuthorizeTimeout bounds qurl-service calls on the knock path. Unlike
	// AuthWithHttp (which inherits the gin request context), the knock handler has
	// no request context to inherit, so we derive a bounded one.
	qurlAuthorizeTimeout = 5 * time.Second

	qurlBootstrapResourceID    = "qurl-bootstrap"
	qurlAccessTokenUserDataKey = "qurl_access_token"
	qurlUserAgentUserDataKey   = "qurl_user_agent"
)

// AuthWithNHP authorizes an NHP knock for a qURL resource and opens the AC
// pinhole. It is the knock-path counterpart of AuthWithHttp.
//
// Initial qurl.link bootstrap carries the qURL access token inside the
// encrypted AgentKnockMsg usrData and uses a sentinel resource id. NHP validates
// the token with qurl-service, binds the authenticated browser pubkey, resolves
// AC routing from the NHP catalog, opens the AC, and returns redirectUrl in the
// ACK. The browser never calls qurl-service / resolve directly.
//
// Steady-state re-knocks carry no token — the token was consumed at bootstrap.
// That path instead:
//
//  1. Resolves the resource -> AC mapping from the server's catalog
//     (helper.AspData), keyed on the knock's ResourceId.
//  2. Asks qurl-service GET /internal/v1/resource/:id/authorize?client_ip=X
//     whether that client IP still holds an active session — the same
//     idempotent, IP-scoped check qurl-router runs per HTTP request.
//  3. On allow, opens the pinhole (capped at the session's remaining
//     lifetime); on deny, returns an error ACK and opens nothing.
//
// Because NHP_KNK / NHP_RKN and relay-forwarded knocks (#2208) all reach this
// via buildKnockAck -> AuthWithNHP, a re-knock re-consults the live session
// automatically. The resource id keys both the catalog lookup and /authorize
// (single-id model, #2208); see docs/design/NHP_RELAY_TOPOLOGY.md.
func AuthWithNHP(req *common.NhpAuthRequest, helper *plugins.NhpServerPluginHelper) (ackMsg *common.ServerKnockAckMsg, err error) {
	// req, req.Msg, req.Ack are non-nil by the HandleKnockRequest contract.
	ackMsg = req.Ack

	if helper == nil {
		return failAck(ackMsg, common.ErrInvalidInput, "qurl.AuthWithNHP: helper is nil")
	}
	if helper.AspData == nil {
		// NewNhpServerHelper plumbs aspData for the knock path; nil means a
		// caller built the helper directly. Fail loud rather than mis-route.
		return failAck(ackMsg, common.ErrAuthServiceProviderNotFound, common.ErrAuthServiceProviderNotFound.Error())
	}
	if helper.AuthWithNhpCallbackFunc == nil {
		return failAck(ackMsg, common.ErrInvalidInput, "qurl.AuthWithNHP: AuthWithNhpCallbackFunc is nil")
	}
	if resolver == nil {
		// Plugin not initialized (Init never ran or failed). Without a resolver
		// there is no way to make the access decision — fail closed.
		return failAck(ackMsg, common.ErrAuthServiceProviderNotFound, "qurl.AuthWithNHP: plugin not initialized (nil resolver)")
	}
	if req.PublicKey == "" {
		// The knock must be agent-authenticated (Noise IK) before its source IP
		// can steer an AC pinhole — same invariant the agent plugin enforces.
		return failAck(ackMsg, common.ErrInvalidInput, "qurl.AuthWithNHP: missing authenticated public key")
	}

	resourceID := req.Msg.ResourceId
	var clientIP string
	if req.SrcAddr != nil {
		clientIP = req.SrcAddr.Ip
	}
	if clientIP == "" {
		return failAck(ackMsg, common.ErrInvalidInput, "qurl.AuthWithNHP: missing source address")
	}

	if accessToken, ok := qurlBootstrapAccessToken(req.Msg); ok {
		return authWithNHPBootstrap(req, helper, accessToken, clientIP)
	}

	// Resolve the resource -> AC mapping from the catalog. The same resourceID
	// keys this lookup and the /authorize call below. identity only influences
	// ResolveResource's tunnel-placement branch (resourceID == TunnelServerResourceID);
	// a normal r_ id is a direct map lookup and tunnel resources are rejected
	// below, so identity is effectively inert here — built for parity with the
	// agent/forward paths.
	identity := qurlplacement.Identity{
		PublicKey: req.PublicKey,
		SourceIP:  clientIP,
		UserID:    req.Msg.UserId,
	}
	res := qurlplacement.ResolveResource(resourceID, identity, helper.AspData)
	if res == nil {
		return failAck(ackMsg, common.ErrResourceNotFound, common.ErrResourceNotFound.Error())
	}
	// Deliberate divergence from the agent plugin: NO `if !res.SkipAuth` fence.
	// The agent plugin uses SkipAuth as its access gate (defense-in-depth vs a
	// DDB-writer regression); for qURL the access gate is the /authorize session
	// check below, so the catalog SkipAuth flag is not load-bearing here. Do not
	// "restore" a SkipAuth check — it would fight the real gate.

	// Access decision: does this client IP still have an active session? The
	// knock path has no inbound HTTP request to correlate, so mint a request id
	// for the nhp->qurl-service hop so qurl-service can trace the /authorize call.
	//
	// The timeout uses context.Background (the plugin has no shutdown-cancelable
	// context; helper.StopSignal is nil on the relay path). qurlAuthorizeTimeout
	// therefore bounds how long an in-flight knock can extend graceful shutdown's
	// transaction drain (endpoints/server/CLAUDE.md Stop() step 5) — kept short
	// for that reason. This is new outbound-HTTP behavior for the knock path (the
	// agent plugin makes no such call).
	requestID := uuid.NewString()
	ctx, cancel := context.WithTimeout(context.Background(), qurlAuthorizeTimeout)
	defer cancel()
	authz, authErr := resolver.Authorize(ctx, resourceID, clientIP, requestID)
	switch {
	case errors.Is(authErr, ErrQurlAccessDenied):
		// Authenticated, but no active session -> deny ACK, no pinhole. The
		// agent re-resolves via the qURL link to mint a fresh session.
		log.Info("[QURL] AuthWithNHP: access denied resource=%s client=%s (no active session)", resourceID, clientIP)
		return failAck(ackMsg, common.ErrQurlSessionExpired, "qurl access denied: no active session")
	case authErr != nil:
		// Any non-deny failure -> error ACK. This includes a malformed /authorize
		// 200 body (ErrInvalidResolveResponse): we treat it as retryable rather
		// than a hard deny on the deliberate bet that a malformed body is more
		// likely a transient qurl-service blip than a permanent contract break,
		// and a re-knock is harmless. Revisit with a distinct non-retryable code
		// if the contract proves to emit malformed-but-stable responses.
		//
		// No callback retry here (unlike AuthWithHttp): on the UDP knock path the
		// agent's re-knock cadence is the retry. The wire ErrMsg stays generic —
		// authErr wraps the internal qurl-service URL + client_ip, which is logged
		// server-side but must not be echoed back to the agent.
		log.Error("[QURL] AuthWithNHP: authorize call failed resource=%s client=%s: %v", resourceID, clientIP, authErr)
		return failAck(ackMsg, common.ErrKnockApiRequestFailed, common.ErrKnockApiRequestFailed.Error())
	}

	if authz.Tunnel {
		// Tunnel resources authorize via the reverse-tunnel-server flow, not
		// the browser qURL knock path. Out of scope here -> deny.
		log.Warning("[QURL] AuthWithNHP: resource=%s is a tunnel resource; not servable on the browser knock path", resourceID)
		return failAck(ackMsg, common.ErrResourceNotFound, "tunnel resource not servable on the qurl knock path")
	}

	// A non-tunnel allow with zero remaining lifetime is a contract violation
	// (URL resources should always return remaining_seconds > 0). Fail closed
	// rather than fall through and open a pinhole that outlives a zero-life
	// session — the exact failure the cap below exists to prevent.
	if authz.RemainingSeconds == 0 {
		log.Warning("[QURL] AuthWithNHP: resource=%s client=%s authorized with zero remaining lifetime; denying", resourceID, clientIP)
		return failAck(ackMsg, common.ErrQurlSessionExpired, "qurl authorize returned zero remaining lifetime")
	}

	// Effective AC-pinhole duration: the catalog's configured OpenTime, clamped
	// to the session's remaining lifetime so the pinhole can't outlive the
	// session (re-knocks refresh it; the re-knock cadence must stay shorter than
	// this). A zero catalog OpenTime is treated as "unset" and falls back to the
	// session's remaining lifetime — never 0, which would reset the agent's
	// open-timer and hammer the server. RemainingSeconds is already > 0 here
	// (zero-life sessions were denied above).
	openTime := res.OpenTime
	if openTime == 0 || authz.RemainingSeconds < openTime {
		openTime = authz.RemainingSeconds
	}
	openRes := res
	if openTime != res.OpenTime {
		// Shallow-copy so the cached catalog ResourceData is not mutated; the
		// Resources map is read-only downstream.
		clone := *res
		clone.OpenTime = openTime
		openRes = &clone
	}

	// Stamp ackMsg.OpenTime for wire serialization so the agent learns how long
	// the AC rule stays open and can pace its re-knock cadence shorter than that
	// (the re-knock is what refreshes the pinhole). The callback
	// handleNhpOpenResource derives its own local openTime for the AC op and
	// does NOT write this field, so — exactly like the agent plugin — we stamp it
	// here from the (capped) openRes. Without it the ack carries OpenTime=0 and
	// the agent's open-timer resets to 0, hammering the server.
	ackMsg.OpenTime = openRes.OpenTime

	log.Info("[QURL] AuthWithNHP: authorized resource=%s client=%s open_time=%d", resourceID, clientIP, openRes.OpenTime)
	return helper.AuthWithNhpCallbackFunc(req, openRes)
}

func authWithNHPBootstrap(req *common.NhpAuthRequest, helper *plugins.NhpServerPluginHelper, accessToken, clientIP string) (*common.ServerKnockAckMsg, error) {
	ackMsg := req.Ack
	if err := ValidateAccessToken(accessToken); err != nil {
		return failAck(ackMsg, common.ErrInvalidInput, "qurl.AuthWithNHP: invalid bootstrap access token")
	}
	if helper.ResolveResourceFunc == nil {
		log.Error("[QURL] AuthWithNHP bootstrap: catalog resolver not wired; cannot resolve AC routing")
		return failAck(ackMsg, common.ErrKnockApiRequestFailed, "qurl resource routing unavailable")
	}

	requestID := uuid.NewString()
	ctx, cancel := context.WithTimeout(context.Background(), qurlAuthorizeTimeout)
	defer cancel()

	resolveResp, resolveErr := resolver.ResolveBrowserRelay(ctx, &BrowserRelayResolveRequest{
		AccessToken:                 accessToken,
		SrcIP:                       clientIP,
		UserAgent:                   qurlBootstrapUserAgent(req.Msg),
		AuthenticatedAgentPublicKey: req.PublicKey,
		RequestID:                   requestID,
	})
	if resolveErr != nil {
		if isTerminalResolveDeny(resolveErr) {
			log.Info("[QURL] AuthWithNHP bootstrap: access denied client=%s err=%v", clientIP, resolveErr)
			return failAck(ackMsg, common.ErrQurlSessionExpired, "qurl bootstrap denied")
		}
		log.Error("[QURL] AuthWithNHP bootstrap: resolve call failed client=%s: %v", clientIP, resolveErr)
		return failAck(ackMsg, common.ErrKnockApiRequestFailed, common.ErrKnockApiRequestFailed.Error())
	}

	catalogRes, err := helper.ResolveResourceFunc(PluginID, resolveResp.NHPResourceID, clientIP)
	if err != nil || catalogRes == nil || len(catalogRes.Resources) == 0 {
		if errors.Is(err, context.Canceled) {
			log.Warning("[QURL] AuthWithNHP bootstrap: catalog routing resolution canceled for nhp_resource_id=%s: %v", resolveResp.NHPResourceID, err)
		} else if err != nil {
			log.Error("[QURL] AuthWithNHP bootstrap: catalog routing resolution failed for nhp_resource_id=%s: %v", resolveResp.NHPResourceID, err)
		} else {
			log.Error("[QURL] AuthWithNHP bootstrap: catalog returned no routing for nhp_resource_id=%s", resolveResp.NHPResourceID)
		}
		return failAck(ackMsg, common.ErrResourceNotFound, "qurl resource routing unresolved")
	}

	openTime := nhpserver.ClampOpenTimeDownward(catalogRes.OpenTime, resolveResp.OpenTime)
	openRes := buildResourceData(resolveResp, catalogRes.Resources, openTime)
	req.Msg.ResourceId = resolveResp.ResourceID
	ackMsg.OpenTime = openRes.OpenTime
	ackMsg.RedirectUrl = resolveResp.QurlSiteURL

	log.Info("[QURL] AuthWithNHP bootstrap: authorized resource=%s nhp_resource=%s client=%s open_time=%d",
		resolveResp.ResourceID, resolveResp.NHPResourceID, clientIP, openRes.OpenTime)
	openedAck, err := helper.AuthWithNhpCallbackFunc(req, openRes)
	if err != nil {
		return openedAck, err
	}
	if openedAck != nil {
		openedAck.RedirectUrl = resolveResp.QurlSiteURL
	}
	return openedAck, nil
}

func isTerminalResolveDeny(err error) bool {
	return errors.Is(err, ErrTokenNotFound) ||
		errors.Is(err, ErrTokenConsumed) ||
		errors.Is(err, ErrTokenExpired) ||
		errors.Is(err, ErrPolicyViolation) ||
		errors.Is(err, ErrAgentIdentityConflict)
}

func qurlBootstrapAccessToken(msg *common.AgentKnockMsg) (string, bool) {
	if msg == nil || msg.UserData == nil {
		return "", false
	}
	raw, ok := msg.UserData[qurlAccessTokenUserDataKey]
	if !ok {
		return "", false
	}
	token, ok := raw.(string)
	if !ok {
		return "", false
	}
	token = strings.TrimSpace(token)
	if !looksLikeQurlAccessToken(token) {
		return "", false
	}
	return token, true
}

func qurlBootstrapUserAgent(msg *common.AgentKnockMsg) string {
	if msg == nil || msg.UserData == nil {
		return ""
	}
	raw, ok := msg.UserData[qurlUserAgentUserDataKey]
	if !ok {
		return ""
	}
	userAgent, ok := raw.(string)
	if !ok {
		return ""
	}
	userAgent = strings.TrimSpace(userAgent)
	if len(userAgent) > 1024 {
		return userAgent[:1024]
	}
	return userAgent
}

func looksLikeQurlAccessToken(token string) bool {
	if !strings.HasPrefix(token, "at_") || len(token) < minTokenLength || len(token) > maxTokenLength {
		return false
	}
	for _, c := range token {
		if !(unicode.IsLetter(c) || unicode.IsDigit(c) || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// failAck stamps the ack with the error and returns it alongside the error,
// matching the (ackMsg, err) contract HandleKnockRequest expects on a reject.
func failAck(ackMsg *common.ServerKnockAckMsg, e *common.Error, msg string) (*common.ServerKnockAckMsg, error) {
	if ackMsg == nil {
		return nil, fmt.Errorf("%w: %s", e, msg)
	}
	ackMsg.ErrCode = e.ErrorCode()
	ackMsg.ErrMsg = msg
	return ackMsg, e
}
