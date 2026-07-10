// Package agent is the umbrella NHP-knock handler for LayerV-platform
// resources accessed by registered customer agents (X25519 keypair +
// DDB-backed pubkey registration).
//
// # Naming and aspId model
//
// The plugin's PluginID is "agent" — named after the AUTH MECHANISM
// (keypair-backed registered agent), not after a product brand or a
// specific resource. The aspId-naming rule across this server is:
//
//	aspId names the auth handler (the code that runs in AuthWithNHP);
//	resources sharing the same auth code share an aspId.
//
// Under that rule:
//
//   - passcode and oidc legitimately stay distinct: each runs a
//     different verification algorithm (OTP check vs IdP token
//     validate) in its own AuthWithNHP. Dispatch happens via
//     FindPluginHandler(aspId).
//
//   - agent is correctly an UMBRELLA: every resource registered here
//     shares the same SkipAuth=true code path below. The X25519 pubkey
//     lookup upstream (resolveAgentPeerForKnock in nhpauth.go) IS the
//     authentication — by the time AuthWithNHP runs, the agent is
//     already verified. Adding a new agent-auth'd LayerV resource means
//     writing one DDB row in the `nhp_resources` table with
//     `auth_service_id = "agent"` and a new resource_id; the bridge
//     (ResourceLookup) picks it up on the next cache miss without a TF
//     render or reimage.
//
//   - qurl looks like an aspId but its AuthWithNHP is a stub
//     (staticplugins/qurl/plugin.go returns ErrPluginNotRegistered).
//     The qurl plugin only handles HTTP-knock (browser/SPA via
//     qurl.link); the shared aspId registry across NHP-knock and
//     HTTP-knock surfaces is an OpenNHP plumbing artifact, not a deep
//     semantic. qurl knocks never reach this plugin and this plugin's
//     resources never reach qurl.
//
// # History
//
// This handler was previously named "layerv" (vendor-branded). The
// rename to "agent" landed alongside the #1976 cutover that removed
// the baked TOML overlay path — the rename signals scope (mechanism,
// not brand) and makes the umbrella semantics self-documenting to
// future contributors.
//
// # NHP-native registration (RequestOTP / RegisterAgent)
//
// Beyond the knock flow, this plugin implements the NHP-native agent
// REGISTRATION surface: RequestOTP triggers a one-time-code email and
// RegisterAgent enrolls the device, both by calling qurl-service
// internal endpoints (POST /internal/v1/agent/{otp,register}) via the
// registrar (registrar.go). The whole surface is FEATURE-FLAG-GATED on
// AGENT_OTP_REGISTRATION_ENABLED (config.go), DEFAULT OFF: when the flag
// is off (or the enabled config is incomplete), RequestOTP returns and
// RegisterAgent stamps the RAK with common.ErrRegistrationDisabled and
// no network call happens — the feature ships dark. When on, results map
// to the N1 registration errCodes (52100 block). The register-ack (RAK)
// shape stays frozen at {errCode,errMsg,aspId}: the qurl-service agent_id
// is used server-side for audit logging only and is delivered to the SDK
// via a separate HTTPS completion fetch, never in the RAK.
//
// # What this plugin does at runtime (knock)
//
// The agent knock flow authenticates customer agents via X25519 (Noise IK)
// plus a DDB-backed pubkey lookup in `qurl-agent-keys`, resolved by
// `resolveAgentPeerForKnock` in `endpoints/server/nhpauth.go` BEFORE
// this plugin runs. The key-authenticated knock IS the primary access
// control — see nhp #1977 security model:
//
//	"Every knock is authenticated by the client's X25519 private key,
//	 validated against the registered public key in
//	 nhp/core/responder.go::validatePeer."
//
// This plugin therefore performs no additional auth. It looks up the
// requested resource against helper.AspData (the in-memory
// authServiceMap entry for the "agent" aspId, populated by the DDB
// bridge on first knock miss per process; see resource_lookup.go)
// and dispatches the AC operations via helper.AuthWithNhpCallbackFunc.
//
// The pre-existing static plugins (passcode, oidc) carry their own
// SDK-backed resourceHandler that reads a per-plugin config directory.
// The agent flow's resource catalog lives in the host server's
// authServiceMap (populated by the DDB bridge from `nhp_resources`
// rows; not per-plugin), so agent reads from helper.AspData instead.
package agent

import (
	"context"
	"errors"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

// Plugin implements plugins.PluginHandler. The struct is empty — all
// state the agent flow needs flows through the per-knock helper
// (AspData + AuthWithNhpCallbackFunc), so there's nothing to stash on
// the receiver.
type Plugin struct{}

// New is the factory registered with the static plugin registry. The
// host server invokes it lazily from `updateResources` when it sees
// an aspId of "agent" — populated in `authServiceMap` by the DDB
// bridge from `nhp_resources` rows on knock receipt
// (resource_lookup.go::queryAndCache). The same trigger path also
// fires for any pre-loaded `[agent]` block in resource.toml, but no
// shipped TOML carries agent-aspId rows post-#1976 — the DDB bridge
// is the production registration path.
func New() plugins.PluginHandler {
	return &Plugin{}
}

func (p *Plugin) Version() string {
	return Version()
}

func (p *Plugin) Signature() string {
	return ""
}

func (p *Plugin) ExportedData() *plugins.PluginParamsOut {
	return nil
}

func (p *Plugin) Init(in *plugins.PluginParamsIn) error {
	return Init(in)
}

func (p *Plugin) Close() error {
	return Close()
}

// RequestOTP triggers the NHP-native registration one-time-code email by calling
// qurl-service POST /internal/v1/agent/otp. It is FIRE-AND-FORGET: the OTP
// dispatch (msghandler.go::dispatchOTP) swallows-and-logs whatever this returns
// and never sends a reply, so returning an error here only affects the server
// log, not the wire.
//
// FLAG GATING: when AGENT_OTP_REGISTRATION_ENABLED is false (the default), or
// when Init latched a config error, this returns common.ErrRegistrationDisabled
// WITHOUT any network call — the feature is inert. When enabled, it maps the
// N1→qurl-service field contract, calls the registrar, and returns nil on the
// 202 dispatch or the mapped error otherwise.
//
// Caller contract: req and req.Msg are non-nil (the dispatch always constructs
// them); a nil Msg would be a caller bug and is guarded defensively.
//
// REDACTION: logs the non-secret api_key_id (Msg.UserId) and a truncated
// device-pubkey prefix only. It NEVER logs Msg.Passcode (the api-key secret).
func (p *Plugin) RequestOTP(req *common.NhpOTPRequest, helper *plugins.NhpServerPluginHelper) error {
	if reg == nil {
		// Disabled or misconfigured: fail closed, no network. initErr (if any)
		// was already surfaced at Init; here we return the honest steady-state
		// verdict the dispatch logs.
		return common.ErrRegistrationDisabled
	}
	if req == nil || req.Msg == nil {
		return common.ErrInvalidInput
	}

	otpReq := &otpAPIRequest{
		APIKeyID:        req.Msg.UserId,
		APIKeySecret:    req.Msg.Passcode,
		DeviceID:        req.Msg.DeviceId,
		DevicePubkeyB64: req.PublicKey,
		SrcIP:           srcIP(req.SrcAddr),
	}

	log.Info("[AGENT] RequestOTP api_key_id=%q device_id=%q pubkey_b64_prefix=%q — dispatching OTP via qurl-service",
		req.Msg.UserId, req.Msg.DeviceId, pubkeyLogPrefix(req.PublicKey))

	// No request-id: the NHP OTP/REG dispatch has no gin/HTTP request context to
	// derive one from (unlike the qURL HTTP-knock path), and NhpServerPluginHelper
	// carries none. Pass empty — the registrar omits the X-Request-ID header then.
	if err := reg.requestOTP(context.Background(), otpReq, ""); err != nil {
		log.Error("[AGENT] RequestOTP api_key_id=%q pubkey_b64_prefix=%q failed: %v",
			req.Msg.UserId, pubkeyLogPrefix(req.PublicKey), err)
		return err
	}
	return nil
}

// RegisterAgent enrolls the agent's device by calling qurl-service POST
// /internal/v1/agent/register and populates the pre-allocated RAK
// (req.Ack, a *common.ServerRegisterAckMsg) with the verdict. It ALWAYS returns
// a non-nil ack so the dispatch (msghandler.go::buildRegisterAck) can deliver a
// decryptable RAK carrying a concrete errCode rather than a silent drop.
//
// FLAG GATING: when disabled/misconfigured, the RAK is stamped
// common.ErrRegistrationDisabled with no network call. When enabled, on the 200
// success the RAK carries ErrCode="0" (common.ErrSuccess); on failure it carries
// the mapped registration errCode.
//
// RAK SHAPE IS FROZEN: ServerRegisterAckMsg is {errCode,errMsg,aspId} and does
// NOT carry agent_id. Per the plan's spec-compliance decision the qurl-service
// agent_id comes back to the SDK via the separate HTTPS completion fetch, NOT the
// RAK — so we log the agent_id server-side for audit and deliberately DO NOT put
// it on the ack. AuthServiceId echoes Msg.AuthServiceId on every path.
//
// RETURN CONTRACT WITH THE DISPATCH: buildRegisterAck prefers a non-nil returned
// ack and, on a non-nil error, stamps registerErrToCode over it only if the
// ack's errCode is still a success sentinel. We fully populate the ack ourselves
// (errCode set on every failure path) and return (ack, nil) — the logical reject
// is IN the ack, not the returned error — so the dispatch delivers our exact
// verdict unchanged. Returning a non-nil error would risk registerErrToCode
// re-mapping a code we already set precisely.
//
// REDACTION: logs api_key_id (Msg.UserId), device_id, and pubkey prefix only.
// It NEVER logs Msg.OTP (the registration credential).
func (p *Plugin) RegisterAgent(req *common.NhpRegisterRequest, helper *plugins.NhpServerPluginHelper) (*common.ServerRegisterAckMsg, error) {
	// The dispatch pre-allocates req.Ack, but guard defensively so a
	// directly-constructed request (e.g. a future forwarder) can't NPE us.
	ack := req.Ack
	if ack == nil {
		ack = &common.ServerRegisterAckMsg{}
	}
	if req.Msg != nil {
		ack.AuthServiceId = req.Msg.AuthServiceId
	}

	if reg == nil {
		return failRAK(ack, common.ErrRegistrationDisabled), nil
	}
	if req.Msg == nil {
		return failRAK(ack, common.ErrInvalidInput), nil
	}

	hostname, version, takeover := registerMetadata(req.Msg.UserData)
	regReq := &registerAPIRequest{
		APIKeyID:        req.Msg.UserId,
		DeviceID:        req.Msg.DeviceId,
		Credential:      req.Msg.OTP,
		DevicePubkeyB64: req.PublicKey,
		Hostname:        hostname,
		Version:         version,
		Takeover:        takeover,
		SrcIP:           srcIP(req.SrcAddr),
	}

	log.Info("[AGENT] RegisterAgent api_key_id=%q device_id=%q pubkey_b64_prefix=%q takeover=%t — enrolling via qurl-service",
		req.Msg.UserId, req.Msg.DeviceId, pubkeyLogPrefix(req.PublicKey), takeover)

	// Empty request-id for the same reason as RequestOTP above.
	agentID, err := reg.registerAgent(context.Background(), regReq, "")
	if err != nil {
		log.Error("[AGENT] RegisterAgent api_key_id=%q pubkey_b64_prefix=%q failed: %v",
			req.Msg.UserId, pubkeyLogPrefix(req.PublicKey), err)
		return failRAK(ack, registerErrToRegCode(err)), nil
	}

	// Success. agent_id is logged for audit ONLY — it does not go on the RAK
	// (frozen shape); the SDK fetches it over HTTPS.
	log.Info("[AGENT] RegisterAgent api_key_id=%q device_id=%q agent_id=%q — enrolled",
		req.Msg.UserId, req.Msg.DeviceId, agentID)
	ack.ErrCode = common.ErrSuccess.ErrorCode()
	ack.ErrMsg = common.ErrSuccess.Error()
	return ack, nil
}

func (p *Plugin) ListService(req *common.NhpListRequest, helper *plugins.NhpServerPluginHelper) (*common.ServerListResultMsg, error) {
	return nil, plugins.ErrPluginNotRegistered
}

func (p *Plugin) AuthWithNHP(req *common.NhpAuthRequest, helper *plugins.NhpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	return AuthWithNHP(req, helper)
}

func (p *Plugin) AuthWithHttp(ctx *gin.Context, req *common.HttpKnockRequest, helper *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	return nil, plugins.ErrPluginNotRegistered
}

// PluginID is the aspId the agent-knock dispatch keys on. Wired in
// lockstep with `var.ac_auth_service_id` (TF default `"agent"` in
// environments/{sandbox,prod}/terraform.tfvars) and the client's
// knock-default in qurl-reverse-tunnel-client/cmd/frpc/knock.go
// (`knockAuthServiceID()` returns `agent` by default; overrideable
// via the `LAYERV_KNOCK_ASP_ID` env var, whose name retains the
// `LAYERV_` namespace prefix even though its default value changed).
// The TF↔Go lockstep is enforced at PR time by
// `scripts/check-asp-and-ac-id-lockstep.sh` (wired into
// `.github/workflows/validate-workflows.yml`) — a rename on either
// side without the other fails CI loud rather than silently
// re-introducing "failed to find service provider with agent" at
// runtime. The client-side ↔ server-side lockstep is reviewer-by-
// grep only; cross-repo enforcement would require a third lint
// reaching into the qurl-reverse-tunnel-client repo.
const PluginID = "agent"

func init() {
	plugins.RegisterPlugin(PluginID, New)
}

// failRAK stamps a fail-closed registration verdict onto the ack and returns it.
// Centralizes the errCode/errMsg write so every failure path (disabled, invalid
// input, mapped qurl-service error) produces the identical ack shape. The ack's
// AuthServiceId is set by the caller before this runs (echoing Msg.AuthServiceId).
func failRAK(ack *common.ServerRegisterAckMsg, e *common.Error) *common.ServerRegisterAckMsg {
	ack.ErrCode = e.ErrorCode()
	ack.ErrMsg = e.Error()
	return ack
}

// registerErrToRegCode resolves the RAK errCode for a registrar error. A
// *common.Error (the mapped qurl-service {code}) is used verbatim; anything else
// — a transport failure, a malformed response, an unexpected status — is a
// server-side/transient fault we fail closed as ErrRegistrationDisabled (the
// honest "registration not serviceable right now" verdict), mirroring the
// host dispatch's registerErrToCode fallback for non-typed errors.
func registerErrToRegCode(err error) *common.Error {
	var ce *common.Error
	if errors.As(err, &ce) {
		return ce
	}
	return common.ErrRegistrationDisabled
}

// qurlErrCodeToRegErr maps a qurl-service error {code} string to the N1
// registration errCode (nhp/common/errors.go, the 52100 block). This is the
// authoritative mapping table for the Q2 contract's error vocabulary — a clean
// 1:1 for every terminal client-error code:
//
//	credential_invalid       → ErrRegistrationCredentialInvalid    (52100)
//	credential_expired       → ErrRegistrationCredentialExpired    (52101)
//	attempts_exceeded        → ErrRegistrationAttemptsExceeded     (52102)
//	agent_identity_conflict  → ErrRegistrationIdentityConflict     (52103)
//	rate_limited             → ErrRegistrationRateLimited          (52104)
//	email_unavailable        → ErrRegistrationEmailUnavailable     (52105)
//	invalid_api_key          → ErrRegistrationApiKeyInvalid        (52106)
//	invalid_device_id        → ErrRegistrationInvalidInput         (52109)
//	bootstrap_key_consumed   → ErrRegistrationBootstrapKeyConsumed (52108)
//	send_failed              → ErrRegistrationDisabled             (52107)  [†]
//	internal_error           → ErrRegistrationDisabled             (52107)  [†]
//	<unknown>                → ErrRegistrationDisabled             (52107)  [†]
//
// invalid_device_id maps to its own code (52109 "invalid registration input"),
// NOT to 52106 "invalid api key": a malformed device_id (reachable via a
// client-side WithDeviceID override) is a distinct failure, and surfacing the
// api-key string would misdirect debugging. Both are terminal client errors
// (not load-shedding), so neither is retried.
//
// [†] send_failed / internal_error / any unrecognized code are server-side
//
//	faults; ErrRegistrationDisabled is the fail-closed catch-all (same choice
//	the host dispatch's registerErrToCode makes for untyped errors). A retryable
//	server fault is intentionally reported as "disabled" rather than fabricating
//	a retry hint the RAK has no field to carry.
func qurlErrCodeToRegErr(code string) *common.Error {
	switch code {
	case "credential_invalid":
		return common.ErrRegistrationCredentialInvalid
	case "credential_expired":
		return common.ErrRegistrationCredentialExpired
	case "attempts_exceeded":
		return common.ErrRegistrationAttemptsExceeded
	case "agent_identity_conflict":
		return common.ErrRegistrationIdentityConflict
	case "rate_limited":
		return common.ErrRegistrationRateLimited
	case "email_unavailable":
		return common.ErrRegistrationEmailUnavailable
	case "invalid_api_key":
		return common.ErrRegistrationApiKeyInvalid
	case "invalid_device_id":
		// Dedicated code so a bad device_id does not surface the misleading
		// "invalid api key" string; terminal client error, non-retryable.
		return common.ErrRegistrationInvalidInput
	case "bootstrap_key_consumed":
		return common.ErrRegistrationBootstrapKeyConsumed
	case "send_failed", "internal_error":
		return common.ErrRegistrationDisabled
	default:
		// Unknown code from a newer qurl-service: fail closed rather than
		// leaking a success. See the table note [†].
		return common.ErrRegistrationDisabled
	}
}

// srcIP extracts the source IP for the qurl-service src_ip field. Returns "" for
// a nil address (the field is omitempty, so an absent source is simply omitted).
func srcIP(addr *common.NetAddress) string {
	if addr == nil {
		return ""
	}
	return addr.Ip
}

// registerMetadata defensively extracts the optional hostname/version/takeover
// from the agent-supplied UserData (Msg.UserData, a map[string]any decoded from
// untrusted JSON). Each value is read only when present AND of the expected type;
// an absent or wrong-typed entry yields the zero value, so hostname/version get
// omitted (omitempty) and takeover defaults false. This never panics on a hostile
// map shape.
func registerMetadata(userData map[string]any) (hostname, version string, takeover bool) {
	if userData == nil {
		return "", "", false
	}
	if v, ok := userData["hostname"].(string); ok {
		hostname = v
	}
	if v, ok := userData["version"].(string); ok {
		version = v
	}
	if v, ok := userData["takeover"].(bool); ok {
		takeover = v
	}
	return hostname, version, takeover
}
