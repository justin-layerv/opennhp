package agent

import (
	"fmt"
	"sync"

	"github.com/OpenNHP/opennhp/endpoints/server/internal/qurlplacement"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

const version = "0.1.0"

func Version() string {
	return PluginID + " v" + version
}

// Package-level registration state, initialized exactly once by Init. Mirrors
// the qURL plugin's main.go pattern (a package-level resolver + sync.Once): the
// host server may call Init more than once (New() is invoked lazily per aspId
// load), so the sync.Once makes construction idempotent and thread-safe. Only
// reg + initErr are package-level (the loaded Config is Init-local, matching the
// qURL plugin where cfg does not escape Init):
//
//   - reg is the qurl-service HTTP client, constructed ONLY when enabled; it
//     stays nil when the feature is disabled/misconfigured, so RequestOTP/
//     RegisterAgent short-circuit to the disabled verdict without any network.
//   - initErr latches a config error so every RequestOTP/RegisterAgent on a
//     misconfigured (enabled-but-incomplete) server fails closed consistently
//     rather than nil-derefing the registrar.
var (
	initOnce sync.Once
	reg      *registrar
	initErr  error
)

// Init loads the agent-registration config and, when the feature is enabled,
// constructs the qurl-service registrar exactly once. Fail-fast: an
// enabled-but-incomplete configuration (missing QURL_API_URL /
// QURL_SERVICE_TOKEN, or a non-http(s) URL) latches initErr here so it surfaces
// at server boot rather than at the first agent OTP.
//
// When the feature is DISABLED (the default), LoadConfig returns a non-error
// disabled config and no registrar is built — the plugin loads inert. This is
// what keeps this PR shipping dark until ops flips AGENT_OTP_REGISTRATION_ENABLED.
func Init(in *plugins.PluginParamsIn) error {
	_ = in // unused but required by the plugin interface

	initOnce.Do(func() {
		cfg, err := LoadConfig()
		if err != nil {
			initErr = fmt.Errorf("[AGENT] failed to initialize: %w", err)
			return
		}
		if !cfg.Enabled {
			log.Info("[AGENT] Plugin initialized: %s (NHP-native registration DISABLED — set AGENT_OTP_REGISTRATION_ENABLED to enable)", Version())
			return
		}
		reg = newRegistrar(cfg)
		log.Info("[AGENT] Plugin initialized: %s (NHP-native registration ENABLED)", Version())
	})

	return initErr
}

// Close releases the registrar's pooled connections. Defensive nil checks: Close
// may run even if Init failed or the feature is disabled (reg is nil then).
func Close() error {
	if reg != nil {
		reg.Close()
	}
	return nil
}

// pubkeyLogPrefix mirrors the helper of the same name in
// `endpoints/server/license_pubkey_gate.go`. Forensic grep across
// the resolve→dispatch boundary (`event=agent_resolved
// pubkey_b64_prefix="..."` upstream → this AC-dispatch line)
// depends on identical truncation AND identical empty-string
// behavior (`"<empty>"`). The upstream helper is package-private
// to `endpoints/server`, so agent carries this local mirror.
// If the upstream shape ever moves to a shared package (e.g.
// `nhp/common`), retire this mirror in lockstep.
func pubkeyLogPrefix(pk string) string {
	if pk == "" {
		return "<empty>"
	}
	if len(pk) > 12 {
		return pk[:12]
	}
	return pk
}

// AuthWithNHP handles the agent knock flow.
//
// Caller contract: req, req.Msg, and req.Ack MUST be non-nil. The
// upstream `HandleKnockRequest` enforces this for every live knock
// path; the plugin trusts the contract and dereferences directly.
// A caller violating this (e.g. a future server-to-server forwarder
// that synthesizes the request) will NPE — same shape as the
// passcode/oidc plugins.
//
// Preconditions enforced upstream (`endpoints/server/nhpauth.go`):
//   - X25519 (Noise IK) handshake validated against
//     `nhp/core/responder.go::validatePeer`.
//   - `resolveAgentPeerForKnock` resolved the agent's pubkey to a
//     registered identity in the `qurl-agent-keys` DDB table.
//   - `ResolveAuthSvcProvider("agent")` returned a non-nil aspData
//     (populated by the DDB bridge from `nhp_resources` rows; see
//     resource_lookup.go) and the helper was constructed with
//     `helper.AspData` populated.
//
// Given those, this handler performs no additional auth: it looks up
// the requested resource in the aspData ResourceGroups and delegates
// AC dispatch (ipset write + access-token issuance) to the host
// server's `handleNhpOpenResource` via `helper.AuthWithNhpCallbackFunc`.
//
// See nhp #1977 for the security model — the key-authenticated knock
// IS the access-control primitive; the AC's ipset is a coarse
// pre-filter only.
func AuthWithNHP(req *common.NhpAuthRequest, helper *plugins.NhpServerPluginHelper) (ackMsg *common.ServerKnockAckMsg, err error) {
	// req, req.Msg, req.Ack are non-nil by upstream contract — built in
	// `HandleKnockRequest` and never nil at the plugin call site.
	ackMsg = req.Ack
	if helper == nil {
		// Programmer error — host server's NewNhpServerHelper always
		// returns non-nil. Use a typed sentinel so the agent-side
		// error-code branching and `errors.Is` consumers recognize
		// the failure shape, instead of an opaque `errors.New`.
		err = common.ErrInvalidInput
		ackMsg.ErrCode = common.ErrInvalidInput.ErrorCode()
		ackMsg.ErrMsg = "agent.AuthWithNHP: helper is nil"
		return
	}
	if helper.AspData == nil {
		// Defensive: the host server's NewNhpServerHelper plumbs
		// aspData for the knock path. A nil here means a caller
		// constructed the helper directly without aspData — fail
		// loud rather than silently mis-routing.
		err = common.ErrAuthServiceProviderNotFound
		ackMsg.ErrCode = common.ErrAuthServiceProviderNotFound.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return
	}
	if req.PublicKey == "" {
		// AuthWithNHP should only run after HandleKnockRequest has
		// authenticated the agent via Noise IK + DDB pubkey lookup. This is an
		// all-agent-knock invariant, not just a qURL tunnel special case. qURL
		// tunnel placement must be keyed by that authenticated pubkey; falling
		// back to the user-controlled UserId would let a regression upstream
		// steer AZ placement.
		err = common.ErrInvalidInput
		ackMsg.ErrCode = common.ErrInvalidInput.ErrorCode()
		ackMsg.ErrMsg = "agent.AuthWithNHP: missing authenticated public key"
		return
	}

	res := resolveResourceForRequest(req, helper.AspData)
	if res == nil {
		// Resource registered under some aspId but not "agent" → routing
		// bug at the agent or stale DDB catalog. ErrResourceNotFound
		// (52004) is the existing code for this class.
		err = common.ErrResourceNotFound
		ackMsg.ErrCode = common.ErrResourceNotFound.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return
	}

	// Defense-in-depth against a DDB writer regression that drops
	// SkipAuth=true. The primary access control is the X25519+DDB
	// pubkey resolution already done by `resolveAgentPeerForKnock`;
	// this plugin carries no backend-auth path, so a resource flagged
	// SkipAuth=false would be a config bug, not a request we can
	// satisfy. (Today the bridge hardcodes SkipAuth=true for every
	// row it materializes — see resource_lookup.go::queryAndCache —
	// so this is a forward-looking fence against a future change
	// that exposes SkipAuth as a per-row field.) Same fence as
	// passcode/oidc.
	if !res.SkipAuth {
		err = common.ErrBackendAuthRequired
		ackMsg.ErrCode = common.ErrBackendAuthRequired.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return
	}
	if helper.AuthWithNhpCallbackFunc == nil {
		// Symmetric with the helper/AspData guards: a caller
		// constructing the helper outside `NewNhpServerHelper` could
		// leave the callback nil; deref'ing it would panic. Fail loud
		// with a typed sentinel + ack stamping like the other guards.
		err = common.ErrInvalidInput
		ackMsg.ErrCode = common.ErrInvalidInput.ErrorCode()
		ackMsg.ErrMsg = "agent.AuthWithNHP: AuthWithNhpCallbackFunc is nil"
		return
	}

	log.Info("agent.AuthWithNHP agent_id=%q pubkey_b64_prefix=%q resource_id=%q open_time=%d — agent pre-authenticated via X25519 + DDB lookup, dispatching AC ops",
		req.Msg.UserId, pubkeyLogPrefix(req.PublicKey), req.Msg.ResourceId, res.OpenTime)

	// `ackMsg.OpenTime` is serialized into the agent's ack response
	// (`HandleKnockRequest` JSON-marshals ackMsg at the end), so the
	// agent knows how long the IP rule will be open. The callback
	// `handleNhpOpenResource` neither reads nor writes the field —
	// it derives its own local `openTime` from `res.OpenTime` and
	// `knkMsg.HeaderType` (see #2096 for the NHP_EXT exit-knock
	// divergence). So we stamp it here for wire serialization.
	//
	// `ResourceHost` is NOT stamped here — the callback re-initializes
	// that map and populates it from the per-resource AC ops, so any
	// pre-callback write would be overwritten. Mirrors oidc's pattern;
	// intentionally diverges from passcode's dead pre-write.
	ackMsg.OpenTime = res.OpenTime
	return helper.AuthWithNhpCallbackFunc(req, res)
}

func resolveResourceForRequest(req *common.NhpAuthRequest, asp *common.AuthServiceProviderData) *common.ResourceData {
	// req, req.Msg, and req.PublicKey are non-empty by AuthWithNHP's upstream
	// caller contract and explicit guard above.
	return qurlplacement.ResolveResource(req.Msg.ResourceId, qurlplacement.Identity{
		PublicKey: req.PublicKey,
		UserID:    req.Msg.UserId,
	}, asp)
}
