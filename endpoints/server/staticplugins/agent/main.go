package agent

import (
	"github.com/OpenNHP/opennhp/endpoints/server/internal/qurlplacement"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

const version = "0.1.0"

func Version() string {
	return PluginID + " v" + version
}

// Init retains the static-plugin lifecycle hook. Native Connector
// registration is handled by the assigned-cell composition before plugin
// dispatch; this plugin owns only registered-agent knock admission.
func Init(in *plugins.PluginParamsIn) error {
	_ = in // unused but required by the plugin interface
	log.Info("[AGENT] Plugin initialized: %s (registered-agent knock admission)", Version())
	return nil
}

// Close implements the static-plugin lifecycle. The plugin owns no resources.
func Close() error {
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
	// the resolved resource. Bodyless NHP_EXT is dispatched outside this
	// callback. So we stamp it here for wire serialization.
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
