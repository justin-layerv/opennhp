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
// # What this plugin does at runtime
//
// The agent flow authenticates customer agents via X25519 (Noise IK)
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
	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/nhp/common"
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
	return nil
}

// RequestOTP / RegisterAgent / ListService / AuthWithHttp: the agent
// flow is knock-only over NHP; no OTP, no register, no list, no HTTP
// login surface. Return ErrPluginNotRegistered so a misrouted request
// fails loud rather than silently no-oping.

func (p *Plugin) RequestOTP(req *common.NhpOTPRequest, helper *plugins.NhpServerPluginHelper) error {
	return plugins.ErrPluginNotRegistered
}

func (p *Plugin) RegisterAgent(req *common.NhpRegisterRequest, helper *plugins.NhpServerPluginHelper) (*common.ServerRegisterAckMsg, error) {
	return nil, plugins.ErrPluginNotRegistered
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
