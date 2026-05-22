// Package layerv is the static plugin handler for the agent-bootstrap
// knock flow introduced in nhp #1977 (FRPS-behind-AC).
//
// The agent-bootstrap flow authenticates customer agents via X25519
// (Noise IK) plus a DDB-backed pubkey lookup in `qurl-agent-keys`
// (resolved by `resolveAgentPeerForKnock` in `endpoints/server/
// nhpauth.go` before the plugin runs). The key-authenticated knock
// IS the primary access control — see #1977 security model:
//
//	"Every knock is authenticated by the client's X25519 private key,
//	 validated against the registered public key in
//	 nhp/core/responder.go::validatePeer."
//
// This plugin therefore performs no additional auth: it looks up the
// requested resource against the resource.toml-loaded
// `["layerv".ResourceGroups...]` overlay (rendered by Terraform from
// `local.frps_resource_toml_overlay` and read via helper.AspData) and
// dispatches the AC operations via helper.AuthWithNhpCallbackFunc.
//
// The pre-existing static plugins (passcode, oidc, qurl) carry their
// own SDK-backed resourceHandler that reads a per-plugin config
// directory. The agent-bootstrap flow's resource catalog lives in the
// host server's aspMap (populated by Terraform; not per-plugin), so
// layerv reads from helper.AspData instead.
package layerv

import (
	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

// Plugin implements plugins.PluginHandler. The struct is empty — all
// state the agent-bootstrap flow needs flows through the per-knock
// helper (AspData + AuthWithNhpCallbackFunc), so there's nothing to
// stash on the receiver.
type Plugin struct{}

// New is the factory registered with the static plugin registry. The
// host server invokes it lazily from `updateResources` when it sees
// an aspId of "layerv" in the loaded resource.toml.
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

// RequestOTP / RegisterAgent / ListService / AuthWithHttp: the
// agent-bootstrap flow is knock-only over NHP; no OTP, no register,
// no list, no HTTP login surface. Return ErrPluginNotRegistered so a
// misrouted request fails loud rather than silently no-oping.

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

// PluginID is the identifier the agent-bootstrap flow's FRPS overlay
// in `terraform/resources.tf` keys on (`var.ac_auth_service_id`,
// defaulted to `"layerv"` in environments/{sandbox,prod}/terraform.tfvars).
// Keep in lockstep with that variable: a rename here without renaming
// the tfvar (or vice versa) silently re-introduces "failed to find
// service provider with layerv" at runtime.
const PluginID = "layerv"

func init() {
	plugins.RegisterPlugin(PluginID, New)
}
