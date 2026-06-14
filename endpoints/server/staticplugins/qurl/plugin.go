package qurl

import (
	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

// Plugin implements plugins.PluginHandler interface for QURL token resolution.
// This plugin handles "quantum-style" URL access tokens that provide short-lived,
// policy-bound, cryptographically protected access to NHP-protected resources.
type Plugin struct{}

// New creates a new QURL plugin instance
func New() plugins.PluginHandler {
	return &Plugin{}
}

// Version returns the plugin version
func (p *Plugin) Version() string {
	return Version()
}

// Signature returns the plugin signature (not implemented)
func (p *Plugin) Signature() string {
	return ""
}

// ExportedData returns exported plugin data (not used)
func (p *Plugin) ExportedData() *plugins.PluginParamsOut {
	return nil
}

// Init initializes the plugin
func (p *Plugin) Init(in *plugins.PluginParamsIn) error {
	return Init(in)
}

// Close shuts down the plugin
func (p *Plugin) Close() error {
	return Close()
}

// RequestOTP handles OTP requests (not implemented for QURL plugin)
func (p *Plugin) RequestOTP(req *common.NhpOTPRequest, helper *plugins.NhpServerPluginHelper) error {
	return plugins.ErrPluginNotRegistered
}

// RegisterAgent handles agent registration (not implemented for QURL plugin)
func (p *Plugin) RegisterAgent(req *common.NhpRegisterRequest, helper *plugins.NhpServerPluginHelper) (*common.ServerRegisterAckMsg, error) {
	return nil, plugins.ErrPluginNotRegistered
}

// ListService handles service listing (not implemented for QURL plugin)
func (p *Plugin) ListService(req *common.NhpListRequest, helper *plugins.NhpServerPluginHelper) (*common.ServerListResultMsg, error) {
	return nil, plugins.ErrPluginNotRegistered
}

// AuthWithNHP authorizes an NHP knock for a qURL resource and opens the AC
// pinhole. It is the knock-path counterpart of AuthWithHttp: the token-based
// HTTP path resolves+mints a session via /resolve, while the knock path (direct
// re-knock or relay-forwarded, #2208) carries no token and instead consults the
// existing session via qurl-service /authorize. See authnhp.go.
func (p *Plugin) AuthWithNHP(req *common.NhpAuthRequest, helper *plugins.NhpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	return AuthWithNHP(req, helper)
}

// AuthWithHttp handles HTTP-based authentication for QURL access tokens
func (p *Plugin) AuthWithHttp(ctx *gin.Context, req *common.HttpKnockRequest, helper *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	return AuthWithHttp(ctx, req, helper)
}

// PluginID is the identifier used to register this plugin
const PluginID = "qurl"

// init registers the plugin with the global registry when this package is imported
func init() {
	plugins.RegisterPlugin(PluginID, New)
}
