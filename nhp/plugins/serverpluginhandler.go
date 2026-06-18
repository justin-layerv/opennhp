package plugins

import (
	"errors"
	"fmt"
	"path/filepath"
	"plugin"

	"github.com/gin-gonic/gin"

	common "github.com/OpenNHP/opennhp/nhp/common"
	log "github.com/OpenNHP/opennhp/nhp/log"
	utils "github.com/OpenNHP/opennhp/nhp/utils"
)

var ExeDirPath string

type PluginHandler interface {
	Version() string
	Signature() string
	ExportedData() *PluginParamsOut
	Init(*PluginParamsIn) error
	Close() error
	RequestOTP(*common.NhpOTPRequest, *NhpServerPluginHelper) error
	RegisterAgent(*common.NhpRegisterRequest, *NhpServerPluginHelper) (*common.ServerRegisterAckMsg, error)
	ListService(*common.NhpListRequest, *NhpServerPluginHelper) (*common.ServerListResultMsg, error)
	AuthWithNHP(*common.NhpAuthRequest, *NhpServerPluginHelper) (*common.ServerKnockAckMsg, error)
	AuthWithHttp(*gin.Context, *common.HttpKnockRequest, *HttpServerPluginHelper) (*common.ServerKnockAckMsg, error)
}

type PluginHandlerSymbol struct {
	sVersion       plugin.Symbol
	sSignature     plugin.Symbol
	sExportedData  plugin.Symbol
	sInit          plugin.Symbol
	sClose         plugin.Symbol
	sRequestOTP    plugin.Symbol
	sRegisterAgent plugin.Symbol
	sListService   plugin.Symbol
	sAuthWithNHP   plugin.Symbol
	sAuthWithHttp  plugin.Symbol
}

var errPluginNotImplemented error = errors.New("plugin not implemented")

func (s *PluginHandlerSymbol) Version() string {
	if s.sVersion == nil {
		return ""
	}
	defer utils.CatchPanic()

	fn, ok := s.sVersion.(func() string)
	if !ok {
		log.Error("plugin: invalid function type for Version")
		return ""
	}
	return fn()
}

func (s *PluginHandlerSymbol) Signature() string {
	if s.sSignature == nil {
		return ""
	}
	defer utils.CatchPanic()

	fn, ok := s.sSignature.(func() string)
	if !ok {
		log.Error("plugin: invalid function type for Signature")
		return ""
	}
	return fn()
}

func (s *PluginHandlerSymbol) ExportedData() *PluginParamsOut {
	if s.sExportedData == nil {
		return nil
	}
	defer utils.CatchPanic()

	fn, ok := s.sExportedData.(func() *PluginParamsOut)
	if !ok {
		log.Error("plugin: invalid function type for ExportedData")
		return nil
	}
	return fn()
}

func (s *PluginHandlerSymbol) Init(in *PluginParamsIn) error {
	if s.sInit == nil {
		return errPluginNotImplemented
	}
	defer utils.CatchPanic()

	fn, ok := s.sInit.(func(*PluginParamsIn) error)
	if !ok {
		return fmt.Errorf("plugin: invalid function type for Init")
	}
	return fn(in)
}

func (s *PluginHandlerSymbol) Close() error {
	if s.sClose == nil {
		return errPluginNotImplemented
	}
	defer utils.CatchPanic()

	fn, ok := s.sClose.(func() error)
	if !ok {
		return fmt.Errorf("plugin: invalid function type for Close")
	}
	return fn()
}

func (s *PluginHandlerSymbol) RequestOTP(req *common.NhpOTPRequest, helper *NhpServerPluginHelper) error {
	if s.sRequestOTP == nil {
		return errPluginNotImplemented
	}
	defer utils.CatchPanic()

	fn, ok := s.sRequestOTP.(func(*common.NhpOTPRequest, *NhpServerPluginHelper) error)
	if !ok {
		return fmt.Errorf("plugin: invalid function type for RequestOTP")
	}
	return fn(req, helper)
}

func (s *PluginHandlerSymbol) RegisterAgent(req *common.NhpRegisterRequest, helper *NhpServerPluginHelper) (*common.ServerRegisterAckMsg, error) {
	if s.sRegisterAgent == nil {
		return nil, errPluginNotImplemented
	}
	defer utils.CatchPanic()

	fn, ok := s.sRegisterAgent.(func(*common.NhpRegisterRequest, *NhpServerPluginHelper) (*common.ServerRegisterAckMsg, error))
	if !ok {
		return nil, fmt.Errorf("plugin: invalid function type for RegisterAgent")
	}
	return fn(req, helper)
}

func (s *PluginHandlerSymbol) ListService(req *common.NhpListRequest, helper *NhpServerPluginHelper) (*common.ServerListResultMsg, error) {
	if s.sListService == nil {
		return nil, errPluginNotImplemented
	}
	defer utils.CatchPanic()

	fn, ok := s.sListService.(func(*common.NhpListRequest, *NhpServerPluginHelper) (*common.ServerListResultMsg, error))
	if !ok {
		return nil, fmt.Errorf("plugin: invalid function type for ListService")
	}
	return fn(req, helper)
}

func (s *PluginHandlerSymbol) AuthWithNHP(req *common.NhpAuthRequest, helper *NhpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	if s.sAuthWithNHP == nil {
		log.Error("AuthWithNHP not implemented")
		return nil, errPluginNotImplemented
	}
	defer utils.CatchPanic()

	fn, ok := s.sAuthWithNHP.(func(*common.NhpAuthRequest, *NhpServerPluginHelper) (*common.ServerKnockAckMsg, error))
	if !ok {
		return nil, fmt.Errorf("plugin: invalid function type for AuthWithNHP")
	}
	return fn(req, helper)
}

func (s *PluginHandlerSymbol) AuthWithHttp(ctx *gin.Context, req *common.HttpKnockRequest, hlpr *HttpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	if s.sAuthWithHttp == nil {
		return nil, errPluginNotImplemented
	}
	defer utils.CatchPanic()

	fn, ok := s.sAuthWithHttp.(func(*gin.Context, *common.HttpKnockRequest, *HttpServerPluginHelper) (*common.ServerKnockAckMsg, error))
	if !ok {
		return nil, fmt.Errorf("plugin: invalid function type for AuthWithHttp")
	}
	return fn(ctx, req, hlpr)
}

func ReadPluginHandler(pluginPath string) PluginHandler {
	fullPath := filepath.Join(ExeDirPath, "plugins", pluginPath)
	log.Debug("Opening plugin: %s (ExeDirPath=%s)", fullPath, ExeDirPath)
	p, err := plugin.Open(fullPath)
	if err != nil {
		log.Error("open plugin %s failed: %v", fullPath, err)
		return nil
	}
	log.Debug("Plugin opened successfully: %s", fullPath)
	s := &PluginHandlerSymbol{}
	s.sVersion, _ = p.Lookup("Version")
	s.sSignature, _ = p.Lookup("Signature")
	s.sExportedData, _ = p.Lookup("ExportedData")
	s.sInit, _ = p.Lookup("Init")
	s.sClose, _ = p.Lookup("Close")
	s.sRequestOTP, _ = p.Lookup("RequestOTP")
	s.sRegisterAgent, _ = p.Lookup("RegisterAgent")
	s.sListService, _ = p.Lookup("ListService")
	s.sAuthWithNHP, _ = p.Lookup("AuthWithNHP")
	s.sAuthWithHttp, _ = p.Lookup("AuthWithHttp")

	return s
}

type PluginParamsIn struct {
	PluginDirPath *string
	Log           *log.Logger
	Hostname      *string
	LocalIp       *string
	LocalMac      *string
}

type PluginParamsOut struct {
}

type NhpPluginPostAuthFunc func(*common.NhpAuthRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error)

type HttpPluginPostAuthFunc func(*common.HttpKnockRequest, *common.ResourceData) (*common.ServerKnockAckMsg, error)

// HttpPluginResolveResourceFunc resolves AC routing for (aspId, resId) from the
// host server's own resource catalog — the same storage-backed resolution the
// headless /nhp/internal/knock path uses. It exists so an HTTP plugin can open
// pinholes against catalog-authoritative routing instead of trusting routing
// data carried in its own upstream response body (layervai/nhp#2540).
//
// No ctx parameter by design: the host wires this to a shutdown-scoped
// (lifecycle) context, NOT the plugin's per-request context. The underlying
// catalog lookup singleflights concurrent knocks for the same hot resource, and
// its closure captures the first caller's context — a per-request context would
// fan a single client's disconnect out to every piggybacked live caller (and to
// the headless path, which shares the singleflight group). So the lookup is
// uncancelable by a browser close; the plugin attributes a client disconnect at
// the knock step instead.
//
// srcIP is the client IP; its role depends on the row type. For the static/ASP-
// placement branch it is the source-identity placement key that selects an AC.
// For the dynamic qURL (q_) rows the qURL plugin actually resolves, the lookup
// is an exact (aspId, resId) match, so srcIP is NOT an AC-selection key there and
// does NOT become the pinhole key — the resolver writes it onto a throwaway
// lookup request and discards it; it only satisfies the resolver's fail-closed
// non-empty check (the actual L3 pinhole source key is the knock request's own
// SrcIp). Returns the resolved ResourceData (caller reads its Resources map and
// OpenTime — the latter as the catalog ceiling for its own downward clamp) or an
// error on a catalog miss / lookup failure — callers MUST fail closed rather
// than fall back to body-supplied routing.
type HttpPluginResolveResourceFunc func(aspId, resId, srcIP string) (*common.ResourceData, error)

type NhpServerPluginHelper struct {
	StopSignal              <-chan struct{}
	AuthWithNhpCallbackFunc NhpPluginPostAuthFunc
	// ResolveResourceFunc resolves AC routing from the host server's catalog
	// (see HttpPluginResolveResourceFunc). qURL relay bootstrap uses it after
	// qurl-service validates the encrypted access token and returns the dynamic
	// q_ catalog key. nil-safe: hand-built test helpers may leave it nil, so
	// callers must branch on `!= nil` and fail closed when it is.
	ResolveResourceFunc HttpPluginResolveResourceFunc

	// AspData is the AuthServiceProviderData matched for the incoming
	// knock's AuthServiceId. Plugins that don't carry a per-plugin
	// resource registry (the agent-bootstrap flow, where the resource
	// catalog lives in the host server's resource.toml `aspMap`) read
	// the requested resource off AspData.ResourceGroups[resourceId].
	// Pre-existing plugins (passcode, oidc) keep their own SDK-backed
	// resourceHandler and don't read this field — nil-safe by design.
	//
	// READ-ONLY: plugins MUST NOT mutate AspData or any value reached
	// through it. The host server treats published aspData as
	// immutable from the lock-free read path, and a plugin write
	// would race every concurrent reader as well as the next
	// `updateResources` rebuild.
	//
	// Concurrency: plugins read AspData and its ResourceGroups
	// lock-free. The host's `updateResources` mutates the fresh
	// aspMap's resources pre-publication (writing `AuthServiceId` /
	// `ResourceId` onto each ResourceData), then atomically swaps
	// `s.authServiceMap` under Lock (`endpoints/server/config.go`).
	// Post-swap the published aspData is effectively immutable from
	// THAT PATH — the lock-free read sees a stable snapshot.
	//
	AspData *common.AuthServiceProviderData
}

type HttpServerPluginHelper struct {
	StopSignal               <-chan struct{}
	AuthWithHttpCallbackFunc HttpPluginPostAuthFunc

	// ResolveResourceFunc resolves AC routing from the host server's
	// catalog (see HttpPluginResolveResourceFunc). The qURL plugin uses it
	// so AC pinhole routing comes from the NHP catalog rather than the
	// qurl-service resolve-response body (#2540). nil-safe: like the metric
	// emitters below, hand-built helpers (unit tests) may leave it nil, so
	// callers must branch on `!= nil` and fail closed when it is.
	ResolveResourceFunc HttpPluginResolveResourceFunc

	// Metric emitters routed through the host server's CloudWatch
	// publisher. Plugins must treat these as nil-safe — the publisher
	// is not always plumbed (notably in unit tests that build the
	// helper by hand), and callers should branch on `!= nil` rather
	// than relying on a no-op default. Latency values are milliseconds.
	RecordLatency func(name string, ms float64)
	IncrCounter   func(name string)
}
