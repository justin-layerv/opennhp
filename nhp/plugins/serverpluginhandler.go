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

type NhpServerPluginHelper struct {
	StopSignal              <-chan struct{}
	AuthWithNhpCallbackFunc NhpPluginPostAuthFunc
}

type HttpServerPluginHelper struct {
	StopSignal               <-chan struct{}
	AuthWithHttpCallbackFunc HttpPluginPostAuthFunc

	// Metric emitters routed through the host server's CloudWatch
	// publisher. Plugins must treat these as nil-safe — the publisher
	// is not always plumbed (notably in unit tests that build the
	// helper by hand), and callers should branch on `!= nil` rather
	// than relying on a no-op default. Latency values are milliseconds.
	RecordLatency func(name string, ms float64)
	IncrCounter   func(name string)
}
