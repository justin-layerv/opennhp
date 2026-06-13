package server

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/OpenNHP/opennhp/nhp/etcd"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/core/verifier"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"
	"github.com/OpenNHP/opennhp/nhp/utils"

	toml "github.com/pelletier/go-toml/v2"
)

var (
	baseConfigWatch  io.Closer
	httpConfigWatch  io.Closer
	acConfigWatch    io.Closer
	agentConfigWatch io.Closer
	resConfigWatch   io.Closer
	srcipConfigWatch io.Closer
	dbConfigWatch    io.Closer
	relayConfigWatch io.Closer
	teeWatch         io.Closer
	errLoadConfig    = errors.New("config load error")
)

// ACRegistryPrefix is the etcd prefix for AC registration entries
const ACRegistryPrefix = "/nhp/ac-registry/"

// ACRegistryEntry represents an AC registration in etcd
// ACs register themselves with their public key
type ACRegistryEntry struct {
	PublicKey    string `toml:"PublicKey"`
	InstanceId   string `toml:"InstanceId"`
	Ip           string `toml:"Ip"`
	Port         int    `toml:"Port"`
	RegisteredAt int64  `toml:"RegisteredAt"`
}

type ServerEtcdConfig struct {
	BaseConfig    Config
	HttpConfig    HttpConfig
	ACs           []*core.UdpPeer
	Agents        []*core.UdpPeer
	DBs           []*core.UdpPeer
	AuthServiceId []*common.AuthServiceProviderData
	SrcIps        []*SrcIpMap
}

type SrcIpMap struct {
	SrcIp string
	Ip    []string
}

type Config struct {
	PrivateKeyBase64    string `json:"privateKey"` //nolint:gosec // G117: config struct, never JSON-marshaled — TOML input only
	Hostname            string `json:"hostname"`
	ListenIp            string `json:"listenIp"`
	ListenPort          int    `json:"listenPort"`
	LogLevel            int    `json:"logLevel"`
	DefaultCipherScheme int    `json:"defaultCipherScheme"`
	// #1157 F9: pelletier/go-toml/v2 (this project's TOML decoder)
	// matches struct fields case-INsensitively regardless of whether
	// a toml: tag is present — verified empirically with v2.3.0
	// against `DisableAgentValidation`, `disableagentvalidation`,
	// `DISABLEAGENTVALIDATION`, and `disableAgentValidation`, all of
	// which parsed to true even with `toml:"DisableAgentValidation"`
	// set. This means an explicit toml tag does NOT close the
	// case-bypass door at runtime — the case-insensitive lint at
	// scripts/check-disable-agent-validation.sh is the structural
	// fence (intentionally `grep -Ei`). Do not add a toml: tag here
	// expecting defense in depth; it provides none.
	DisableAgentValidation bool         `json:"disableAgentValidation"`
	WebRTC                 WebRTCConfig `toml:"webrtc"`

	// StaleACConnThresholdSeconds overrides the default DefaultStaleACConnThreshold
	// (30s) for filtering AC connections out of NHP-AOP broadcast targeting.
	// A connection that has not received a packet in this window is treated
	// as dead. Lowering this aggressively risks filtering out a healthy AC
	// that has briefly stopped responding (e.g., GC pause); raising it gives
	// the broadcast more time on dead peers. Tune from MetricACConnStaleFiltered
	// rate against demonstrably-live ACs. Zero / negative values fall back
	// to the default.
	StaleACConnThresholdSeconds int `json:"staleACConnThresholdSeconds"`

	// ACPeerGracePeriodSeconds overrides the default grace window for the
	// /health/knock-ready AC peer check. The check returns pass-with-cached-
	// count for this long after the live AC connection count drops to zero,
	// so single-keepalive-cycle flickers (the per-AC-ID slice momentarily
	// emptying before the next NHP_AOL re-registers it) do not flap NLB
	// target health or false-fail per-instance smoke probes. Past this
	// window a sustained zero flips to fail honestly.
	//
	// Zero or unset → DefaultACPeerGracePeriod (30s, == AC's
	// KeepaliveInterval × KeepaliveMaxRetries). Negative disables the
	// grace window entirely (legacy immediate-fail behavior); use only
	// when intentionally testing the underlying counter contract.
	//
	// Positive values outside [MinACPeerGracePeriod, MaxACPeerGracePeriod]
	// (10s–5m) are clamped into that range, with a boot-log warning
	// — see acPeerGracePeriodFromConfig in httpserver.go.
	//
	// Restart required: the checker is built once at initHealthManager
	// and hot-reload (SIGHUP) does not re-thread this value into the
	// active checker. Changes to config.toml take effect at process
	// restart.
	ACPeerGracePeriodSeconds int `json:"acPeerGracePeriodSeconds"`
}

type RemoteConfig struct {
	Provider   string
	Key        string
	Endpoints  []string
	Username   string
	Password   string //nolint:gosec // G117: no JSON tag, never serialized — TOML config for etcd
	TLS        bool
	CACert     string
	ClientCert string
	ClientKey  string //nolint:gosec // G117: no JSON tag, never serialized — TLS client key path
}

type HttpConfig struct {
	EnableHttp     bool
	EnableTLS      bool
	HttpListenIp   string
	HttpListenPort int
	TLSCertFile    string
	TLSKeyFile     string
	ReadTimeoutMs  int
	WriteTimeoutMs int
	IdleTimeoutMs  int
}

type Peers struct {
	ACs    []*core.UdpPeer
	Agents []*core.UdpPeer
	DBs    []*core.UdpPeer
	Relays []*core.UdpPeer
}

func (s *UdpServer) loadBaseConfig() error {
	// config.toml - REQUIRED for server to start
	fileName := filepath.Join(ExeDirPath, "etc", "config.toml")
	content, err := s.loadConfigFile(fileName)
	if err != nil {
		return fmt.Errorf("failed to read base config %s: %w", fileName, err)
	}

	var config Config
	if err := toml.Unmarshal(content, &config); err != nil {
		return fmt.Errorf("failed to parse base config %s: %w", fileName, err)
	}

	// Validate required fields
	if config.PrivateKeyBase64 == "" {
		return fmt.Errorf("privateKeyBase64 is required in %s", fileName)
	}

	if err = s.updateBaseConfig(config); err != nil {
		return fmt.Errorf("failed to apply base config: %w", err)
	}

	baseConfigWatch = utils.WatchFile(fileName, func() {
		log.Info("[Server] base config %s has been updated, reloading", fileName)
		if content, err = s.loadConfigFile(fileName); err == nil {
			if err = toml.Unmarshal(content, &config); err == nil {
				if updateErr := s.updateBaseConfig(config); updateErr != nil {
					log.Error("[Server] failed to apply base config update from %s: %v", fileName, updateErr)
				}
			}

		}
	})
	return nil
}

func (s *UdpServer) loadHttpConfig() error {
	// http.toml - optional, enables HTTP endpoint
	fileName := filepath.Join(ExeDirPath, "etc", "http.toml")
	content, err := s.loadConfigFile(fileName)
	if err != nil {
		if os.IsNotExist(err) {
			log.Info("http.toml not found, HTTP endpoint disabled")
			return nil
		}
		return fmt.Errorf("failed to read http config %s: %w", fileName, err)
	}

	var httpConf HttpConfig
	if err := toml.Unmarshal(content, &httpConf); err != nil {
		return fmt.Errorf("failed to parse http config %s: %w", fileName, err)
	}

	if err = s.updateHttpConfig(httpConf); err != nil {
		return fmt.Errorf("failed to apply http config: %w", err)
	}

	httpConfigWatch = utils.WatchFile(fileName, func() {
		log.Info("[Server] http config %s has been updated, reloading", fileName)
		if content, err = s.loadConfigFile(fileName); err == nil {
			if err = toml.Unmarshal(content, &httpConf); err == nil {
				if updateErr := s.updateHttpConfig(httpConf); updateErr != nil {
					log.Error("[Server] failed to apply http config update from %s: %v", fileName, updateErr)
				}
			}
		}
	})
	return nil
}

func (s *UdpServer) loadPeers() error {
	// ac.toml - optional, contains AC peer configurations
	fileNameAC := filepath.Join(ExeDirPath, "etc", "ac.toml")
	contentAC, err := s.loadConfigFile(fileNameAC)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to read AC peer config %s: %w", fileNameAC, err)
		}
		log.Info("ac.toml not found, no AC peers configured")
	} else {
		var acPeers Peers
		if err := toml.Unmarshal(contentAC, &acPeers); err != nil {
			return fmt.Errorf("failed to parse AC peer config %s: %w", fileNameAC, err)
		}
		if err := s.updateACPeers(acPeers.ACs); err != nil {
			return fmt.Errorf("failed to apply AC peers: %w", err)
		}
		acConfigWatch = utils.WatchFile(fileNameAC, func() {
			log.Info("[Server] AC peer config %s has been updated, reloading", fileNameAC)
			if contentAC, err = s.loadConfigFile(fileNameAC); err == nil {
				if err = toml.Unmarshal(contentAC, &acPeers); err == nil {
					if updateErr := s.updateACPeers(acPeers.ACs); updateErr != nil {
						log.Error("[Server] failed to apply AC peer update from %s: %v", fileNameAC, updateErr)
					}
				}
			}
		})
	}

	// agent.toml - optional, contains agent peer configurations
	fileNameAgent := filepath.Join(ExeDirPath, "etc", "agent.toml")
	contentAgent, err := s.loadConfigFile(fileNameAgent)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to read agent peer config %s: %w", fileNameAgent, err)
		}
		log.Info("agent.toml not found, no agent peers configured")
	} else {
		// Cloud-mode + agent.toml coexistence is structurally incompatible.
		// The cloud-mode agent registry lives in qurl-agent-keys DDB and
		// agent peers are inserted into agentPeerMap + device.peerMap on
		// first knock; updateAgentPeers (called from this load path and
		// from the agent.toml WatchFile callback below) builds a fresh
		// map from the file and removes from s.device any pubkey not in
		// the new map — wiping every DDB-resolved peer on each file
		// touch in cloud mode. Refuse boot so the operator sees the
		// conflict at deploy time rather than at the first agent-config
		// watcher fire-and-wipe.
		//
		// The terraform user_data template for cloud-mode servers
		// intentionally does NOT ship agent.toml; this guard catches
		// drift between that template and the deployed filesystem.
		cloudMode := s.storageConfig != nil && s.storageConfig.Backend == StorageBackendDynamoDB
		if cloudMode && s.agentPeerLookup != nil {
			return fmt.Errorf("agent peer registry conflict: %s exists AND cloud-mode agent peer DDB lookup is wired (storage_backend=%q, AgentKeysTable set). The two registries cannot coexist — every agent.toml watcher fire would wipe DDB-resolved peers from agentPeerMap and device.peerMap. Remove %s from this deployment, or disable the cloud-mode agent path by clearing AgentKeysTable in storage.toml",
				fileNameAgent, s.storageConfig.Backend, fileNameAgent)
		}

		var agentPeers Peers
		if err := toml.Unmarshal(contentAgent, &agentPeers); err != nil {
			return fmt.Errorf("failed to parse agent peer config %s: %w", fileNameAgent, err)
		}
		if err := s.updateAgentPeers(agentPeers.Agents); err != nil {
			return fmt.Errorf("failed to apply agent peers: %w", err)
		}
		agentConfigWatch = utils.WatchFile(fileNameAgent, func() {
			log.Info("[Server] agent peer config %s has been updated, reloading", fileNameAgent)
			if contentAgent, err = s.loadConfigFile(fileNameAgent); err == nil {
				if err = toml.Unmarshal(contentAgent, &agentPeers); err == nil {
					if updateErr := s.updateAgentPeers(agentPeers.Agents); updateErr != nil {
						log.Error("[Server] failed to apply agent peer update from %s: %v", fileNameAgent, updateErr)
					}
				}
			}
		})
	}

	// db.toml - optional, contains DB peer configurations
	fileNameDE := filepath.Join(ExeDirPath, "etc", "db.toml")
	contentDE, err := s.loadConfigFile(fileNameDE)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to read DB peer config %s: %w", fileNameDE, err)
		}
		log.Info("db.toml not found, no DB peers configured")
	} else {
		var dePeers Peers
		if err := toml.Unmarshal(contentDE, &dePeers); err != nil {
			return fmt.Errorf("failed to parse DB peer config %s: %w", fileNameDE, err)
		}
		if err := s.updateDePeers(dePeers.DBs); err != nil {
			return fmt.Errorf("failed to apply DB peers: %w", err)
		}
		dbConfigWatch = utils.WatchFile(fileNameDE, func() {
			log.Info("[Server] DB peer config %s has been updated, reloading", fileNameDE)
			if contentDE, err = s.loadConfigFile(fileNameDE); err == nil {
				if err = toml.Unmarshal(contentDE, &dePeers); err == nil {
					if updateErr := s.updateDePeers(dePeers.DBs); updateErr != nil {
						log.Error("[Server] failed to apply DB peer update from %s: %v", fileNameDE, updateErr)
					}
				}
			}
		})
	}

	// relay.toml - optional, contains NHP_RELAY peer configurations (#2208).
	// Registering the relay's static pubkey lets the server authenticate the
	// NHP_RLY packets it forwards. The handler that processes NHP_RLY lands
	// in a follow-up PR; until then a registered relay is authenticated but
	// its NHP_RLY falls through to the default (unhandled) dispatch.
	fileNameRelay := filepath.Join(ExeDirPath, "etc", "relay.toml")
	contentRelay, err := s.loadConfigFile(fileNameRelay)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to read relay peer config %s: %w", fileNameRelay, err)
		}
		log.Info("relay.toml not found, no relay peers configured")
	} else {
		var relayPeers Peers
		if err := toml.Unmarshal(contentRelay, &relayPeers); err != nil {
			return fmt.Errorf("failed to parse relay peer config %s: %w", fileNameRelay, err)
		}
		if err := s.updateRelayPeers(relayPeers.Relays); err != nil {
			return fmt.Errorf("failed to apply relay peers: %w", err)
		}
		relayConfigWatch = utils.WatchFile(fileNameRelay, func() {
			log.Info("[Server] relay peer config %s has been updated, reloading", fileNameRelay)
			if contentRelay, err = s.loadConfigFile(fileNameRelay); err == nil {
				if err = toml.Unmarshal(contentRelay, &relayPeers); err == nil {
					if updateErr := s.updateRelayPeers(relayPeers.Relays); updateErr != nil {
						log.Error("[Server] failed to apply relay peer update from %s: %v", fileNameRelay, updateErr)
					}
				}
			}
		})
	}

	// tee.toml - optional, errors handled inside updateTee
	fileNameTee := filepath.Join(ExeDirPath, "etc", "tee.toml")
	if err := s.updateTee(fileNameTee); err != nil {
		log.Error("[Server] failed to load TEE config from %s: %v", fileNameTee, err)
	}
	teeWatch = utils.WatchFile(fileNameTee, func() {
		log.Info("[Server] TEE config %s has been updated, reloading", fileNameTee)
		if err := s.updateTee(fileNameTee); err != nil {
			log.Error("[Server] failed to apply TEE config update from %s: %v", fileNameTee, err)
		}
	})

	return nil
}

func (s *UdpServer) loadResources() error {
	// resource.toml
	fileName := filepath.Join(ExeDirPath, "etc", "resource.toml")
	content, err := os.ReadFile(fileName)
	if err != nil {
		log.Error("[Server] failed to read resource config %s: %v", fileName, err)
		return nil // optional config, watcher will pick up changes
	}
	aspMap := make(common.AuthSvcProviderMap)
	// update
	if err := toml.Unmarshal(content, &aspMap); err != nil {
		log.Error("[Server] failed to parse resource config %s: %v", fileName, err)
		return nil
	}
	if err := s.updateResources(aspMap); err != nil {
		log.Error("[Server] failed to apply resource config from %s: %v", fileName, err)
	}

	resConfigWatch = utils.WatchFile(fileName, func() {
		log.Info("[Server] resource config %s has been updated, reloading", fileName)
		if content, err := s.loadConfigFile(fileName); err == nil {
			freshAspMap := make(common.AuthSvcProviderMap)
			if err := toml.Unmarshal(content, &freshAspMap); err == nil {
				if updateErr := s.updateResources(freshAspMap); updateErr != nil {
					log.Error("[Server] failed to apply resource config update from %s: %v", fileName, updateErr)
				}
			} else {
				log.Error("[Server] failed to parse resource config %s on reload: %v", fileName, err)
			}
		}
	})
	return nil
}

func (s *UdpServer) loadSourceIps() error {
	// srcip.toml
	fileName := filepath.Join(ExeDirPath, "etc", "srcip.toml")
	content, err := os.ReadFile(fileName)
	if err != nil {
		log.Error("[Server] failed to read source IP config %s: %v", fileName, err)
		return nil // optional config, watcher will pick up changes
	}

	// update
	srcIpMap := make(map[string][]*common.NetAddress)
	if err := toml.Unmarshal(content, &srcIpMap); err != nil {
		log.Error("[Server] failed to parse source IP config %s: %v", fileName, err)
		return nil
	}
	if err := s.updateSourceIps(srcIpMap); err != nil {
		log.Error("[Server] failed to apply source IP config from %s: %v", fileName, err)
	}

	srcipConfigWatch = utils.WatchFile(fileName, func() {
		log.Info("[Server] source IP config %s has been updated, reloading", fileName)
		if content, err = s.loadConfigFile(fileName); err == nil {
			if err = toml.Unmarshal(content, &srcIpMap); err == nil {
				if updateErr := s.updateSourceIps(srcIpMap); updateErr != nil {
					log.Error("[Server] failed to apply source IP config update from %s: %v", fileName, updateErr)
				}
			}
		}
	})
	return nil
}

func (s *UdpServer) initRemoteConn() error {
	// remote.toml
	fileName := filepath.Join(ExeDirPath, "etc", "remote.toml")

	_, e := os.Stat(fileName)
	if os.IsNotExist(e) {
		//remote.toml file not found,use local config
		return nil
	}

	content, err := os.ReadFile(fileName)
	if err != nil {
		log.Error("[Server] failed to read remote config %s: %v", fileName, err)
		return err
	}

	var conf RemoteConfig
	if err = toml.Unmarshal(content, &conf); err != nil {
		log.Error("[Server] failed to parse remote config %s: %v", fileName, err)
		return err
	}

	if strings.EqualFold(conf.Provider, "etcd") {
		if len(conf.Endpoints) == 0 {
			log.Error("[Server] remote config %s has no endpoints, falling back to local configuration", fileName)
			return nil
		}

		if len(conf.Key) == 0 {
			log.Error("[Server] remote config %s has no key, falling back to local configuration", fileName)
			return nil
		}

		s.etcdConn = &etcd.EtcdConn{
			Endpoints:  conf.Endpoints,
			Username:   conf.Username,
			Password:   conf.Password,
			Key:        conf.Key,
			TLS:        conf.TLS,
			CACert:     conf.CACert,
			ClientCert: conf.ClientCert,
			ClientKey:  conf.ClientKey,
		}

		return s.etcdConn.InitClient()
	}

	return errors.New("unknown remote provider")
}

func (s *UdpServer) loadRemoteConfig() error {
	value, err := s.etcdConn.GetValue()
	if err != nil {
		return err
	}
	//base config has been loaded and no secondary loading is required
	if err = s.updateEtcdConfig(value, false); err != nil {
		return err
	}

	go s.etcdConn.WatchValue(func(val []byte) {
		s.remoteConfigUpdateMutex.Lock()
		defer s.remoteConfigUpdateMutex.Unlock()
		if updateErr := s.updateEtcdConfig(val, true); updateErr != nil {
			log.Error("[Server] failed to apply etcd config update (%d bytes): %v", len(val), updateErr)
		}
	})

	return nil
}

func (s *UdpServer) updateEtcdConfig(content []byte, baseLoad bool) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	log.Info("Parsing etcd config (%d bytes): %q", len(content), string(content))
	var serverEtcdConfig ServerEtcdConfig
	if err = toml.Unmarshal(content, &serverEtcdConfig); err != nil {
		log.Error("[Server] failed to parse etcd config (%d bytes): %v", len(content), err)
		return err
	}
	log.Info("Unmarshaled serverEtcdConfig.AuthServiceId has %d entries", len(serverEtcdConfig.AuthServiceId))

	// SECURITY: Never update base config from etcd.
	// Private keys, LogLevel, and base config MUST come from local config.toml.
	// The etcd config typically doesn't have BaseConfig fields, so TOML unmarshaling
	// defaults them to Go's zero values (LogLevel=0, etc.) which would override local settings.
	// The local config.toml contains the per-instance private key and operational settings.
	_ = baseLoad // Explicitly ignore - base config always from local

	// Only update HttpConfig from etcd if it's explicitly set
	// (non-zero port or EnableHttp=true). Otherwise keep local http.toml config.
	// This allows etcd to be used purely for AC registry without requiring HttpConfig.
	if serverEtcdConfig.HttpConfig.EnableHttp || serverEtcdConfig.HttpConfig.HttpListenPort > 0 {
		if updateErr := s.updateHttpConfig(serverEtcdConfig.HttpConfig); updateErr != nil {
			log.Error("[Server] failed to apply http config from etcd: %v", updateErr)
		}
	}

	// Only update AC/Agent/DB peers from etcd config if they are explicitly defined.
	// When using AC registry (/nhp/ac-registry/), ACs register dynamically and are
	// managed by reconcileACPeersFromRegistry(). We must NOT wipe those peers when
	// the etcd config is updated without [[ACs]] section.
	if len(serverEtcdConfig.ACs) > 0 {
		log.Info("Updating %d AC peers from etcd config", len(serverEtcdConfig.ACs))
		if updateErr := s.updateACPeers(serverEtcdConfig.ACs); updateErr != nil {
			log.Error("[Server] failed to apply AC peers from etcd: %v", updateErr)
		}
	} else {
		log.Debug("No [[ACs]] in etcd config, preserving existing AC peers (registry mode)")
	}
	if len(serverEtcdConfig.Agents) > 0 {
		log.Info("Updating %d Agent peers from etcd config", len(serverEtcdConfig.Agents))
		if updateErr := s.updateAgentPeers(serverEtcdConfig.Agents); updateErr != nil {
			log.Error("[Server] failed to apply agent peers from etcd: %v", updateErr)
		}
	} else {
		log.Debug("No [[Agents]] in etcd config, preserving existing Agent peers")
	}
	if len(serverEtcdConfig.DBs) > 0 {
		log.Info("Updating %d DB peers from etcd config", len(serverEtcdConfig.DBs))
		if updateErr := s.updateDePeers(serverEtcdConfig.DBs); updateErr != nil {
			log.Error("[Server] failed to apply DB peers from etcd: %v", updateErr)
		}
	} else {
		log.Debug("No [[DBs]] in etcd config, preserving existing DB peers")
	}

	// Only update resources from etcd if AuthServiceId is explicitly configured.
	// Otherwise, keep the local resource.toml config (plugins are statically compiled).
	if len(serverEtcdConfig.AuthServiceId) > 0 {
		aspMap := make(common.AuthSvcProviderMap)
		for _, aspData := range serverEtcdConfig.AuthServiceId {
			aspId := aspData.AuthSvcId
			aspMap[aspId] = aspData
		}
		log.Info("Parsed %d AuthServiceId entries from etcd config", len(aspMap))
		for aspId, aspData := range aspMap {
			log.Debug("  AuthServiceId[%s]: PluginPath=%q", aspId, aspData.PluginPath)
		}
		if updateErr := s.updateResources(aspMap); updateErr != nil {
			log.Error("[Server] failed to apply resources from etcd: %v", updateErr)
		}
	} else {
		log.Info("No AuthServiceId in etcd config, using local resource.toml")
	}

	srcIpMap := make(map[string][]*common.NetAddress)
	for _, srcIp := range serverEtcdConfig.SrcIps {
		ips := make([]*common.NetAddress, 0)
		for _, ip := range srcIp.Ip {
			addr := &common.NetAddress{
				Ip: ip,
			}
			ips = append(ips, addr)
		}
		srcIpMap[srcIp.SrcIp] = ips
	}
	if updateErr := s.updateSourceIps(srcIpMap); updateErr != nil {
		log.Error("[Server] failed to apply source IPs from etcd: %v", updateErr)
	}

	return nil
}

func (s *UdpServer) loadConfigFile(file string) (content []byte, err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})
	content, err = os.ReadFile(file)
	if err != nil {
		log.Error("[Server] failed to read config file %s: %v", file, err)
	}
	return
}

func (s *UdpServer) updateBaseConfig(conf Config) (err error) {
	if s.config == nil {
		s.config = &conf
		s.log.SetLogLevel(conf.LogLevel)
		if conf.WebRTC.Enable {
			s.webrtcServer = NewWebRTCServer(s, &conf.WebRTC)
			if err := s.webrtcServer.Start(); err != nil {
				log.Error("failed to start WebRTC server: %v", err)
			}
		}
		return nil
	}

	// update
	if s.config.LogLevel != conf.LogLevel {
		log.Info("set base log level to %d", conf.LogLevel)
		s.log.SetLogLevel(conf.LogLevel)
		s.config.LogLevel = conf.LogLevel
	}

	if s.config.DisableAgentValidation != conf.DisableAgentValidation {
		if s.device != nil {
			// Re-apply the cloud-mode override on hot-reload —
			// without this, an operator edit that flips
			// DisableAgentValidation back to false silently undoes
			// the override that Start() applied (every cloud-mode
			// agent first-knock then fails at the responder layer
			// with no metric to alarm on, because the lookup is
			// still wired but never reached).
			s.device.SetOption(core.DeviceOptions{
				DisableAgentPeerValidation: s.computeEffectiveDisableAgentValidation(conf.DisableAgentValidation),
			})
		}
		s.config.DisableAgentValidation = conf.DisableAgentValidation
	}

	if s.config.DefaultCipherScheme != conf.DefaultCipherScheme {
		log.Info("set default cipher scheme to %d", conf.DefaultCipherScheme)
		s.config.DefaultCipherScheme = conf.DefaultCipherScheme
	}

	// handle WebRTC configuration change
	if conf.WebRTC.Enable && s.webrtcServer == nil {
		s.webrtcServer = NewWebRTCServer(s, &conf.WebRTC)
		if err := s.webrtcServer.Start(); err != nil {
			log.Error("failed to start WebRTC server: %v", err)
		}
	}
	if !conf.WebRTC.Enable && s.webrtcServer != nil {
		s.webrtcServer.Stop()
		s.webrtcServer = nil
	}
	s.config.WebRTC = conf.WebRTC

	return nil
}

// applyHttpTimeoutDefaults floors any zero-or-too-small timeout in conf to
// the binary defaults in constants.go. The floor exists to fence the
// CloudFront/CDN keep-alive race that produces intermittent 502 on POST
// (PR #1795): IdleTimeoutMs MUST stay >= proxy origin keep-alive + buffer,
// or CF reuses an idle conn the server has FIN'd and the next POST gets
// RST. Plan-time enforcement lives at `terraform_data.http_keepalive_contract`
// in terraform/main.tf; this helper covers the etcd-seed / http.toml
// override paths that bypass TF.
//
// 1000ms floor matches the TF variable validation
// (terraform/modules/compute/variables.tf::http_timeouts_ms). TF rejects
// sub-floor values at plan time; this helper floors-up + warns at runtime
// — TF is the deployment authority, the Go floor catches the bypass paths.
//
// CONTRACT: the warnings emitted here are load-bearing, not incidental.
// Operators rely on them to confirm a sub-floor override was rejected,
// and on the asymmetric IdleTimeoutMs below-default warning to be
// reminded that a sub-default IdleTimeoutMs may re-open the keep-alive
// race. Below-default warning fires ONLY for IdleTimeoutMs because only
// IdleTimeoutMs participates in the CF origin-keep-alive race; Read/Write
// timeouts are per-request and have no analogous proxy-pool coupling.
// A future change that drops a warning while keeping the floor passes
// every test in config_test.go (warnings aren't captured today, see
// #1807) and silently regresses this contract. Warning gate is `!= 0`
// not `> 0` so negative values — arguably MORE deliberate operator
// overrides than the bare 0 — also surface a warning.
//
// Reload behavior: called from file-watch and etcd reload paths, so an
// uncorrected sub-floor config re-emits the warning on every reload.
// Intentional — each reload reaffirms the effective config — but watch
// for log-spam in noisy reload environments (#1803 tracks dedup gating).
//
// Pure-logic helper (no method receiver, no I/O beyond the warning log)
// so config_test.go can table-drive the behavior without spinning up an
// UdpServer.
func applyHttpTimeoutDefaults(conf *HttpConfig) {
	if conf.ReadTimeoutMs < 1000 {
		if conf.ReadTimeoutMs != 0 {
			log.Warning("[Server] http ReadTimeoutMs override %d ignored (below 1000ms floor); defaulting to %d", conf.ReadTimeoutMs, DefaultHttpRequestReadTimeoutMs)
		}
		conf.ReadTimeoutMs = DefaultHttpRequestReadTimeoutMs
	}
	if conf.WriteTimeoutMs < 1000 {
		if conf.WriteTimeoutMs != 0 {
			log.Warning("[Server] http WriteTimeoutMs override %d ignored (below 1000ms floor); defaulting to %d", conf.WriteTimeoutMs, DefaultHttpResponseWriteTimeoutMs)
		}
		conf.WriteTimeoutMs = DefaultHttpResponseWriteTimeoutMs
	}
	if conf.IdleTimeoutMs < 1000 {
		if conf.IdleTimeoutMs != 0 {
			log.Warning("[Server] http IdleTimeoutMs override %d ignored (below 1000ms floor); defaulting to %d", conf.IdleTimeoutMs, DefaultHttpServerIdleTimeoutMs)
		}
		conf.IdleTimeoutMs = DefaultHttpServerIdleTimeoutMs
	} else if conf.IdleTimeoutMs < DefaultHttpServerIdleTimeoutMs {
		// Below-default but above-floor: permitted; warn for the
		// keep-alive race risk. See docstring CONTRACT block for why
		// only IdleTimeoutMs gets the below-default warning.
		log.Warning("[Server] http IdleTimeoutMs override %d is below DefaultHttpServerIdleTimeoutMs (%d). Deployments behind connection-pooling proxies (CloudFront, etc.) require IdleTimeout > origin_keepalive_timeout to avoid the 502-on-reused-stale-conn race. Verify your topology actually allows the lower value before suppressing this warning.", conf.IdleTimeoutMs, DefaultHttpServerIdleTimeoutMs)
	}
}

func (s *UdpServer) updateHttpConfig(httpConf HttpConfig) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	applyHttpTimeoutDefaults(&httpConf)

	// update
	if httpConf.EnableHttp {
		// start http server
		if s.httpServer == nil || !s.httpServer.IsRunning() {
			if s.httpServer != nil {
				// stop old http server
				go s.httpServer.Stop()
			}
			hs := &HttpServer{}
			s.httpServer = hs
			err = hs.Start(s, &httpConf)
			if err != nil {
				return err
			}
		}
	} else {
		// stop http server
		if s.httpServer != nil && s.httpServer.IsRunning() {
			go s.httpServer.Stop()
			s.httpServer = nil
		}
	}

	s.httpConfig = &httpConf
	return nil
}

// updatePeers is a generic helper that adds new peers of the given type to the
// device, removes stale peers that are no longer in the list, and atomically
// swaps the peer map under the provided mutex.
func (s *UdpServer) updatePeers(peers []*core.UdpPeer, peerType int, mu *sync.Mutex, peerMap *map[string]*core.UdpPeer) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	newMap := make(map[string]*core.UdpPeer)
	for _, p := range peers {
		p.Type = peerType
		s.device.AddPeer(p)
		newMap[p.PublicKeyBase64()] = p
	}

	// remove old peers from device
	mu.Lock()
	defer mu.Unlock()
	for pubKey := range *peerMap {
		if _, found := newMap[pubKey]; !found {
			s.device.RemovePeer(pubKey)
		}
	}
	*peerMap = newMap

	return nil
}

func (s *UdpServer) updateACPeers(peers []*core.UdpPeer) error {
	return s.updatePeers(peers, core.NHP_AC, &s.acPeerMapMutex, &s.acPeerMap)
}

func (s *UdpServer) updateAgentPeers(peers []*core.UdpPeer) error {
	return s.updatePeers(peers, core.NHP_AGENT, &s.agentPeerMapMutex, &s.agentPeerMap)
}

// updateRelayPeers registers the configured NHP_RELAY peers (relay.toml) with
// the device so their forwarded NHP_RLY packets can be authenticated (#2208).
func (s *UdpServer) updateRelayPeers(peers []*core.UdpPeer) error {
	return s.updatePeers(peers, core.NHP_RELAY, &s.relayPeerMapMutex, &s.relayPeerMap)
}

func (s *UdpServer) updateResources(aspMap common.AuthSvcProviderMap) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	for aspId, aspData := range aspMap {
		if aspData == nil {
			log.Info("AuthServiceId %q has empty config (using static plugin registry)", aspId)
			continue
		}
		aspData.AuthSvcId = aspId
		// updateResources force-loads (LoadPlugin closes the old
		// handler and re-runs h.Init on every TOML reload) so an
		// operator-driven `resource.toml` edit that bumps a plugin's
		// PluginPath or relies on Init re-running to pick up
		// Hostname/LocalIp changes still takes effect. The
		// per-aspId sync.Once in loadPluginOnce is scoped to the
		// DDB-knock path only (applyAspMapDelta → ensurePluginLoaded)
		// so that path serializes concurrent first-knocks without
		// nullifying TOML-reload semantics.
		//
		// Narrow race: a TOML reload concurrent with a DDB-knock
		// first-load for the same aspId could call h.Init twice
		// (LoadPlugin's Close path only fires when its own RLock
		// check finds an existing entry; both racers might observe
		// "not found"). Acceptable in practice — TOML reloads are
		// one-shot events at runtime (and post-cutover the overlay
		// is gone entirely), and the "loser" handler's Init
		// resources leak silently once. The operator-workflow
		// preservation wins over closing the theoretical race; the
		// race is documented in the loadPluginOnce godoc.
		h := plugins.GetPluginHandler(aspId, aspData.PluginPath)
		if h != nil {
			if loadErr := s.LoadPlugin(aspId, h); loadErr != nil {
				log.Error("failed to load plugin for AuthServiceId %q: %v", aspId, loadErr)
			} else {
				log.Info("Loaded plugin for AuthServiceId %q", aspId)
			}
		} else if len(aspData.PluginPath) > 0 {
			log.Error("Failed to load plugin for AuthServiceId %q from path %q", aspId, aspData.PluginPath)
		} else {
			log.Debug("AuthServiceId %q has no plugin configured", aspId)
		}

		for resId, res := range aspData.ResourceGroups {
			// Note: res is a pointer, so we can update its value
			res.AuthServiceId = aspId
			res.ResourceId = resId
		}
	}

	s.authServiceMapMutex.Lock()
	defer s.authServiceMapMutex.Unlock()
	s.authServiceMap = aspMap

	// Note: DDB-resolved aspIds installed by ResourceLookup via
	// applyAspMapDelta are wiped by the full-replace above. Self-heal:
	// the next knock for that aspId hits FindAuthSvcProvider miss →
	// ResourceLookup cache-hit republish → applyAspMapDelta's fast-
	// path pointer-equal check fails (the wipe nulled the entry) →
	// fresh-build branch fires → DDB-resolved entry is re-installed.
	// Heal time: one knock.
	//
	// Reload re-pay caveat: every loadResources re-trigger (SIGHUP,
	// config-watch fire, etc.) pays one extra DDB Query per active
	// aspId on the next knock to re-warm. Cost scales with the
	// number of active aspId partitions: today this is `1 query ×
	// small N` (only "agent" is active); a future per-tenant schema
	// where the bridge fans out across many real customer ULIDs
	// would scale rewarm cost with active partitions × reload
	// frequency. Today reload triggers are rare (operator-driven
	// config changes) so this is a non-issue; don't optimize
	// prematurely (e.g., by preserving DDB-installed entries
	// through the wipe — that would re-introduce the
	// stale-after-reload class of bug `applyAspMapDelta` exists to
	// avoid). When the multi-tenant schema lands, revisit: the
	// candidate optimization is preserving entries whose
	// `loadResources` snapshot didn't include them (i.e., they
	// came purely from the bridge, not from baked TOML), so the
	// full-replace stops wiping them.
	//
	// Historical: pre-#1976 the `agent` aspId was ALSO carried in the
	// baked TOML overlay, which made the full-replace above
	// authoritative for that aspId until the bridge's 60s TTL expired
	// and the next miss re-queried DDB. Post-#1976 no shipped TOML
	// carries `agent` rows, so the "BOTH sources" branch is
	// structurally unreachable; the comment above describes the only
	// path that fires in production today.

	return nil
}

func (s *UdpServer) updateSourceIps(srcIpMap map[string][]*common.NetAddress) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	s.srcIpAssociatedAddrMapMutex.Lock()
	defer s.srcIpAssociatedAddrMapMutex.Unlock()
	s.srcIpAssociatedAddrMap = srcIpMap

	return nil
}

func (s *UdpServer) StopConfigWatch() {
	for _, w := range []io.Closer{
		baseConfigWatch, httpConfigWatch, acConfigWatch,
		agentConfigWatch, resConfigWatch, srcipConfigWatch,
		dbConfigWatch, relayConfigWatch, teeWatch,
	} {
		if w != nil {
			_ = w.Close()
		}
	}
}

func (s *UdpServer) updateDePeers(peers []*core.UdpPeer) error {
	return s.updatePeers(peers, core.NHP_DB, &s.dbPeerMapMutex, &s.dbPeerMap)
}

// update tee
func (s *UdpServer) updateTee(file string) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	content, err := os.ReadFile(file)
	if err != nil {
		log.Error("[Server] failed to read TEE config %s: %v", file, err)
		return err
	}

	var tees TeeAttestationReports
	teeMap := make(map[string]*TeeAttestationReport)
	if err := toml.Unmarshal(content, &tees); err != nil {
		log.Error("[Server] failed to parse TEE config %s: %v", file, err)
		return err
	}
	for _, tee := range tees.TEEs {
		teeMap[tee.Measure] = tee
	}

	s.teeMapMutex.Lock()
	defer s.teeMapMutex.Unlock()
	s.teeMap = teeMap
	return nil
}

func (s *UdpServer) AppraiseEvidence(evidenceBase64 string) bool {
	var measure string
	var sn string

	attestationVerifier, err := verifier.NewVerifier(evidenceBase64)
	if err != nil {
		log.Error("failed to create attestation verifier: %v", err)
		return false
	}

	if err := attestationVerifier.Verify(); err != nil {
		log.Error("failed to verify attestation: %v", err)
		return false
	}

	measure = attestationVerifier.GetMeasure()
	sn = attestationVerifier.GetSerialNumber()

	s.teeMapMutex.Lock()
	defer s.teeMapMutex.Unlock()

	if _, exist := s.teeMap[measure]; exist {
		s.teeMap[measure].Verified = true
		return s.teeMap[measure].SerialNumber == sn
	}

	return false
}

// ============================================================================
// AC Registry - Dynamic AC Trust via etcd
// ACs register themselves with their public keys; server watches for changes
// ============================================================================

// acRegistryMap stores AC entries indexed by instance ID for reconciliation
var (
	acRegistryMapMutex sync.Mutex
	acRegistryMap      = make(map[string]*ACRegistryEntry)
)

// loadACRegistry loads all AC registrations from etcd and starts watching for changes
func (s *UdpServer) loadACRegistry() error {
	if s.etcdConn == nil {
		log.Info("No etcd connection, skipping AC registry loading")
		return nil
	}

	// Load existing AC registrations
	entries, err := s.etcdConn.GetPrefix(ACRegistryPrefix)
	if err != nil {
		log.Error("Failed to load AC registry from etcd: %v", err)
		return err
	}

	log.Info("Loading %d AC registrations from etcd", len(entries))

	// Parse and process each entry
	acRegistryMapMutex.Lock()
	for key, value := range entries {
		entry, err := parseACRegistryEntry(value)
		if err != nil {
			log.Error("Failed to parse AC registry entry %s: %v", key, err)
			continue
		}

		acRegistryMap[entry.InstanceId] = entry
		pubKeyPreview := entry.PublicKey
		if len(pubKeyPreview) > 20 {
			pubKeyPreview = pubKeyPreview[:20]
		}
		log.Info("Loaded AC registration: instance=%s, ip=%s, pubkey=%s...",
			entry.InstanceId, entry.Ip, pubKeyPreview)
	}
	acRegistryMapMutex.Unlock()

	// Reconcile AC peers with loaded registry
	s.reconcileACPeersFromRegistry()

	// Start watching for changes
	go s.watchACRegistry()

	return nil
}

// parseACRegistryEntry parses a TOML-formatted AC registry entry
func parseACRegistryEntry(data []byte) (*ACRegistryEntry, error) {
	var entry ACRegistryEntry
	if err := toml.Unmarshal(data, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

// watchACRegistry watches the AC registry prefix for changes
func (s *UdpServer) watchACRegistry() {
	log.Info("Starting AC registry watcher on prefix: %s", ACRegistryPrefix)

	s.etcdConn.WatchPrefix(ACRegistryPrefix, etcd.WatchPrefixCallbacks{
		OnPut: func(key string, value []byte) {
			entry, err := parseACRegistryEntry(value)
			if err != nil {
				log.Error("Failed to parse AC registry update for %s: %v", key, err)
				return
			}

			log.Info("AC registry PUT: instance=%s, ip=%s", entry.InstanceId, entry.Ip)

			acRegistryMapMutex.Lock()
			acRegistryMap[entry.InstanceId] = entry
			acRegistryMapMutex.Unlock()

			// Reconcile peers
			s.reconcileACPeersFromRegistry()
		},
		OnDelete: func(key string) {
			// Extract instance ID from key (format: /nhp/ac-registry/{instance-id})
			instanceId := strings.TrimPrefix(key, ACRegistryPrefix)

			log.Info("AC registry DELETE: instance=%s", instanceId)

			acRegistryMapMutex.Lock()
			delete(acRegistryMap, instanceId)
			acRegistryMapMutex.Unlock()

			// Reconcile peers
			s.reconcileACPeersFromRegistry()
		},
	})
}

// reconcileACPeersFromRegistry updates the AC peer list based on registry entries
func (s *UdpServer) reconcileACPeersFromRegistry() {
	acRegistryMapMutex.Lock()
	defer acRegistryMapMutex.Unlock()

	// Build list of UdpPeer from registry entries
	peers := make([]*core.UdpPeer, 0, len(acRegistryMap))
	for _, entry := range acRegistryMap {
		peer := &core.UdpPeer{}
		// Set peer fields from registry entry
		peer.Hostname = ""
		peer.Ip = entry.Ip
		peer.Port = entry.Port
		peer.PubKeyBase64 = entry.PublicKey
		peer.ExpireTime = common.FarFutureExpiry

		peers = append(peers, peer)
	}

	log.Info("Reconciling AC peers: %d entries from registry", len(peers))

	// Update AC peers using existing mechanism
	if err := s.updateACPeers(peers); err != nil {
		log.Error("Failed to update AC peers from registry: %v", err)
	}
}

// ============================================================================
// Storage Backend Configuration
// See docs/design/PLUGGABLE_STORAGE_BACKEND.md for architecture details.
// ============================================================================

// loadStorageConfig loads storage backend configuration from storage.toml.
// If no config file exists, returns default configuration (DynamoDB).
func (s *UdpServer) loadStorageConfig() (*StorageConfig, error) {
	fileName := filepath.Join(ExeDirPath, "etc", "storage.toml")
	content, err := s.loadConfigFile(fileName)
	if err != nil {
		if os.IsNotExist(err) {
			log.Info("storage.toml not found, using default DynamoDB configuration")
			defaultCfg := DefaultStorageConfig()
			return &defaultCfg, nil
		}
		return nil, fmt.Errorf("failed to read storage config %s: %w", fileName, err)
	}

	var cfg StorageConfig
	if err := toml.Unmarshal(content, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse storage config %s: %w", fileName, err)
	}

	// Apply defaults for unset values
	if cfg.Backend == "" {
		cfg.Backend = "dynamodb"
	}
	if cfg.Cache.MaxEntries == 0 {
		cfg.Cache.MaxEntries = 10000
	}
	if cfg.Cache.DefaultTTL == 0 {
		cfg.Cache.DefaultTTL = 60
	}
	if cfg.Cache.ReassignmentTTL == 0 {
		cfg.Cache.ReassignmentTTL = 5
	}
	if cfg.Cache.ReassignmentWindow == 0 {
		cfg.Cache.ReassignmentWindow = 300
	}

	// Apply rate limit defaults if the [RateLimit] section was not configured at all
	if cfg.RateLimit.MaxFailuresPerIP == 0 && cfg.RateLimit.MaxFailuresPerACID == 0 &&
		cfg.RateLimit.WindowSeconds == 0 {
		cfg.RateLimit = DefaultRateLimitConfig()
	}

	log.Info("Loaded storage configuration: backend=%s", cfg.Backend)
	return &cfg, nil
}
