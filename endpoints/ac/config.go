package ac

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/utils"
)

var (
	baseConfigWatch io.Closer
	httpConfigWatch io.Closer
	serverPeerWatch io.Closer

	errLoadConfig = fmt.Errorf("config load error")
)

const (
	FilterMode_IPTABLES = iota // 0
	FilterMode_EBPFXDP         // 1
)

type Config struct {
	PrivateKeyBase64    string          `json:"privateKey"`
	ACId                string          `json:"acId"`
	DefaultIp           string          `json:"defaultIp"`
	AuthServiceId       string          `json:"aspId"`
	ResourceIds         []string        `json:"resIds"`
	Servers             []*core.UdpPeer `json:"servers"`
	IpPassMode          int             `json:"ipPassMode"` // 0: pass the knock source IP, 1: use pre-access mode and release the access source IP
	LogLevel            int             `json:"logLevel"`
	DefaultCipherScheme int             `json:"defaultCipherScheme"`
	FilterMode          int             `json:"filterMode"`

	// ============================================================================
	// Per-AC Server Assignment Configuration (Required)
	// See docs/design/PLUGGABLE_STORAGE_BACKEND.md section 6.2 for details.
	// These fields enable AC to register with NHP servers and receive
	// its assigned server list via NHP_ARD (redispatch).
	// ============================================================================
	LicenseKey         string `json:"licenseKey"`         // License key for authentication (globally unique)
	ServerEndpoint     string `json:"serverEndpoint"`     // Required: Server endpoint for registration (e.g., "server.nhp.sandbox.internal")
	ACVersion          string `json:"acVersion"`          // AC software version for compatibility
	ServerPubKeyBase64 string `json:"serverPubKeyBase64"` // Required: Shared registration public key (all servers share this for NLB)
	ServerPort         int    `json:"serverPort"`         // Server port for initial registration (default: 62206)
}

type HttpConfig struct {
	EnableHttp     bool
	EnableTLS      bool
	HttpListenPort int
	TLSCertFile    string
	TLSKeyFile     string
}

type Peers struct {
	Servers []*core.UdpPeer
}

func (a *UdpAC) loadBaseConfig() error {
	// config.toml - REQUIRED for AC to start
	fileName := filepath.Join(ExeDirPath, "etc", "config.toml")
	content, err := os.ReadFile(fileName)
	if err != nil {
		return fmt.Errorf("failed to read base config %s: %w", fileName, err)
	}

	var conf Config
	if err := toml.Unmarshal(content, &conf); err != nil {
		return fmt.Errorf("failed to parse base config %s: %w", fileName, err)
	}

	// Validate required fields before proceeding
	if conf.PrivateKeyBase64 == "" {
		return fmt.Errorf("PrivateKeyBase64 is required in %s", fileName)
	}

	if err := a.updateBaseConfig(conf); err != nil {
		return fmt.Errorf("failed to apply base config: %w", err)
	}

	baseConfigWatch = utils.WatchFile(fileName, func() {
		log.Info("base config: %s has been updated", fileName)
		if content, err = a.loadConfigFile(fileName); err == nil {
			if err = toml.Unmarshal(content, &conf); err == nil {
				a.updateBaseConfig(conf)
			}

		}
	})
	return nil
}

func (a *UdpAC) loadHttpConfig() error {
	// http.toml - optional, enables HTTP endpoint
	fileName := filepath.Join(ExeDirPath, "etc", "http.toml")
	content, err := os.ReadFile(fileName)
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

	if err := a.updateHttpConfig(httpConf); err != nil {
		return fmt.Errorf("failed to apply http config: %w", err)
	}

	httpConfigWatch = utils.WatchFile(fileName, func() {
		log.Info("http config: %s has been updated", fileName)
		if content, err = a.loadConfigFile(fileName); err == nil {
			if err = toml.Unmarshal(content, &httpConf); err == nil {
				a.updateHttpConfig(httpConf)
			}
		}
	})
	return nil
}

func (a *UdpAC) loadPeers() error {
	// server.toml - contains NHP server peer configurations
	fileName := filepath.Join(ExeDirPath, "etc", "server.toml")
	log.Info("loading server peers from: %s (ExeDirPath=%s)", fileName, ExeDirPath)
	content, err := os.ReadFile(fileName)
	if err != nil {
		if os.IsNotExist(err) {
			log.Info("server.toml not found at %s, no server peers configured", fileName)
			return nil
		}
		return fmt.Errorf("failed to read server peer config %s: %w", fileName, err)
	}

	log.Debug("loaded server.toml content (%d bytes): %s", len(content), string(content))
	var peers Peers
	if err := toml.Unmarshal(content, &peers); err != nil {
		return fmt.Errorf("failed to parse server peer config %s: %w", fileName, err)
	}
	log.Info("parsed %d server peers from server.toml", len(peers.Servers))

	if err := a.updateServerPeers(peers.Servers); err != nil {
		return fmt.Errorf("failed to apply server peers: %w", err)
	}

	serverPeerWatch = utils.WatchFile(fileName, func() {
		log.Info("server peer config: %s has been updated", fileName)
		if content, err = a.loadConfigFile(fileName); err == nil {
			if err = toml.Unmarshal(content, &peers); err == nil {
				a.updateServerPeers(peers.Servers)
			}
		}
	})

	return nil
}

func (a *UdpAC) updateBaseConfig(conf Config) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	if a.config == nil {
		a.config = &conf
		a.log.SetLogLevel(conf.LogLevel)
		return err
	}

	// update
	if a.config.LogLevel != conf.LogLevel {
		log.Info("set base log level to %d", conf.LogLevel)
		a.log.SetLogLevel(conf.LogLevel)
		a.config.LogLevel = conf.LogLevel
	}

	if a.config.DefaultIp != conf.DefaultIp {
		log.Info("set default ip mode to %s", conf.DefaultIp)
		a.config.DefaultIp = conf.DefaultIp
	}

	if a.config.IpPassMode != conf.IpPassMode {
		log.Info("set ip pass mode to %d", conf.IpPassMode)
		a.config.IpPassMode = conf.IpPassMode
	}

	if a.config.DefaultCipherScheme != conf.DefaultCipherScheme {
		log.Info("set default cipher scheme to %d", conf.DefaultCipherScheme)
		a.config.DefaultCipherScheme = conf.DefaultCipherScheme
	}

	return err
}

func (a *UdpAC) updateHttpConfig(httpConf HttpConfig) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	// update
	if httpConf.EnableHttp {
		// start http server
		if a.httpServer == nil || !a.httpServer.IsRunning() {
			if a.httpServer != nil {
				// stop old http server
				go a.httpServer.Stop()
			}
			hs := &HttpAC{}
			a.httpServer = hs
			err = hs.Start(a, &httpConf)
			if err != nil {
				return err
			}
		}
	} else {
		// stop http server
		if a.httpServer != nil && a.httpServer.IsRunning() {
			go a.httpServer.Stop()
			a.httpServer = nil
		}
	}

	a.httpConfig = &httpConf
	return err
}

func (a *UdpAC) updateServerPeers(peers []*core.UdpPeer) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	log.Info("updating server peers: count=%d", len(peers))
	serverPeerMap := make(map[string]*core.UdpPeer)
	for _, p := range peers {
		log.Debug("loading server peer: host=%s, ip=%s, port=%d, pubKeyBase64=%q, pubKeyLen=%d",
			p.Hostname, p.Ip, p.Port, p.PubKeyBase64, len(p.PublicKey()))
		p.Type = core.NHP_SERVER
		a.device.AddPeer(p)
		serverPeerMap[p.PublicKeyBase64()] = p
	}
	a.config.Servers = peers

	// remove old peers from device
	a.serverPeerMutex.Lock()
	defer a.serverPeerMutex.Unlock()
	for pubKey := range a.serverPeerMap {
		if _, found := serverPeerMap[pubKey]; !found {
			a.device.RemovePeer(pubKey)
		}
	}
	a.serverPeerMap = serverPeerMap

	return err
}
func (a *UdpAC) loadConfigFile(file string) (content []byte, err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})
	content, err = os.ReadFile(file)
	if err != nil {
		log.Error("failed to read base config: %v", err)
	}
	return
}

func (a *UdpAC) IpPassMode() int {
	return a.config.IpPassMode
}

func (a *UdpAC) StopConfigWatch() {
	if baseConfigWatch != nil {
		baseConfigWatch.Close()
	}
	if httpConfigWatch != nil {
		httpConfigWatch.Close()
	}
	if serverPeerWatch != nil {
		serverPeerWatch.Close()
	}
}
