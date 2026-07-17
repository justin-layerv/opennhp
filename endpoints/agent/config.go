package agent

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/utils"
)

var (
	baseConfigWatch     io.Closer
	dhpConfigWatch      io.Closer
	serverConfigWatch   io.Closer
	resourceConfigWatch io.Closer

	errLoadConfig = errors.New("config load error")

	secretCreated = "/var/run/secret.created"
)

type Config struct {
	LogLevel            int    `json:"logLevel"`
	DefaultCipherScheme int    `json:"defaultCipherScheme"`
	PrivateKeyBase64    string `json:"privateKey"` //nolint:gosec // G117: config struct, never JSON-marshaled — TOML input only
	KnockUser           `mapstructure:",squash"`
	*DHPConfig
}

type DHPConfig struct {
	TEEPrivateKeyBase64 string `json:"teePrivateKeyBase64"`
}

func (c *Config) GetAgentEcdh() (core.Ecdh, error) {
	teePrk, err := base64.StdEncoding.DecodeString(c.PrivateKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}
	return core.ECDHFromKey(core.ECC_CURVE25519, teePrk)
}

func (c *Config) GetTeeEcdh() (core.Ecdh, error) {
	teePrk, err := base64.StdEncoding.DecodeString(c.TEEPrivateKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode TEE private key: %w", err)
	}
	return core.ECDHFromKey(core.ECC_CURVE25519, teePrk)
}

func (c *Config) GetEccType() core.EccTypeEnum {
	return core.ECC_CURVE25519
}

type Peers struct {
	Servers []*core.UdpPeer
}

type Resources struct {
	Resources []*KnockResource
}

func (a *UdpAgent) loadBaseConfig() error {
	// config.toml
	fileName := filepath.Join(ExeDirPath, "etc", "config.toml")
	if err := a.updateBaseConfig(fileName); err != nil {
		// report base config error
		return err
	}

	baseConfigWatch = utils.WatchFile(fileName, func() {
		log.Info("[Agent] base config %s has been updated, reloading", fileName)
		if updateErr := a.updateBaseConfig(fileName); updateErr != nil {
			log.Error("[Agent] failed to apply base config update from %s: %v", fileName, updateErr)
		}
	})
	return nil
}

func (a *UdpAgent) loadDHPConfig() error {
	// dhp.toml
	fileName := filepath.Join(ExeDirPath, "etc", "dhp.toml")
	// optional config, may not exist yet
	if updateErr := a.updateDHPConfig(fileName); updateErr != nil {
		log.Debug("DHP config not loaded: %v", updateErr)
	}

	dhpConfigWatch = utils.WatchFile(fileName, func() {
		log.Info("[Agent] DHP config %s has been updated, reloading", fileName)
		if updateErr := a.updateDHPConfig(fileName); updateErr != nil {
			log.Error("[Agent] failed to apply DHP config update from %s: %v", fileName, updateErr)
		}
	})

	return nil
}

func (a *UdpAgent) loadPeers() error {
	// server.toml
	fileName := filepath.Join(ExeDirPath, "etc", "server.toml")
	// optional config, may not exist yet
	if updateErr := a.updateServerPeers(fileName); updateErr != nil {
		log.Debug("server peers not loaded: %v", updateErr)
	}

	serverConfigWatch = utils.WatchFile(fileName, func() {
		log.Info("[Agent] server peer config %s has been updated, reloading", fileName)
		if updateErr := a.updateServerPeers(fileName); updateErr != nil {
			log.Error("[Agent] failed to apply server peer update from %s: %v", fileName, updateErr)
		}
	})

	return nil
}

func (a *UdpAgent) loadResources() error {
	// resource.toml
	fileName := filepath.Join(ExeDirPath, "etc", "resource.toml")
	// optional config, may not exist yet
	if updateErr := a.updateResources(fileName); updateErr != nil {
		if errors.Is(updateErr, ErrRegisteredAgentKnockLoopUnsupported) {
			return fmt.Errorf("load resource config: %w", updateErr)
		}
		log.Debug("resources not loaded: %v", updateErr)
	}

	resourceConfigWatch = utils.WatchFile(fileName, func() {
		log.Info("[Agent] resource config %s has been updated, reloading", fileName)
		if updateErr := a.updateResources(fileName); updateErr != nil {
			log.Error("[Agent] failed to apply resource config update from %s: %v", fileName, updateErr)
		}
	})

	return nil
}

func (a *UdpAgent) updateBaseConfig(file string) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	content, err := os.ReadFile(file)
	if err != nil {
		log.Error("[Agent] failed to read base config %s: %v", file, err)
		return err
	}

	var conf Config
	if err := toml.Unmarshal(content, &conf); err != nil {
		log.Error("[Agent] failed to parse base config %s: %v", file, err)
		return err
	}

	a.knockUserMutex.Lock()
	a.knockUser = &KnockUser{
		UserId:         conf.UserId,
		OrganizationId: conf.OrganizationId,
		UserData:       conf.UserData,
	}
	a.knockUserMutex.Unlock()

	if a.config == nil {
		a.config = &conf
		a.log.SetLogLevel(conf.LogLevel)
		return nil
	}

	// update
	if a.config.LogLevel != conf.LogLevel {
		log.Info("set base log level to %d", conf.LogLevel)
		a.log.SetLogLevel(conf.LogLevel)
		a.config.LogLevel = conf.LogLevel
	}

	if a.config.DefaultCipherScheme != conf.DefaultCipherScheme {
		log.Info("set default cipher scheme to %d", conf.DefaultCipherScheme)
		a.config.DefaultCipherScheme = conf.DefaultCipherScheme
	}

	return nil
}

func (a *UdpAgent) updateDHPConfig(file string) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	content, err := os.ReadFile(file)
	if err != nil {
		log.Error("[Agent] failed to read DHP config %s: %v", file, err)
		return err
	}

	var conf DHPConfig
	if err := toml.Unmarshal(content, &conf); err != nil {
		log.Error("[Agent] failed to parse DHP config %s: %v", file, err)
		return err
	}

	// Only set on first load; subsequent reloads are a no-op to preserve
	// write-once semantics (readers access DHPConfig without synchronization).
	if a.config.DHPConfig == nil {
		a.config.DHPConfig = &conf
	}
	return nil
}

func (a *UdpAgent) updateServerPeers(file string) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	content, err := os.ReadFile(file)
	if err != nil {
		log.Error("[Agent] failed to read server peer config %s: %v", file, err)
		return err
	}

	// update
	var peers Peers
	serverPeerMap := make(map[string]*core.UdpPeer)
	if err := toml.Unmarshal(content, &peers); err != nil {
		log.Error("[Agent] failed to parse server peer config %s: %v", file, err)
		return err
	}
	for _, p := range peers.Servers {
		p.Type = core.NHP_SERVER
		a.device.AddPeer(p)
		serverPeerMap[p.PublicKeyBase64()] = p
	}

	// remove old peers from device
	a.serverPeerMutex.Lock()
	defer a.serverPeerMutex.Unlock()
	for pubKey := range a.serverPeerMap {
		if _, found := serverPeerMap[pubKey]; !found {
			a.device.RemovePeer(pubKey)
		}
	}
	a.serverPeerMap = serverPeerMap

	return nil
}

func (a *UdpAgent) updateResources(file string) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	content, err := os.ReadFile(file)
	if err != nil {
		log.Error("[Agent] failed to read resource config %s: %v", file, err)
		return err
	}

	var resources Resources
	targetMap := make(map[string]*KnockTarget)
	if err := toml.Unmarshal(content, &resources); err != nil {
		log.Error("[Agent] failed to parse resource config %s: %v", file, err)
		return err
	}
	for _, res := range resources.Resources {
		if res.AuthServiceId == common.RegisteredAgentAuthServiceID {
			return ErrRegisteredAgentKnockLoopUnsupported
		}
		peer := a.FindServerPeerFromResource(res)
		if peer == nil {
			log.Error("[Agent] no server peer found for resource %s (server=%s)", res.Id(), res.ServerHost())
			continue
		}
		targetMap[res.Id()] = &KnockTarget{
			KnockResource: *res,
			ServerPeer:    peer,
		}
	}

	a.knockTargetMapMutex.Lock()
	firstLoad := a.knockTargetMap == nil
	a.knockTargetMap = targetMap
	a.knockTargetMapMutex.Unlock()

	if firstLoad {
		// Initial load during Start() (before the knock loop and file-watcher
		// exist), so there's nothing to notify. The write above is taken under
		// the mutex anyway — uniformly with the reload path below — so a
		// programmatic-init caller that races the watcher callback can't trip
		// -race on knockTargetMap.
		return nil
	}

	// renew knock cycle. Non-blocking send (matches AddResource /
	// RemoveResource): this runs from a debounced file-watcher callback
	// (utils.WatchFile fires via time.AfterFunc, untracked by any
	// WaitGroup) that can land after Stop(). The previous blocking send
	// guarded only by a len()==0 check both raced (two watchers could each
	// observe 0, and the second would block) and risked blocking forever
	// once the consumer routine had exited. knockTargetMapUpdated is never
	// closed (see Stop()), so a late send lands harmlessly in the size-1
	// buffer.
	mapUpdated := a.mapUpdatedSignal() // snapshot under RLock (#3103)
	select {
	case mapUpdated <- struct{}{}:
	default:
	}

	return nil
}

func (a *UdpAgent) StopConfigWatch() {
	for _, w := range []io.Closer{baseConfigWatch, dhpConfigWatch, serverConfigWatch, resourceConfigWatch} {
		if w != nil {
			_ = w.Close()
		}
	}
}

func (a *UdpAgent) NewEcdhFromConfigFile() (core.Ecdh, error) {
	fileName := filepath.Join(ExeDirPath, "etc", "config.toml")

	content, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	var conf Config
	if err := toml.Unmarshal(content, &conf); err != nil {
		return nil, err
	}

	return core.NewECDH(conf.GetEccType())
}

func (a *UdpAgent) rotateKey(file, tomlKey string) error {
	ecdh, err := a.NewEcdhFromConfigFile()
	if err != nil {
		return err
	}
	return utils.UpdateTomlConfig(file, tomlKey, ecdh.PrivateKeyBase64())
}

func (a *UdpAgent) RotateTeeKey() error {
	return a.rotateKey(filepath.Join(ExeDirPath, "etc", "dhp.toml"), "TEEPrivateKeyBase64")
}

func (a *UdpAgent) RotateAgentKey() error {
	return a.rotateKey(filepath.Join(ExeDirPath, "etc", "config.toml"), "PrivateKeyBase64")
}

func (a *UdpAgent) InitializeSecret() error {
	if _, err := os.Stat(secretCreated); os.IsNotExist(err) {
		err := a.RotateAgentKey()
		if err != nil {
			return err
		}
		err = a.RotateTeeKey()
		if err != nil {
			return err
		}

		_, err = os.Create(secretCreated)
		if err != nil {
			return err
		}
	}

	return nil
}
