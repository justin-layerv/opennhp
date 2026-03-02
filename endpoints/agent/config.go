package agent

import (
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"

	toml "github.com/pelletier/go-toml/v2"

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
	PrivateKeyBase64    string `json:"privateKey"`
	KnockUser           `mapstructure:",squash"`
	*DHPConfig
}

type DHPConfig struct {
	TEEPrivateKeyBase64 string `json:"teePrivateKeyBase64"`
}

func (c *Config) GetAgentEcdh() core.Ecdh {
	teePrk, _ := base64.StdEncoding.DecodeString(c.PrivateKeyBase64)
	return core.ECDHFromKey(core.ECC_CURVE25519, teePrk)
}

func (c *Config) GetTeeEcdh() core.Ecdh {
	teePrk, _ := base64.StdEncoding.DecodeString(c.TEEPrivateKeyBase64)
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
		log.Info("base config: %s has been updated", fileName)
		if updateErr := a.updateBaseConfig(fileName); updateErr != nil {
			log.Error("failed to apply base config update: %v", updateErr)
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
		log.Info("DHP config: %s has been updated", fileName)
		if updateErr := a.updateDHPConfig(fileName); updateErr != nil {
			log.Error("failed to apply DHP config update: %v", updateErr)
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
		log.Info("server peer config: %s has been updated", fileName)
		if updateErr := a.updateServerPeers(fileName); updateErr != nil {
			log.Error("failed to apply server peers update: %v", updateErr)
		}
	})

	return nil
}

func (a *UdpAgent) loadResources() error {
	// resource.toml
	fileName := filepath.Join(ExeDirPath, "etc", "resource.toml")
	// optional config, may not exist yet
	if updateErr := a.updateResources(fileName); updateErr != nil {
		log.Debug("resources not loaded: %v", updateErr)
	}

	resourceConfigWatch = utils.WatchFile(fileName, func() {
		log.Info("resource config: %s has been updated", fileName)
		if updateErr := a.updateResources(fileName); updateErr != nil {
			log.Error("failed to apply resource config update: %v", updateErr)
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
		log.Error("failed to read base config: %v", err)
		return err
	}

	var conf Config
	if err := toml.Unmarshal(content, &conf); err != nil {
		log.Error("failed to unmarshal base config: %v", err)
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
		log.Error("failed to read DHP config: %v", err)
		return err
	}

	var conf DHPConfig
	if err := toml.Unmarshal(content, &conf); err != nil {
		log.Error("failed to unmarshal DHP config: %v", err)
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
		log.Error("failed to read server peer config: %v", err)
		return err
	}

	// update
	var peers Peers
	serverPeerMap := make(map[string]*core.UdpPeer)
	if err := toml.Unmarshal(content, &peers); err != nil {
		log.Error("failed to unmarshal server config: %v", err)
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
		log.Error("failed to read resource config: %v", err)
		return err
	}

	var resources Resources
	targetMap := make(map[string]*KnockTarget)
	if err := toml.Unmarshal(content, &resources); err != nil {
		log.Error("failed to unmarshal resource config: %v", err)
		return err
	}
	for _, res := range resources.Resources {
		peer := a.FindServerPeerFromResource(res)
		if peer == nil {
			log.Error("failed to find corresponding server peer for resource %s", res.Id())
			continue
		}
		targetMap[res.Id()] = &KnockTarget{
			KnockResource: *res,
			ServerPeer:    peer,
		}
	}

	if a.knockTargetMap == nil {
		a.knockTargetMap = targetMap
		return nil
	}

	// update
	a.knockTargetMapMutex.Lock()
	a.knockTargetMap = targetMap
	a.knockTargetMapMutex.Unlock()

	// renew knock cycle
	if len(a.signals.knockTargetMapUpdated) == 0 {
		a.signals.knockTargetMapUpdated <- struct{}{}
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
