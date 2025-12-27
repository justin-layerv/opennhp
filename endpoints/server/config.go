package server

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

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
	teeWatch         io.Closer
	errLoadConfig    = fmt.Errorf("config load error")
)

// ACRegistryPrefix is the etcd prefix for AC registration entries
const ACRegistryPrefix = "/nhp/ac-registry/"

// ACRegistryEntry represents an AC registration in etcd
// ACs register themselves with their public key and AWS identity
type ACRegistryEntry struct {
	PublicKey         string `toml:"PublicKey"`
	InstanceId        string `toml:"InstanceId"`
	Ip                string `toml:"Ip"`
	Port              int    `toml:"Port"`
	RegisteredAt      int64  `toml:"RegisteredAt"`
	IdentityDocument  string `toml:"IdentityDocument"`  // base64 encoded
	IdentitySignature string `toml:"IdentitySignature"` // base64 encoded
}

// AWSIdentityDocument represents the parsed AWS Instance Identity Document
type AWSIdentityDocument struct {
	AccountId        string `json:"accountId"`
	Architecture     string `json:"architecture"`
	AvailabilityZone string `json:"availabilityZone"`
	ImageId          string `json:"imageId"`
	InstanceId       string `json:"instanceId"`
	InstanceType     string `json:"instanceType"`
	PrivateIp        string `json:"privateIp"`
	Region           string `json:"region"`
	Version          string `json:"version"`
}

// awsIdentityVerificationEnabled controls whether AWS identity verification is performed
// This is auto-detected based on environment but can be overridden
var awsIdentityVerificationEnabled = false

// expectedAWSAccountId is the AWS account ID that ACs must belong to
// Set via environment variable NHP_AWS_ACCOUNT_ID or auto-detected
var expectedAWSAccountId = ""

// initAWSIdentityVerification initializes AWS identity verification if running in AWS
func initAWSIdentityVerification() {
	// Check if explicitly disabled
	if os.Getenv("NHP_DISABLE_AWS_IDENTITY") == "true" {
		log.Info("AWS identity verification explicitly disabled")
		return
	}

	// Check if we're in AWS by trying to reach the metadata service
	if isRunningInAWS() {
		awsIdentityVerificationEnabled = true

		// Get expected account ID from environment or auto-detect
		expectedAWSAccountId = os.Getenv("NHP_AWS_ACCOUNT_ID")
		if expectedAWSAccountId == "" {
			// Try to auto-detect from our own identity
			if doc, err := getOwnAWSIdentity(); err == nil {
				expectedAWSAccountId = doc.AccountId
				log.Info("Auto-detected AWS account ID: %s", expectedAWSAccountId)
			}
		}

		log.Info("AWS identity verification enabled (account: %s)", expectedAWSAccountId)
	} else {
		log.Info("Not running in AWS, identity verification disabled")
	}
}

// isRunningInAWS checks if we're running in an AWS environment
func isRunningInAWS() bool {
	// Try to reach the EC2 metadata service with a short timeout
	client := &http.Client{Timeout: 1 * time.Second}

	// First get a token (IMDSv2)
	req, err := http.NewRequest("PUT", "http://169.254.169.254/latest/api/token", nil)
	if err != nil {
		return false
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}

// getOwnAWSIdentity gets this instance's AWS identity document
func getOwnAWSIdentity() (*AWSIdentityDocument, error) {
	client := &http.Client{Timeout: 2 * time.Second}

	// Get token
	tokenReq, _ := http.NewRequest("PUT", "http://169.254.169.254/latest/api/token", nil)
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")
	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		return nil, err
	}
	defer tokenResp.Body.Close()
	tokenBytes, _ := io.ReadAll(tokenResp.Body)
	token := string(tokenBytes)

	// Get identity document
	docReq, _ := http.NewRequest("GET", "http://169.254.169.254/latest/dynamic/instance-identity/document", nil)
	docReq.Header.Set("X-aws-ec2-metadata-token", token)
	docResp, err := client.Do(docReq)
	if err != nil {
		return nil, err
	}
	defer docResp.Body.Close()

	var doc AWSIdentityDocument
	if err := json.NewDecoder(docResp.Body).Decode(&doc); err != nil {
		return nil, err
	}

	return &doc, nil
}

// AWS certificates are defined in aws_certs.go
// Use AWSRegionCertificates or GetAWSCertificate(region) to access them

// verifyAWSIdentity verifies an AC's AWS Instance Identity Document
// Returns the parsed document if valid, error if invalid
func verifyAWSIdentity(entry *ACRegistryEntry) (*AWSIdentityDocument, error) {
	if entry.IdentityDocument == "" || entry.IdentitySignature == "" {
		return nil, errors.New("missing identity document or signature")
	}

	// Decode base64 document and signature
	docBytes, err := base64.StdEncoding.DecodeString(entry.IdentityDocument)
	if err != nil {
		return nil, fmt.Errorf("failed to decode identity document: %w", err)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(entry.IdentitySignature)
	if err != nil {
		return nil, fmt.Errorf("failed to decode identity signature: %w", err)
	}

	// Parse the document
	var doc AWSIdentityDocument
	if err := json.Unmarshal(docBytes, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse identity document: %w", err)
	}

	// Verify instance ID matches
	if doc.InstanceId != entry.InstanceId {
		return nil, fmt.Errorf("instance ID mismatch: document=%s, entry=%s", doc.InstanceId, entry.InstanceId)
	}

	// Verify IP matches
	if doc.PrivateIp != entry.Ip {
		return nil, fmt.Errorf("IP mismatch: document=%s, entry=%s", doc.PrivateIp, entry.Ip)
	}

	// Verify account ID if configured
	if expectedAWSAccountId != "" && doc.AccountId != expectedAWSAccountId {
		return nil, fmt.Errorf("account ID mismatch: document=%s, expected=%s", doc.AccountId, expectedAWSAccountId)
	}

	// Get region-specific certificate from aws_certs.go
	certPEM := GetAWSCertificate(doc.Region)
	if certPEM == "" {
		return nil, fmt.Errorf("no AWS certificate configured for region: %s (supported: %v)", doc.Region, SupportedAWSRegions())
	}

	// Verify signature using AWS public certificate
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("failed to parse AWS certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AWS certificate: %w", err)
	}

	// Verify the signature (AWS uses PKCS1v15 with SHA256)
	err = cert.CheckSignature(x509.SHA256WithRSA, docBytes, sigBytes)
	if err != nil {
		// Try SHA1 for older signatures
		err = cert.CheckSignature(x509.SHA1WithRSA, docBytes, sigBytes)
		if err != nil {
			return nil, fmt.Errorf("signature verification failed: %w", err)
		}
	}

	return &doc, nil
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
	PrivateKeyBase64       string       `json:"privateKey"`
	Hostname               string       `json:"hostname"`
	ListenIp               string       `json:"listenIp"`
	ListenPort             int          `json:"listenPort"`
	LogLevel               int          `json:"logLevel"`
	DefaultCipherScheme    int          `json:"defaultCipherScheme"`
	DisableAgentValidation bool         `json:"disableAgentValidation"`
	WebRTC                 WebRTCConfig `toml:"webrtc"`
}

type RemoteConfig struct {
	Provider   string
	Key        string
	Endpoints  []string
	Username   string
	Password   string
	TLS        bool
	CACert     string
	ClientCert string
	ClientKey  string
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
}

func (s *UdpServer) loadBaseConfig() error {
	// config.toml
	fileName := filepath.Join(ExeDirPath, "etc", "config.toml")
	content, err := s.loadConfigFile(fileName)
	if err != nil {
		log.Error("load base config err: %v", err)
		return err
	}
	var config Config
	if err := toml.Unmarshal(content, &config); err != nil {
		log.Error("failed to unmarshal base config: %v", err)
	}
	if err = s.updateBaseConfig(config); err != nil {
		// report base config error
		return err
	}

	baseConfigWatch = utils.WatchFile(fileName, func() {
		log.Info("base config: %s has been updated", fileName)
		if content, err = s.loadConfigFile(fileName); err == nil {
			if err = toml.Unmarshal(content, &config); err == nil {
				s.updateBaseConfig(config)
			}

		}
	})
	return nil
}

func (s *UdpServer) loadHttpConfig() error {
	// http.toml
	fileName := filepath.Join(ExeDirPath, "etc", "http.toml")
	content, err := s.loadConfigFile(fileName)
	if err != nil {
		log.Error("load http config err: %v", err)
		return err
	}
	var httpConf HttpConfig
	if err := toml.Unmarshal(content, &httpConf); err != nil {
		log.Error("failed to unmarshal http config: %v", err)
	}
	if err = s.updateHttpConfig(httpConf); err != nil {
		// ignore error
		_ = err
	}

	httpConfigWatch = utils.WatchFile(fileName, func() {
		log.Info("http config: %s has been updated", fileName)
		if content, err = s.loadConfigFile(fileName); err == nil {
			if err = toml.Unmarshal(content, &httpConf); err == nil {
				s.updateHttpConfig(httpConf)
			}
		}

	})
	return nil
}

func (s *UdpServer) loadPeers() error {
	// ac.toml
	fileNameAC := filepath.Join(ExeDirPath, "etc", "ac.toml")

	contentAC, err := s.loadConfigFile(fileNameAC)
	if err != nil {
		log.Error("load ac peer config err: %v", err)
		return err
	}
	var acPeers Peers
	if err := toml.Unmarshal(contentAC, &acPeers); err != nil {
		log.Error("failed to unmarshal ac peers config: %v", err)
	}

	if err := s.updateACPeers(acPeers.ACs); err != nil {
		// ignore error
		_ = err
	}

	acConfigWatch = utils.WatchFile(fileNameAC, func() {
		log.Info("ac peer config: %s has been updated", fileNameAC)
		if contentAC, err = s.loadConfigFile(fileNameAC); err == nil {
			if err = toml.Unmarshal(contentAC, &acPeers); err == nil {
				s.updateACPeers(acPeers.ACs)
			}
		}
	})

	// agent.toml
	fileNameAgent := filepath.Join(ExeDirPath, "etc", "agent.toml")
	contentAgent, err := s.loadConfigFile(fileNameAgent)
	if err != nil {
		log.Error("load agent peer config err: %v", err)
		return err
	}
	var agentPeers Peers
	if err := toml.Unmarshal(contentAgent, &agentPeers); err != nil {
		log.Error("failed to unmarshal agent peers config: %v", err)
	}
	if err := s.updateAgentPeers(agentPeers.Agents); err != nil {
		// ignore error
		_ = err
	}

	agentConfigWatch = utils.WatchFile(fileNameAgent, func() {
		log.Info("agent peer config: %s has been updated", fileNameAgent)
		if contentAgent, err = s.loadConfigFile(fileNameAgent); err == nil {
			if err = toml.Unmarshal(contentAgent, &agentPeers); err == nil {
				s.updateAgentPeers(agentPeers.Agents)
			}
		}
	})

	//db.toml
	fileNameDE := filepath.Join(ExeDirPath, "etc", "db.toml")
	contentDE, err := s.loadConfigFile(fileNameDE)
	if err != nil {
		log.Error("load db peer config err: %v", err)
		return err
	}
	var dePeers Peers
	if err := toml.Unmarshal(contentDE, &dePeers); err != nil {
		log.Error("failed to unmarshal db peers config: %v", err)
	}
	if err := s.updateDePeers(dePeers.DBs); err != nil {
		// ignore error
		_ = err
	}
	dbConfigWatch = utils.WatchFile(fileNameDE, func() {
		log.Info("device peer config: %s has been updated", fileNameDE)
		if contentDE, err = s.loadConfigFile(fileNameDE); err == nil {
			if err = toml.Unmarshal(contentDE, &dePeers); err == nil {
				s.updateDePeers(dePeers.DBs)
			}
		}
	})

	// tee.toml
	fileNameTee := filepath.Join(ExeDirPath, "etc", "tee.toml")
	if err := s.updateTee(fileNameTee); err != nil {
		// ignore error
		_ = err
	}
	teeWatch = utils.WatchFile(fileNameTee, func() {
		log.Info("tee: %s has been updated", fileNameTee)
		s.updateTee(fileNameTee)
	})

	return nil
}

func (s *UdpServer) loadResources() error {
	// resource.toml
	fileName := filepath.Join(ExeDirPath, "etc", "resource.toml")
	content, err := os.ReadFile(fileName)
	if err != nil {
		log.Error("failed to read resource config: %v", err)
	}
	aspMap := make(common.AuthSvcProviderMap)
	// update
	if err := toml.Unmarshal(content, &aspMap); err != nil {
		log.Error("failed to unmarshal resource config: %v", err)
	}
	if err := s.updateResources(aspMap); err != nil {
		// ignore error
		_ = err
	}

	resConfigWatch = utils.WatchFile(fileName, func() {
		log.Info("resource config: %s has been updated", fileName)
		if content, err = s.loadConfigFile(fileName); err == nil {
			if err = toml.Unmarshal(content, &resConfigWatch); err == nil {
				s.updateResources(aspMap)
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
		log.Error("failed to read src ip config: %v", err)
	}

	// update
	srcIpMap := make(map[string][]*common.NetAddress)
	if err := toml.Unmarshal(content, &srcIpMap); err != nil {
		log.Error("failed to unmarshal src ip config: %v", err)
	}
	if err := s.updateSourceIps(srcIpMap); err != nil {
		// ignore error
		_ = err
	}

	srcipConfigWatch = utils.WatchFile(fileName, func() {
		log.Info("src ip config: %s has been updated", fileName)
		if content, err = s.loadConfigFile(fileName); err == nil {
			if err = toml.Unmarshal(content, &srcIpMap); err == nil {
				s.updateSourceIps(srcIpMap)
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
		log.Error("failed to read remote config: %v", err)
		return err
	}

	var conf RemoteConfig
	if err = toml.Unmarshal(content, &conf); err != nil {
		log.Error("failed to unmarshal remote config: %v", err)
		return err
	}

	if strings.EqualFold(conf.Provider, "etcd") {
		if len(conf.Endpoints) == 0 {
			log.Error("remote config has no endpoints,open nhp server will startup with local configuration")
			return nil
		}

		if len(conf.Key) == 0 {
			log.Error("remote config has no key,open nhp server will startup with local configuration")
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

		err = s.etcdConn.InitClient()
		return err
	} else {
		return errors.New("unknown remote provider")
	}

}

func (s *UdpServer) loadRemoteBaseConfig() error {
	var serverEtcdConfig ServerEtcdConfig
	value, err := s.etcdConn.GetValue()
	if err != nil {
		return err
	}
	if err = toml.Unmarshal(value, &serverEtcdConfig); err != nil {
		log.Error("failed to unmarshal remote config: %v", err)
		return err
	}

	err = s.updateBaseConfig(serverEtcdConfig.BaseConfig)
	return err
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
		s.updateEtcdConfig(val, true)
	})

	return nil
}

func (s *UdpServer) updateEtcdConfig(content []byte, baseLoad bool) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	var serverEtcdConfig ServerEtcdConfig
	if err = toml.Unmarshal(content, &serverEtcdConfig); err != nil {
		log.Error("failed to unmarshal remote config: %v", err)
		return err
	}
	if baseLoad {
		s.updateBaseConfig(serverEtcdConfig.BaseConfig)
	}
	s.updateHttpConfig(serverEtcdConfig.HttpConfig)
	s.updateACPeers(serverEtcdConfig.ACs)
	s.updateAgentPeers(serverEtcdConfig.Agents)
	s.updateDePeers(serverEtcdConfig.DBs)

	aspMap := make(common.AuthSvcProviderMap)
	for _, aspData := range serverEtcdConfig.AuthServiceId {
		aspId := aspData.AuthSvcId
		aspMap[aspId] = aspData
	}
	s.updateResources(aspMap)

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
	s.updateSourceIps(srcIpMap)

	return err
}

func (s *UdpServer) loadConfigFile(file string) (content []byte, err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})
	content, err = os.ReadFile(file)
	if err != nil {
		log.Error("failed to read base config: %v", err)
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
		return err
	}

	// update
	if s.config.LogLevel != conf.LogLevel {
		log.Info("set base log level to %d", conf.LogLevel)
		s.log.SetLogLevel(conf.LogLevel)
		s.config.LogLevel = conf.LogLevel
	}

	if s.config.DisableAgentValidation != conf.DisableAgentValidation {
		if s.device != nil {
			s.device.SetOption(core.DeviceOptions{
				DisableAgentPeerValidation: conf.DisableAgentValidation,
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

	return err
}

func (s *UdpServer) updateHttpConfig(httpConf HttpConfig) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	// set http default timeout values
	// 4.5s for read timeout, 4s for write timeout, 5s for idle timeout
	if httpConf.ReadTimeoutMs == 0 {
		httpConf.ReadTimeoutMs = DefaultHttpRequestReadTimeoutMs
	}
	if httpConf.WriteTimeoutMs == 0 {
		httpConf.WriteTimeoutMs = DefaultHttpResponseWriteTimeoutMs
	}
	if httpConf.IdleTimeoutMs == 0 {
		httpConf.IdleTimeoutMs = DefaultHttpServerIdleTimeoutMs
	}

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
	return err
}

func (s *UdpServer) updateACPeers(peers []*core.UdpPeer) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	acPeerMap := make(map[string]*core.UdpPeer)
	for _, p := range peers {
		p.Type = core.NHP_AC
		s.device.AddPeer(p)
		acPeerMap[p.PublicKeyBase64()] = p
	}

	// remove old peers from device
	s.acPeerMapMutex.Lock()
	defer s.acPeerMapMutex.Unlock()
	for pubKey := range s.acPeerMap {
		if _, found := acPeerMap[pubKey]; !found {
			s.device.RemovePeer(pubKey)
		}
	}
	s.acPeerMap = acPeerMap

	return err
}

func (s *UdpServer) updateAgentPeers(peers []*core.UdpPeer) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})
	agentPeerMap := make(map[string]*core.UdpPeer)
	for _, p := range peers {
		p.Type = core.NHP_AGENT
		s.device.AddPeer(p)
		agentPeerMap[p.PublicKeyBase64()] = p
	}

	// remove old peers from device
	s.agentPeerMapMutex.Lock()
	defer s.agentPeerMapMutex.Unlock()
	for pubKey := range s.agentPeerMap {
		if _, found := agentPeerMap[pubKey]; !found {
			s.device.RemovePeer(pubKey)
		}
	}
	s.agentPeerMap = agentPeerMap

	return err
}

func (s *UdpServer) updateResources(aspMap common.AuthSvcProviderMap) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	for aspId, aspData := range aspMap {
		aspData.AuthSvcId = aspId
		if len(aspData.PluginPath) > 0 {
			h := plugins.ReadPluginHandler(aspData.PluginPath)
			if h != nil {
				s.LoadPlugin(aspId, h)
			}
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

	return err
}

func (s *UdpServer) updateSourceIps(srcIpMap map[string][]*common.NetAddress) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	s.srcIpAssociatedAddrMapMutex.Lock()
	defer s.srcIpAssociatedAddrMapMutex.Unlock()
	s.srcIpAssociatedAddrMap = srcIpMap

	return err
}

func (s *UdpServer) StopConfigWatch() {
	if baseConfigWatch != nil {
		baseConfigWatch.Close()
	}
	if httpConfigWatch != nil {
		httpConfigWatch.Close()
	}
	if acConfigWatch != nil {
		acConfigWatch.Close()
	}
	if agentConfigWatch != nil {
		agentConfigWatch.Close()
	}
	if resConfigWatch != nil {
		resConfigWatch.Close()
	}
	if srcipConfigWatch != nil {
		srcipConfigWatch.Close()
	}
	//add dbConfigWatch
	if dbConfigWatch != nil {
		dbConfigWatch.Close()
	}
	if teeWatch != nil {
		teeWatch.Close()
	}
}

// updateDePeers
func (s *UdpServer) updateDePeers(peers []*core.UdpPeer) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	dbPeerMap := make(map[string]*core.UdpPeer)
	for _, p := range peers {
		p.Type = core.NHP_DB
		s.device.AddPeer(p)
		dbPeerMap[p.PublicKeyBase64()] = p
	}

	// remove old peers from device
	s.dbPeerMapMutex.Lock()
	defer s.dbPeerMapMutex.Unlock()
	for pubKey := range s.dbPeerMap {
		if _, found := dbPeerMap[pubKey]; !found {
			s.device.RemovePeer(pubKey)
		}
	}
	s.dbPeerMap = dbPeerMap
	return err
}

// update tee
func (s *UdpServer) updateTee(file string) (err error) {
	utils.CatchPanicThenRun(func() {
		err = errLoadConfig
	})

	content, err := os.ReadFile(file)
	if err != nil {
		log.Error("failed to read tee config: %v", err)
	}

	var tees TeeAttestationReports
	teeMap := make(map[string]*TeeAttestationReport)
	if err := toml.Unmarshal(content, &tees); err != nil {
		log.Error("failed to unmarshal device peer config: %v", err)
	}
	for _, tee := range tees.TEEs {
		teeMap[tee.Measure] = tee
	}

	s.teeMapMutex.Lock()
	defer s.teeMapMutex.Unlock()
	s.teeMap = teeMap
	return err
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

	// Initialize AWS identity verification (auto-detects if in AWS)
	initAWSIdentityVerification()

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

		// Verify AWS identity if enabled
		if awsIdentityVerificationEnabled {
			if _, err := verifyAWSIdentity(entry); err != nil {
				log.Error("AWS identity verification failed for %s: %v", entry.InstanceId, err)
				continue // Skip this AC
			}
			log.Info("AWS identity verified for instance %s", entry.InstanceId)
		}

		acRegistryMap[entry.InstanceId] = entry
		log.Info("Loaded AC registration: instance=%s, ip=%s, pubkey=%s...",
			entry.InstanceId, entry.Ip, entry.PublicKey[:20])
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

			// Verify AWS Instance Identity if running in AWS
			if awsIdentityVerificationEnabled {
				if _, err := verifyAWSIdentity(entry); err != nil {
					log.Error("AWS identity verification failed for %s: %v", entry.InstanceId, err)
					return // Reject this AC registration
				}
				log.Info("AWS identity verified for instance %s", entry.InstanceId)
			}

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
		peer.ExpireTime = 1924991999 // Far future expiry

		peers = append(peers, peer)
	}

	log.Info("Reconciling AC peers: %d entries from registry", len(peers))

	// Update AC peers using existing mechanism
	if err := s.updateACPeers(peers); err != nil {
		log.Error("Failed to update AC peers from registry: %v", err)
	}
}
