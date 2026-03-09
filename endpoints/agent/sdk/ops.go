// Package sdk provides shared business logic for NHP agent SDK bindings.
// Both the CGo (agent/main) and gomobile (agent/iossdk) wrappers delegate
// to these functions, keeping platform-specific code to a thin conversion layer.
package sdk

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/OpenNHP/opennhp/endpoints/agent"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// instance holds the singleton agent. Only one binary (CGo or gomobile)
// is compiled at a time, so a package-level variable is safe.
var instance *agent.UdpAgent

// Init initializes the NHP agent singleton with the given working directory and
// log level. Configuration files are read from workingDir/etc/ and logs are
// written to workingDir/logs/.
//
// logLevel: 0 = silent, 1 = error, 2 = info, 3 = debug, 4 = verbose.
//
// Returns true on success or if the agent is already initialized.
func Init(workingDir string, logLevel int) bool {
	if instance != nil {
		return true
	}

	instance = &agent.UdpAgent{}
	if err := instance.Start(workingDir, logLevel); err != nil {
		instance = nil
		return false
	}
	return true
}

// Close synchronously stops and releases the NHP agent singleton.
// Safe to call when the agent is not initialized.
func Close() {
	if instance == nil {
		return
	}
	instance.Stop()
	instance = nil
}

// KnockloopStart reads resource and server configuration from workingDir/etc/
// and asynchronously starts the knock loop thread.
//
// Returns the number of resources being knocked, or -1 if the agent is not
// initialized.
func KnockloopStart() int {
	if instance == nil {
		return -1
	}
	return instance.StartKnockLoop()
}

// KnockloopStop synchronously stops the knock loop thread.
func KnockloopStop() {
	if instance == nil {
		return
	}
	instance.StopKnockLoop()
}

// SetKnockUser configures the user identity presented during knock requests.
//
//   - userId:   user identifier (optional but recommended)
//   - devId:    device identifier (optional)
//   - orgId:    organization identifier (optional)
//   - userData: additional fields as a JSON string (optional)
//
// Returns false if the agent is not initialized or userData is invalid JSON.
func SetKnockUser(userId, devId, orgId, userData string) bool {
	if instance == nil {
		return false
	}
	var data map[string]any
	if len(userData) > 0 {
		if err := json.Unmarshal([]byte(userData), &data); err != nil {
			return false
		}
	}
	instance.SetDeviceId(devId)
	instance.SetKnockUser(userId, orgId, data)
	return true
}

// AddServer registers an NHP server that the agent can knock.
//
//   - pubkey: server's base64-encoded public key (required)
//   - ip:     server IP address (required if host is empty)
//   - host:   server hostname  (required if ip is empty)
//   - port:   server UDP port  (0 → default 62206)
//   - expire: public key expiry as epoch seconds (0 → no expiry)
//
// Returns false if the agent is not initialized or inputs are invalid.
func AddServer(pubkey, ip, host string, port int, expire int64) bool {
	if instance == nil {
		return false
	}
	if pubkey == "" || (ip == "" && host == "") {
		return false
	}
	if port == 0 {
		port = common.DefaultNHPPort
	}
	instance.AddServer(&core.UdpPeer{
		Type:         core.NHP_SERVER,
		PubKeyBase64: pubkey,
		Ip:           ip,
		Port:         port,
		Hostname:     host,
		ExpireTime:   expire,
	})
	return true
}

// RemoveServer removes a previously registered NHP server by its public key.
func RemoveServer(pubkey string) {
	if instance == nil || pubkey == "" {
		return
	}
	instance.RemoveServer(pubkey)
}

// AddResource registers a knock-on resource.
//
//   - aspId:           authentication service provider identifier (required)
//   - resId:           resource identifier (required)
//   - serverIp:        NHP server IP managing this resource (required if serverHostname is empty)
//   - serverHostname:  NHP server hostname (required if serverIp is empty)
//   - serverPort:      NHP server port
//
// Returns false if the agent is not initialized or inputs are invalid.
func AddResource(aspId, resId, serverIp, serverHostname string, serverPort int) bool {
	if instance == nil {
		return false
	}
	if aspId == "" || resId == "" || (serverIp == "" && serverHostname == "") {
		return false
	}
	return instance.AddResource(&agent.KnockResource{
		AuthServiceId:  aspId,
		ResourceId:     resId,
		ServerIp:       serverIp,
		ServerHostname: serverHostname,
		ServerPort:     serverPort,
	}) == nil
}

// RemoveResource removes a previously registered resource.
func RemoveResource(aspId, resId string) {
	if instance == nil || aspId == "" || resId == "" {
		return
	}
	instance.RemoveResource(aspId, resId)
}

func errAckMsg(e *common.Error) *common.ServerKnockAckMsg {
	return &common.ServerKnockAckMsg{ErrCode: e.ErrorCode(), ErrMsg: e.Error()}
}

// buildTarget validates inputs, builds a KnockTarget, and returns it.
// On failure, returns nil target and an ackMsg populated with the error.
func buildTarget(aspId, resId, serverIp, serverHostname string, serverPort int) (*agent.KnockTarget, *common.ServerKnockAckMsg) {
	if instance == nil {
		return nil, errAckMsg(common.ErrNoAgentInstance)
	}
	if aspId == "" || resId == "" || (serverIp == "" && serverHostname == "") {
		return nil, errAckMsg(common.ErrInvalidInput)
	}

	resource := &agent.KnockResource{
		AuthServiceId:  aspId,
		ResourceId:     resId,
		ServerIp:       serverIp,
		ServerHostname: serverHostname,
		ServerPort:     serverPort,
	}
	peer := instance.FindServerPeerFromResource(resource)
	if peer == nil {
		return nil, errAckMsg(common.ErrKnockServerNotFound)
	}

	return &agent.KnockTarget{
		KnockResource: *resource,
		ServerPeer:    peer,
	}, nil
}

// KnockResource sends a single knock request to the NHP server managing the
// specified resource. The server must have been registered via [AddServer]
// beforehand.
//
// Returns a JSON string containing the server's ack message with fields:
// errCode, errMsg, resHost, opnTime, aspToken, agentAddr, preActs,
// redirectUrl.
func KnockResource(aspId, resId, serverIp, serverHostname string, serverPort int) string {
	target, ackMsg := buildTarget(aspId, resId, serverIp, serverHostname, serverPort)
	if target != nil {
		ackMsg, _ = instance.Knock(target)
	}
	bytes, err := json.Marshal(ackMsg)
	if err != nil {
		log.Error("[Agent SDK] KnockResource failed to marshal ack message: %v", err)
		return "{}"
	}
	return string(bytes)
}

// ExitResource tells the NHP server to revoke the agent's access permission
// for the specified resource.
//
// Returns true if the exit request succeeded.
func ExitResource(aspId, resId, serverIp, serverHostname string, serverPort int) bool {
	target, _ := buildTarget(aspId, resId, serverIp, serverHostname, serverPort)
	if target == nil {
		return false
	}
	_, err := instance.ExitKnockRequest(target)
	return err == nil
}

// GenerateKeys creates a new Curve25519 key pair and returns the result as
// "privateKeyBase64|publicKeyBase64".
func GenerateKeys() string {
	e, err := core.NewECDH(core.ECC_CURVE25519)
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	return fmt.Sprintf("%s|%s", e.PrivateKeyBase64(), e.PublicKeyBase64())
}

// PrivkeyToPubkey derives the public key from a base64-encoded Curve25519
// private key. Returns an empty string on failure.
func PrivkeyToPubkey(privateBase64 string) string {
	privKeyBytes, err := base64.StdEncoding.DecodeString(privateBase64)
	if err != nil {
		return ""
	}
	e, err := core.ECDHFromKey(core.ECC_CURVE25519, privKeyBytes)
	if err != nil {
		return ""
	}
	return e.PublicKeyBase64()
}
