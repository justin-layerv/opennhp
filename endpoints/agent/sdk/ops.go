// Package sdk provides shared business logic for NHP agent SDK bindings.
// Both the CGo (agent/main) and gomobile (agent/iossdk) wrappers delegate
// to these functions, keeping platform-specific code to a thin conversion layer.
package sdk

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/OpenNHP/opennhp/endpoints/agent"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// instance holds the singleton agent. Only one binary (CGo or gomobile) is
// compiled at a time. generationMu prevents a new Init from overlapping the
// previous instance's Stop. instanceMu protects publication and gives short
// operations a lease against teardown. Knock and Exit only snapshot the pointer:
// UdpAgent's lifecycle guard makes those blocking operations safe to race with
// Stop, and releasing instanceMu lets Close interrupt their response wait.
var (
	generationMu sync.Mutex
	instanceMu   sync.RWMutex
	instance     *agent.UdpAgent
)

// Init initializes the NHP agent singleton with the given working directory and
// log level. Configuration files are read from workingDir/etc/ and logs are
// written to workingDir/logs/.
//
// logLevel: 0 = silent, 1 = error, 2 = info, 3 = debug, 4 = verbose.
//
// Returns true on success or if the agent is already initialized.
func Init(workingDir string, logLevel int) bool {
	generationMu.Lock()
	defer generationMu.Unlock()
	instanceMu.RLock()
	if instance != nil {
		instanceMu.RUnlock()
		return true
	}
	instanceMu.RUnlock()

	candidate := &agent.UdpAgent{}
	if err := candidate.Start(workingDir, logLevel); err != nil {
		return false
	}
	instanceMu.Lock()
	instance = candidate
	instanceMu.Unlock()
	return true
}

// Close synchronously stops and releases the NHP agent singleton.
// Safe to call when the agent is not initialized.
func Close() {
	generationMu.Lock()
	defer generationMu.Unlock()
	instanceMu.Lock()
	if instance == nil {
		instanceMu.Unlock()
		return
	}
	closing := instance
	instance = nil
	instanceMu.Unlock()
	closing.Stop()
}

// KnockloopStart reads resource and server configuration from workingDir/etc/
// and asynchronously starts the knock loop thread.
//
// Returns the number of resources being knocked, or -1 if the agent is not
// initialized OR not running (e.g. racing a Stop()/RestartAgent, so the loop
// wasn't started). Native/cgo callers must treat -1 as "not started", not a count.
func KnockloopStart() int {
	instanceMu.RLock()
	defer instanceMu.RUnlock()
	if instance == nil {
		return -1
	}
	return instance.StartKnockLoop()
}

// KnockloopStop synchronously stops the knock loop thread.
func KnockloopStop() {
	instanceMu.RLock()
	defer instanceMu.RUnlock()
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
	instanceMu.RLock()
	defer instanceMu.RUnlock()
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
//   - port:   server UDP port  (0 → default 443, the public NHP edge port)
//   - expire: public key expiry as epoch seconds (0 → no expiry)
//
// Returns false if the agent is not initialized or inputs are invalid.
func AddServer(pubkey, ip, host string, port int, expire int64) bool {
	instanceMu.RLock()
	defer instanceMu.RUnlock()
	if instance == nil {
		return false
	}
	if pubkey == "" || (ip == "" && host == "") {
		return false
	}
	if port == 0 {
		port = common.DefaultNHPClientPort
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
	instanceMu.RLock()
	defer instanceMu.RUnlock()
	if instance == nil || pubkey == "" {
		return
	}
	instance.RemoveServer(pubkey)
}

// AddResource registers a knock-on resource for the background knock loop.
//
//   - aspId:           authentication service provider identifier (required)
//   - resId:           resource identifier (required)
//   - serverIp:        NHP server IP managing this resource (required if serverHostname is empty)
//   - serverHostname:  NHP server hostname (required if serverIp is empty)
//   - serverPort:      NHP server port
//
// Registered-agent authentication (aspId "agent") is intentionally unsupported
// by the background loop because each access lifecycle requires a caller-owned
// runID and positive runAttempt. Such callers must use
// [KnockResourceWithRunBinding] and retire the returned receipt with
// [RetireSession].
//
// Returns false if the agent is not initialized, inputs are invalid, or aspId
// selects registered-agent authentication.
func AddResource(aspId, resId, serverIp, serverHostname string, serverPort int) bool {
	instanceMu.RLock()
	defer instanceMu.RUnlock()
	if instance == nil {
		return false
	}
	if aspId == "" || resId == "" || (serverIp == "" && serverHostname == "") {
		return false
	}
	if aspId == common.RegisteredAgentAuthServiceID {
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
	instanceMu.RLock()
	defer instanceMu.RUnlock()
	if instance == nil || aspId == "" || resId == "" {
		return
	}
	instance.RemoveResource(aspId, resId)
}

func errAckMsg(e *common.Error) *common.ServerKnockAckMsg {
	return &common.ServerKnockAckMsg{ErrCode: e.ErrorCode(), ErrMsg: e.Error()}
}

func exactCloseErrJSON(e *common.Error) string {
	bytes, err := json.Marshal(&common.ServerExactSessionCloseAckMsg{ErrCode: e.ErrorCode(), ErrMsg: e.Error()})
	if err != nil {
		return "{}"
	}
	return string(bytes)
}

func exactCloseResultJSON(ack *common.ServerExactSessionCloseAckMsg, callErr error) string {
	if ack != nil {
		if raw, err := json.Marshal(ack); err == nil {
			var strict common.ServerExactSessionCloseAckMsg
			if common.DecodeServerExactSessionCloseAckMsg(raw, &strict) == nil {
				return string(raw)
			}
		}
	}
	var nhpErr *common.Error
	if errors.As(callErr, &nhpErr) && nhpErr != nil {
		return exactCloseErrJSON(nhpErr)
	}
	if callErr != nil {
		// The only nil-ACK operational path today is route resolution. Keep its
		// public denial stable instead of serializing JSON null or remote error text.
		return exactCloseErrJSON(common.ErrKnockServerNotFound)
	}
	return exactCloseErrJSON(common.ErrTransactionFailedByClosedConnection)
}

// buildTarget validates inputs, builds a KnockTarget, and returns it.
// On failure, returns nil target and an ackMsg populated with the error.
func buildTarget(current *agent.UdpAgent, aspId, resId, runID string, runAttempt uint64,
	serverIp, serverHostname string, serverPort int,
) (*agent.KnockTarget, *common.ServerKnockAckMsg) {
	if current == nil {
		return nil, errAckMsg(common.ErrNoAgentInstance)
	}
	if aspId == "" || resId == "" {
		return nil, errAckMsg(common.ErrInvalidInput)
	}
	if err := common.ValidateAgentKnockRunIDForAuthService(aspId, runID); err != nil {
		return nil, errAckMsg(common.ErrKnockRunIDInvalid)
	}
	if aspId == common.RegisteredAgentAuthServiceID && runAttempt == 0 {
		return nil, errAckMsg(common.ErrKnockRunAttemptInvalid)
	}
	if serverIp == "" && serverHostname == "" {
		return nil, errAckMsg(common.ErrInvalidInput)
	}

	resource := &agent.KnockResource{
		AuthServiceId:  aspId,
		ResourceId:     resId,
		RunID:          runID,
		RunAttempt:     runAttempt,
		ServerIp:       serverIp,
		ServerHostname: serverHostname,
		ServerPort:     serverPort,
	}
	peer := current.FindServerPeerFromResource(resource)
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
// This legacy wrapper carries no runID. Calls with aspId "agent" therefore
// fail closed with [common.ErrKnockRunIDInvalid]; registered-agent callers must
// use [KnockResourceWithRunBinding].
//
// Returns a JSON string containing the server's ack message with fields:
// errCode, errMsg, resHost, opnTime, aspToken, agentAddr, preActs,
// redirectUrl.
func KnockResource(aspId, resId, serverIp, serverHostname string, serverPort int) string {
	return KnockResourceWithRunBinding(aspId, resId, "", 0, serverIp, serverHostname, serverPort)
}

// KnockResourceWithRunID is the legacy runID-only wrapper. It cannot create a
// registered-agent session because that contract also requires a positive
// runAttempt; registered callers must use [KnockResourceWithRunBinding].
// Legacy auth services may continue to use this wrapper.
func KnockResourceWithRunID(aspId, resId, runID, serverIp, serverHostname string, serverPort int) string {
	return KnockResourceWithRunBinding(aspId, resId, runID, 0, serverIp, serverHostname, serverPort)
}

// KnockResourceWithRunBinding sends one registered-agent knock carrying the
// caller-owned immutable RunID and positive attempt. A successful JSON ACK
// contains the server-issued exact-session receipt consumed by RetireSession.
func KnockResourceWithRunBinding(aspId, resId, runID string, runAttempt uint64,
	serverIp, serverHostname string, serverPort int,
) string {
	instanceMu.RLock()
	current := instance
	instanceMu.RUnlock()
	target, ackMsg := buildTarget(current, aspId, resId, runID, runAttempt, serverIp, serverHostname, serverPort)
	if target != nil {
		ackMsg, _ = current.Knock(target)
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
// This legacy resource-shaped exit has no exact session receipt. Calls with
// aspId "agent" fail closed; registered callers must use [RetireSession].
//
// Returns true if the exit request succeeded.
func ExitResource(aspId, resId, serverIp, serverHostname string, serverPort int) bool {
	return ExitResourceWithRunID(aspId, resId, "", serverIp, serverHostname, serverPort)
}

// ExitResourceWithRunID is retained only as a fail-loud legacy API. A runID is
// not sufficient authority to retire an exact registered-agent session, so
// registered callers must use [RetireSession].
func ExitResourceWithRunID(aspId, resId, runID, serverIp, serverHostname string, serverPort int) bool {
	instanceMu.RLock()
	current := instance
	instanceMu.RUnlock()
	target, _ := buildTarget(current, aspId, resId, runID, 0, serverIp, serverHostname, serverPort)
	if target == nil {
		return false
	}
	_, err := current.ExitKnockRequest(target)
	return err == nil
}

// RetireSession sends the receipt-based exact-session EXT to the same server
// route supplied for the original knock and returns the dedicated close ACK as
// JSON. knockAckJSON must be the successful ACK returned by
// KnockResourceWithRunBinding; resource-shaped exit input is not accepted.
func RetireSession(knockAckJSON, serverIp, serverHostname string, serverPort int) string {
	instanceMu.RLock()
	current := instance
	instanceMu.RUnlock()
	if current == nil {
		return exactCloseErrJSON(common.ErrNoAgentInstance)
	}
	receipt, err := common.DecodeAgentSessionReceiptFromKnockAckJSON([]byte(knockAckJSON))
	if err != nil {
		return exactCloseErrJSON(common.ErrInvalidInput)
	}
	route := &agent.KnockResource{ServerIp: serverIp, ServerHostname: serverHostname, ServerPort: serverPort}
	peer := current.FindServerPeerFromResource(route)
	target, err := agent.NewSessionRetirementTarget(receipt, peer)
	if err != nil {
		return exactCloseErrJSON(common.ErrKnockServerNotFound)
	}
	ack, exitErr := current.ExitKnockRequest(target)
	return exactCloseResultJSON(ack, exitErr)
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
