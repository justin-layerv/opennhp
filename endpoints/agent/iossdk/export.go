package iossdk

import (
	_ "golang.org/x/mobile/bind"

	"github.com/OpenNHP/opennhp/endpoints/agent/sdk"
)

func NhpAgentInit(workingDir string, logLevel int) bool {
	return sdk.Init(workingDir, logLevel)
}

func NhpAgentClose() {
	sdk.Close()
}

//export NhpAgentKnockloopStart
func NhpAgentKnockloopStart() int {
	return sdk.KnockloopStart()
}

func NhpAgentKnockloopStop() {
	sdk.KnockloopStop()
}

func NhpAgentSetKnockUser(userId string, devId string, orgId string, userData string) bool {
	return sdk.SetKnockUser(userId, devId, orgId, userData)
}

func NhpAgentAddServer(pubkey string, ip string, host string, port int, expire int64) bool {
	return sdk.AddServer(pubkey, ip, host, port, expire)
}

func NhpAgentRemoveServer(pubkey string) {
	sdk.RemoveServer(pubkey)
}

func NhpAgentAddResource(aspId string, resId string, serverIp string, serverHostname string, serverPort int) bool {
	return sdk.AddResource(aspId, resId, serverIp, serverHostname, serverPort)
}

func NhpAgentRemoveResource(aspId string, resId string) {
	sdk.RemoveResource(aspId, resId)
}

func NhpAgentKnockResource(aspId string, resId string, serverIp string, serverHostname string, serverPort int) string {
	return sdk.KnockResource(aspId, resId, serverIp, serverHostname, serverPort)
}

func NhpAgentKnockResourceWithRunID(aspId string, resId string, runID string, serverIp string, serverHostname string, serverPort int) string {
	return sdk.KnockResourceWithRunID(aspId, resId, runID, serverIp, serverHostname, serverPort)
}

func NhpAgentKnockResourceWithRunBinding(aspId string, resId string, runID string, runAttempt int64, serverIp string, serverHostname string, serverPort int) string {
	if runAttempt <= 0 {
		return sdk.KnockResourceWithRunBinding(aspId, resId, runID, 0, serverIp, serverHostname, serverPort)
	}
	return sdk.KnockResourceWithRunBinding(aspId, resId, runID, uint64(runAttempt), serverIp, serverHostname, serverPort)
}

func NhpAgentExitResource(aspId string, resId string, serverIp string, serverHostname string, serverPort int) bool {
	return sdk.ExitResource(aspId, resId, serverIp, serverHostname, serverPort)
}

func NhpAgentExitResourceWithRunID(aspId string, resId string, runID string, serverIp string, serverHostname string, serverPort int) bool {
	return sdk.ExitResourceWithRunID(aspId, resId, runID, serverIp, serverHostname, serverPort)
}

func NhpAgentRetireSession(knockAckJSON string, serverIp string, serverHostname string, serverPort int) string {
	return retireSessionJSON(knockAckJSON, serverIp, serverHostname, serverPort)
}

func retireSessionJSON(knockAckJSON, serverIP, serverHostname string, serverPort int) string {
	return sdk.RetireSession(knockAckJSON, serverIP, serverHostname, serverPort)
}

//export NhpGenerateKeys
func NhpGenerateKeys() string {
	return sdk.GenerateKeys()
}

//export NhpPrivkeyToPubkey
func NhpPrivkeyToPubkey(privateBase64 string) string {
	return sdk.PrivkeyToPubkey(privateBase64)
}
