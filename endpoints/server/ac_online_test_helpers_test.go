package server

import "github.com/OpenNHP/opennhp/nhp/common"

const testACOnlineBootID = "00112233445566778899aabbccddeeff"

// readyACOnlineMsg keeps legacy registration-gate tests focused on the gate
// they name. Cloud AOL now has a mandatory process-scoped session-control
// readiness tuple, so omitting it would short-circuit before F3/F5/licensing.
func readyACOnlineMsg(acID, licenseKey string) common.ACOnlineMsg {
	return common.ACOnlineMsg{
		ACId:                   acID,
		LicenseKey:             licenseKey,
		BootID:                 testACOnlineBootID,
		SessionFlushGeneration: 1,
		SessionFlushComplete:   true,
	}
}
