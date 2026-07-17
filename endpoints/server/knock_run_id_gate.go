package server

import "github.com/OpenNHP/opennhp/nhp/common"

// validateRegisteredAgentKnockRunID scopes the mandatory RunID policy to the
// native keypair-backed registered-agent auth handler. Other auth-service IDs
// retain the generic protocol parser's missing/empty legacy behavior, and HTTP
// knock construction never enters this UDP boundary.
func validateRegisteredAgentKnockRunID(knkMsg *common.AgentKnockMsg) error {
	if knkMsg == nil {
		return common.ErrInvalidAgentKnockRunID
	}
	if knkMsg.AuthServiceId != common.RegisteredAgentAuthServiceID {
		return nil
	}
	return common.ValidateAgentKnockRunID(knkMsg.RunID)
}
