package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	wasmEngine "github.com/OpenNHP/opennhp/nhp/core/wasm/engine"
	"github.com/OpenNHP/opennhp/nhp/log"
	utils "github.com/OpenNHP/opennhp/nhp/utils"
	"golang.org/x/crypto/bcrypt"
)

// HandleOTPRequest
// Server will not respond to agent's otp request
func (s *UdpServer) HandleOTPRequest(ppd *core.PacketParserData) (err error) {
	defer s.wg.Done()
	s.wg.Add(1)

	transactionId := ppd.SenderTrxId
	addrStr := ppd.ConnData.RemoteAddr.String()

	otpMsg := &common.AgentOTPMsg{}
	err = json.Unmarshal(ppd.BodyMessage, otpMsg)
	if err != nil {
		log.Error("server-agent(#%d@%s)[HandleOTPRequest] failed to parse %s message: %v", transactionId, addrStr, core.HeaderTypeToString(ppd.HeaderType), err)
		return err
	}

	handler := s.FindPluginHandler(otpMsg.AuthServiceId)
	if handler == nil {
		return common.ErrAuthHandlerNotFound
	}

	otpReq := &common.NhpOTPRequest{
		Msg: otpMsg,
		SrcAddr: &common.NetAddress{
			Ip:   ppd.ConnData.RemoteAddr.IP.String(),
			Port: ppd.ConnData.RemoteAddr.Port,
		},
	}

	err = handler.RequestOTP(otpReq, s.NewNhpServerHelper(ppd))
	if err != nil {
		log.Error("server-agent(%s#%d@%s)[HandleOTPRequest] error: %v", otpMsg.UserId, transactionId, addrStr, err)
		return err
	}

	log.Info("server-agent(%s#%d@%s)[HandleOTPRequest] succeeded", otpMsg.UserId, transactionId, addrStr)
	return nil
}

// HandleRegisterRequest
// Server will respond with success or error with NHP_RAK message
func (s *UdpServer) HandleRegisterRequest(ppd *core.PacketParserData) (err error) {
	defer s.wg.Done()
	s.wg.Add(1)

	transactionId := ppd.SenderTrxId
	addrStr := ppd.ConnData.RemoteAddr.String()
	regMsg := &common.AgentRegisterMsg{}
	rakMsg := &common.ServerRegisterAckMsg{}

	func() {
		err = json.Unmarshal(ppd.BodyMessage, regMsg)
		if err != nil {
			log.Error("server-agent(#%d@%s)[HandleRegisterRequest] failed to parse %s message: %v", transactionId, addrStr, core.HeaderTypeToString(ppd.HeaderType), err)
			rakMsg.ErrCode = common.ErrJsonParseFailed.ErrorCode()
			rakMsg.ErrMsg = err.Error()
			return
		}

		handler := s.FindPluginHandler(regMsg.AuthServiceId)
		if handler == nil {
			err = common.ErrAuthHandlerNotFound
			rakMsg.ErrCode = common.ErrAuthHandlerNotFound.ErrorCode()
			rakMsg.ErrMsg = err.Error()
			return
		}

		agentPubkey := base64.StdEncoding.EncodeToString(ppd.RemotePubKey)

		regReq := &common.NhpRegisterRequest{
			Msg:       regMsg,
			Ack:       rakMsg,
			PublicKey: agentPubkey,
			SrcAddr: &common.NetAddress{
				Ip:   ppd.ConnData.RemoteAddr.IP.String(),
				Port: ppd.ConnData.RemoteAddr.Port,
			},
		}

		rakMsg, err = handler.RegisterAgent(regReq, s.NewNhpServerHelper(ppd))
		if err != nil {
			log.Error("server-agent(%s#%d@%s)[HandleRegisterRequest] error: %v", regMsg.UserId, transactionId, addrStr, err)
			return
		}

		log.Info("server-agent(%s#%d@%s)[HandleRegisterRequest] succeeded", regMsg.UserId, transactionId, addrStr)
	}()

	// send NHP_RAK message
	rakBytes, _ := json.Marshal(rakMsg)
	rakMd := &core.MsgData{
		HeaderType:     core.NHP_RAK,
		TransactionId:  transactionId,
		Compress:       true,
		PrevParserData: ppd,
		Message:        rakBytes,
	}

	// forward to a specific transaction
	transaction := ppd.ConnData.FindRemoteTransaction(transactionId)
	if transaction == nil {
		log.Error("server-agent(%s#%d@%s)[HandleRegisterRequest] transaction is not available", regMsg.UserId, transactionId, addrStr)
		err = common.ErrTransactionIdNotFound
		return err
	}

	transaction.NextMsgCh <- rakMd

	return err
}

// HandleListRequest
// Server will respond with success or error with NHP_LRT message
func (s *UdpServer) HandleListRequest(ppd *core.PacketParserData) (err error) {
	defer s.wg.Done()
	s.wg.Add(1)

	transactionId := ppd.SenderTrxId
	addrStr := ppd.ConnData.RemoteAddr.String()
	lstMsg := &common.AgentListMsg{}
	lrtMsg := &common.ServerListResultMsg{}

	func() {
		err = json.Unmarshal(ppd.BodyMessage, lstMsg)
		if err != nil {
			log.Error("server-agent(#%d@%s)[HandleListRequest] failed to parse %s message: %v", transactionId, addrStr, core.HeaderTypeToString(ppd.HeaderType), err)
			lrtMsg.ErrCode = common.ErrJsonParseFailed.ErrorCode()
			lrtMsg.ErrMsg = err.Error()
			return
		}

		handler := s.FindPluginHandler(lstMsg.AuthServiceId)
		if handler == nil {
			err = common.ErrAuthHandlerNotFound
			lrtMsg.ErrCode = common.ErrAuthHandlerNotFound.ErrorCode()
			lrtMsg.ErrMsg = err.Error()
			return
		}

		agentPubkey := base64.StdEncoding.EncodeToString(ppd.RemotePubKey)
		listReq := &common.NhpListRequest{
			Msg:       lstMsg,
			Ack:       lrtMsg,
			PublicKey: agentPubkey,
			SrcAddr: &common.NetAddress{
				Ip:   ppd.ConnData.RemoteAddr.IP.String(),
				Port: ppd.ConnData.RemoteAddr.Port,
			},
		}

		lrtMsg, err = handler.ListService(listReq, s.NewNhpServerHelper(ppd))
		if err != nil {
			log.Error("server-agent(%s#%d@%s)[HandleListRequest] error: %v", lstMsg.UserId, transactionId, addrStr, err)
			return
		}

		log.Info("server-agent(%s#%d@%s)[HandleListRequest] succeeded", lstMsg.UserId, transactionId, addrStr)
	}()

	lrtBytes, _ := json.Marshal(lrtMsg)
	ackMd := &core.MsgData{
		HeaderType:     core.NHP_LRT,
		TransactionId:  transactionId,
		Compress:       true,
		PrevParserData: ppd,
		Message:        lrtBytes,
	}

	// forward to a specific transaction
	transaction := ppd.ConnData.FindRemoteTransaction(transactionId)
	if transaction == nil {
		log.Error("server-agent(%s#%d@%s)[HandleListRequest] transaction is not available", lstMsg.UserId, transactionId, addrStr)
		err = common.ErrTransactionIdNotFound
		return err
	}

	transaction.NextMsgCh <- ackMd

	return err
}

func (s *UdpServer) HandleACOnline(ppd *core.PacketParserData) (err error) {
	defer s.wg.Done()
	s.wg.Add(1)

	transactionId := ppd.SenderTrxId
	addrStr := ppd.ConnData.RemoteAddr.String()
	aolMsg := &common.ACOnlineMsg{}

	err = json.Unmarshal(ppd.BodyMessage, aolMsg)
	if err != nil {
		log.Error("server-ac(#%d@%s)[HandleACOnline] failed to parse %s message: %v", transactionId, addrStr, core.HeaderTypeToString(ppd.HeaderType), err)
		return err
	}

	acId := aolMsg.ACId

	// Check if AC should be redirected to its assigned servers (per-AC server assignment).
	// This only applies when storage is configured and AC provides a license key.
	// See docs/design/PLUGGABLE_STORAGE_BACKEND.md section 6.2 for details.
	if s.storage != nil && aolMsg.LicenseKey != "" {
		redirected, ardErr := s.handleACServerAssignment(ppd, aolMsg, transactionId, addrStr)
		if ardErr != nil {
			log.Error("server-ac(%s#%d@%s)[HandleACOnline] server assignment lookup error: %v", acId, transactionId, addrStr, ardErr)
			// Fall through to direct registration on error
		} else if redirected {
			// AC was redirected via NHP_ARD to its assigned servers
			return nil
		}
		// This server is assigned to handle this AC, continue with registration
	}

	// Register AC connection and send NHP_AAK
	acPubkeyBase64 := base64.StdEncoding.EncodeToString(ppd.RemotePubKey)
	s.acPeerMapMutex.Lock()
	acPeer := s.acPeerMap[acPubkeyBase64] // recvAddr updated by responder.go (unless cloud mode, see below)
	s.acPeerMapMutex.Unlock()

	// In cloud mode (storage_backend=dynamodb), AC peers are not pre-registered.
	// We need to validate the AC via license check and create the peer dynamically.
	// See docs/design/PLUGGABLE_STORAGE_BACKEND.md Section 6.2 for details.
	cloudMode := s.storageConfig != nil && s.storageConfig.Backend == "dynamodb"
	if acPeer == nil && cloudMode {
		// Validate AC license before accepting connection
		validationErr := s.validateACLicense(ppd, aolMsg, transactionId, addrStr)
		if validationErr != nil {
			// Send error response
			aakMsg := &common.ServerACAckMsg{
				ErrCode: validationErr.ErrorCode(),
				ErrMsg:  validationErr.Error(),
			}
			aakBytes, _ := json.Marshal(aakMsg)
			aakMd := &core.MsgData{
				HeaderType:     core.NHP_AAK,
				TransactionId:  transactionId,
				Compress:       true,
				PrevParserData: ppd,
				Message:        aakBytes,
			}
			if transaction := ppd.ConnData.FindRemoteTransaction(transactionId); transaction != nil {
				transaction.NextMsgCh <- aakMd
			}
			return validationErr
		}

		// License valid - create peer from packet data and add to peer pool
		acPeer = &core.UdpPeer{
			Hostname:     acId,
			Ip:           ppd.ConnData.RemoteAddr.IP.String(),
			Port:         ppd.ConnData.RemoteAddr.Port,
			PubKeyBase64: acPubkeyBase64,
			ExpireTime:   0, // No expiration - managed via keepalives
			Type:         core.NHP_AC,
		}
		// Initialize recvAddr from the current packet. Normally this is done by
		// responder.go during packet validation, but in cloud mode peer validation
		// is disabled (DisableACPeerValidation=true) so we must do it here.
		// Without this, processACOperation fails with nil peer address.
		acPeer.UpdateRecv(ppd.LocalInitTime, ppd.ConnData.RemoteAddr)
		s.AddACPeer(acPeer)
		log.Info("server-ac(%s#%d@%s)[HandleACOnline] Cloud mode: created AC peer after license validation", acId, transactionId, addrStr)
	}

	acConn := &ACConn{
		ConnData:       ppd.ConnData,
		ACPeer:         acPeer,
		ACCipherScheme: ppd.CipherScheme,
		ACId:           acId,
		ServiceId:      aolMsg.AuthServiceId,
		Apps:           aolMsg.ResourceIds,
	}

	s.acConnectionMapMutex.Lock()
	s.acConnectionMap[acId] = acConn
	s.acConnectionMapMutex.Unlock()

	// Include server's direct address so AC can establish direct connection.
	// When AC connects through NLB, the AC's connected UDP socket only accepts
	// packets from the NLB IP. By providing the server's direct address, the AC
	// can create a new connection directly to the server for subsequent traffic.
	serverAddr := fmt.Sprintf("%s:%d", s.localIp, s.listenAddr.Port)

	aakMsg := &common.ServerACAckMsg{
		ErrCode:      common.ErrSuccess.ErrorCode(),
		ACAddr:       ppd.ConnData.RemoteAddr.String(),
		Registered:   true, // This server is handling the AC
		ServerAddr:   serverAddr,
		ServerPubKey: s.device.PublicKeyBase64(),
	}
	aakBytes, _ := json.Marshal(aakMsg)

	aakMd := &core.MsgData{
		HeaderType:     core.NHP_AAK,
		TransactionId:  transactionId,
		Compress:       true,
		PrevParserData: ppd,
		Message:        aakBytes,
	}

	// forward to a specific transaction
	transaction := ppd.ConnData.FindRemoteTransaction(transactionId)
	if transaction == nil {
		log.Error("server-ac(@%s#%d@%s)[HandleACOnline] transaction is not available", acId, transactionId, addrStr)
		err = common.ErrTransactionIdNotFound
		return err
	}

	transaction.NextMsgCh <- aakMd

	return nil
}

// handleACServerAssignment checks if the AC should be redirected to its assigned servers.
// Returns (true, nil) if AC was redirected via NHP_ARD.
// Returns (false, nil) if this server should handle the AC (or AC not found in storage).
// Returns (false, error) on storage error.
//
// IMPORTANT: Before redirecting, this function filters assignments to only include
// servers that are currently healthy according to Cloud Map. This prevents ACs from
// being redirected to terminated servers (stale assignments).
// See docs/ARCHITECTURE.md "Stale DynamoDB Assignment Resilience" for details.
func (s *UdpServer) handleACServerAssignment(
	ppd *core.PacketParserData,
	aolMsg *common.ACOnlineMsg,
	transactionId uint64,
	addrStr string,
) (redirected bool, err error) {
	acId := aolMsg.ACId
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Look up AC assignment from storage
	assignment, err := s.storage.GetACAssignment(ctx, acId)
	if err != nil {
		if IsNotFoundError(err) {
			// AC not found in storage - accept connection directly (no assignment exists yet)
			log.Info("server-ac(%s#%d@%s)[HandleACOnline] AC not found in storage, accepting directly", acId, transactionId, addrStr)
			return false, nil
		}
		log.Error("server-ac(%s#%d@%s)[HandleACOnline] storage error looking up AC assignment: %v", acId, transactionId, addrStr, err)
		return false, err
	}

	// Filter assignment to only healthy servers (via Cloud Map health discovery).
	// This prevents redirecting ACs to terminated servers (stale assignments).
	// If Cloud Map is unavailable, all servers are considered healthy (fail-open).
	// Note: Use a separate context for Cloud Map to avoid timeout cascading from DynamoDB.
	cloudMapCtx, cloudMapCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cloudMapCancel()
	healthyServers := FilterHealthyServers(cloudMapCtx, s.cloudMap, assignment.AssignedServers)
	if len(healthyServers) == 0 {
		// All assigned servers are unhealthy - accept AC directly rather than
		// redirecting to dead servers. This breaks the failure loop.
		log.Warning("server-ac(%s#%d@%s)[HandleACOnline] all %d assigned servers unhealthy, accepting directly",
			acId, transactionId, addrStr, len(assignment.AssignedServers))
		return false, nil
	}
	if len(healthyServers) < len(assignment.AssignedServers) {
		log.Info("server-ac(%s#%d@%s)[HandleACOnline] filtered to %d/%d healthy servers",
			acId, transactionId, addrStr, len(healthyServers), len(assignment.AssignedServers))
	}

	// Check if this server is assigned to the AC (using filtered healthy servers)
	serverID := s.config.Hostname // Use hostname as server identifier
	isAssigned := false
	for _, srv := range healthyServers {
		if srv.ID == serverID {
			isAssigned = true
			break
		}
	}

	if isAssigned {
		log.Info("server-ac(%s#%d@%s)[HandleACOnline] this server (%s) is assigned to AC", acId, transactionId, addrStr, serverID)
		return false, nil
	}

	// Not assigned - send NHP_ARD to redirect AC to healthy assigned servers
	log.Info("server-ac(%s#%d@%s)[HandleACOnline] redirecting AC to %d healthy assigned servers", acId, transactionId, addrStr, len(healthyServers))

	targets := make([]common.RedirectTarget, len(healthyServers))
	for i, srv := range healthyServers {
		targets[i] = common.RedirectTarget{
			IP:           srv.IP,
			Port:         srv.Port,
			PubKeyBase64: srv.PubKey,
			AZ:           srv.AZ,
			ServerID:     srv.ID,
		}
	}

	ardMsg := &common.ACRedispatchMsg{
		Targets: targets,
		ErrCode: common.ErrSuccess.ErrorCode(),
	}
	ardBytes, _ := json.Marshal(ardMsg)

	ardMd := &core.MsgData{
		HeaderType:     core.NHP_ARD,
		TransactionId:  transactionId,
		Compress:       true,
		PrevParserData: ppd,
		Message:        ardBytes,
	}

	// Forward to the transaction
	transaction := ppd.ConnData.FindRemoteTransaction(transactionId)
	if transaction == nil {
		log.Error("server-ac(%s#%d@%s)[HandleACOnline] transaction not found for NHP_ARD", acId, transactionId, addrStr)
		return false, common.ErrTransactionIdNotFound
	}

	transaction.NextMsgCh <- ardMd
	return true, nil
}

// dummyBcryptHash is used for constant-time license validation to prevent timing attacks.
// When a license is not found, we still perform a bcrypt comparison against this dummy
// hash to ensure the response time is similar regardless of whether the license exists.
// This prevents attackers from enumerating valid license keys based on response timing.
// Format: $2a$10$ (7 chars) + 22 char salt + 31 char hash = 60 chars total
var dummyBcryptHash = []byte("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")

// licenseKeyPrefix returns the first 8 hex chars of the SHA256 hash of a license key.
// This provides enough context for log correlation without exposing the full key.
func licenseKeyPrefix(licenseKey string) string {
	hash := sha256.Sum256([]byte(licenseKey))
	return hex.EncodeToString(hash[:4]) // First 4 bytes = 8 hex chars
}

// validateACLicense validates AC credentials against DynamoDB in cloud mode.
// Returns nil if validation succeeds, or an error if validation fails.
// See docs/design/PLUGGABLE_STORAGE_BACKEND.md Section 6.2 for the validation flow.
//
// Security: This function uses constant-time comparison to prevent timing attacks.
// The bcrypt comparison is ALWAYS performed (with real or dummy hash) BEFORE any
// fast checks (active, expired) to ensure uniform response time for all cases.
// This prevents attackers from distinguishing between different failure modes.
func (s *UdpServer) validateACLicense(
	ppd *core.PacketParserData,
	aolMsg *common.ACOnlineMsg,
	transactionId uint64,
	addrStr string,
) *common.Error {
	acId := aolMsg.ACId

	// Check if license key is provided - required in cloud mode
	// This fast check is OK since missing key is an obvious client error, not useful for enumeration
	if aolMsg.LicenseKey == "" {
		log.Warning("server-ac(%s#%d@%s)[validateACLicense] missing license key",
			acId, transactionId, addrStr)
		return common.ErrServerACOpsFailed
	}

	// Compute key prefix for log correlation (first 8 hex chars of SHA256)
	// This helps operators debug without exposing full license keys
	keyPrefix := licenseKeyPrefix(aolMsg.LicenseKey)

	// Look up license from storage using license key SHA256 as the partition key
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	license, err := s.storage.GetLicense(ctx, aolMsg.LicenseKey)

	// TIMING ATTACK PROTECTION: Always perform bcrypt comparison before any fast checks.
	// This ensures uniform response time regardless of license existence or validity.
	// The bcrypt operation (~100ms) dominates response time, hiding fast checks.
	var bcryptErr error
	if err != nil || license == nil || license.LicenseKeyHash == "" {
		// Use dummy hash when license not found or has no hash
		bcryptErr = bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(aolMsg.LicenseKey))
	} else {
		// Use real hash when license exists
		bcryptErr = bcrypt.CompareHashAndPassword([]byte(license.LicenseKeyHash), []byte(aolMsg.LicenseKey))
	}

	// Now perform fast checks AFTER the timing-sensitive bcrypt operation
	// Storage error or not found
	if err != nil {
		if IsNotFoundError(err) {
			log.Warning("server-ac(%s#%d@%s)[validateACLicense] license not found (key=%s...)",
				acId, transactionId, addrStr, keyPrefix)
		} else {
			log.Error("server-ac(%s#%d@%s)[validateACLicense] storage error (key=%s...): %v",
				acId, transactionId, addrStr, keyPrefix, err)
		}
		return common.ErrServerACOpsFailed
	}

	// License record exists but has no hash (misconfiguration)
	if license.LicenseKeyHash == "" {
		log.Error("server-ac(%s#%d@%s)[validateACLicense] license record has no key hash (key=%s..., misconfiguration)",
			acId, transactionId, addrStr, keyPrefix)
		return common.ErrServerACOpsFailed
	}

	// Check if license is active
	if !license.Active {
		log.Warning("server-ac(%s#%d@%s)[validateACLicense] license inactive (key=%s...)",
			acId, transactionId, addrStr, keyPrefix)
		return common.ErrServerACOpsFailed
	}

	// Check if license is expired
	if license.ExpiresAt > 0 && time.Now().Unix() > license.ExpiresAt {
		log.Warning("server-ac(%s#%d@%s)[validateACLicense] license expired (key=%s..., at %d)",
			acId, transactionId, addrStr, keyPrefix, license.ExpiresAt)
		return common.ErrServerACOpsFailed
	}

	// bcrypt validation result (computed earlier for constant-time)
	if bcryptErr != nil {
		log.Warning("server-ac(%s#%d@%s)[validateACLicense] license key mismatch (key=%s...)",
			acId, transactionId, addrStr, keyPrefix)
		return common.ErrServerACOpsFailed
	}

	log.Info("server-ac(%s#%d@%s)[validateACLicense] license validated (key=%s...), tier=%s, customer=%s",
		acId, transactionId, addrStr, keyPrefix, license.Tier, license.CustomerID)
	return nil
}

func (s *UdpServer) HandleDBOnline(ppd *core.PacketParserData) (err error) {
	defer s.wg.Done()
	s.wg.Add(1)

	transactionId := ppd.SenderTrxId
	addrStr := ppd.ConnData.RemoteAddr.String()
	dolMsg := &common.DBOnlineMsg{}

	err = json.Unmarshal(ppd.BodyMessage, dolMsg)
	if err != nil {
		log.Error("server-db(#%d@%s)[HandleDBOnline] failed to parse %s message: %v", transactionId, addrStr, core.HeaderTypeToString(ppd.HeaderType), err)
		return err
	}

	dbId := dolMsg.DBId
	dbPubkeyBase64 := base64.StdEncoding.EncodeToString(ppd.RemotePubKey)
	s.dbPeerMapMutex.Lock()
	dbPeer := s.dbPeerMap[dbPubkeyBase64] // ac peer's recvAddr has already been updated by nhp packet parser
	s.dbPeerMapMutex.Unlock()

	dbConn := &DBConn{
		ConnData:       ppd.ConnData,
		DBPeer:         dbPeer,
		DBCipherScheme: ppd.CipherScheme,
		DBId:           dbId,
	}

	s.dbConnectionMapMutex.Lock()
	s.dbConnectionMap[dbId] = dbConn
	s.dbConnectionMapMutex.Unlock()

	aakMsg := &common.ServerDBAckMsg{
		ErrCode: common.ErrSuccess.ErrorCode(),
		DBAddr:  ppd.ConnData.RemoteAddr.String(),
	}
	aakBytes, _ := json.Marshal(aakMsg)

	aakMd := &core.MsgData{
		HeaderType:     core.NHP_DBA,
		TransactionId:  transactionId,
		Compress:       true,
		PrevParserData: ppd,
		Message:        aakBytes,
	}

	// forward to a specific transaction
	transaction := ppd.ConnData.FindRemoteTransaction(transactionId)
	if transaction == nil {
		log.Error("server-db(@%s#%d@%s)[HandleDBOnline] transaction is not available", dbId, transactionId, addrStr)
		err = common.ErrTransactionIdNotFound
		return err
	}

	transaction.NextMsgCh <- aakMd

	return nil
}

func (s *UdpServer) HandleDHPDARMessage(ppd *core.PacketParserData) (err error) {
	defer s.wg.Done()
	s.wg.Add(1)

	transactionId := ppd.SenderTrxId
	addrStr := ppd.ConnData.RemoteAddr.String()
	darMsg := &common.DARMsg{}

	err = json.Unmarshal(ppd.BodyMessage, darMsg)
	if err != nil {
		log.Error("server-agent(#%d@%s)[HandleDHPDARMessage] failed to parse %s message: %v", transactionId, addrStr, core.HeaderTypeToString(ppd.HeaderType), err)
		return err
	}

	doId := darMsg.DoId
	config, err := ReadZdtoConfig(doId)
	dsaMsg := &common.DSAMsg{}
	if err != nil {
		dsaMsg.DoId = doId
		dsaMsg.ErrCode = 1
		dsaMsg.ErrMsg = err.Error()
	} else {
		dsaMsg.DoId = doId
		dsaMsg.SpoId = config.Spo.PolicyId
		dsaMsg.Spo = &config.Spo
		dsaMsg.TTL = int((30 * time.Minute).Milliseconds())
		s.UpdateTeePublicKeyAndConsumerEphemeralPublicKey(darMsg.TeePublicKey, darMsg.ConsumerEphemeralPublicKey, ppd.RemotePubKey)
	}

	aakBytes, _ := json.Marshal(dsaMsg)
	log.Debug("dagMsg:%s", (string)(aakBytes))
	aakMd := &core.MsgData{
		HeaderType:     core.NHP_DSA,
		TransactionId:  transactionId,
		Compress:       true,
		PrevParserData: ppd,
		Message:        aakBytes,
	}
	// forward to a specific transaction
	transaction := ppd.ConnData.FindRemoteTransaction(transactionId)
	if transaction == nil {
		log.Error("server-agent(@%s#%d@%s)[HandleDHPDARMessage] transaction is not available", doId, transactionId, addrStr)
		err = common.ErrTransactionIdNotFound
		return err
	}

	transaction.NextMsgCh <- aakMd

	return nil
}

func (s *UdpServer) HandleDHPDAVMessage(ppd *core.PacketParserData) (err error) {
	defer s.wg.Done()
	s.wg.Add(1)

	transactionId := ppd.SenderTrxId
	addrStr := ppd.ConnData.RemoteAddr.String()
	davMsg := &common.DAVMsg{}

	err = json.Unmarshal(ppd.BodyMessage, davMsg)
	if err != nil {
		log.Error("server-agent(#%d@%s)[HandleDHPDAVMessage] failed to parse %s message: %v", transactionId, addrStr, core.HeaderTypeToString(ppd.HeaderType), err)
		return err
	}

	doId := davMsg.DoId
	config, err := ReadZdtoConfig(doId)

	if err := s.onAttestationVerify(&config.Spo, davMsg.Evidence); err != nil {
		log.Error("server-agent(#%d@%s)[HandleDHPDAVMessage] failed to verify attesation: %s with error: %s", transactionId, addrStr, davMsg.Evidence, err.Error())
		return err
	}

	dagMsg := &common.DAGMsg{}
	if err != nil {
		dagMsg.DoId = doId
		dagMsg.ErrCode = 1
		dagMsg.ErrMsg = err.Error()
	} else {
		dagMsg.DoId = doId

		teePublicKey, consumerEphemeralPublicKey := s.GetTeePublicKeyBase64AndConsumerEphemeralPublicKeyBase64(ppd.RemotePubKey)

		dwrMsg := &common.DWRMsg{
			DoId:                       doId,
			TeePublicKey:               teePublicKey,
			ConsumerEphemeralPublicKey: consumerEphemeralPublicKey,
		}

		dbConn, found := s.dbConnectionMap[config.DbId]
		if !found {
			log.Critical("dbConn not found for dbId:%s", config.DbId)
			err = common.ErrDBOffline
			dagMsg.ErrCode = 1
			dagMsg.ErrMsg = err.Error()
		} else {
			dwaMsg, err := s.ProcessDataPrivateKeyWrapping(dwrMsg, dbConn)
			if err != nil || dwaMsg.ErrCode != 0 {
				dagMsg.ErrCode = dwaMsg.ErrCode
				dagMsg.ErrMsg = dwaMsg.ErrMsg
			}

			dagMsg.Kao = dwaMsg.Kao
			dagMsg.Spo = &config.Spo
			dagMsg.DataSourceType = config.DataSourceType
			dagMsg.AccessUrl = config.AccessUrl
			dagMsg.AccessByNHP = config.AccessByNHP
			dagMsg.DoType = config.DoType
		}
	}

	aakBytes, _ := json.Marshal(dagMsg)
	log.Debug("dagMsg:%s", (string)(aakBytes))
	aakMd := &core.MsgData{
		HeaderType:     core.NHP_DAG,
		TransactionId:  transactionId,
		Compress:       true,
		PrevParserData: ppd,
		Message:        aakBytes,
	}
	// forward to a specific transaction
	transaction := ppd.ConnData.FindRemoteTransaction(transactionId)
	if transaction == nil {
		log.Error("server-agent(@%s#%d@%s)[HandleDHPDARMessage] transaction is not available", doId, transactionId, addrStr)
		err = common.ErrTransactionIdNotFound
		return err
	}

	transaction.NextMsgCh <- aakMd

	return nil
}

// HandleDHPDRGMessage
func (s *UdpServer) HandleDHPDRGMessage(ppd *core.PacketParserData) (err error) {
	defer s.wg.Done()
	s.wg.Add(1)

	transactionId := ppd.SenderTrxId
	addrStr := ppd.ConnData.RemoteAddr.String()
	aolMsg := &common.DRGMsg{}

	err = json.Unmarshal(ppd.BodyMessage, aolMsg)
	if err != nil {
		log.Error("server-Device(#%d@%s)[HandleDHPDRGMessage] failed to parse %s message: %v", transactionId, addrStr, core.HeaderTypeToString(ppd.HeaderType), err)
		return err
	}

	doId := aolMsg.DoId

	err = SaveZdtoConfig(aolMsg)

	errCode := 0 //success
	errMsg := ""

	if err != nil {
		errCode = 1
		errMsg = err.Error()
	}

	aakMsg := &common.DAKMsg{
		DoId:    doId,
		ErrCode: errCode,
		ErrMsg:  errMsg,
	}
	aakBytes, _ := json.Marshal(aakMsg)

	aakMd := &core.MsgData{
		HeaderType:     core.NHP_DAK,
		TransactionId:  transactionId,
		Compress:       true,
		PrevParserData: ppd,
		Message:        aakBytes,
	}

	// forward to a specific transaction

	transaction := ppd.ConnData.FindRemoteTransaction(transactionId)
	if transaction == nil {
		log.Error("server-DB(@%s#%d@%s)[HandleDHPDRGMessage] transaction is not available", doId, transactionId, addrStr)
		err = common.ErrTransactionIdNotFound
		return err
	}
	transaction.NextMsgCh <- aakMd
	return nil
}

func (s *UdpServer) onAttestationVerify(spo *common.SmartPolicy, attestation string) error {
	if spo.Policy == "" {
		return nil
	}

	wasmBytes, err := base64.StdEncoding.DecodeString(spo.Policy)
	if err != nil {
		wasmPath, err := utils.DownloadFileToTemp(spo.Policy, "wasm-")
		defer os.Remove(filepath.Dir(wasmPath))
		defer os.Remove(wasmPath)
		if err != nil {
			return err
		}
		wasmBytes, err = os.ReadFile(wasmPath)
		if err != nil {
			return err
		}
	}

	engine := wasmEngine.NewEngine()
	err = engine.LoadWasm(wasmBytes)
	defer engine.Close()
	if err != nil {
		return err
	}

	if engine.OnAttestationVerify(attestation) {
		return nil
	} else {
		return fmt.Errorf("attestation verification failed")
	}
}

func SaveZdtoConfig(drgMsg *common.DRGMsg) error {
	objectId := drgMsg.DoId
	configFileName := "data-" + objectId + ".json"

	etcDir := filepath.Join(ExeDirPath, "etc", "ztdo")
	configPath := filepath.Join(etcDir, configFileName)

	if existingDrgMsg, err := ReadZdtoConfig(objectId); err == nil {
		// alway keep original date source type
		drgMsg.DataSourceType = existingDrgMsg.DataSourceType

		if drgMsg.AccessUrl == "" { // provider update access url
			drgMsg.AccessUrl = existingDrgMsg.AccessUrl
		}

		os.Remove(configPath)
	}

	// Make sure the etc directory exists
	if err := os.MkdirAll(etcDir, 0755); err != nil {
		return fmt.Errorf("failed to create etc directory: %v", err)
	}

	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("%v already exists, please delete it first", configFileName)
	}

	file, err := os.Create(configPath)
	if err != nil {
		return fmt.Errorf("failed to create config.json: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(drgMsg)
}

// read data-<doId>.json to DRGMsg Object
func ReadZdtoConfig(doId string) (common.DRGMsg, error) {
	etcDir := filepath.Join(ExeDirPath, "etc", "ztdo")
	configFilePath := filepath.Join(etcDir, "data-"+doId+".json")
	file, err := os.Open(configFilePath)
	if err != nil {
		return common.DRGMsg{}, fmt.Errorf("could not open file: %v", err)
	}
	defer file.Close()

	fileContentByte, err := io.ReadAll(file)
	if err != nil {
		return common.DRGMsg{}, fmt.Errorf("error reading file: %v", err)
	}

	var config common.DRGMsg

	err = json.Unmarshal(fileContentByte, &config)
	if err != nil {
		return common.DRGMsg{}, fmt.Errorf("json parsing error: %s", err)
	}
	return config, nil
}
