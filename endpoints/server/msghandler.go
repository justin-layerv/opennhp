package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"golang.org/x/crypto/bcrypt"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	wasmEngine "github.com/OpenNHP/opennhp/nhp/core/wasm/engine"
	"github.com/OpenNHP/opennhp/nhp/log"
	utils "github.com/OpenNHP/opennhp/nhp/utils"
)

const (
	// MaxServersPerAssignment is the maximum number of servers assigned to a single AC.
	MaxServersPerAssignment = 3

	// AssignmentTTLSeconds is the TTL for AC assignments (30 minutes).
	AssignmentTTLSeconds int64 = 1800

	// DefaultStorageTimeout is the default timeout for storage and Cloud Map operations.
	DefaultStorageTimeout = 5 * time.Second

	// DefaultForwardTimeout is the timeout for the full HTTP knock forward chain
	// (DynamoDB lookup + Cloud Map health check + up to 3 HTTP round-trips at 2s each).
	DefaultForwardTimeout = 10 * time.Second

	// DefaultStaleACConnThreshold is the default duration after which an AC
	// connection is considered dead for broadcast purposes. Set to the same
	// window the AC itself uses to decide a server is down: KeepaliveInterval
	// (10s) × KeepaliveMaxRetries (3) = 30s (see endpoints/ac/registration.go).
	// Past that point the AC will have entered its own re-registration path,
	// so NHP-AOP sent on a connection silent this long will sit until the
	// server-side transaction timeout — wasting the broadcast budget on a
	// peer that will not ACK. recvPacketRoutine updates
	// ConnectionData.LastLocalRecvTime on every inbound packet (including
	// keepalives), so a live connection stays fresh without extra work.
	//
	// Override per-server via Config.StaleACConnThresholdSeconds; the floor
	// MinStaleACConnThreshold (5s) is enforced on the resolved value to
	// prevent a misconfiguration from filtering every connection on every
	// knock.
	DefaultStaleACConnThreshold = 30 * time.Second

	// MinStaleACConnThreshold is the floor enforced when resolving the
	// effective threshold from Config.StaleACConnThresholdSeconds. A value
	// below this would filter out connections that haven't quite finished
	// their first keepalive cycle (KeepaliveInterval = 10s on the AC side).
	MinStaleACConnThreshold = 5 * time.Second

	// TTLRefreshMinInterval is the minimum time between TTL refreshes for the same AC.
	// Prevents excessive DynamoDB writes from frequent AC re-registrations.
	TTLRefreshMinInterval = 5 * time.Minute
)

// Metric counter names for CloudWatch. Using constants prevents typos
// and enables discoverability across the codebase.
const (
	MetricKnockRequest              = "KnockRequest"
	MetricKnockLatency              = "KnockLatency"
	MetricAuthSuccess               = "AuthSuccess"
	MetricAuthFailure               = "AuthFailure"
	MetricAutoAssignment            = "AutoAssignment"
	MetricKnockForwardSuccess       = "KnockForwardSuccess"
	MetricKnockForwardFailure       = "KnockForwardFailure"
	MetricKnockForwardSkippedDead   = "KnockForwardSkippedDead"
	MetricKnockForwardFallback      = "KnockForwardFallback"
	MetricCloudMapDeregisterFailure = "CloudMapDeregisterFailure"
	MetricKnockNoAC                 = "KnockNoAC"
	MetricACPeerCount               = "ACPeerCount"
	// MetricACGraceAbsorbed increments once per /health/knock-ready probe
	// where ACPeerChecker returned pass from the grace-window branch
	// (live count was zero but the last-non-zero timestamp was inside
	// ACPeerGracePeriodSeconds). A rising rate means the debounce is
	// doing real work (single-keepalive flickers) rather than hiding
	// sustained AC-side degradation. Pair with KnockNoAC to distinguish:
	//   - GraceAbsorbed up AND KnockNoAC flat → debounce is absorbing
	//     transients as designed; rollout is healthy.
	//   - GraceAbsorbed up AND KnockNoAC up   → AC cluster is actually
	//     broken and the grace window is masking it; page oncall.
	MetricACGraceAbsorbed              = "ACGraceAbsorbed"
	MetricACRegistrationSuccess        = "ACRegistrationSuccess"
	MetricACRegistrationFailure        = "ACRegistrationFailure"
	MetricACRegistrationLatency        = "ACRegistrationLatency"
	MetricBroadcastPartialFail         = "BroadcastPartialFail"
	MetricBroadcastDurationMs          = "BroadcastDurationMs"
	MetricLicenseValidationRateLimited = "LicenseValidationRateLimited"
	MetricASGFilterFailOpen            = "ASGFilterFailOpen"

	// MetricTransactionClosed counts every SendMessage / SendPacket
	// call that returns common.ErrTransactionClosed because the
	// RemoteTransaction exited between FindRemoteTransaction and the
	// channel send. Post PR #1096 this is the observable rate of the
	// race that used to panic the server; a sudden spike is a
	// regression signal worth alarming on.
	MetricTransactionClosed = "TransactionClosed"

	// MetricServerStartupEvent fires once per server process start,
	// emitted via CloudWatch Embedded Metric Format (EMF). The Go
	// server writes a JSON line to stdout at startup; docker's
	// awslogs driver ships it to the nhp-server stderr log group,
	// and CloudWatch auto-extracts the metric into LayerV/NHP.
	//
	// Emitted in two dim-set variants (see recordServerStartup):
	// a per-instance series (Environment/Cell/InstanceId, used by
	// dashboards and ad-hoc investigation) and a fleet-wide series
	// (Environment/Cell, drives the server_instance_restart alarm
	// via a classic Sum-over-5min threshold).
	MetricServerStartupEvent = "ServerStartupEvent"
)

// Multi-AC broadcast observability metric names (issue #376).
const (
	MetricBroadcastTotal       = "BroadcastTotal"       // total broadcast invocations
	MetricBroadcastSuccess     = "BroadcastSuccess"     // at least one AC succeeded
	MetricBroadcastAllFail     = "BroadcastAllFail"     // every AC in the broadcast failed
	MetricBroadcastACLatencyMs = "BroadcastACLatencyMs" // per-AC operation duration within a broadcast
	MetricACConnsPerID         = "ACConnsPerID"         // gauge: max AC connections across all AC IDs
	MetricTotalACConns         = "TotalACConns"         // gauge: total AC connections across all AC IDs
	MetricACConnEviction       = "ACConnEviction"       // MaxACConnsPerID eviction events

	// MetricACConnStaleFiltered counts AC connections skipped by the
	// broadcast-time staleness filter (DefaultStaleACConnThreshold or its
	// per-server override). A non-zero rate is expected during AC
	// reconnects (blue/green switch, EC2 refresh, NAT rebind); a sustained
	// rate against a healthy AC means the server is not clearing stale
	// entries on disconnect. Emitted once per call site per knock with the
	// dropped count (not once per dropped connection), so a single
	// broadcast filtering three stale entries adds 3.
	//
	// Operator guidance:
	//   - Burst spikes during deploys/refresh: expected, no action.
	//   - Sustained > N/min against a single AC ID for > 5 minutes outside
	//     a deploy window: investigate. The AC has likely rotated keys or
	//     IPs without a clean disconnect; check AC logs for recent
	//     re-registration events and CloudMap deregister history.
	//   - Threshold for an alarm depends on knock volume; suggest starting
	//     with "rate > 60/min sustained for 10 min" once a baseline exists.
	MetricACConnStaleFiltered = "ACConnStaleFiltered"
)

// udpCorrelationCtx creates a context with a correlation ID derived from UDP handler
// metadata (e.g. AC ID and NHP transaction ID). This enables storage log lines to be
// correlated with specific NHP transactions instead of showing req_id=-.
func udpCorrelationCtx(timeout time.Duration, id string, transactionId uint64) (context.Context, context.CancelFunc) {
	correlationID := fmt.Sprintf("udp-%s-%d", id, transactionId)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	return ContextWithRequestID(ctx, correlationID), cancel
}

// recordTransactionClosed increments MetricTransactionClosed iff err is
// the transaction-closed race (not ErrTransactionIdNotFound and not a
// random transport error). Single helper so every forward site that
// calls a Send*() helper emits the same counter under the same
// condition — callers never have to remember the errors.Is check.
func (s *UdpServer) recordTransactionClosed(err error) {
	if err != nil && s.metrics != nil && errors.Is(err, common.ErrTransactionClosed) {
		s.metrics.IncrCounter(MetricTransactionClosed)
	}
}

// recordServerStartup emits MetricServerStartupEvent as two EMF counter
// events: one with the InstanceId dim set (per-instance series, used
// by dashboards and ad-hoc incident investigation) and one without
// (fleet-wide series, drives the server_instance_restart alarm in
// terraform/modules/monitoring).
//
// Both fire from the publisher's EMF output (docker-captured stdout);
// CloudWatch auto-extracts them into LayerV/NHP. Called once per
// process start from Start() before plugin loading / listener setup
// so init crashes still register.
//
// The fleet-wide series is what the alarm consumes because AWS
// CloudWatch metric alarms reject the SEARCH expression ("SEARCH is
// not supported on Metric Alarms"), so a per-InstanceId metric_math
// alarm is not possible. ASG churn also rules out enumerating
// InstanceIds in TF. Fleet-wide sum + threshold tuned to fleet size
// is the only tractable form; per-instance resolution is available
// from the other series for investigation only.
//
// No-ops when s.instanceID is empty (IMDS unreachable at boot) or
// when the publisher is unavailable (non-cloud local testing). The
// log-filter panic alarm still covers Go runtime panics that bypass
// this path -- those can't EMF-emit because the process is already
// dying.
func (s *UdpServer) recordServerStartup() {
	if s.instanceID == "" || s.metrics == nil {
		return
	}
	s.metrics.EmitEMFCounterNow(MetricServerStartupEvent, []types.Dimension{
		{Name: dimNameInstanceId, Value: aws.String(s.instanceID)},
	})
	s.metrics.EmitEMFCounterNow(MetricServerStartupEvent, nil)
}

// forwardToTransaction finds the remote transaction and forwards the message to it.
// Returns common.ErrTransactionIdNotFound if the transaction is not available,
// or common.ErrTransactionClosed if the transaction exited between lookup and
// delivery.
//
// Log format follows the codebase convention: component(id#txn@addr)[handler] message
func (s *UdpServer) forwardToTransaction(connData *core.ConnectionData, transactionId uint64, md *core.MsgData, component, handler, id, addrStr string) error {
	transaction := connData.FindRemoteTransaction(transactionId)
	if transaction == nil {
		log.Error("%s(%s#%d@%s)[%s] transaction is not available", component, id, transactionId, addrStr, handler)
		return common.ErrTransactionIdNotFound
	}
	if err := transaction.SendMessage(md); err != nil {
		log.Error("%s(%s#%d@%s)[%s] transaction closed before message could be forwarded: %v", component, id, transactionId, addrStr, handler, err)
		s.recordTransactionClosed(err)
		return err
	}
	return nil
}

// makeMsgData creates a MsgData for sending a response back through the
// same connection that delivered the request.
func makeMsgData(ppd *core.PacketParserData, headerType int, msg []byte) *core.MsgData {
	return &core.MsgData{
		HeaderType:     headerType,
		TransactionId:  ppd.SenderTrxId,
		Compress:       true,
		PrevParserData: ppd,
		Message:        msg,
	}
}

// HandleOTPRequest
// Server will not respond to agent's otp request
func (s *UdpServer) HandleOTPRequest(ppd *core.PacketParserData) (err error) {
	s.wg.Add(1)
	defer s.wg.Done()

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
	s.wg.Add(1)
	defer s.wg.Done()

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
	rakBytes, marshalErr := json.Marshal(rakMsg)
	if marshalErr != nil {
		log.Error("server-agent(%s#%d@%s)[HandleRegisterRequest] failed to marshal RAK message: %v", regMsg.UserId, transactionId, addrStr, marshalErr)
		return marshalErr
	}
	rakMd := makeMsgData(ppd, core.NHP_RAK, rakBytes)

	if fwdErr := s.forwardToTransaction(ppd.ConnData, transactionId, rakMd, "server-agent", "HandleRegisterRequest", regMsg.UserId, addrStr); fwdErr != nil {
		return fwdErr
	}
	return err
}

// HandleListRequest
// Server will respond with success or error with NHP_LRT message
func (s *UdpServer) HandleListRequest(ppd *core.PacketParserData) (err error) {
	s.wg.Add(1)
	defer s.wg.Done()

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

	lrtBytes, marshalErr := json.Marshal(lrtMsg)
	if marshalErr != nil {
		log.Error("server-agent(%s#%d@%s)[HandleListRequest] failed to marshal LRT message: %v", lstMsg.UserId, transactionId, addrStr, marshalErr)
		return marshalErr
	}
	ackMd := makeMsgData(ppd, core.NHP_LRT, lrtBytes)

	if fwdErr := s.forwardToTransaction(ppd.ConnData, transactionId, ackMd, "server-agent", "HandleListRequest", lstMsg.UserId, addrStr); fwdErr != nil {
		return fwdErr
	}
	return err
}

func (s *UdpServer) HandleACOnline(ppd *core.PacketParserData) (err error) {
	s.wg.Add(1)
	defer s.wg.Done()

	regStart := time.Now()
	transactionId := ppd.SenderTrxId
	addrStr := ppd.ConnData.RemoteAddr.String()
	aolMsg := &common.ACOnlineMsg{}

	err = json.Unmarshal(ppd.BodyMessage, aolMsg)
	if err != nil {
		log.Error("server-ac(#%d@%s)[HandleACOnline] failed to parse %s message: %v", transactionId, addrStr, core.HeaderTypeToString(ppd.HeaderType), err)
		s.metrics.IncrCounter(MetricACRegistrationFailure)
		return err
	}

	acId := aolMsg.ACId

	// Check if AC should be redirected to its assigned servers (per-AC server assignment).
	// This only applies when storage is configured and AC provides a license key.
	// See docs/design/PLUGGABLE_STORAGE_BACKEND.md section 6.2 for details.
	var assignedPeers []common.RedirectTarget
	if s.storage != nil && aolMsg.LicenseKey != "" {
		redirected, peers, ardErr := s.handleACServerAssignment(ppd, aolMsg, transactionId, addrStr)
		if ardErr != nil {
			log.Error("server-ac(%s#%d@%s)[HandleACOnline] server assignment lookup error: %v", acId, transactionId, addrStr, ardErr)
			// Fall through to direct registration on error
		} else if redirected {
			// AC was redirected via NHP_ARD to its assigned servers
			return nil
		} else {
			assignedPeers = peers
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
	cloudMode := s.storageConfig != nil && s.storageConfig.Backend == StorageBackendDynamoDB
	if acPeer == nil && cloudMode {
		// Validate AC license before accepting connection
		validationErr := s.validateACLicense(ppd, aolMsg, transactionId, addrStr)
		if validationErr != nil {
			// Send error response
			aakMsg := &common.ServerACAckMsg{
				ErrCode: validationErr.ErrorCode(),
				ErrMsg:  validationErr.Error(),
			}
			aakBytes, marshalErr := json.Marshal(aakMsg)
			if marshalErr != nil {
				log.Error("server-ac(%s#%d@%s)[HandleACOnline] failed to marshal AAK error message: %v", acId, transactionId, addrStr, marshalErr)
				s.metrics.IncrCounter(MetricACRegistrationFailure)
				return validationErr
			}
			aakMd := makeMsgData(ppd, core.NHP_AAK, aakBytes)
			if transaction := ppd.ConnData.FindRemoteTransaction(transactionId); transaction != nil {
				// Best-effort: license validation has already failed, so we
				// return validationErr regardless of whether the AAK delivers.
				// A SendMessage failure here means the transaction exited
				// before we could send the error response (e.g., timeout);
				// the AC will observe the transaction timeout and retry.
				if sendErr := transaction.SendMessage(aakMd); sendErr != nil {
					log.Error("server-ac(%s#%d@%s)[HandleACOnline] failed to forward license-validation AAK: %v", acId, transactionId, addrStr, sendErr)
					s.recordTransactionClosed(sendErr)
				}
			}
			s.metrics.IncrCounter(MetricACRegistrationFailure)
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
	} else if acPeer != nil {
		// Existing peer found - update its receive address to handle re-registration
		// from a different source port (e.g., after socket recreation).
		// In non-cloud mode, responder.go updates this, but in cloud mode with an
		// existing peer, we must update it here to ensure processACOperation uses
		// the correct address.
		oldRecvAddr := acPeer.RecvAddr()
		acPeer.UpdateRecv(ppd.LocalInitTime, ppd.ConnData.RemoteAddr)
		if oldRecvAddr != nil && oldRecvAddr.String() != ppd.ConnData.RemoteAddr.String() {
			log.Info("server-ac(%s#%d@%s)[HandleACOnline] Updated peer recvAddr from %s",
				acId, transactionId, addrStr, oldRecvAddr.String())
		}
	}

	acConn := &ACConn{
		ConnData:       ppd.ConnData,
		ACPeer:         acPeer,
		ACCipherScheme: ppd.CipherScheme,
		ACId:           acId,
		ServiceId:      aolMsg.AuthServiceId,
		Apps:           aolMsg.ResourceIds,
	}

	// Register the AC connection, supporting multiple ACs with the same AC ID (blue/green).
	// If the same IP re-registers (e.g., socket recreation), update in-place.
	// If a new IP registers, append (different AC instance with same AC ID).
	s.acConnectionMapMutex.Lock()
	existingConns := s.acConnectionMap[acId]

	updated := false
	var staleConn *ACConn
	for i, existing := range existingConns {
		if existing.ConnData.RemoteAddr.IP.Equal(ppd.ConnData.RemoteAddr.IP) {
			// Same IP, possibly different port → re-registration (e.g., socket recreation)
			oldAddr := existing.ConnData.RemoteAddr.String()
			newAddr := ppd.ConnData.RemoteAddr.String()
			if oldAddr != newAddr {
				staleConn = existing
				log.Info("server-ac(%s#%d@%s)[HandleACOnline] Updating connection from %s (same IP, new port)",
					acId, transactionId, addrStr, oldAddr)
			}
			existingConns[i] = acConn
			updated = true
			break
		}
	}

	if !updated {
		// New IP → different AC instance with same AC ID (blue/green)
		log.Info("server-ac(%s#%d@%s)[HandleACOnline] New AC instance registered (total: %d)",
			acId, transactionId, addrStr, len(existingConns)+1)
		if len(existingConns) >= MaxACConnsPerID {
			staleConn = existingConns[0]
			existingConns = existingConns[1:]
			s.metrics.IncrCounter(MetricACConnEviction)
			log.Warning("server-ac(%s)[HandleACOnline] Max connections per AC ID reached (%d), evicting oldest",
				acId, MaxACConnsPerID)
		}
		existingConns = append(existingConns, acConn)
	}

	s.acConnectionMap[acId] = existingConns
	s.acConnectionMapMutex.Unlock()

	// Clean up stale connection outside the lock (if any)
	if staleConn != nil {
		oldAddrStr := staleConn.ConnData.RemoteAddr.String()
		s.remoteConnectionMapMutex.Lock()
		if oldUdpConn, found := s.remoteConnectionMap[oldAddrStr]; found {
			delete(s.remoteConnectionMap, oldAddrStr)
			log.Debug("server-ac(%s)[HandleACOnline] Removed stale UdpConn from remoteConnectionMap: %s",
				acId, oldAddrStr)
			go oldUdpConn.Close()
		}
		s.remoteConnectionMapMutex.Unlock()
	}

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
		Peers:        assignedPeers, // All assigned servers so AC connects to each one
	}
	aakBytes, marshalErr := json.Marshal(aakMsg)
	if marshalErr != nil {
		log.Error("server-ac(%s#%d@%s)[HandleACOnline] failed to marshal AAK message: %v", acId, transactionId, addrStr, marshalErr)
		s.metrics.IncrCounter(MetricACRegistrationFailure)
		return marshalErr
	}
	aakMd := makeMsgData(ppd, core.NHP_AAK, aakBytes)

	// Emit server-side AC registration metrics (issue #239).
	// Counted here because the server's registration work (validation,
	// assignment, peer list) is complete. If forwardToTransaction fails
	// to deliver the AAK, the AC will re-register via its retry loop;
	// the AC-side metrics capture that perspective independently.
	s.metrics.IncrCounter(MetricACRegistrationSuccess)
	s.metrics.RecordLatency(MetricACRegistrationLatency, float64(time.Since(regStart).Milliseconds()))

	return s.forwardToTransaction(ppd.ConnData, transactionId, aakMd, "server-ac", "HandleACOnline", acId, addrStr)
}

// handleACServerAssignment checks if the AC should be redirected to its assigned servers.
// Returns (true, nil, nil) if AC was redirected via NHP_ARD.
// Returns (false, peers, nil) if this server should handle the AC. peers contains
// all assigned servers so the caller can include them in the NHP_AAK response.
// Returns (false, nil, error) on storage error.
//
// When an AC has no assignment in storage, this function auto-assigns the AC to
// healthy servers discovered via Cloud Map, writes the assignment to storage,
// and sends NHP_ARD so the AC connects to all assigned servers.
func (s *UdpServer) handleACServerAssignment(
	ppd *core.PacketParserData,
	aolMsg *common.ACOnlineMsg,
	transactionId uint64,
	addrStr string,
) (redirected bool, peers []common.RedirectTarget, err error) {
	acId := aolMsg.ACId
	ctx, cancel := udpCorrelationCtx(DefaultStorageTimeout, acId, transactionId)
	defer cancel()

	// Look up AC assignment from storage
	assignment, err := s.storage.GetACAssignment(ctx, acId)
	if err != nil {
		if IsNotFoundError(err) {
			// AC not found in storage — perform auto-assignment
			log.Info("server-ac(%s#%d@%s)[HandleACOnline] AC not in storage, auto-assigning", acId, transactionId, addrStr)
			redirected, autoErr := s.autoAssignAC(ppd, aolMsg, transactionId, addrStr, 0)
			return redirected, nil, autoErr
		}
		log.Error("server-ac(%s#%d@%s)[HandleACOnline] storage error looking up AC assignment: %v", acId, transactionId, addrStr, err)
		return false, nil, err
	}

	// Check TTL expiry (DynamoDB TTL deletion is async — expired items may still exist)
	if assignment.TTL != nil && *assignment.TTL < time.Now().Unix() {
		log.Info("server-ac(%s#%d@%s)[HandleACOnline] assignment expired (TTL=%d), re-assigning", acId, transactionId, addrStr, *assignment.TTL)
		redirected, autoErr := s.autoAssignAC(ppd, aolMsg, transactionId, addrStr, assignment.Version)
		return redirected, nil, autoErr
	}

	// Filter assignment to only healthy servers (via Cloud Map health discovery).
	cloudMapCtx, cloudMapCancel := udpCorrelationCtx(DefaultStorageTimeout, acId, transactionId)
	defer cloudMapCancel()
	healthyServers := FilterHealthyServers(cloudMapCtx, s.cloudMap, assignment.AssignedServers)
	if len(healthyServers) == 0 {
		// All assigned servers are unhealthy — re-assign with fresh servers
		log.Warning("server-ac(%s#%d@%s)[HandleACOnline] all %d assigned servers unhealthy, re-assigning",
			acId, transactionId, addrStr, len(assignment.AssignedServers))
		redirected, autoErr := s.autoAssignAC(ppd, aolMsg, transactionId, addrStr, assignment.Version)
		return redirected, nil, autoErr
	}

	// Determine this server's identity
	serverID := s.getServerID()
	isAssigned := false
	for _, srv := range healthyServers {
		if srv.ID == serverID {
			isAssigned = true
			break
		}
	}

	if isAssigned {
		// This server is assigned — refresh TTL and accept directly.
		// Return the full list of assigned servers (including this one) so the
		// caller can include them in the NHP_AAK response. The AC will connect
		// to all of its assigned servers (typically 3, one per AZ). Without this,
		// only the first AC (which triggers auto-assignment and receives NHP_ARD)
		// connects to all its assigned servers; subsequent ACs only connect
		// to the one server the NLB routed them to, breaking knock fan-out.
		// Note: the responding server is included in the list. HandleRedispatch
		// will attempt to connect to it at its direct IP (not the NLB VIP), which
		// is harmless — the old NLB peer is removed after the new connections succeed.
		s.refreshAssignmentTTL(acId)
		log.Info("server-ac(%s#%d@%s)[HandleACOnline] this server (%s) is assigned to AC, returning %d peers",
			acId, transactionId, addrStr, serverID, len(healthyServers))
		return false, serverInfosToRedirectTargets(healthyServers, s.device.PublicKeyBase64()), nil
	}

	// This server is NOT in the assignment but the AC connected here.
	// Update assignment: add self, keep existing healthy ones (up to 3 total).
	// This rebuilds redundancy when assigned servers die and AC reconnects to a new server.
	log.Info("server-ac(%s#%d@%s)[HandleACOnline] this server (%s) not assigned, updating assignment", acId, transactionId, addrStr, serverID)
	updated := s.updateAssignmentWithSelf(assignment, healthyServers)
	if updated != nil {
		if ardErr := s.sendARD(ppd, acId, transactionId, addrStr, updated); ardErr != nil {
			log.Warning("server-ac(%s#%d@%s)[HandleACOnline] failed to send ARD after assignment update: %v", acId, transactionId, addrStr, ardErr)
		}
	} else {
		// Fallback: just redirect to existing healthy servers
		if ardErr := s.sendARD(ppd, acId, transactionId, addrStr, healthyServers); ardErr != nil {
			log.Warning("server-ac(%s#%d@%s)[HandleACOnline] failed to send ARD: %v", acId, transactionId, addrStr, ardErr)
		}
	}

	// Accept the AC locally since we added ourselves to the assignment
	return false, nil, nil
}

// autoAssignAC discovers healthy servers, picks up to 3 across AZs, writes the
// assignment to storage, and sends NHP_ARD so the AC connects to all assigned servers.
// existingVersion is the version of any existing assignment in storage (0 for new).
// When replacing an expired or stale assignment, pass its version so the conditional
// write uses the correct expected version instead of attribute_not_exists.
// Returns (false, nil) to let this server also handle the AC directly.
func (s *UdpServer) autoAssignAC(
	ppd *core.PacketParserData,
	aolMsg *common.ACOnlineMsg,
	transactionId uint64,
	addrStr string,
	existingVersion int,
) (bool, error) {
	acId := aolMsg.ACId

	// Cloud Map required for auto-assignment
	if s.cloudMap == nil {
		log.Info("server-ac(%s#%d@%s)[autoAssignAC] no Cloud Map client, accepting directly", acId, transactionId, addrStr)
		return false, nil
	}

	cloudMapCtx, cloudMapCancel := udpCorrelationCtx(DefaultStorageTimeout, acId, transactionId)
	defer cloudMapCancel()

	allServers, err := s.cloudMap.DiscoverServerInstances(cloudMapCtx)
	if err != nil {
		log.Warning("server-ac(%s#%d@%s)[autoAssignAC] Cloud Map discovery failed: %v, accepting directly", acId, transactionId, addrStr, err)
		return false, nil
	}

	if len(allServers) == 0 {
		log.Warning("server-ac(%s#%d@%s)[autoAssignAC] no servers in Cloud Map, accepting directly", acId, transactionId, addrStr)
		return false, nil
	}

	// Filter to same-ASG servers to prevent blue/green cross-color assignment.
	// Must happen before selectServersForAssignment but after DiscoverServerInstances
	// because the CloudMap cache is also used by HTTP forwarding where cross-color
	// forwarding is legitimate during transitions.
	var asgFailOpen bool
	allServers, asgFailOpen = filterServersByASG(allServers, s.asgName)
	if asgFailOpen && s.metrics != nil {
		s.metrics.IncrCounter(MetricASGFilterFailOpen)
	}

	// Select up to 3 servers with AZ distribution, ensuring this server is included
	selected := s.selectServersForAssignment(allServers, MaxServersPerAssignment)

	// Strip ASGName from selected servers before persisting — it's a server-side
	// filtering concern, not needed by ACs or in DynamoDB.
	for i := range selected {
		selected[i].ASGName = ""
	}

	// Build assignment. When replacing an existing (expired/stale) assignment,
	// use its version + 1 so the conditional write succeeds against the existing item.
	// For brand-new assignments (existingVersion == 0), Version 1 with attribute_not_exists works.
	version := existingVersion + 1
	now := time.Now().Unix()
	ttl := now + AssignmentTTLSeconds
	assignment := &ACAssignment{
		ACID:            acId,
		CustomerID:      "", // populated from license if available
		AssignedServers: selected,
		Version:         version,
		CreatedAt:       now,
		LastSeen:        now,
		TTL:             &ttl,
	}

	// Populate customer ID from license if available
	if aolMsg.LicenseKey != "" {
		licCtx, licCancel := udpCorrelationCtx(DefaultStorageTimeout, acId, transactionId)
		license, licErr := s.storage.GetLicense(licCtx, aolMsg.LicenseKey)
		licCancel()
		if licErr == nil {
			assignment.CustomerID = license.CustomerID
		}
	}

	// Write assignment to storage
	saveCtx, saveCancel := udpCorrelationCtx(DefaultStorageTimeout, acId, transactionId)
	defer saveCancel()
	if saveErr := s.storage.SaveACAssignment(saveCtx, assignment); saveErr != nil {
		log.Warning("server-ac(%s#%d@%s)[autoAssignAC] failed to save assignment: %v, accepting directly", acId, transactionId, addrStr, saveErr)
		return false, nil
	}

	log.Info("server-ac(%s#%d@%s)[autoAssignAC] assigned to %d servers (AZs: %v)",
		acId, transactionId, addrStr, len(selected), serverAZs(selected))
	s.metrics.IncrCounter(MetricAutoAssignment)

	// Send NHP_ARD with all assigned servers (including this one)
	// so the AC connects directly to each server's private IP
	if ardErr := s.sendARD(ppd, acId, transactionId, addrStr, selected); ardErr != nil {
		log.Warning("server-ac(%s#%d@%s)[autoAssignAC] failed to send ARD: %v", acId, transactionId, addrStr, ardErr)
	}

	// Return false so this server also processes the AC registration locally
	return false, nil
}

// selectServersForAssignment picks up to maxCount servers with AZ distribution.
// Ensures this server is included in the selection.
func (s *UdpServer) selectServersForAssignment(allServers []ServerInfo, maxCount int) []ServerInfo {
	selfID := s.getServerID()

	// Group servers by AZ
	byAZ := make(map[string][]ServerInfo)
	var selfServer *ServerInfo
	for i := range allServers {
		srv := &allServers[i]
		if srv.ID == selfID {
			selfServer = srv
		}
		byAZ[srv.AZ] = append(byAZ[srv.AZ], *srv)
	}

	// Collect AZ keys for deterministic round-robin
	azKeys := make([]string, 0, len(byAZ))
	for az := range byAZ {
		azKeys = append(azKeys, az)
	}
	sort.Strings(azKeys)

	selected := make([]ServerInfo, 0, maxCount)
	selectedIDs := make(map[string]bool)

	// Always include this server first
	if selfServer != nil {
		selected = append(selected, *selfServer)
		selectedIDs[selfServer.ID] = true
	}

	// Round-robin across AZs to distribute
	azIdx := make(map[string]int)
	for len(selected) < maxCount {
		added := false
		for _, az := range azKeys {
			if len(selected) >= maxCount {
				break
			}
			servers := byAZ[az]
			idx := azIdx[az]
			for idx < len(servers) {
				srv := servers[idx]
				idx++
				azIdx[az] = idx
				if !selectedIDs[srv.ID] {
					selected = append(selected, srv)
					selectedIDs[srv.ID] = true
					added = true
					break
				}
			}
		}
		if !added {
			break // No more servers available
		}
	}

	return selected
}

// getServerID returns this server's identifier for assignment matching.
// In cloud mode, uses the EC2 instance ID (populated from IMDS).
// Falls back to hostname if instance ID is not available.
func (s *UdpServer) getServerID() string {
	if s.instanceID != "" {
		return s.instanceID
	}
	return s.config.Hostname
}

// refreshAssignmentTTL extends the TTL of an AC assignment in the background.
// Throttled to at most once per TTLRefreshMinInterval per AC to prevent excessive writes.
// Tracked by s.wg to prevent data races on storage during shutdown.
func (s *UdpServer) refreshAssignmentTTL(acID string) {
	// Throttle: skip if we refreshed recently for this AC
	now := time.Now()
	if v, loaded := s.ttlRefreshTimes.LoadOrStore(acID, now); loaded {
		if now.Sub(v.(time.Time)) < TTLRefreshMinInterval {
			return
		}
		// Optimistically update to prevent concurrent goroutines from also passing the check.
		// On save failure, we delete the entry so the next call retries.
		s.ttlRefreshTimes.Store(acID, now)
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		correlationID := fmt.Sprintf("udp-ttl-refresh-%s", acID)
		getCtx, getCancel := context.WithTimeout(context.Background(), DefaultStorageTimeout)
		getCtx = ContextWithRequestID(getCtx, correlationID)
		existing, err := s.storage.GetACAssignment(getCtx, acID)
		getCancel()
		if err != nil {
			s.ttlRefreshTimes.Delete(acID) // allow retry on next call
			return
		}

		// Clone to avoid mutating the cached pointer
		ttl := time.Now().Unix() + AssignmentTTLSeconds
		refreshed := existing.Clone()
		refreshed.LastSeen = time.Now().Unix()
		refreshed.TTL = &ttl

		saveCtx, saveCancel := context.WithTimeout(context.Background(), DefaultStorageTimeout)
		saveCtx = ContextWithRequestID(saveCtx, correlationID)
		defer saveCancel()
		if err := s.storage.SaveACAssignment(saveCtx, refreshed); err != nil {
			if IsVersionConflictError(err) {
				// Another server refreshed TTL concurrently — safe to ignore
				log.Debug("TTL refresh version conflict for AC %s (concurrent update)", acID)
			} else {
				log.Debug("Failed to refresh TTL for AC %s: %v", acID, err)
				s.ttlRefreshTimes.Delete(acID) // allow retry on next call
			}
		}
	}()
}

// sendARD sends NHP_ARD to redirect the AC to the given servers.
func (s *UdpServer) sendARD(
	ppd *core.PacketParserData,
	acId string,
	transactionId uint64,
	addrStr string,
	servers []ServerInfo,
) error {
	ardMsg := &common.ACRedispatchMsg{
		Targets: serverInfosToRedirectTargets(servers, s.device.PublicKeyBase64()),
		ErrCode: common.ErrSuccess.ErrorCode(),
	}
	ardBytes, marshalErr := json.Marshal(ardMsg)
	if marshalErr != nil {
		log.Error("server-ac(%s#%d@%s)[sendARD] failed to marshal ARD message: %v", acId, transactionId, addrStr, marshalErr)
		return marshalErr
	}
	ardMd := makeMsgData(ppd, core.NHP_ARD, ardBytes)

	return s.forwardToTransaction(ppd.ConnData, transactionId, ardMd, "server-ac", "HandleACOnline/ARD", acId, addrStr)
}

// updateAssignmentWithSelf adds this server to an existing AC assignment,
// keeping existing healthy servers up to a total of MaxServersPerAssignment.
// Returns the updated server list on success, or nil on failure.
func (s *UdpServer) updateAssignmentWithSelf(assignment *ACAssignment, healthyServers []ServerInfo) []ServerInfo {
	selfID := s.getServerID()

	// Construct this server's ServerInfo from local state (no Cloud Map call needed —
	// the server knows its own identity)
	selfInfo := ServerInfo{
		ID:         selfID,
		IP:         s.localIp,
		InternalIP: s.localIp,
		AZ:         s.instanceAZ,
		Port:       s.config.ListenPort,
		PubKey:     s.device.PublicKeyBase64(),
	}

	// Build updated list: self + existing healthy (up to max total)
	updated := []ServerInfo{selfInfo}
	for _, srv := range healthyServers {
		if len(updated) >= MaxServersPerAssignment {
			break
		}
		if srv.ID != selfID {
			updated = append(updated, srv)
		}
	}

	// Clone to avoid mutating the cached pointer.
	// If Save fails, the cache retains the original unmodified assignment.
	ttl := time.Now().Unix() + AssignmentTTLSeconds
	newAssignment := assignment.Clone()
	newAssignment.AssignedServers = updated
	newAssignment.Version = assignment.Version + 1
	newAssignment.LastSeen = time.Now().Unix()
	newAssignment.TTL = &ttl

	correlationID := fmt.Sprintf("udp-assign-update-%s", assignment.ACID)
	saveCtx, saveCancel := context.WithTimeout(context.Background(), DefaultStorageTimeout)
	saveCtx = ContextWithRequestID(saveCtx, correlationID)
	defer saveCancel()
	if err := s.storage.SaveACAssignment(saveCtx, newAssignment); err != nil {
		if IsVersionConflictError(err) {
			log.Info("updateAssignmentWithSelf: version conflict for %s (concurrent update), skipping", assignment.ACID)
		} else {
			log.Warning("updateAssignmentWithSelf: failed to save updated assignment for %s: %v", assignment.ACID, err)
		}
		return nil
	}

	log.Info("updateAssignmentWithSelf: AC %s updated to %d servers (AZs: %v)", assignment.ACID, len(updated), serverAZs(updated))
	return updated
}

// serverAZs returns a list of AZs from a list of servers (for logging).
func serverAZs(servers []ServerInfo) []string {
	azs := make([]string, len(servers))
	for i, s := range servers {
		azs[i] = s.AZ
	}
	return azs
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

	// RATE LIMITING: Check if this source IP or AC ID has exceeded the failure threshold.
	// This runs BEFORE the expensive bcrypt operation to save resources under attack.
	// Rate-limited requests still return the generic error to avoid leaking information.
	if s.licenseRateLimiter != nil {
		if rlErr := s.licenseRateLimiter.CheckRateLimit(addrStr, acId); rlErr != nil {
			log.Warning("server-ac(%s#%d@%s)[validateACLicense] %s",
				acId, transactionId, addrStr, rlErr.Message)
			if s.metrics != nil {
				s.metrics.IncrCounter(MetricLicenseValidationRateLimited)
			}
			return common.ErrServerACOpsFailed
		}
	}

	// Compute key prefix for log correlation (first 8 hex chars of SHA256)
	// This helps operators debug without exposing full license keys
	keyPrefix := licenseKeyPrefix(aolMsg.LicenseKey)

	// Look up license from storage using license key SHA256 as the partition key
	ctx, cancel := udpCorrelationCtx(DefaultStorageTimeout, acId, transactionId)
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
		s.recordLicenseFailure(addrStr, acId)
		return common.ErrServerACOpsFailed
	}

	// License record exists but has no hash (misconfiguration)
	if license.LicenseKeyHash == "" {
		log.Error("server-ac(%s#%d@%s)[validateACLicense] license record has no key hash (key=%s..., misconfiguration)",
			acId, transactionId, addrStr, keyPrefix)
		s.recordLicenseFailure(addrStr, acId)
		return common.ErrServerACOpsFailed
	}

	// Check if license is active
	if !license.Active {
		log.Warning("server-ac(%s#%d@%s)[validateACLicense] license inactive (key=%s...)",
			acId, transactionId, addrStr, keyPrefix)
		s.recordLicenseFailure(addrStr, acId)
		return common.ErrServerACOpsFailed
	}

	// Check if license is expired
	if license.ExpiresAt > 0 && time.Now().Unix() > license.ExpiresAt {
		log.Warning("server-ac(%s#%d@%s)[validateACLicense] license expired (key=%s..., at %d)",
			acId, transactionId, addrStr, keyPrefix, license.ExpiresAt)
		s.recordLicenseFailure(addrStr, acId)
		return common.ErrServerACOpsFailed
	}

	// bcrypt validation result (computed earlier for constant-time)
	if bcryptErr != nil {
		log.Warning("server-ac(%s#%d@%s)[validateACLicense] license key mismatch (key=%s...)",
			acId, transactionId, addrStr, keyPrefix)
		s.recordLicenseFailure(addrStr, acId)
		return common.ErrServerACOpsFailed
	}

	log.Info("server-ac(%s#%d@%s)[validateACLicense] license validated (key=%s...), tier=%s, customer=%s",
		acId, transactionId, addrStr, keyPrefix, license.Tier, license.CustomerID)
	return nil
}

// recordLicenseFailure records a failed license validation attempt for rate limiting.
func (s *UdpServer) recordLicenseFailure(addrStr, acId string) {
	if s.licenseRateLimiter != nil {
		s.licenseRateLimiter.RecordFailure(addrStr, acId)
	}
}

func (s *UdpServer) HandleDBOnline(ppd *core.PacketParserData) (err error) {
	s.wg.Add(1)
	defer s.wg.Done()

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
	aakBytes, marshalErr := json.Marshal(aakMsg)
	if marshalErr != nil {
		log.Error("server-db(%s#%d@%s)[HandleDBOnline] failed to marshal DBA message: %v", dbId, transactionId, addrStr, marshalErr)
		return marshalErr
	}
	aakMd := makeMsgData(ppd, core.NHP_DBA, aakBytes)

	return s.forwardToTransaction(ppd.ConnData, transactionId, aakMd, "server-db", "HandleDBOnline", dbId, addrStr)
}

func (s *UdpServer) HandleDHPDARMessage(ppd *core.PacketParserData) (err error) {
	s.wg.Add(1)
	defer s.wg.Done()

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
	dsaMsg := &common.DSAMsg{DoId: doId}
	if err != nil {
		// err is either common.ErrInvalidDoID or errReadConfigFailed —
		// both fixed sentinels with no attacker-controlled bytes, so
		// echoing err.Error() on the wire is safe. The raw cause was
		// already logged at WARN / ERROR inside ReadZdtoConfig.
		log.Error("server-agent(#%d@%s)[HandleDHPDARMessage] read ztdo config for DoId=%q: %v", transactionId, addrStr, doId, err)
		dsaMsg.ErrCode = 1
		dsaMsg.ErrMsg = err.Error()
	} else {
		dsaMsg.SpoId = config.Spo.PolicyId
		dsaMsg.Spo = &config.Spo
		dsaMsg.TTL = int((30 * time.Minute).Milliseconds())
		s.UpdateTeePublicKeyAndConsumerEphemeralPublicKey(darMsg.TeePublicKey, darMsg.ConsumerEphemeralPublicKey, ppd.RemotePubKey)
	}

	aakBytes, marshalErr := json.Marshal(dsaMsg)
	if marshalErr != nil {
		log.Error("server-agent(DoId=%q,trx=#%d@%s)[HandleDHPDARMessage] failed to marshal DSA message: %v", doId, transactionId, addrStr, marshalErr)
		return marshalErr
	}
	log.Debug("dagMsg:%s", (string)(aakBytes))
	aakMd := makeMsgData(ppd, core.NHP_DSA, aakBytes)
	return s.forwardToTransaction(ppd.ConnData, transactionId, aakMd, "server-agent", "HandleDHPDARMessage", doId, addrStr)
}

func (s *UdpServer) HandleDHPDAVMessage(ppd *core.PacketParserData) (err error) {
	s.wg.Add(1)
	defer s.wg.Done()

	transactionId := ppd.SenderTrxId
	addrStr := ppd.ConnData.RemoteAddr.String()
	davMsg := &common.DAVMsg{}

	err = json.Unmarshal(ppd.BodyMessage, davMsg)
	if err != nil {
		log.Error("server-agent(#%d@%s)[HandleDHPDAVMessage] failed to parse %s message: %v", transactionId, addrStr, core.HeaderTypeToString(ppd.HeaderType), err)
		return err
	}

	doId := davMsg.DoId
	config, configErr := ReadZdtoConfig(doId)

	// dagMsg is populated below and always sent via forwardToTransaction —
	// mirror the DAR handler's pattern so a legitimate agent asking for a
	// missing / malformed DoId gets an explicit DAG error response, not a
	// hung request. Pre-PR this path had a shadowed err that silently ran
	// onAttestationVerify against a zero-value Spo; that's closed here by
	// skipping the attestation branch when configErr != nil.
	dagMsg := &common.DAGMsg{DoId: doId}
	if configErr != nil {
		// configErr is either common.ErrInvalidDoID or errReadConfigFailed —
		// both fixed sentinels, so echoing on the wire is safe. Raw cause
		// logged inside ReadZdtoConfig.
		log.Error("server-agent(#%d@%s)[HandleDHPDAVMessage] read ztdo config for DoId=%q: %v", transactionId, addrStr, doId, configErr)
		dagMsg.ErrCode = 1
		dagMsg.ErrMsg = configErr.Error()
	} else {
		if attestErr := s.onAttestationVerify(&config.Spo, davMsg.Evidence); attestErr != nil {
			log.Error("server-agent(#%d@%s)[HandleDHPDAVMessage] failed to verify attestation: %s with error: %s", transactionId, addrStr, davMsg.Evidence, attestErr.Error())
			return attestErr
		}

		teePublicKey, consumerEphemeralPublicKey := s.GetTeePublicKeyBase64AndConsumerEphemeralPublicKeyBase64(ppd.RemotePubKey)

		dwrMsg := &common.DWRMsg{
			DoId:                       doId,
			TeePublicKey:               teePublicKey,
			ConsumerEphemeralPublicKey: consumerEphemeralPublicKey,
		}

		dbConn, found := s.dbConnectionMap[config.DbId]
		if !found {
			log.Critical("dbConn not found for dbId:%q", config.DbId)
			dagMsg.ErrCode = 1
			dagMsg.ErrMsg = common.ErrDBOffline.Error()
		} else {
			dwaMsg, dwaErr := s.ProcessDataPrivateKeyWrapping(dwrMsg, dbConn)
			// ProcessDataPrivateKeyWrapping can return (nil, err) on a
			// marshal failure in its upstream chain. Derefing dwaMsg
			// below would panic the handler; handle that path first.
			// The nil branch catches any dwaMsg==nil shape — including
			// the (nil, nil) case today's implementation shouldn't produce
			// but a future refactor could, and the narrower condition
			// would otherwise fall through to the default Kao deref.
			switch {
			case dwaMsg == nil:
				// Scrub dwaErr on the wire — upstream marshal failures
				// can wrap filesystem paths or other internal detail.
				// Operator signal stays in the log.
				log.Error("server-agent(#%d@%s)[HandleDHPDAVMessage] dwaMsg nil for DoId=%q: %v", transactionId, addrStr, doId, dwaErr)
				dagMsg.ErrCode = 1
				dagMsg.ErrMsg = "data private key wrapping failed"
			case dwaErr != nil || dwaMsg.ErrCode != 0:
				// Error branch — do NOT populate success fields (Kao,
				// Spo, DataSourceType, ...). Pre-fix this block fell
				// through to the success population below, shipping
				// partial config alongside an error code.
				// Belt-and-suspenders on ErrCode: every error path in
				// ProcessDataPrivateKeyWrapping that returns non-nil
				// dwaMsg also sets ErrCode != 0; the dwaErr!=nil slot
				// is a guard against a future error path forgetting.
				// TODO(#1161): retire the else-branch once the
				// (dwaErr != nil) => (dwaMsg.ErrCode != 0) invariant
				// is codified upstream (e.g. via dwaMsg.Validate()).
				if dwaMsg.ErrCode != 0 {
					dagMsg.ErrCode = dwaMsg.ErrCode
					dagMsg.ErrMsg = dwaMsg.ErrMsg
				} else {
					log.Error("server-agent(#%d@%s)[HandleDHPDAVMessage] dwaErr with zero ErrCode for DoId=%q: %v", transactionId, addrStr, doId, dwaErr)
					dagMsg.ErrCode = 1
					dagMsg.ErrMsg = "data private key wrapping failed"
				}
			default:
				dagMsg.Kao = dwaMsg.Kao
				dagMsg.Spo = &config.Spo
				dagMsg.DataSourceType = config.DataSourceType
				dagMsg.AccessUrl = config.AccessUrl
				dagMsg.AccessByNHP = config.AccessByNHP
				dagMsg.DoType = config.DoType
			}
		}
	}

	aakBytes, marshalErr := json.Marshal(dagMsg)
	if marshalErr != nil {
		log.Error("server-agent(DoId=%q,trx=#%d@%s)[HandleDHPDAVMessage] failed to marshal DAG message: %v", doId, transactionId, addrStr, marshalErr)
		return marshalErr
	}
	log.Debug("dagMsg:%s", (string)(aakBytes))
	aakMd := makeMsgData(ppd, core.NHP_DAG, aakBytes)
	return s.forwardToTransaction(ppd.ConnData, transactionId, aakMd, "server-agent", "HandleDHPDAVMessage", doId, addrStr)
}

// HandleDHPDRGMessage
func (s *UdpServer) HandleDHPDRGMessage(ppd *core.PacketParserData) (err error) {
	s.wg.Add(1)
	defer s.wg.Done()

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
		// err is either common.ErrInvalidDoID or errSaveConfigFailed —
		// both fixed sentinels, echoing on the wire is safe. Raw cause
		// already logged inside SaveZdtoConfig.
		log.Error("server-db(#%d@%s)[HandleDHPDRGMessage] save ztdo config for DoId=%q: %v", transactionId, addrStr, doId, err)
		errCode = 1
		errMsg = err.Error()
	}

	aakMsg := &common.DAKMsg{
		DoId:    doId,
		ErrCode: errCode,
		ErrMsg:  errMsg,
	}
	aakBytes, marshalErr := json.Marshal(aakMsg)
	if marshalErr != nil {
		log.Error("server-db(DoId=%q,trx=#%d@%s)[HandleDHPDRGMessage] failed to marshal DAK message: %v", doId, transactionId, addrStr, marshalErr)
		return marshalErr
	}
	aakMd := makeMsgData(ppd, core.NHP_DAK, aakBytes)

	return s.forwardToTransaction(ppd.ConnData, transactionId, aakMd, "server-db", "HandleDHPDRGMessage", doId, addrStr)
}

func (s *UdpServer) onAttestationVerify(spo *common.SmartPolicy, attestation string) error {
	if spo.Policy == "" {
		return nil
	}

	wasmBytes, err := base64.StdEncoding.DecodeString(spo.Policy)
	if err != nil {
		wasmPath, err := utils.DownloadFileToTemp(spo.Policy, "wasm-")
		if err != nil {
			return err
		}
		defer func() { _ = os.Remove(filepath.Dir(wasmPath)) }() // LIFO: runs second, removes empty dir
		defer func() { _ = os.Remove(wasmPath) }()               // LIFO: runs first, removes file
		wasmBytes, err = os.ReadFile(wasmPath)
		if err != nil {
			return err
		}
	}

	engine := wasmEngine.NewEngine()
	defer engine.Close()
	if err = engine.LoadWasm(wasmBytes); err != nil {
		return err
	}

	if engine.OnAttestationVerify(attestation) {
		return nil
	}
	return errors.New("attestation verification failed")
}

// errReadConfigFailed / errSaveConfigFailed are fixed sentinels returned
// from ReadZdtoConfig / SaveZdtoConfig when a non-validation error fires
// (os.Open / os.MkdirAll / utils.SaveStructAsJsonFile all wrap
// *PathError with the full filesystem path, which would leak ExeDirPath
// if echoed on the wire). The raw underlying error goes to the server
// log; callers echo these sentinels to the wire without further scrub.
// Kept unexported — only in-package callers (HandleDHPDRGMessage /
// HandleDHPDAVMessage) distinguish invalid-input vs. read vs. save, and
// they do so by the call site, not errors.Is. Promote to nhp/common
// alongside ErrInvalidDoID if a cross-package caller ever needs the
// classification.
var (
	errReadConfigFailed = errors.New("ztdo config read failed")
	errSaveConfigFailed = errors.New("ztdo config save failed")
)

func SaveZdtoConfig(drgMsg *common.DRGMsg) error {
	objectId := drgMsg.DoId
	if err := common.ValidateDoID(objectId); err != nil {
		// Intrusion-detection signal: post-auth malformed DoId is either
		// an agent bug or an attack attempt. Log %q of the raw value for
		// operator triage; the sentinel returned to the caller carries
		// none of the attacker bytes.
		log.Warning("server[SaveZdtoConfig] rejected DoId=%q: %v", objectId, err)
		return err
	}
	configFileName := "data-" + objectId + ".json"

	etcDir := filepath.Join(ExeDirPath, "etc", "ztdo")
	configPath := filepath.Join(etcDir, configFileName)

	if existingDrgMsg, err := ReadZdtoConfig(objectId); err == nil {
		// alway keep original date source type
		drgMsg.DataSourceType = existingDrgMsg.DataSourceType

		if drgMsg.AccessUrl == "" { // provider update access url
			drgMsg.AccessUrl = existingDrgMsg.AccessUrl
		}

		_ = os.Remove(configPath)
	}

	// All non-validation errors below wrap *PathError with the full
	// filesystem path. Log raw with DoId context for triage, return the
	// scrubbed sentinel on the wire.
	if err := os.MkdirAll(etcDir, 0755); err != nil {
		log.Error("server[SaveZdtoConfig] DoId=%q mkdir: %v", objectId, err)
		return errSaveConfigFailed
	}

	if _, err := os.Stat(configPath); err == nil {
		log.Error("server[SaveZdtoConfig] DoId=%q already exists at %s", objectId, configPath)
		return errSaveConfigFailed
	}

	if err := utils.SaveStructAsJsonFile(configPath, drgMsg); err != nil {
		log.Error("server[SaveZdtoConfig] DoId=%q write: %v", objectId, err)
		return errSaveConfigFailed
	}
	return nil
}

// ReadZdtoConfig reads data-<doId>.json into a DRGMsg. Validates doId
// before touching the filesystem and scrubs filesystem-path errors
// before returning — callers may echo the returned error on the wire
// without leaking ExeDirPath.
func ReadZdtoConfig(doId string) (common.DRGMsg, error) {
	if err := common.ValidateDoID(doId); err != nil {
		log.Warning("server[ReadZdtoConfig] rejected DoId=%q: %v", doId, err)
		return common.DRGMsg{}, err
	}
	etcDir := filepath.Join(ExeDirPath, "etc", "ztdo")
	configFilePath := filepath.Join(etcDir, "data-"+doId+".json")
	file, err := os.Open(configFilePath)
	if err != nil {
		// os.ErrNotExist is the normal happy-path result on a first save —
		// SaveZdtoConfig probes via ReadZdtoConfig to decide whether to
		// carry forward the prior DataSourceType. Logging those at ERROR
		// polluted the server error log with "no such file" on every new
		// DoId and made real read failures harder to triage. Demote the
		// not-exist case to DEBUG; keep everything else at ERROR since
		// those are genuine failures (permission denied, partial FS, etc).
		if errors.Is(err, fs.ErrNotExist) {
			log.Debug("server[ReadZdtoConfig] DoId=%q not found: %v", doId, err)
		} else {
			log.Error("server[ReadZdtoConfig] DoId=%q open: %v", doId, err)
		}
		return common.DRGMsg{}, errReadConfigFailed
	}
	defer func() { _ = file.Close() }()

	fileContentByte, err := io.ReadAll(file)
	if err != nil {
		log.Error("server[ReadZdtoConfig] DoId=%q read: %v", doId, err)
		return common.DRGMsg{}, errReadConfigFailed
	}

	var config common.DRGMsg

	if err := json.Unmarshal(fileContentByte, &config); err != nil {
		log.Error("server[ReadZdtoConfig] DoId=%q unmarshal: %v", doId, err)
		return common.DRGMsg{}, errReadConfigFailed
	}
	return config, nil
}
