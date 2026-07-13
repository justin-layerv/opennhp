package core

import (
	"encoding/base64"
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/OpenNHP/opennhp/nhp/log"
)

type DeviceTypeEnum = int

const (
	NHP_NO_DEVICE = iota
	NHP_AGENT
	NHP_SERVER
	NHP_AC
	NHP_RELAY
	NHP_DB
	DHP_AGENT
)

type DeviceOptions struct {
	DisableAgentPeerValidation  bool
	DisableServerPeerValidation bool
	DisableACPeerValidation     bool
	DisableRelayPeerValidation  bool
	DisableDePeerValidation     bool
}

// ReceiveQueueDrop identifies the bounded inbound stage that shed work. The
// values are stable metric labels for endpoint-owned telemetry.
type ReceiveQueueDrop string

const (
	ReceiveQueueDropDecrypt   ReceiveQueueDrop = "decrypt_queue"
	ReceiveQueueDropDecrypted ReceiveQueueDrop = "decrypted_queue"
)

type NhpError interface {
	Error() string
	ErrorCode() string
	ErrorNumber() int
}

func defaultDeviceOptions(t int) (option DeviceOptions) {
	switch t {
	case NHP_AGENT:
	case NHP_SERVER:
	case NHP_DB:
	case NHP_AC:
		// NHP_AC does not validate, nor store any agent peer. Related message: NHP-ACC (agent-ac pre-access)
		option.DisableAgentPeerValidation = true
	case NHP_RELAY:
	}

	return option
}

type Device struct {
	optionMutex sync.Mutex
	option      DeviceOptions

	counterIndex uint64
	deviceType   int
	staticEcdh   Ecdh

	peerMapMutex sync.Mutex
	peerMap      map[string]Peer

	localTransactionMutex sync.Mutex
	localTransactionMap   map[uint64]*LocalTransaction

	pool     *PacketBufferPool
	Overload atomic.Bool

	// cookieSigningKey enables stateless overload cookies for servers. A
	// cluster that shares this key can validate an agent's RKN on any sibling
	// instance without relying on per-connection CookieStore state.
	cookieSigningMu         sync.RWMutex
	cookieSigningKey        []byte
	cookieTimeWindowSec     int64
	cookieSigningConfigured atomic.Bool

	wg      sync.WaitGroup
	signals struct {
		stop chan struct{}
	}

	DecryptedMsgQueue chan *PacketParserData
	packetToMsgQueue  chan *PacketData
	msgToPacketQueue  chan *MsgData

	// recvReplayDedupeFn, when non-nil, is invoked by
	// packetToMsgRoutine immediately after validatePeer succeeds and
	// BEFORE body decryption, for every inbound packet that clears the
	// per-connection replay/flood/stale gates. Returning a non-nil
	// error drops the packet through the same error-delivery path a
	// validatePeer failure takes (so a matched transaction sees the
	// error on its response channel, an unmatched packet is silently
	// destroyed).
	//
	// It is the cross-connection replay-dedupe chokepoint. A
	// transaction REQUEST (e.g. NHP_AOP on the AC) is consumed in one
	// endpoint handler, so the AC dedupes there directly. A transaction
	// RESPONSE (NHP_ART on the server) is forked by
	// transaction-correlation BEFORE decryption — matched responses go
	// to the waiting transaction, unmatched ones to the generic queue —
	// so no single endpoint-side hook observes every response. This is
	// that single point, the one place every ART (matched originals and
	// unmatched replays alike) is recorded so a replay is recognized.
	// The endpoint owns the cache, the metric, and the message-type
	// scoping; core only provides the call site. See
	// endpoints/server/art_replay_cache.go (#1457) for the production
	// consumer.
	//
	// Concurrency: set once via SetRecvReplayDedupe BEFORE Start spawns
	// the packetToMsgRoutine workers; the `go` in Start establishes the
	// happens-before, so the lock-free read in packetToMsgRoutine is
	// safe. A future caller needing live reconfiguration must promote
	// this to an atomic.Pointer.
	recvReplayDedupeFn func(*PacketParserData) error

	// cookieMintFailureFn, when non-nil, is invoked when a server rejects a
	// knock under overload but cannot enqueue the COK challenge it intended to
	// send. Core owns the fail-closed decision; endpoints own the metric.
	//
	// Concurrency: set once via SetCookieMintFailureHook BEFORE Start spawns
	// workers, matching recvReplayDedupeFn's happens-before contract.
	cookieMintFailureFn func(reason string)

	// receiveQueueDropFn reports bounded inbound queue sheds to the owning
	// endpoint. Set once before Start; core remains metrics-backend agnostic.
	receiveQueueDropFn func(ReceiveQueueDrop)
}

func NewDevice(t int, prk []byte, option *DeviceOptions) *Device {
	d := &Device{
		deviceType: t,
	}

	if option != nil {
		d.option = *option
	} else {
		d.option = defaultDeviceOptions(t)
	}

	var err error
	d.staticEcdh, err = ECDHFromKey(ECC_CURVE25519, prk)
	if err != nil {
		log.Critical("Failed to set private key: %v", err)
		return nil
	}

	d.pool = &PacketBufferPool{}
	d.pool.Init(PacketBufferPoolSize)

	d.peerMap = make(map[string]Peer)
	d.localTransactionMap = make(map[uint64]*LocalTransaction)

	d.DecryptedMsgQueue = make(chan *PacketParserData, RecvQueueSize)
	d.msgToPacketQueue = make(chan *MsgData, SendQueueSize)
	d.packetToMsgQueue = make(chan *PacketData, RecvQueueSize)
	d.signals.stop = make(chan struct{})

	return d
}

func (d *Device) SetOption(option DeviceOptions) {
	d.optionMutex.Lock()
	defer d.optionMutex.Unlock()

	d.option = option
}

// Option returns the current device options under the same mutex
// SetOption writes. Used by callers that need to inspect the live
// runtime state (e.g., tests asserting that a hot-reload override
// landed) without racing the writer.
func (d *Device) Option() DeviceOptions {
	d.optionMutex.Lock()
	defer d.optionMutex.Unlock()

	return d.option
}

// SetRecvReplayDedupe installs the post-validation replay-dedupe hook
// invoked by packetToMsgRoutine. Call it before Start — see the
// recvReplayDedupeFn field doc for the happens-before contract and why
// this chokepoint exists. Devices that do not dedupe (agent, db, AC)
// leave it unset.
func (d *Device) SetRecvReplayDedupe(fn func(*PacketParserData) error) {
	d.recvReplayDedupeFn = fn
}

// SetCookieMintFailureHook installs the observability hook invoked when a
// server intended to return a COK but could not mint or marshal one. Call it
// before Start; devices that do not care about this signal leave it unset.
func (d *Device) SetCookieMintFailureHook(fn func(reason string)) {
	d.cookieMintFailureFn = fn
}

// SetReceiveQueueDropHook installs endpoint-owned telemetry for inbound queue
// sheds. Call before Start, matching the other lock-free lifecycle hooks.
func (d *Device) SetReceiveQueueDropHook(fn func(ReceiveQueueDrop)) {
	d.receiveQueueDropFn = fn
}

// ReceiveQueueDepths returns observational snapshots of bounded inbound queue
// occupancy. Callers must not use these values for admission decisions.
func (d *Device) ReceiveQueueDepths() (decrypt, decrypted int) {
	if d == nil {
		return 0, 0
	}
	return len(d.packetToMsgQueue), len(d.DecryptedMsgQueue)
}

func (d *Device) recordReceiveQueueDrop(reason ReceiveQueueDrop) {
	if d != nil && d.receiveQueueDropFn != nil {
		d.receiveQueueDropFn(reason)
	}
}

func (d *Device) recordCookieMintFailure(reason string) {
	if d == nil || d.cookieMintFailureFn == nil {
		return
	}
	d.cookieMintFailureFn(reason)
}

// SetStatelessCookieParams installs the signing key and rolling window used by
// server overload cookies. Empty keys or non-positive windows disable the
// stateless path; callers may still use legacy per-connection CookieStore state.
func (d *Device) SetStatelessCookieParams(key []byte, windowSec int) {
	d.cookieSigningMu.Lock()
	defer d.cookieSigningMu.Unlock()

	if len(key) == 0 || windowSec <= 0 {
		if d.cookieSigningKey != nil {
			SetZero(d.cookieSigningKey)
		}
		d.cookieSigningKey = nil
		d.cookieTimeWindowSec = 0
		d.cookieSigningConfigured.Store(false)
		return
	}
	if d.cookieSigningKey != nil {
		SetZero(d.cookieSigningKey)
	}
	d.cookieSigningKey = append([]byte(nil), key...)
	d.cookieTimeWindowSec = int64(windowSec)
	d.cookieSigningConfigured.Store(true)
}

// StatelessCookieParams returns an independent copy of the configured signing
// key and its window. A nil key with a zero window means stateless cookies are
// disabled on this device.
func (d *Device) StatelessCookieParams() ([]byte, int64) {
	d.cookieSigningMu.RLock()
	defer d.cookieSigningMu.RUnlock()
	if d.cookieSigningKey == nil {
		return nil, d.cookieTimeWindowSec
	}
	return append([]byte(nil), d.cookieSigningKey...), d.cookieTimeWindowSec
}

func (d *Device) statelessCookieParamsConfigured() bool {
	return d != nil && d.cookieSigningConfigured.Load()
}

// statelessCookieParamsInto copies the configured cookie key into dst while
// holding the device lock, then lets callers do HMAC work after the lock is
// released. Production keys are SymmetricKeySize bytes, so the stack buffers at
// call sites avoid heap churn while keeping the critical section to a memcpy.
func (d *Device) statelessCookieParamsInto(dst []byte) ([]byte, int64) {
	d.cookieSigningMu.RLock()
	defer d.cookieSigningMu.RUnlock()
	if len(d.cookieSigningKey) == 0 {
		return nil, d.cookieTimeWindowSec
	}
	if len(dst) < len(d.cookieSigningKey) {
		return append([]byte(nil), d.cookieSigningKey...), d.cookieTimeWindowSec
	}
	key := dst[:len(d.cookieSigningKey)]
	copy(key, d.cookieSigningKey)
	return key, d.cookieTimeWindowSec
}

func (d *Device) Start() {
	cpus := runtime.NumCPU()
	d.wg.Add(2 * cpus)
	for i := 0; i < cpus; i++ {
		go d.msgToPacketRoutine(i)
		go d.packetToMsgRoutine(i)
	}
}

// Stop halts the message routines but intentionally does NOT iterate
// or invalidate peerMap — concurrent callers may still call AddPeer
// during teardown. peerMap is reclaimed when the Device itself is
// garbage-collected. Stop must remain tolerant of concurrent AddPeer
// for any caller relying on this contract.
func (d *Device) Stop() {
	close(d.signals.stop)
	d.wg.Wait()
	close(d.msgToPacketQueue)
	close(d.packetToMsgQueue)
	close(d.DecryptedMsgQueue)
}

func (d *Device) PublicKeyBase64() string {
	return d.staticEcdh.PublicKeyBase64()
}

func (d *Device) NextCounterIndex() uint64 {
	return atomic.AddUint64(&d.counterIndex, 1)
}

// Asynchronous multi-channel processing.
func (d *Device) msgToPacketRoutine(id int) {
	defer d.wg.Done()
	defer log.Info("msgToPacketRoutine %d: quit", id)

	log.Info("msgToPacketRoutine %d: start", id)

	for {
		select {
		case <-d.signals.stop:
			return

		case md, ok := <-d.msgToPacketQueue:
			if !ok {
				return
			}
			if md == nil {
				log.Warning("msgToPacketRoutine %d: msgToPacketRoutine gets nil data", id)
				continue
			}

			// message encryption workflow: raw message -> encryption -> raw packet -> connection.SendQueue
			func() {
				msgType := HeaderTypeToString(md.HeaderType)
				log.Debug("msgToPacketRoutine %d: encrypting [%s] raw message: %s", id, msgType, md.Message)
				log.Evaluate("msgToPacketRoutine %d: encrypting [%s] raw message: %s", id, msgType, md.Message)

				var mad *MsgAssemblerData
				var err error
				var localTransaction *LocalTransaction

				// error handling
				defer func() {
					if x := recover(); x != nil {
						recovered := fmt.Errorf("!!!recovered from panic: %v\n%s", x, string(debug.Stack()))
						err = ErrRuntimePanic.WithExtra(recovered)
						// Keep "msgToPacketRoutine" plus ErrRuntimePanic's
						// message text in this line; Terraform's
						// server-async-runtime-panic log filter keys on both.
						log.Error("msgToPacketRoutine %d: [%s] recovered from panic: %v", id, msgType, err)
					}
					if err != nil {
						if mad == nil {
							if md.ResponseMsgCh != nil {
								md.ResponseMsgCh <- &PacketParserData{Error: err}
							}
							return
						}

						if localTransaction != nil {
							// Once a local transaction owns mad, complete it through the
							// transaction path so its defer remains the single cleanup owner.
							// This preserves the ResponseMsgCh single-writer invariant: a
							// given channel is written exactly once — here (via the
							// transaction) OR by the pre-transaction error paths above,
							// never both. Every ResponseMsgCh consumer relies on that (see
							// the transaction.go note); don't add a second direct writer.
							if txErr := localTransaction.SendExternalMsg(&PacketParserData{Error: err}); txErr != nil {
								log.Debug("msgToPacketRoutine %d: [%s] recovered error after local transaction closed: %v", id, msgType, txErr)
							}
							return
						}

						mad.Error = err
						mad.Destroy()

						// inform preset channel with error
						if mad.ResponseMsgCh != nil {
							mad.ResponseMsgCh <- &PacketParserData{
								Error: err,
							}
						}
						// This reports ordinary pre-divert errors. If the
						// encryptedPktCh send below can panic in the future,
						// recover at that send site instead of relying on this defer.
						if mad.encryptedPktCh != nil {
							mad.encryptedPktCh <- mad
						}
					}
				}()

				// process keepalive separately
				if md.HeaderType == NHP_KPL {
					// createKeepalivePacket returns non-nil mad even on error, so
					// the deferred err handler above is nil-safe.
					mad, err = d.createKeepalivePacket(md)
					if err != nil {
						return
					}
					// Match the normal encrypt path's explicit packet diversion. A
					// KPL caller that supplied EncryptedPktCh owns the assembler and
					// must consume/destroy it; it must never park waiting while the
					// packet is instead forwarded to ConnData.
					if mad.encryptedPktCh != nil {
						mad.encryptedPktCh <- mad
						return
					}
					if mad.connData == nil {
						err = fmt.Errorf("missing connection data for %s outbound packet", msgType)
						log.Error("msgToPacketRoutine %d: [%s] %v", id, msgType, err)
						return
					}
					// send out keepalive packet
					mad.connData.ForwardOutboundPacket(mad.BasePacket)
					return
				}

				mad, err = d.createMsgAssemblerData(md)
				// createMsgAssemblerData guarantees mad non-nil even on
				// err, so the deferred err handler above is nil-safe.
				if err != nil {
					return
				}

				err = mad.setPeerPublicKey(nil)
				if err != nil {
					log.Error("msgToPacketRoutine %d: [%s] message randomization failed: %v", id, msgType, err)
					log.Evaluate("msgToPacketRoutine %d: [%s] message randomization failed: %v", id, msgType, err)
					return
				}

				err = mad.encryptBody()
				if err != nil {
					log.Error("msgToPacketRoutine %d: [%s] message encryption failed: %v", id, msgType, err)
					log.Evaluate("msgToPacketRoutine %d: [%s] message encryption failed: %v", id, msgType, err)
					return
				}
				log.Debug("msgToPacketRoutine %d: complete encrypting [%s]", id, msgType)
				log.Evaluate("msgToPacketRoutine %d: complete encrypting [%s]", id, msgType)

				// deliver encrypted packet to specific channel, but be sure to release the packet buffer after use
				if mad.encryptedPktCh != nil {
					mad.encryptedPktCh <- mad
					return
				}

				// The encryptedPktCh divert above is the legitimate nil-connData path.
				if mad.connData == nil {
					err = fmt.Errorf("missing connection data for %s outbound packet", msgType)
					log.Error("msgToPacketRoutine %d: [%s] %v", id, msgType, err)
					return
				}

				// create local transaction if needed
				log.Debug("msgToPacketRoutine IsTransactionRequest:deviceType:%d HeaderType:%d", d.deviceType, mad.HeaderType)
				if d.IsTransactionRequest(mad.HeaderType) {
					// save initiator transaction
					mad.BasePacket.KeepAfterSend = true // packet is kept after sending and deleted at transaction level
					t := newLocalTransaction(mad.header.Counter(), mad.connData, mad, d.LocalTransactionTimeout(mad.HeaderType))
					d.AddLocalTransaction(t)
					localTransaction = t
					log.Debug("AddLocalTransaction:deviceType=%d,HeaderType=%d", d.deviceType, mad.HeaderType)
				}

				// send out fully encrypted packet
				mad.connData.ForwardOutboundPacket(mad.BasePacket)
			}()
		}
	}
}

// Synchronous linear processing.
func (d *Device) MsgToPacket(md *MsgData) (mad *MsgAssemblerData, err error) {
	defer func() {
		if x := recover(); x != nil {
			mad = nil
			err = fmt.Errorf("!!!recovered from panic: %v\n%s", x, string(debug.Stack()))
			err = ErrRuntimePanic.WithExtra(err)
		}
	}()

	if md.ExternalPacket == nil {
		var buf [PacketBufferSize]byte
		md.ExternalPacket = &Packet{
			Buf:        &buf,
			Content:    buf[:],
			HeaderType: md.HeaderType,
		}
	}
	//md.Compress = len(md.Message) > 64 // no gain for compression if size is small
	// use new transaction id if not specified
	if md.TransactionId == 0 {
		md.TransactionId = d.NextCounterIndex()
	}

	// process keepalive separately
	if md.HeaderType == NHP_KPL {
		return d.createKeepalivePacket(md)
	}

	mad, err = d.createMsgAssemblerData(md)
	defer mad.Destroy()
	if err != nil {
		return nil, err
	}
	err = mad.setPeerPublicKey(nil)
	if err != nil {
		return nil, err
	}
	err = mad.encryptBody()
	if err != nil {
		return nil, err
	}

	return mad, nil
}

// Asynchronous multi-channel processing.
func (d *Device) packetToMsgRoutine(id int) {
	defer d.wg.Done()
	defer log.Info("packetToMsgRoutine %d: quit", id)

	log.Info("packetToMsgRoutine %d: start", id)

	for {
		select {
		case <-d.signals.stop:
			return

		case pd, ok := <-d.packetToMsgQueue:
			if !ok {
				return
			}
			if pd == nil {
				log.Warning("packetToMsgRoutine %d: packetToMsgQueue gets nil data", id)
				continue
			}

			// packet decryption workflow: connection.RecvQueue -> raw packet -> decryption -> raw message
			func() {
				msgType := HeaderTypeToString(pd.BasePacket.HeaderType)
				log.Debug("packetToMsgRoutine %d: decrypting [%s] raw packet", id, msgType)
				log.Evaluate("packetToMsgRoutine %d: decrypting [%s] raw packet", id, msgType)

				var ppd *PacketParserData
				var err error

				// error handling
				defer func() {
					if err != nil {
						ppd.Error = err
						ppd.Destroy()

						// inform preset channel with error
						if ppd.feedbackMsgCh != nil {
							ppd.feedbackMsgCh <- ppd
						}
						if ppd.decryptedMsgCh != nil {
							ppd.decryptedMsgCh <- ppd
						}
					}
				}()

				ppd, err = d.createPacketParserData(pd)
				if err != nil {
					log.Debug("packetToMsgRoutine %d: [%s] packet precheck failed: %v", id, msgType, err)
					log.Evaluate("packetToMsgRoutine %d: [%s] packet precheck failed: %v", id, msgType, err)
					return
				}

				err = ppd.validatePeer()
				if err != nil {
					log.Debug("packetToMsgRoutine %d: [%s] packet validation failed: %v", id, msgType, err)
					log.Evaluate("packetToMsgRoutine %d: [%s] packet validation failed: %v", id, msgType, err)
					return
				}

				// Cross-connection replay-dedupe chokepoint (#1457): runs
				// after validatePeer authenticates ppd.RemotePubKey /
				// ppd.RemoteSendTime and before the body decrypt, so a
				// recognized replay costs no decrypt work. A non-nil error
				// drops the packet via the validation-failure path. Unset
				// on agent/db/AC → skipped. See the recvReplayDedupeFn
				// field doc for why a RESPONSE needs this chokepoint.
				if d.recvReplayDedupeFn != nil {
					if err = d.recvReplayDedupeFn(ppd); err != nil {
						log.Debug("packetToMsgRoutine %d: [%s] packet dropped by replay dedupe: %v", id, msgType, err)
						log.Evaluate("packetToMsgRoutine %d: [%s] packet dropped by replay dedupe: %v", id, msgType, err)
						return
					}
				}

				err = ppd.decryptBody()
				if err != nil {
					log.Error("packetToMsgRoutine: %d: [%s] packet decryption failed: %v", id, msgType, err)
					log.Evaluate("packetToMsgRoutine: %d: [%s] packet decryption failed: %v", id, msgType, err)
					return
				}

				log.Debug("packetToMsgRoutine: %d: complete decrypting [%s] message: %s", id, msgType, ppd.BodyMessage)
				log.Evaluate("packetToMsgRoutine: %d: complete decrypting [%s] message: %s", id, msgType, ppd.BodyMessage)
				log.Debug("packetToMsgRoutine: complete decrypting feedbackMsgCh:%d,headerType:%s", d.deviceType, HeaderTypeToString(ppd.HeaderType))
				// deliver decrypted message to specific channel
				if ppd.decryptedMsgCh != nil {
					log.Debug("packetToMsgRoutine: complete decrypting decryptedMsgCh is not nil")
					ppd.Destroy()
					ppd.decryptedMsgCh <- ppd
					return
				}

				if ppd.feedbackMsgCh != nil {
					log.Debug("packetToMsgRoutine: complete decrypting feedbackMsgCh  is not nil")
					ppd.Destroy()
					ppd.feedbackMsgCh <- ppd
					return
				}
				log.Debug("packetToMsgRoutine: complete decrypting start IsTransactionRequest:deviceType:%d,headerType:%s", d.deviceType, HeaderTypeToString(ppd.HeaderType))
				// start and save responder transaction
				if d.IsTransactionRequest(ppd.HeaderType) {
					// ppd is owned and to be destroyed by transaction
					t := newRemoteTransaction(ppd.SenderTrxId, ppd.ConnData, ppd, d.RemoteTransactionTimeout())
					ppd.ConnData.AddRemoteTransaction(t)
					log.Debug("IsTransactionRequest:true")
				}

				// release packet buffer, but still keep the decrypted message
				ppd.Destroy()
				// deliver decrypted message to generic channel
				select {
				case d.DecryptedMsgQueue <- ppd:

				default:
					// ppd not delivered, set error to destroy the ppd
					d.recordReceiveQueueDrop(ReceiveQueueDropDecrypted)
					log.Critical("packetToMsgRoutine: %d: decryptedMessageCh is full, discarding message", id)
				}
			}()
		}
	}
}

// Synchronous linear processing.
func (d *Device) PacketToMsg(pd *PacketData) (ppd *PacketParserData, err error) {
	defer func() {
		if x := recover(); x != nil {
			ppd = nil
			err = fmt.Errorf("!!!recovered from panic: %v\n%s", x, string(debug.Stack()))
			err = ErrRuntimePanic.WithExtra(err)
		}
	}()

	var packetType int
	packetType, _, err = d.RecvPrecheck(pd.BasePacket)
	if err != nil {
		return nil, err
	}
	// skip processing keepalive packet
	if packetType == NHP_KPL {
		return &PacketParserData{HeaderType: NHP_KPL}, nil
	}

	pd.InitTime = time.Now().UnixNano()
	ppd, err = d.createPacketParserData(pd)
	defer ppd.Destroy()
	if err != nil {
		return nil, err
	}
	err = ppd.validatePeer()
	if err != nil {
		return nil, err
	}
	err = ppd.decryptBody()
	if err != nil {
		return nil, err
	}

	return ppd, nil
}

// SendMsgToPacket enqueues md for the msgToPacketRoutine to encrypt and send.
//
// This send MUST stay non-blocking (discard-on-full). endpoints/agent's Stop()
// reorders a.wg.Wait() ahead of device.Stop() specifically because this can't
// stall a caller: sendMessageRoutine returns on the agent's stop signal without
// the device torn down. Making this a blocking send would silently reintroduce
// a teardown deadlock/panic window there — see
// docs/design/AGENT_LIFECYCLE_TEARDOWN.md ("Stop() ordering").
func (d *Device) SendMsgToPacket(md *MsgData) {
	select {
	case d.msgToPacketQueue <- md:
		// process encryption and send encrypted packet via connection
	default:
		// discard
		log.Critical("msgToPacketQueue is full, discarding message")
	}
}

// RecvPacketToMsg transfers ownership of pd.BasePacket to Device. It returns
// false when the bounded decrypt queue is full; that rejection path releases
// the pooled packet before returning.
func (d *Device) RecvPacketToMsg(pd *PacketData) bool {
	select {
	case d.packetToMsgQueue <- pd:
		// process decryption and deliver plain text message to DecryptedMessageCh
		return true
	default:
		// Ownership transferred to Device at the call. Release on a failed
		// enqueue so a flood cannot drain the fixed packet pool.
		d.recordReceiveQueueDrop(ReceiveQueueDropDecrypt)
		if pd != nil && pd.BasePacket != nil {
			d.ReleasePoolPacket(pd.BasePacket)
		}
		log.Critical("packetToMsgQueue is full, discarding packet")
		return false
	}
}

// udpPeersShareAddress returns true if two UdpPeers point to the same
// network endpoint. Compares IP+Port for IP-based peers, Hostname+Port
// for hostname-only peers (e.g., NLB drain targets).
func udpPeersShareAddress(a, b *UdpPeer) bool {
	if a.Port != b.Port {
		return false
	}
	if a.Ip != "" || b.Ip != "" {
		return a.Ip == b.Ip
	}
	return a.Hostname == b.Hostname
}

func (d *Device) AddPeer(peer Peer) {
	d.peerMapMutex.Lock()
	defer d.peerMapMutex.Unlock()

	key := peer.PublicKeyBase64()
	existing, found := d.peerMap[key]
	if !found {
		d.peerMap[key] = peer
		return
	}

	udpPeer, isUdp := peer.(*UdpPeer)
	if !isUdp {
		d.peerMap[key] = peer
		return
	}

	// Existing is already a PeerGroup — add the new member
	if group, isGroup := existing.(*PeerGroup); isGroup {
		if !group.AddMember(udpPeer) {
			keyPrefix := key
			if len(keyPrefix) > 8 {
				keyPrefix = keyPrefix[:8] + "..."
			}
			// A refused member is absent from the device pool, but the
			// caller's next packet will still be sent to it. The response
			// then fails PeerGroup.CheckRecvAddress (the existing members
			// hold their addresses within MinimalPeerAddressHoldTime) and
			// surfaces as ErrPeerAddressMismatch — a cryptographic-binding
			// error — rather than a peer-pool-full signal. This WARNING is
			// what makes the actual cause findable in the next trace.
			log.Warning("AddPeer: peer group for key %s is at MaxPeerGroupSize=%d; refused new member %s — caller cannot reach this peer until the group drains",
				keyPrefix, MaxPeerGroupSize, udpPeer.Host())
			return
		}
		log.Info("AddPeer: added member %s to peer group (size %d)", udpPeer.Host(), group.Len())
		return
	}

	// Existing is a single UdpPeer — check if same address (re-registration)
	existingUdp, isExistingUdp := existing.(*UdpPeer)
	if isExistingUdp && udpPeersShareAddress(existingUdp, udpPeer) {
		d.peerMap[key] = peer
		return
	}

	// Different address, same key — promote to PeerGroup
	if isExistingUdp {
		group := NewPeerGroup(existingUdp, udpPeer)
		d.peerMap[key] = group
		keyPrefix := key
		if len(keyPrefix) > 8 {
			keyPrefix = keyPrefix[:8] + "..."
		}
		log.Info("AddPeer: promoted to peer group for key %s (%s + %s)",
			keyPrefix, existingUdp.Host(), udpPeer.Host())
		return
	}

	// Existing is some other Peer type — overwrite
	d.peerMap[key] = peer
}

func (d *Device) RemovePeer(pubKey string) {
	d.peerMapMutex.Lock()
	defer d.peerMapMutex.Unlock()

	delete(d.peerMap, pubKey)
}

// RemovePeerByAddress removes a specific member from a PeerGroup.
// If the group has only one member left, it is demoted back to a single peer.
// If the entry is a single peer (not a group), the entire entry is removed.
func (d *Device) RemovePeerByAddress(pubKey string, addr string) {
	d.peerMapMutex.Lock()
	defer d.peerMapMutex.Unlock()

	existing, found := d.peerMap[pubKey]
	if !found {
		return
	}

	group, isGroup := existing.(*PeerGroup)
	if !isGroup {
		delete(d.peerMap, pubKey)
		return
	}

	group.RemoveMember(addr)
	switch group.Len() {
	case 0:
		delete(d.peerMap, pubKey)
	case 1:
		d.peerMap[pubKey] = group.Members()[0]
	}
}

func (d *Device) ResetPeers() {
	d.peerMapMutex.Lock()
	defer d.peerMapMutex.Unlock()

	d.peerMap = make(map[string]Peer)
}

func (d *Device) LookupPeer(pk []byte) Peer {
	// Encode into a stack-allocated buffer and use string(buf[:n]) directly
	// as the map index. The Go compiler elides the string allocation in map
	// lookups (since Go 1.12), avoiding the heap allocation that
	// EncodeToString would cause.
	var buf [PublicKeyBase64SizeEx]byte // fits both PublicKeySize (44 B) and PublicKeySizeEx (88 B)
	n := base64.StdEncoding.EncodedLen(len(pk))
	if n > len(buf) {
		// Unexpected key size; fall back to the allocating path.
		key := base64.StdEncoding.EncodeToString(pk)
		d.peerMapMutex.Lock()
		defer d.peerMapMutex.Unlock()
		if peer, found := d.peerMap[key]; found {
			return peer
		}
		return nil
	}
	base64.StdEncoding.Encode(buf[:n], pk)

	d.peerMapMutex.Lock()
	defer d.peerMapMutex.Unlock()

	peer, found := d.peerMap[string(buf[:n])]
	if found {
		return peer
	}
	return nil
}

func (d *Device) IsOverload() bool {
	return d.Overload.Load()
}

func (d *Device) SetOverload(overloaded bool) {
	d.Overload.Store(overloaded)
}

func (d *Device) GetEcdhByCipherScheme(cipherScheme int) Ecdh {
	return d.staticEcdh
}
