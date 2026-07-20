package connectorhub

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/core/scheme/curve"
)

const (
	// hubWorkerRequestBudget is anchored when the UDP datagram is read. It
	// includes admission, authentication, application handling, and response
	// encryption; the Authority adapter performs no internal retry.
	hubWorkerRequestBudget = 2500 * time.Millisecond
	// hubWorkerResponseReserve requires Authority invocation and public result
	// mapping to finish before the final Noise-sealing, queueing, and UDP-write
	// window.
	hubWorkerResponseReserve = 100 * time.Millisecond
	hubWorkerWriteBudget     = 250 * time.Millisecond
)

var (
	ErrInvalidWorkerConfiguration = errors.New("connector hub: invalid worker configuration")
	ErrWorkerAlreadyServed        = errors.New("connector hub: worker already served")
)

// WorkerConfig is deliberately explicit: every bound is required and there is
// no generic NHP server/plugin configuration surface to inherit accidentally.
type WorkerConfig struct {
	PrivateKeyBase64        string
	ActiveCookieKeyBase64   string
	PreviousCookieKeyBase64 string
	Handler                 *Handler
	Observer                WorkerObserver

	MaxConcurrentPackets  int
	PacketsPerSecond      int
	PacketBurst           int
	MaxConcurrentPerPeer  int
	ResponseQueueCapacity int
}

type outboundDatagram struct {
	payload      []byte
	remote       *net.UDPAddr
	outcome      WorkerOutcome
	requestBytes int
	deadline     time.Time
}

// Worker is the dedicated UDP-only Connector Hub engine. NewWorker transfers
// ownership of conn to the worker; Serve closes it after ingress, producers,
// and the single response writer have stopped.
type Worker struct {
	conn     *net.UDPConn
	device   *core.Device
	handler  *Handler
	observer WorkerObserver

	aggregate *aggregateAdmission
	peers     *peerAdmission
	replay    *packetReplayCache
	writes    chan outboundDatagram

	packetPool sync.Pool
	workers    sync.WaitGroup
	writer     sync.WaitGroup
	served     atomic.Bool
}

func NewWorker(conn *net.UDPConn, config WorkerConfig) (*Worker, error) {
	if conn == nil || config.Handler == nil || config.Handler.authority == nil || config.Handler.admission == nil ||
		!validHandlerEnvironment(config.Handler.environment) ||
		config.MaxConcurrentPackets <= 0 || config.PacketsPerSecond <= 0 || config.PacketBurst <= 0 ||
		config.MaxConcurrentPackets > core.RecvQueueSize ||
		config.MaxConcurrentPerPeer <= 0 || config.MaxConcurrentPerPeer > config.MaxConcurrentPackets ||
		config.ResponseQueueCapacity <= 0 || config.ResponseQueueCapacity > core.SendQueueSize {
		return nil, ErrInvalidWorkerConfiguration
	}
	// The derived replay ceiling below is also the direct upper bound for
	// PacketsPerSecond and PacketBurst; neither can grow independently of the
	// fixed full-window replay state required to support it.
	replayCapacity, ok := deriveReplayCapacity(config.MaxConcurrentPackets, config.PacketsPerSecond, config.PacketBurst)
	// Reuse the core packet-pool cardinality as the process-level ceiling: Hub
	// replay metadata may never outnumber the maximum 4 KiB packet allocations
	// the NHP process already treats as its 1 GiB memory boundary.
	if !ok || replayCapacity > core.PacketBufferPoolSize {
		return nil, ErrInvalidWorkerConfiguration
	}

	privateKey, err := decodeCanonicalKey(config.PrivateKeyBase64, core.PrivateKeySize)
	if err != nil {
		return nil, ErrInvalidWorkerConfiguration
	}
	defer clear(privateKey)
	activeCookieKey, err := decodeCanonicalKey(config.ActiveCookieKeyBase64, core.SymmetricKeySize)
	if err != nil {
		return nil, ErrInvalidWorkerConfiguration
	}
	defer clear(activeCookieKey)
	var previousCookieKey []byte
	if config.PreviousCookieKeyBase64 != "" {
		previousCookieKey, err = decodeCanonicalKey(config.PreviousCookieKeyBase64, core.SymmetricKeySize)
		if err != nil {
			return nil, ErrInvalidWorkerConfiguration
		}
		defer clear(previousCookieKey)
	}

	device := core.NewDevice(core.NHP_SERVER, privateKey, &core.DeviceOptions{AllowUnregisteredAgentLST: true})
	if device == nil {
		return nil, ErrInvalidWorkerConfiguration
	}
	if err := device.SetHubLSTCookieKeys(activeCookieKey, previousCookieKey); err != nil {
		return nil, ErrInvalidWorkerConfiguration
	}

	observer := config.Observer
	if observer == nil {
		observer = noopWorkerObserver{}
	}
	worker := &Worker{
		conn:      conn,
		device:    device,
		handler:   config.Handler,
		observer:  observer,
		aggregate: newAggregateAdmission(config.MaxConcurrentPackets, config.PacketsPerSecond, config.PacketBurst, time.Now()),
		peers:     newPeerAdmission(config.MaxConcurrentPerPeer),
		replay:    newPacketReplayCache(replayCapacity),
		writes:    make(chan outboundDatagram, config.ResponseQueueCapacity),
	}
	worker.packetPool.New = func() any { return make([]byte, core.PacketBufferSize) }
	return worker, nil
}

// deriveReplayCapacity prevents capacity eviction from becoming a replay
// bypass. Admission happens before crypto, so while one digest is live the
// number of later authenticated insertions is bounded by the token-bucket
// burst plus its full-window refill. MaxConcurrent accounts for the current
// packet and older admitted handlers that can reach the cache afterward. The
// fixed protocol window and this overflow-checked bound therefore ensure the
// oldest-entry eviction loop encounters only expired state in production.
func deriveReplayCapacity(maxConcurrent, ratePerSecond, burst int) (int, bool) {
	if maxConcurrent <= 0 || ratePerSecond <= 0 || burst <= 0 {
		return 0, false
	}
	maxInt := uint64(^uint(0) >> 1)
	base := uint64(maxConcurrent) + uint64(burst)
	windowSeconds := uint64(core.HubLSTReplayWindowSeconds)
	if base > maxInt || uint64(ratePerSecond) > (maxInt-base)/windowSeconds {
		return 0, false
	}
	return int(base + uint64(ratePerSecond)*windowSeconds), true
}

func decodeCanonicalKey(encoded string, size int) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != size || isAllZeroFullScan(decoded) || base64.StdEncoding.EncodeToString(decoded) != encoded {
		clear(decoded)
		return nil, ErrInvalidWorkerConfiguration
	}
	return decoded, nil
}

// isAllZeroFullScan deliberately examines every key byte. Do not replace it
// with core.IsZero: that helper returns after the first nonzero byte.
func isAllZeroFullScan(value []byte) bool {
	var combined byte
	for _, b := range value {
		combined |= b
	}
	return combined == 0
}

func (w *Worker) PublicKeyBase64() string {
	if w == nil || w.device == nil {
		return ""
	}
	return w.device.PublicKeyBase64()
}

// Serve runs one reader, bounded packet workers, and one UDP writer. It may be
// called only once. Cancellation interrupts ingress, cancels in-flight Handler
// contexts, drains all producer goroutines, drains the response writer with a
// bounded deadline per datagram, wipes cookie keys, and finally closes conn.
func (w *Worker) Serve(ctx context.Context) error {
	if w == nil || ctx == nil {
		return ErrInvalidWorkerConfiguration
	}
	if !w.served.CompareAndSwap(false, true) {
		return ErrWorkerAlreadyServed
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	w.writer.Add(1)
	go w.writeResponses()

	// ReadFromUDP has no context parameter. Advancing the read deadline is the
	// only cancellation interrupt; conn stays open until the writer has drained.
	interruptDone := make(chan struct{})
	go func() {
		select {
		case <-runCtx.Done():
			_ = w.conn.SetReadDeadline(time.Now())
		case <-interruptDone:
		}
	}()

	err := w.readPackets(runCtx)
	cancel()
	close(interruptDone)
	w.workers.Wait()
	close(w.writes)
	w.writer.Wait()
	_ = w.device.SetHubLSTCookieKeys(nil, nil)
	closeErr := w.conn.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func (w *Worker) readPackets(ctx context.Context) error {
	readBuffer := make([]byte, core.PacketBufferSize+1)
	defer clear(readBuffer)
	for {
		n, remote, err := w.conn.ReadFromUDP(readBuffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// The worker exclusively owns the socket and sets a read deadline
			// only to interrupt cancellation. Any other read error means ingress
			// is no longer trustworthy, so fail the worker instead of retrying an
			// unknown persistent error in a hot loop. The process owner decides
			// whether to restart the listener.
			return err
		}
		receivedAt := time.Now()
		if !validHubEnvelope(readBuffer[:n]) {
			w.observer.ObserveWorkerOutcome(WorkerOutcomeEnvelopeRejected)
			continue
		}

		release, outcome, ok := w.aggregate.acquire(receivedAt)
		if !ok {
			w.observer.ObserveWorkerOutcome(outcome)
			continue
		}

		packet := w.packetPool.Get().([]byte)
		copy(packet, readBuffer[:n])
		packet = packet[:n]
		w.workers.Add(1)
		// ReadFromUDP currently returns a fresh address, but the explicit clone
		// makes goroutine ownership independent of that allocation behavior.
		go w.handlePacket(ctx, receivedAt, cloneUDPAddr(remote), packet, release)
	}
}

func validHubEnvelope(packet []byte) bool {
	if len(packet) < curve.HeaderSize || len(packet) > core.PacketBufferSize {
		return false
	}
	// Delegate the raw Curve header layout to core rather than duplicating its
	// preamble, type/size, and flag offsets on this public pre-crypto path.
	envelope := &core.Packet{Content: packet}
	headerType, payloadSize := envelope.HeaderTypeAndSize()
	if headerType != core.NHP_LST || payloadSize == 0 || curve.HeaderSize+payloadSize != len(packet) {
		return false
	}
	flag := envelope.Flag()
	return flag == 0 || flag == common.NHP_FLAG_HUB_LST_COOKIE_PROOF
}

func (w *Worker) handlePacket(parent context.Context, receivedAt time.Time, remote *net.UDPAddr, packet []byte, release func()) {
	defer w.workers.Done()
	defer release()
	defer func() {
		// The inactive tail can retain ciphertext from a prior longer datagram.
		clear(packet[:cap(packet)])
		w.packetPool.Put(packet[:core.PacketBufferSize])
	}()

	deadline := receivedAt.Add(hubWorkerRequestBudget)
	if parent.Err() != nil || !deadline.After(time.Now()) {
		w.observer.ObserveWorkerOutcome(WorkerOutcomeDeadlineRejected)
		return
	}
	requestCtx, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	digest := sha256.Sum256(packet)
	ppd, err := w.device.PacketToMsg(&core.PacketData{
		BasePacket: &core.Packet{Content: packet, HeaderType: core.NHP_LST},
		ConnData:   &core.ConnectionData{Device: w.device, RemoteAddr: remote},
	})
	if err != nil {
		var challenge *core.HubLSTCookieChallengeError
		if !errors.As(err, &challenge) {
			w.observer.ObserveWorkerOutcome(WorkerOutcomeCryptoRejected)
			return
		}
		response := challenge.Packet()
		if len(response) == 0 {
			w.observer.ObserveWorkerOutcome(WorkerOutcomeCryptoRejected)
			return
		}
		// Core enforces the same strict reduction today. Retain this worker-side
		// check as defense in depth against future core construction drift.
		if len(response) >= len(packet) {
			clear(response)
			w.observer.ObserveWorkerOutcome(WorkerOutcomeChallengeSizeRejected)
			return
		}
		if requestCtx.Err() != nil {
			clear(response)
			w.observer.ObserveWorkerOutcome(WorkerOutcomeDeadlineRejected)
			return
		}
		if !w.acceptReplay(digest, time.Now()) {
			clear(response)
			return
		}
		w.enqueueResponse(response, remote, WorkerOutcomeChallengeSent, len(packet), deadline)
		return
	}
	if ppd == nil {
		w.observer.ObserveWorkerOutcome(WorkerOutcomeCryptoRejected)
		return
	}
	// PacketToMsg deep-copies the decrypted application body and Destroy only
	// releases packet/hash state. Hub LSTs can carry setup or recovery
	// credentials, so retain plaintext only through handling and response seal.
	defer clear(ppd.BodyMessage)
	if ppd.HeaderType != core.NHP_LST || ppd.HeaderFlag != common.NHP_FLAG_HUB_LST_COOKIE_PROOF {
		w.observer.ObserveWorkerOutcome(WorkerOutcomeCryptoRejected)
		return
	}
	if !w.acceptReplay(digest, time.Now()) {
		return
	}
	releasePeer, outcome, ok := w.peers.acquire(ppd.RemotePubKey)
	if !ok {
		w.observer.ObserveWorkerOutcome(outcome)
		return
	}
	defer releasePeer()

	handlerDeadline := deadline.Add(-hubWorkerResponseReserve)
	if !handlerDeadline.After(time.Now()) {
		w.observer.ObserveWorkerOutcome(WorkerOutcomeDeadlineRejected)
		return
	}
	handlerCtx, cancelHandler := context.WithDeadline(requestCtx, handlerDeadline)
	result := w.handler.HandleAssignment(handlerCtx, ppd.BodyMessage, ppd.RemotePubKey)
	cancelHandler()
	w.observer.ObserveHandlerResult(result.Classification, result.RequestRejection)
	if requestCtx.Err() != nil {
		clear(result.Body)
		w.observer.ObserveWorkerOutcome(WorkerOutcomeDeadlineRejected)
		return
	}
	if !w.hasHandlerBody(result.Body) {
		return
	}
	defer clear(result.Body)
	// PacketToMsg has already destroyed pooled packet/hash state, but its
	// response-correlation fields intentionally survive for this synchronous
	// PrevParserData seal.
	mad, err := w.device.MsgToPacket(&core.MsgData{
		HeaderType:     core.NHP_LRT,
		PrevParserData: ppd,
		Compress:       false,
		Message:        result.Body,
	})
	if err != nil {
		// MsgToPacket owns and destroys its assembler on every error return.
		w.observer.ObserveWorkerOutcome(WorkerOutcomeResponseEncodeRejected)
		return
	}
	// ConsumeEncryptedPacket also destroys the assembler. Keep this defensive
	// defer so a future early return between assembly and consumption preserves
	// the same ownership rule; Destroy is intentionally idempotent.
	defer mad.Destroy()
	response, err := core.ConsumeEncryptedPacket(mad)
	if err != nil {
		w.observer.ObserveWorkerOutcome(WorkerOutcomeResponseEncodeRejected)
		return
	}
	if requestCtx.Err() != nil {
		clear(response)
		w.observer.ObserveWorkerOutcome(WorkerOutcomeDeadlineRejected)
		return
	}
	w.enqueueResponse(response, remote, WorkerOutcomeResponseSent, 0, deadline)
}

func (w *Worker) acceptReplay(digest [sha256.Size]byte, now time.Time) bool {
	// Anchor replay retention after authentication. Crypto-processing delay can
	// only lengthen retention; the capacity's MaxConcurrentPackets term covers
	// packets admitted before the replay-window rate horizon but still in flight.
	switch w.replay.accept(digest, now) {
	case packetReplayAccepted:
		return true
	case packetReplayExact:
		w.observer.ObserveWorkerOutcome(WorkerOutcomeReplayRejected)
	case packetReplayCapacityFull:
		w.observer.ObserveWorkerOutcome(WorkerOutcomeReplayCapacityRejected)
	default:
		// An internal enum drift must fail closed and remain low cardinality.
		w.observer.ObserveWorkerOutcome(WorkerOutcomeReplayCapacityRejected)
	}
	return false
}

func (w *Worker) hasHandlerBody(body []byte) bool {
	if len(body) != 0 {
		return true
	}
	w.observer.ObserveWorkerOutcome(WorkerOutcomeHandlerDropped)
	return false
}

func (w *Worker) enqueueResponse(
	payload []byte,
	remote *net.UDPAddr,
	outcome WorkerOutcome,
	requestBytes int,
	deadline time.Time,
) {
	if len(payload) == 0 || remote == nil {
		clear(payload)
		w.observer.ObserveWorkerOutcome(WorkerOutcomeResponseInvalidRejected)
		return
	}
	// remote is the handlePacket goroutine's private clone; ownership transfers
	// with the datagram, so cloning again here only adds a hot-path allocation.
	select {
	case w.writes <- outboundDatagram{
		payload: payload, remote: remote, outcome: outcome,
		requestBytes: requestBytes, deadline: deadline,
	}:
	default:
		clear(payload)
		w.observer.ObserveWorkerOutcome(WorkerOutcomeResponseQueueRejected)
	}
}

func (w *Worker) writeResponses() {
	defer w.writer.Done()
	// A single writer makes UDP socket ownership and payload wiping linear. One
	// kernel-blocked write can delay later datagrams, but that head-of-line cost
	// is intentionally capped by hubWorkerWriteBudget, each request's receipt
	// deadline, and the bounded nonblocking queue.
	for response := range w.writes {
		now := time.Now()
		if !response.deadline.After(now) {
			w.observer.ObserveWorkerOutcome(WorkerOutcomeDeadlineRejected)
			clear(response.payload)
			continue
		}
		writeDeadline := now.Add(hubWorkerWriteBudget)
		if response.deadline.Before(writeDeadline) {
			writeDeadline = response.deadline
		}
		if err := w.conn.SetWriteDeadline(writeDeadline); err != nil {
			w.observer.ObserveWorkerOutcome(WorkerOutcomeWriteFailed)
			clear(response.payload)
			continue
		}
		written, err := w.conn.WriteToUDP(response.payload, response.remote)
		if err != nil || written != len(response.payload) {
			w.observer.ObserveWorkerOutcome(WorkerOutcomeWriteFailed)
		} else {
			w.observer.ObserveWorkerOutcome(response.outcome)
			if response.outcome == WorkerOutcomeChallengeSent {
				w.observer.ObserveChallengeDatagramBytes(response.requestBytes, len(response.payload))
			}
		}
		clear(response.payload)
	}
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	return &net.UDPAddr{IP: bytes.Clone(addr.IP), Port: addr.Port, Zone: addr.Zone}
}
