package core

import (
	"context"
	"sync"
	"time"

	common "github.com/OpenNHP/opennhp/nhp/common"
	log "github.com/OpenNHP/opennhp/nhp/log"
)

type LocalTransaction struct {
	transactionId uint64
	connData      *ConnectionData
	mad           *MsgAssemblerData
	NextPacketCh  chan *Packet           // higher level entities should redirect packet to this channel
	ExternalMsgCh chan *PacketParserData // a channel to receive an external msg to complete the transaction
	done          chan struct{}          // closed by Run() on exit; used by Send*() to avoid sending on a closed channel
	timeout       int
}

type RemoteTransaction struct {
	transactionId uint64
	connData      *ConnectionData
	parserData    *PacketParserData
	NextMsgCh     chan *MsgData // higher level entities should redirect message to this channel
	complete      chan struct{} // specialized responders finish after diverting encryption/physical write
	done          chan struct{} // closed by Run() on exit; used by SendMessage() to avoid sending on a closed channel
	timeout       int
	testCloseOnce *sync.Once // test-only; nil for real transactions (see NewRemoteTransactionForTest)
}

// newLocalTransaction is the single production constructor for
// LocalTransaction. It enforces that done is non-nil so SendPacket /
// SendExternalMsg's select can never degrade to the pre-fix blocking
// send (a receive on a nil channel blocks forever inside select).
func newLocalTransaction(id uint64, connData *ConnectionData, mad *MsgAssemblerData, timeout int) *LocalTransaction {
	return &LocalTransaction{
		transactionId: id,
		connData:      connData,
		mad:           mad,
		NextPacketCh:  make(chan *Packet),
		ExternalMsgCh: make(chan *PacketParserData),
		done:          make(chan struct{}),
		timeout:       timeout,
	}
}

// newRemoteTransaction mirrors newLocalTransaction for RemoteTransaction.
func newRemoteTransaction(id uint64, connData *ConnectionData, parserData *PacketParserData, timeout int) *RemoteTransaction {
	return &RemoteTransaction{
		transactionId: id,
		connData:      connData,
		parserData:    parserData,
		NextMsgCh:     make(chan *MsgData),
		complete:      make(chan struct{}),
		done:          make(chan struct{}),
		timeout:       timeout,
	}
}

// SendMessage forwards md to the transaction's Run() goroutine, or
// returns common.ErrTransactionClosed if the transaction has exited.
// Safe to call concurrently; blocks until delivered or closed.
func (t *RemoteTransaction) SendMessage(md *MsgData) error {
	select {
	case t.NextMsgCh <- md:
		return nil
	case <-t.done:
		return common.ErrTransactionClosed
	}
}

// SendMessageContext is the bounded handoff used by operations whose absolute
// receipt deadline is shorter than the generic remote-transaction lifetime. It
// never spawns a sender goroutine, so returning via ctx leaves no blocked sender
// that can deliver later. As with every Go select, cancellation racing an already
// ready receiver may choose either ready case; callers needing receiver-side
// expiry must carry and enforce that metadata at the receiver too.
func (t *RemoteTransaction) SendMessageContext(ctx context.Context, md *MsgData) error {
	if ctx == nil {
		return context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case t.NextMsgCh <- md:
		return nil
	case <-t.done:
		return common.ErrTransactionClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// CompleteContext finishes a remote transaction after a specialized bounded
// responder has fully consumed the request. The responder may have
// synchronously encrypted a reply and diverted its physical write from the
// generic SendMsgToPacket path, or deliberately selected a no-reply terminal
// outcome. Run remains the sole owner of parser cleanup and map removal, while
// ctx bounds the completion rendezvous.
func (t *RemoteTransaction) CompleteContext(ctx context.Context) error {
	if t == nil || t.complete == nil || t.done == nil {
		return common.ErrTransactionClosed
	}
	if ctx == nil {
		return context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case t.complete <- struct{}{}:
		return nil
	case <-t.done:
		return common.ErrTransactionClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Done returns a channel that is closed when the transaction exits.
func (t *RemoteTransaction) Done() <-chan struct{} {
	return t.done
}

// SendPacket forwards pkt to the local transaction's Run() goroutine,
// or returns common.ErrTransactionClosed if it has exited.
func (t *LocalTransaction) SendPacket(pkt *Packet) error {
	select {
	case t.NextPacketCh <- pkt:
		return nil
	case <-t.done:
		return common.ErrTransactionClosed
	}
}

// SendExternalMsg forwards ppd to the local transaction's Run() goroutine
// via ExternalMsgCh, or returns common.ErrTransactionClosed if it has
// exited.
func (t *LocalTransaction) SendExternalMsg(ppd *PacketParserData) error {
	select {
	case t.ExternalMsgCh <- ppd:
		return nil
	case <-t.done:
		return common.ErrTransactionClosed
	}
}

// Done returns a channel that is closed when the transaction exits.
func (t *LocalTransaction) Done() <-chan struct{} {
	return t.done
}

func (d *Device) IsTransactionRequest(t int) bool {

	// NHP_KPL is handled separately
	log.Debug("IsTransactionRequest: deviceType:%d", d.deviceType)
	switch d.deviceType {
	case NHP_AGENT:
		switch t {
		case NHP_REG, NHP_LST, NHP_KNK, DHP_KNK, NHP_RKN, NHP_EXT, NHP_DAR, NHP_DAV:
			return true
		}
	case NHP_SERVER:
		switch t {
		// NHP_FWD: Server-to-server forwarding (Phase 2 - Per-AC Assignment)
		case NHP_REG, NHP_LST, NHP_KNK, DHP_KNK, NHP_RKN, NHP_EXT, NHP_AOL, NHP_AOP, NHP_DAK, NHP_DAG, NHP_DSA, NHP_DAR, NHP_DAV, NHP_DRG, NHP_DOL, NHP_DWR, NHP_FWD:
			return true
		}
	case NHP_AC:
		switch t {
		case NHP_AOL, NHP_AOP:
			return true
		}
	case NHP_DB:
		switch t {
		case NHP_DRG, NHP_DOL, NHP_DWR:
			return true
		}
	case NHP_RELAY:

		// no transaction request for relay
	}

	return false
}

func (d *Device) LocalTransactionTimeout(msgType int) int {
	// NHP_KPL is handled separately
	switch d.deviceType {
	case NHP_AGENT:
		return AgentLocalTransactionResponseTimeoutMs
	case NHP_SERVER:
		// The server→AC open (NHP_AOP) is the DNS-fast qURL knock hot path and gets its
		// own aggressive timeout; every OTHER server-initiated transaction (NHP_DWR DB
		// key-wrap, NHP_FWD forward, …) keeps the conservative shared value — those are
		// not intra-VPC-fast and are not idempotently retried.
		if msgType == NHP_AOP {
			return ServerACOpenTransactionResponseTimeoutMs
		}
		return ServerLocalTransactionResponseTimeoutMs
	case NHP_AC:
		if msgType == NHP_AOL {
			return ACRegistrationTransactionResponseTimeoutMs
		}
		return ACLocalTransactionResponseTimeoutMs
	case NHP_DB:
		return DELocalTransactionResponseTimeoutMs
	case NHP_RELAY:
		// no transaction request for relay
	}

	return 0
}

func (d *Device) RemoteTransactionTimeout() int {
	return RemoteTransactionProcessTimeoutMs
}

func (d *Device) IsTransactionResponse(t int) bool {
	// NHP_KPL is handled separately
	switch d.deviceType {
	case NHP_AGENT:
		switch t {
		case NHP_RAK, NHP_LRT, NHP_ACK, NHP_DAG, NHP_DSA:
			// note NHP_COK is not handled as transaction for agent
			return true
		}
	case NHP_SERVER:
		switch t {
		// NHP_FRT: Server-to-server forward result (Phase 2 - Per-AC Assignment)
		case NHP_RAK, NHP_LRT, NHP_ACK, NHP_AAK, NHP_ART, NHP_DAK, NHP_DWA, NHP_FRT:
			// note NHP_COK is not handled as transaction for server
			return true
		}
	case NHP_AC:
		switch t {
		case NHP_AAK, NHP_ART:
			return true
		}
	case NHP_DB:
		switch t {
		case NHP_DAK, NHP_DBA:
			return true
		}
	case NHP_RELAY:
		// no transaction response for relay
	}

	return false
}

// LocalTransaction
func (d *Device) AddLocalTransaction(t *LocalTransaction) {
	d.localTransactionMutex.Lock()
	defer d.localTransactionMutex.Unlock()

	d.localTransactionMap[t.transactionId] = t

	d.wg.Add(1)
	go t.Run()
}

func (d *Device) FindLocalTransaction(id uint64) *LocalTransaction {
	d.localTransactionMutex.Lock()
	defer d.localTransactionMutex.Unlock()

	t, found := d.localTransactionMap[id]
	if found {
		return t
	}

	return nil
}

// LocalTransactionCount returns the number of in-flight local transactions
// currently awaiting a response or timeout. Used by graceful shutdown to
// wait for outstanding server->AC (and other locally-initiated) transactions
// to complete before closing connection StopSignals — without this drain,
// any in-flight transaction at close time returns
// ErrTransactionFailedByClosedConnection to its caller (e.g. surfaces as
// `knock_failed` on the qURL plugin's HTTP response during a canary roll).
func (d *Device) LocalTransactionCount() int {
	d.localTransactionMutex.Lock()
	defer d.localTransactionMutex.Unlock()
	return len(d.localTransactionMap)
}

func (t *LocalTransaction) Run() {
	log.Debug("Local transaction %d start", t.transactionId)
	defer log.Debug("Local transaction %d quit", t.transactionId)

	device := t.mad.device
	var err error

	// clear up
	defer func() {
		t.mad.Destroy()

		// delete + close(done) under the same mutex: Find*() returning
		// non-nil implies done is still open, so Send*() either delivers
		// or takes the done branch — never races a close on a message
		// channel (that's why we don't close NextPacketCh/ExternalMsgCh).
		device.localTransactionMutex.Lock()
		delete(device.localTransactionMap, t.transactionId)
		close(t.done)
		device.localTransactionMutex.Unlock()

		// if local transaction is expecting a response, return an error.
		// ResponseMsgCh single-writer invariant: this defer and the
		// ExternalMsgCh completion below are the transaction's only two writers,
		// and they're mutually exclusive (the completion path returns with
		// err == nil, so this defer's `err != nil` guard skips). Exactly one
		// write per transaction is a universal contract for every ResponseMsgCh
		// consumer: the unbuffered block-receive consumers (endpoints/{server,
		// ac,db}) would leave a second writer blocked forever, and the
		// close-on-receive + size-1-buffer consumer (endpoints/agent's
		// awaitTransactionResponse) would get a send-on-closed panic /
		// full-buffer deadlock. Don't add a second writer.
		if err != nil && t.mad.ResponseMsgCh != nil {
			t.mad.ResponseMsgCh <- &PacketParserData{Error: err}
		}

		device.wg.Done()
	}()

	timer := time.NewTimer(time.Duration(t.timeout) * time.Millisecond)
	defer timer.Stop()

	select {
	case pkt := <-t.NextPacketCh:
		initTime := pkt.ReceivedAtNanos
		if initTime == 0 {
			// Non-server transports do not yet stamp Packet. Preserve their
			// historical behavior while server UDP/WebRTC responses retain the
			// immutable receipt captured before queueing.
			initTime = time.Now().UnixNano()
		}
		pd := &PacketData{
			BasePacket:        pkt,
			PrevAssemblerData: t.mad,
			InitTime:          initTime,
		}

		if !device.RecvPacketToMsg(pd) {
			// Do not leave the transaction waiter without a ResponseMsgCh
			// writer when bounded decrypt admission rejects the packet.
			err = ErrServerOverload
		}
		return

	case ppd := <-t.ExternalMsgCh:
		// redirect it to mad.ResponseMsgCh and complete the transaction
		// externally. Second of the transaction's two mutually-exclusive
		// ResponseMsgCh writers (see the single-writer note in the defer above).
		if t.mad.ResponseMsgCh != nil {
			t.mad.ResponseMsgCh <- ppd
		}
		return

	case <-t.connData.StopSignal:
		log.Warning("Local transaction %d stopped due to closed connection", t.transactionId)
		err = common.ErrTransactionFailedByClosedConnection
		return

	case <-device.signals.stop:
		// not needed in most case, just in case the device is closed first than connection by mistake
		log.Warning("Local transaction %d stopped due to closed device", t.transactionId)
		err = common.ErrTransactionFailedByClosedDevice
		return

	case <-timer.C:
		log.Warning("Local transaction %d stopped due to timeout", t.transactionId)
		err = common.ErrTransactionFailedByTimeout
		return
	}
}

// RemoteTransaction
func (c *ConnectionData) AddRemoteTransaction(t *RemoteTransaction) {
	c.RemoteTransactionMutex.Lock()
	defer c.RemoteTransactionMutex.Unlock()

	c.RemoteTransactionMap[t.transactionId] = t

	c.Add(1)
	go t.Run()
}

func (c *ConnectionData) FindRemoteTransaction(id uint64) *RemoteTransaction {
	if c.IsClosed() {
		log.Warning("connection is closed, all transactions are cleared")
		return nil
	}

	c.RemoteTransactionMutex.Lock()
	defer c.RemoteTransactionMutex.Unlock()

	t, found := c.RemoteTransactionMap[id]
	if found {
		return t
	}

	return nil
}

func (t *RemoteTransaction) Run() {
	log.Debug("Remote transaction %d start", t.transactionId)
	defer log.Debug("Remote transaction %d quit", t.transactionId)

	conn := t.connData

	defer func() {
		t.parserData.Destroy()

		// delete + close(done) under the same mutex: Find*() returning
		// non-nil implies done is still open, so SendMessage either
		// delivers or takes the done branch — never races a close on
		// NextMsgCh (that's why we don't close the message channel).
		conn.RemoteTransactionMutex.Lock()
		// A later request may occupy the same transaction-id slot while this
		// owner is still finishing. Stale cleanup must not erase that
		// replacement.
		if current := conn.RemoteTransactionMap[t.transactionId]; current == t {
			delete(conn.RemoteTransactionMap, t.transactionId)
		}
		close(t.done)
		conn.RemoteTransactionMutex.Unlock()

		conn.Done()
	}()

	timer := time.NewTimer(time.Duration(t.timeout) * time.Millisecond)
	defer timer.Stop()

	select {
	case md := <-t.NextMsgCh:
		md.PrevParserData = t.parserData
		conn.Device.SendMsgToPacket(md)
		return

	case <-t.complete:
		return

	case <-conn.StopSignal:
		log.Warning("Remote transaction %d stopped due to closed connection", t.transactionId)
		return

	case <-timer.C:
		log.Warning("Remote transaction %d stopped due to timeout", t.transactionId)
		return
	}
}
