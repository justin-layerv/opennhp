package core

import (
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
	log.Info("IsTransactionRequest: deviceType:%d", d.deviceType)
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

func (d *Device) LocalTransactionTimeout() int {
	// NHP_KPL is handled separately
	switch d.deviceType {
	case NHP_AGENT:
		return AgentLocalTransactionResponseTimeoutMs
	case NHP_SERVER:
		return ServerLocalTransactionResponseTimeoutMs
	case NHP_AC:
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

		// if local transaction is expecting a response, return an error
		if err != nil && t.mad.ResponseMsgCh != nil {
			t.mad.ResponseMsgCh <- &PacketParserData{Error: err}
		}

		device.wg.Done()
	}()

	timer := time.NewTimer(time.Duration(t.timeout) * time.Millisecond)
	defer timer.Stop()

	select {
	case pkt := <-t.NextPacketCh:
		pd := &PacketData{
			BasePacket:        pkt,
			PrevAssemblerData: t.mad,
			InitTime:          time.Now().UnixNano(),
		}

		device.RecvPacketToMsg(pd)
		return

	case ppd := <-t.ExternalMsgCh:
		// redirect it to mad.ResponseMsgCh and complete the transaction externally
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
		delete(conn.RemoteTransactionMap, t.transactionId)
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

	case <-conn.StopSignal:
		log.Warning("Remote transaction %d stopped due to closed connection", t.transactionId)
		return

	case <-timer.C:
		log.Warning("Remote transaction %d stopped due to timeout", t.transactionId)
		return
	}
}
