package core

import "sync"

// NewRemoteTransactionForTest constructs a RemoteTransaction with only
// the fields tests need — id, message channel, and a fresh done channel
// guarded by a sync.Once so CloseForTest is idempotent. Exists because
// the struct fields are unexported and tests outside the core package
// cannot build one directly.
func NewRemoteTransactionForTest(id uint64, ch chan *MsgData) *RemoteTransaction {
	return &RemoteTransaction{
		transactionId: id,
		NextMsgCh:     ch,
		done:          make(chan struct{}),
		testCloseOnce: &sync.Once{},
	}
}

// CloseForTest closes the transaction's done channel so SendMessage
// returns ErrTransactionClosed. Idempotent via testCloseOnce.
//
// No-op on transactions built by device.go (testCloseOnce is nil for
// those); real transactions close done exactly once from Run()'s defer.
func (t *RemoteTransaction) CloseForTest() {
	if t.testCloseOnce == nil {
		return
	}
	t.testCloseOnce.Do(func() { close(t.done) })
}

// NewLocalTransactionForTest mirrors NewRemoteTransactionForTest for
// LocalTransaction, so external packages can construct one without
// reaching into unexported fields.
func NewLocalTransactionForTest(id uint64) *LocalTransaction {
	return &LocalTransaction{
		transactionId: id,
		NextPacketCh:  make(chan *Packet),
		ExternalMsgCh: make(chan *PacketParserData),
		done:          make(chan struct{}),
		testCloseOnce: &sync.Once{},
	}
}

// CloseForTest closes the local transaction's done channel so
// SendPacket / SendExternalMsg return ErrTransactionClosed. Idempotent.
// No-op on transactions built by device.go.
func (t *LocalTransaction) CloseForTest() {
	if t.testCloseOnce == nil {
		return
	}
	t.testCloseOnce.Do(func() { close(t.done) })
}
