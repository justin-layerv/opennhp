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

// SeedLocalTransactionForTest inserts a placeholder LocalTransaction
// into the device's local transaction map without spinning up the
// transaction's Run() goroutine. Used by graceful-shutdown drain
// tests to simulate "in-flight transaction at shutdown" without
// requiring a full UDP/AC handshake setup.
//
// DO NOT call .Run(), .SendPacket(), or .SendExternalMsg() on the
// returned map entry — the placeholder has nil done/connData/mad
// fields and any such call will panic. The only safe operations are
// LocalTransactionCount() and the matching RemoveLocalTransactionForTest.
func SeedLocalTransactionForTest(d *Device, id uint64) {
	d.localTransactionMutex.Lock()
	defer d.localTransactionMutex.Unlock()
	d.localTransactionMap[id] = &LocalTransaction{transactionId: id}
}

// RemoveLocalTransactionForTest pairs with SeedLocalTransactionForTest:
// removes the placeholder so a drain wait can observe the count
// reaching zero. Idempotent (no-op if id is absent).
func RemoveLocalTransactionForTest(d *Device, id uint64) {
	d.localTransactionMutex.Lock()
	defer d.localTransactionMutex.Unlock()
	delete(d.localTransactionMap, id)
}
