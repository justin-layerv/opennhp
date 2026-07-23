package core

import (
	"sync"
	"time"
)

// NewRemoteTransactionForTest constructs a RemoteTransaction with only
// the fields tests need — id, message channel, and a fresh done channel
// guarded by a sync.Once so CloseForTest is idempotent. Exists because
// the struct fields are unexported and tests outside the core package
// cannot build one directly.
func NewRemoteTransactionForTest(id uint64, ch chan *MsgData) *RemoteTransaction {
	return &RemoteTransaction{
		transactionId: id,
		NextMsgCh:     ch,
		complete:      make(chan struct{}),
		done:          make(chan struct{}),
		testCloseOnce: &sync.Once{},
	}
}

// StartRemoteTransactionForTest starts the production RemoteTransaction.Run
// lifecycle for a synchronously decrypted request. PacketToMsg deliberately
// does not install transactions (the async packet-to-message routine normally
// owns that step), so end-to-end transport tests use this helper instead of a
// channel-only stand-in when they need to exercise responder completion and
// cleanup exactly as production does.
func StartRemoteTransactionForTest(parserData *PacketParserData, timeout time.Duration) *RemoteTransaction {
	timeoutMillis := int(timeout / time.Millisecond)
	if parserData == nil || parserData.ConnData == nil || timeoutMillis <= 0 {
		return nil
	}
	// PacketToMsg has already called Destroy before returning the parser. Give
	// Run a cleanup-only shallow copy with no packet ownership so its production
	// defer cannot release the same pooled packet twice.
	cleanupParser := *parserData
	cleanupParser.basePacket = nil
	cleanupParser.digestHash = nil
	cleanupParser.chainHash = nil
	cleanupParser.owningRemoteTransaction = nil
	if cleanupParser.device == nil {
		// Synthetic endpoint tests do not have access to PacketParserData's
		// unexported device field. A zero Device is sufficient for the cleanup-only
		// parser because ReleasePoolPacket is nil-safe.
		cleanupParser.device = &Device{}
	}
	transaction := newRemoteTransaction(
		parserData.SenderTrxId,
		parserData.ConnData,
		&cleanupParser,
		timeoutMillis,
	)
	parserData.owningRemoteTransaction = transaction
	parserData.ConnData.AddRemoteTransaction(transaction)
	return transaction
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
