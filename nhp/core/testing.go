package core

// NewRemoteTransactionForTest creates a RemoteTransaction with the given id and
// message channel. It is intended for use in tests only — callers outside the
// core package cannot construct RemoteTransaction directly because the fields
// are unexported.
func NewRemoteTransactionForTest(id uint64, ch chan *MsgData) *RemoteTransaction {
	return &RemoteTransaction{
		transactionId: id,
		NextMsgCh:     ch,
	}
}
