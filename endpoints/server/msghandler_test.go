package server

import (
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

func TestForwardToTransaction(t *testing.T) {
	t.Run("transaction not found returns error", func(t *testing.T) {
		connData := &core.ConnectionData{
			RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
		}

		md := &core.MsgData{}
		err := forwardToTransaction(connData, 42, md, "server-agent", "TestHandler", "user1", "1.2.3.4:5678")

		if err != common.ErrTransactionIdNotFound {
			t.Errorf("expected ErrTransactionIdNotFound, got %v", err)
		}
	})

	t.Run("transaction found forwards message", func(t *testing.T) {
		connData := &core.ConnectionData{
			RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
		}

		msgCh := make(chan *core.MsgData, 1) // buffered to avoid blocking in test
		connData.RemoteTransactionMap[99] = core.NewRemoteTransactionForTest(99, msgCh)

		md := &core.MsgData{
			HeaderType: core.NHP_ACK,
		}
		err := forwardToTransaction(connData, 99, md, "server-agent", "TestHandler", "user1", "1.2.3.4:5678")

		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}

		select {
		case got := <-msgCh:
			if got != md {
				t.Errorf("expected forwarded message to be the same pointer")
			}
		default:
			t.Error("expected message to be sent to NextMsgCh")
		}
	})
}
