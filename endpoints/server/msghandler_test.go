package server

import (
	"os"
	"path/filepath"
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

func TestTempFileCleanupOrder(t *testing.T) {
	// Simulate the temp directory+file created by utils.DownloadFileToTemp
	dir, err := os.MkdirTemp("", "wasm-test-")
	if err != nil {
		t.Fatal(err)
	}

	file := filepath.Join(dir, "test.wasm")
	if err := os.WriteFile(file, []byte("test"), 0600); err != nil {
		os.RemoveAll(dir)
		t.Fatal(err)
	}

	// Reproduce the defer order from onAttestationVerify.
	// LIFO: last defer runs first, so file is removed before directory.
	func() {
		defer os.Remove(filepath.Dir(file)) // runs second — removes empty dir
		defer os.Remove(file)               // runs first — removes file
	}()

	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("temp file was not removed: %s", file)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("temp directory was not removed: %s", dir)
		os.RemoveAll(dir) // cleanup on failure
	}
}
