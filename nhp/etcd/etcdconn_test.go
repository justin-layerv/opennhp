package etcd

import (
	"testing"
)

// TestEtcdConn_CloseWithoutWatch verifies that Close() doesn't panic
// when called on a connection that never started watching.
// This is a regression test for the nil channel panic fix.
func TestEtcdConn_CloseWithoutWatch(t *testing.T) {
	conn := &EtcdConn{
		Endpoints: []string{"localhost:2379"},
		// Note: client is nil, signals.stop is nil
	}

	// This should NOT panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Close() panicked: %v", r)
		}
	}()

	conn.Close()
}

// TestEtcdConn_CloseWithNilClient verifies Close() handles nil client gracefully.
func TestEtcdConn_CloseWithNilClient(t *testing.T) {
	conn := &EtcdConn{
		Endpoints: []string{"localhost:2379"},
		client:    nil,
	}

	// Should not panic - early return when client is nil
	conn.Close()
}

// TestEtcdConn_CloseIdempotent verifies Close() can be called multiple times.
func TestEtcdConn_CloseIdempotent(t *testing.T) {
	conn := &EtcdConn{
		Endpoints: []string{"localhost:2379"},
		client:    nil,
	}

	// Multiple closes should not panic
	conn.Close()
	conn.Close()
	conn.Close()
}
