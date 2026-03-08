package etcd

import (
	"context"
	"errors"
	"testing"
)

func TestWatchPrefixCallbacks_Struct(t *testing.T) {
	// Test that the struct is correctly defined
	called := false
	callbacks := WatchPrefixCallbacks{
		OnPut: func(key string, value []byte) {
			called = true
		},
		OnDelete: func(key string) {
			called = true
		},
	}

	// Verify callbacks are callable
	if callbacks.OnPut == nil {
		t.Error("OnPut should not be nil")
	}
	if callbacks.OnDelete == nil {
		t.Error("OnDelete should not be nil")
	}

	// Call the callback
	callbacks.OnPut("test-key", []byte("test-value"))
	if !called {
		t.Error("OnPut callback should have been called")
	}
}

func TestEtcdConn_Struct(t *testing.T) {
	// Test struct initialization
	conn := &EtcdConn{
		Endpoints:  []string{"https://etcd.example.com:2379"},
		Username:   "user",
		Password:   "pass",
		Key:        "test/key",
		TLS:        true,
		CACert:     "/path/to/ca.crt",
		ClientCert: "/path/to/client.crt",
		ClientKey:  "/path/to/client.key",
	}

	if len(conn.Endpoints) != 1 {
		t.Errorf("Expected 1 endpoint, got %d", len(conn.Endpoints))
	}
	if conn.Endpoints[0] != "https://etcd.example.com:2379" {
		t.Errorf("Unexpected endpoint: %s", conn.Endpoints[0])
	}
	if !conn.TLS {
		t.Error("TLS should be enabled")
	}
}

func TestEtcdConn_NoInit(t *testing.T) {
	// Test that methods fail gracefully without initialization
	conn := &EtcdConn{}

	// GetValue should fail without client
	_, err := conn.GetValue()
	if !errors.Is(err, ErrClientNotInitialized) {
		t.Errorf("GetValue: expected ErrClientNotInitialized, got %v", err)
	}

	// GetValueWithKey should fail without client
	_, err = conn.GetValueWithKey(context.Background(), "/test/key")
	if !errors.Is(err, ErrClientNotInitialized) {
		t.Errorf("GetValueWithKey: expected ErrClientNotInitialized, got %v", err)
	}

	// SetValueWithKey should fail without client
	err = conn.SetValueWithKey(context.Background(), "/test/key", "value")
	if !errors.Is(err, ErrClientNotInitialized) {
		t.Errorf("SetValueWithKey: expected ErrClientNotInitialized, got %v", err)
	}

	// SetValue should fail without client
	err = conn.SetValue("value")
	if !errors.Is(err, ErrClientNotInitialized) {
		t.Errorf("SetValue: expected ErrClientNotInitialized, got %v", err)
	}

	// GetPrefix should fail without client
	_, err = conn.GetPrefix("/test")
	if !errors.Is(err, ErrClientNotInitialized) {
		t.Errorf("GetPrefix: expected ErrClientNotInitialized, got %v", err)
	}

	// GetPrefixWithContext should fail without client
	_, err = conn.GetPrefixWithContext(context.Background(), "/test")
	if !errors.Is(err, ErrClientNotInitialized) {
		t.Errorf("GetPrefixWithContext: expected ErrClientNotInitialized, got %v", err)
	}
}

func TestEtcdConfig_Struct(t *testing.T) {
	// Test the config struct
	config := EtcdConfig{
		Key:       "test/key",
		Endpoints: []string{"endpoint1", "endpoint2"},
		Username:  "user",
		Password:  "secret",
	}

	if config.Key != "test/key" {
		t.Errorf("Key mismatch: got %s", config.Key)
	}
	if len(config.Endpoints) != 2 {
		t.Errorf("Expected 2 endpoints, got %d", len(config.Endpoints))
	}
}
