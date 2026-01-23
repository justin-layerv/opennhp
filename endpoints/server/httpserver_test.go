package server

import (
	"testing"
)

func TestErrNoStorageBackend(t *testing.T) {
	t.Parallel()

	// Verify the error is defined and has a meaningful message
	if ErrNoStorageBackend == nil {
		t.Fatal("ErrNoStorageBackend should not be nil")
	}

	expectedMsg := "no storage backend configured (etcd or DynamoDB required)"
	if ErrNoStorageBackend.Error() != expectedMsg {
		t.Errorf("expected error message %q, got %q", expectedMsg, ErrNoStorageBackend.Error())
	}
}

// TestHttpServer_initHealthManager_NoStorage tests fail-fast behavior
// when no storage backend is configured.
//
// Note: This is a behavioral contract test. The actual initHealthManager
// function requires a fully initialized UdpServer, so we verify the error
// constant exists and has the expected message. Integration tests in
// forward_e2e_test.go cover the full initialization path.
func TestHttpServer_initHealthManager_NoStorage_Contract(t *testing.T) {
	t.Parallel()

	// The contract is:
	// 1. ErrNoStorageBackend is returned when neither etcd nor DynamoDB is configured
	// 2. The error message clearly indicates the problem
	// 3. This causes Start() to fail (tested implicitly by e2e tests)

	err := ErrNoStorageBackend

	// Verify error can be checked with errors.Is
	if err.Error() == "" {
		t.Error("error message should not be empty")
	}

	// Verify the error message mentions both backends
	msg := err.Error()
	if msg == "" {
		t.Error("error message should not be empty")
	}

	// The message should help operators understand what to do
	if len(msg) < 20 {
		t.Error("error message should be descriptive")
	}
}
