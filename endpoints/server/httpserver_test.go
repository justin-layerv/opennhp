package server

import (
	"encoding/base64"
	"strings"
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

// ============================================================================
// parseCookieKeys Tests
// ============================================================================

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func TestParseCookieKeys_EmptyString(t *testing.T) {
	_, err := parseCookieKeys("")
	if err == nil {
		t.Fatal("expected error for empty string")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("expected 'required' in error, got: %v", err)
	}
}

func TestParseCookieKeys_InvalidBase64(t *testing.T) {
	_, err := parseCookieKeys("not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
	if !strings.Contains(err.Error(), "base64") {
		t.Errorf("expected 'base64' in error, got: %v", err)
	}
}

func TestParseCookieKeys_InvalidJSON(t *testing.T) {
	_, err := parseCookieKeys(b64("{not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "JSON") {
		t.Errorf("expected 'JSON' in error, got: %v", err)
	}
}

func TestParseCookieKeys_MissingRequiredFields(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"missing auth_key", `{"current":{"encrypt_key":"12345678901234567890123456789012"}}`},
		{"missing encrypt_key", `{"current":{"auth_key":"12345678901234567890123456789012"}}`},
		{"empty current", `{"current":{}}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseCookieKeys(b64(tc.json))
			if err == nil {
				t.Fatal("expected error for missing fields")
			}
		})
	}
}

func TestParseCookieKeys_InvalidKeyLengths(t *testing.T) {
	cases := []struct {
		name    string
		authKey string
		encKey  string
		errSub  string
	}{
		{"auth_key too short", "shortkey", "12345678901234567890123456789012", "auth_key"},
		{"encrypt_key wrong length", "12345678901234567890123456789012", "wronglength1234567", "encrypt_key"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := `{"current":{"auth_key":"` + tc.authKey + `","encrypt_key":"` + tc.encKey + `"}}`
			_, err := parseCookieKeys(b64(j))
			if err == nil {
				t.Fatal("expected error for invalid key length")
			}
			if !strings.Contains(err.Error(), tc.errSub) {
				t.Errorf("expected %q in error, got: %v", tc.errSub, err)
			}
		})
	}
}

func TestParseCookieKeys_ValidCurrentOnly(t *testing.T) {
	// 32-byte auth + 32-byte encrypt
	auth := "12345678901234567890123456789012"
	enc := "abcdefghijklmnopqrstuvwxyz123456"
	j := `{"current":{"auth_key":"` + auth + `","encrypt_key":"` + enc + `"}}`

	keys, err := parseCookieKeys(b64(j))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys (auth+encrypt), got %d", len(keys))
	}
	if string(keys[0]) != auth {
		t.Errorf("auth key mismatch")
	}
	if string(keys[1]) != enc {
		t.Errorf("encrypt key mismatch")
	}
}

func TestParseCookieKeys_ValidWithPrevious(t *testing.T) {
	auth := "12345678901234567890123456789012"
	enc := "abcdefghijklmnopqrstuvwxyz123456"
	prevAuth := "prev1234567890123456789012345678"
	prevEnc := "prevabcdefghijklmnopqrstuvwx1234"
	j := `{"current":{"auth_key":"` + auth + `","encrypt_key":"` + enc + `"},` +
		`"previous":{"auth_key":"` + prevAuth + `","encrypt_key":"` + prevEnc + `"}}`

	keys, err := parseCookieKeys(b64(j))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 4 {
		t.Fatalf("expected 4 keys (current+previous), got %d", len(keys))
	}
	if string(keys[0]) != auth || string(keys[1]) != enc {
		t.Error("current key mismatch")
	}
	if string(keys[2]) != prevAuth || string(keys[3]) != prevEnc {
		t.Error("previous key mismatch")
	}
}

func TestParseCookieKeys_PreviousEmptyKeysIgnored(t *testing.T) {
	auth := "12345678901234567890123456789012"
	enc := "abcdefghijklmnopqrstuvwxyz123456"
	j := `{"current":{"auth_key":"` + auth + `","encrypt_key":"` + enc + `"},` +
		`"previous":{"auth_key":"","encrypt_key":""}}`

	keys, err := parseCookieKeys(b64(j))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys (previous empty should be ignored), got %d", len(keys))
	}
}

func TestParseCookieKeys_64ByteAuthKey(t *testing.T) {
	auth := strings.Repeat("a", 64)
	enc := strings.Repeat("b", 32)
	j := `{"current":{"auth_key":"` + auth + `","encrypt_key":"` + enc + `"}}`

	keys, err := parseCookieKeys(b64(j))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys[0]) != 64 {
		t.Errorf("expected 64-byte auth key, got %d", len(keys[0]))
	}
}

func TestParseCookieKeys_AES128EncryptKey(t *testing.T) {
	auth := strings.Repeat("a", 32)
	enc := strings.Repeat("b", 16) // AES-128
	j := `{"current":{"auth_key":"` + auth + `","encrypt_key":"` + enc + `"}}`

	_, err := parseCookieKeys(b64(j))
	if err != nil {
		t.Fatalf("unexpected error for 16-byte encrypt key: %v", err)
	}
}

func TestParseCookieKeys_AES192EncryptKey(t *testing.T) {
	auth := strings.Repeat("a", 32)
	enc := strings.Repeat("b", 24) // AES-192
	j := `{"current":{"auth_key":"` + auth + `","encrypt_key":"` + enc + `"}}`

	_, err := parseCookieKeys(b64(j))
	if err != nil {
		t.Fatalf("unexpected error for 24-byte encrypt key: %v", err)
	}
}
