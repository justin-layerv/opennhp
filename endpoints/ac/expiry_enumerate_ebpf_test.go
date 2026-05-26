package ac

import (
	"strings"
	"testing"
)

// TestValidateMapKeySize covers the single-axis helper directly —
// production callers (enumerateBpfMap) use it instead of any
// bundled wrapper to avoid arg-swap risk. A regression that
// swapped args inside the helper would only be caught here.
func TestValidateMapKeySize(t *testing.T) {
	if err := validateMapKeySize("/sys/fs/bpf/whitelist", 24, 24); err != nil {
		t.Errorf("match: got %v want nil", err)
	}
	err := validateMapKeySize("/sys/fs/bpf/whitelist", 28, 24)
	if err == nil {
		t.Fatal("mismatch: expected error")
	}
	if !strings.Contains(err.Error(), "key-size mismatch") {
		t.Errorf("error should mention key-size mismatch; got %v", err)
	}
	if !strings.Contains(err.Error(), "/sys/fs/bpf/whitelist") {
		t.Errorf("error should mention the pin path; got %v", err)
	}
	if !strings.Contains(err.Error(), "kernel=28") || !strings.Contains(err.Error(), "expected=24") {
		t.Errorf("error should report both sizes for operator triage; got %v", err)
	}
}

// TestValidateMapValueSize is the symmetric value-axis direct fence.
// ValueSize drift is the higher-blast-radius mismatch: the
// ExpireTime field is read at a fixed offset via unsafe.Offsetof,
// so a value-size change without a corresponding offset update
// would silently decode the wrong 8 bytes.
func TestValidateMapValueSize(t *testing.T) {
	if err := validateMapValueSize("/sys/fs/bpf/whitelist", 16, 16); err != nil {
		t.Errorf("match: got %v want nil", err)
	}
	err := validateMapValueSize("/sys/fs/bpf/whitelist", 20, 16)
	if err == nil {
		t.Fatal("mismatch: expected error")
	}
	if !strings.Contains(err.Error(), "value-size mismatch") {
		t.Errorf("error should mention value-size mismatch; got %v", err)
	}
	if !strings.Contains(err.Error(), "kernel=20") || !strings.Contains(err.Error(), "expected=16") {
		t.Errorf("error should report both sizes for operator triage; got %v", err)
	}
}
