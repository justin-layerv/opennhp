package verifier

import "testing"

func TestFallbackVerifier_Fields(t *testing.T) {
	v := &FallbackVerifier{
		Measure:      "test-measure",
		SerialNumber: "test-sn",
	}
	if got := v.GetMeasure(); got != "test-measure" {
		t.Errorf("GetMeasure() = %q, want %q", got, "test-measure")
	}
	if got := v.GetSerialNumber(); got != "test-sn" {
		t.Errorf("GetSerialNumber() = %q, want %q", got, "test-sn")
	}
}
