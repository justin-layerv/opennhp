package ac

import "fmt"

// validateMapKeySize checks that the kernel-loaded BPF map's key
// size matches what the caller expects to decode.
//
// mapLabel is a diagnostic-only identifier (typically a pin path)
// included verbatim in the error message; the helper never reads
// it as a filesystem path.
func validateMapKeySize(mapLabel string, kernel, expected int) error {
	if kernel != expected {
		return fmt.Errorf("map %s: key-size mismatch (kernel=%d, expected=%d) — refusing to decode garbage", mapLabel, kernel, expected)
	}
	return nil
}

// validateMapValueSize checks that the kernel-loaded BPF map's
// value size matches what the caller expects to decode.
//
// Same diagnostic-only mapLabel contract as validateMapKeySize.
func validateMapValueSize(mapLabel string, kernel, expected int) error {
	if kernel != expected {
		return fmt.Errorf("map %s: value-size mismatch (kernel=%d, expected=%d) — refusing to decode garbage", mapLabel, kernel, expected)
	}
	return nil
}
