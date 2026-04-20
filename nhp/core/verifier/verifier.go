package verifier

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrVerifierPayloadTooLarge — sentinel for errors.Is so callers can tell
// a size-cap rejection apart from a malformed-input rejection.
var ErrVerifierPayloadTooLarge = errors.New("verifier payload exceeds decompression cap")

type Verifier interface {
	// This interface is used to ask verifier to verify the attestation report
	// which is collected from attestor which is NHP Agent in DHP.
	// After receiving the attestation result, NHP Server makes application-specific decisions.
	Verify() error

	// GetSerialNumber returns the serial number from the attestation report
	GetSerialNumber() string

	// GetMeasure returns the measure from the attestation report
	GetMeasure() string
}

type FallbackVerifier struct {
	TestPurpose  string `json:"test_purpose"`
	Measure      string `json:"measure"`
	SerialNumber string `json:"serial_number"`
}

func (f *FallbackVerifier) Verify() error {
	return nil
}

func (f *FallbackVerifier) GetSerialNumber() string {
	return f.SerialNumber
}

func (f *FallbackVerifier) GetMeasure() string {
	return f.Measure
}

func NewFallbackVerifier(evidence []byte) (*FallbackVerifier, error) {
	fallbackVerifier := &FallbackVerifier{}

	err := json.Unmarshal(evidence, fallbackVerifier)
	if err != nil {
		return nil, err
	}

	return fallbackVerifier, nil
}

// maxVerifierPayload bounds the zlib-decompressed evidence. TEE payloads
// fit in tens of KB; 1 MiB leaves three orders of magnitude of headroom
// without letting a zlib bomb (260 KB → 570 MB amplification) saturate
// memory.
const maxVerifierPayload = 1 << 20

func NewVerifier(compressedEvidenceBase64 string) (Verifier, error) {
	compressedEvidence, err := base64.StdEncoding.DecodeString(compressedEvidenceBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode evidence: %w", err)
	}

	r, err := zlib.NewReader(bytes.NewReader(compressedEvidence))
	if err != nil {
		return nil, fmt.Errorf("failed to create zlib reader: %w", err)
	}
	defer func() { _ = r.Close() }()
	// +1 so a payload exactly at the limit is accepted and anything larger
	// exceeds the cap explicitly.
	evidenceBytes, err := io.ReadAll(io.LimitReader(r, maxVerifierPayload+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read evidence: %w", err)
	}
	if len(evidenceBytes) > maxVerifierPayload {
		return nil, fmt.Errorf("%w: read %d bytes, cap %d", ErrVerifierPayloadTooLarge, len(evidenceBytes), maxVerifierPayload)
	}

	verifier, err := NewFallbackVerifier(evidenceBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	return verifier, nil
}
