package common

import (
	"bytes"
	"errors"
	"testing"
)

func TestReadNHPSessionID_IsEightByteUint64AndSkipsZero(t *testing.T) {
	input := append(make([]byte, nhpSessionIDBytes), []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}...)
	got, err := readNHPSessionID(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("readNHPSessionID: %v", err)
	}
	if want := uint64(0x0123456789abcdef); got != want {
		t.Fatalf("session ID = %#x, want %#x", got, want)
	}
}

func TestReadNHPSessionID_FailsClosedOnEntropyError(t *testing.T) {
	if got, err := readNHPSessionID(errorReader{}); got != 0 || err == nil {
		t.Fatalf("readNHPSessionID = (%d, %v), want (0, error)", got, err)
	}
	if got, err := readNHPSessionID(nil); got != 0 || err == nil {
		t.Fatalf("readNHPSessionID(nil) = (%d, %v), want (0, error)", got, err)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }
