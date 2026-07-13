package common

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
)

// RelayRequestIDBytes is the entropy and decoded-size contract for relay
// request correlation IDs. The raw bytes are encoded with unpadded base64url.
const RelayRequestIDBytes = 16

// NewRelayRequestID returns a cryptographically random 128-bit relay request
// correlation ID encoded as unpadded base64url.
func NewRelayRequestID() (string, error) {
	var raw [RelayRequestIDBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// ValidRelayRequestID reports whether id is the exact relay request-ID wire
// shape: unpadded base64url decoding to 16 bytes.
func ValidRelayRequestID(id string) bool {
	if len(id) != base64.RawURLEncoding.EncodedLen(RelayRequestIDBytes) {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(id)
	return err == nil && len(raw) == RelayRequestIDBytes
}

// DecodeRelayJSONStrict decodes exactly one relay envelope, rejecting unknown
// fields and any trailing JSON value. Both relay and server must use this
// shared boundary so their authenticated envelope contracts cannot drift.
func DecodeRelayJSONStrict(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}
