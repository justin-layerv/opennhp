package common

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
)

const nhpSessionIDBytes = 8

const nhpSessionOwnerIDBytes = 16

const nhpACBootIDBytes = 16

// NHPAgentPublicKeyBytes is the Curve25519 public-key width carried by the
// NHP-AOP Public Key field.
const NHPAgentPublicKeyBytes = 32

// ValidNHPAgentPublicKey reports whether value is the canonical standard-base64
// encoding of exactly one NHP-Agent public key.
func ValidNHPAgentPublicKey(value string) bool {
	decoded, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(decoded) == NHPAgentPublicKeyBytes && base64.StdEncoding.EncodeToString(decoded) == value
}

// NewNHPSessionOwnerID returns a per-process boot identity for scoping AOP/ART
// session ownership when a server fleet shares one authenticated Noise key.
func NewNHPSessionOwnerID() (string, error) {
	var raw [nhpSessionOwnerIDBytes]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// ValidNHPSessionOwnerID reports whether id is the canonical lowercase
// 128-bit process identity carried by the internal AOP/ART extension.
func ValidNHPSessionOwnerID(id string) bool {
	if len(id) != nhpSessionOwnerIDBytes*2 {
		return false
	}
	raw, err := hex.DecodeString(id)
	return err == nil && len(raw) == nhpSessionOwnerIDBytes && hex.EncodeToString(raw) == id
}

// NewNHPACBootID returns a process-boot identity for one AC runtime. It is
// intentionally distinct from the AC static key: blue/green processes can
// share that key while their session-control state and fail-closed lease are
// independent.
func NewNHPACBootID() (string, error) {
	var raw [nhpACBootIDBytes]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// ValidNHPACBootID reports whether id is the canonical lowercase 128-bit AC
// process-boot identity carried by NHP_AOL.
func ValidNHPACBootID(id string) bool {
	if len(id) != nhpACBootIDBytes*2 {
		return false
	}
	raw, err := hex.DecodeString(id)
	return err == nil && len(raw) == nhpACBootIDBytes && hex.EncodeToString(raw) == id
}

// NewNHPSessionID returns a non-zero, cryptographically random 8-byte session
// identifier for one NHP access request. A zero value is reserved for
// "unassigned" on optional JSON fields, so the generator retries if entropy
// happens to decode to zero.
//
// Entropy failure is process-fatal by design, matching GenerateOpaqueToken:
// issuing predictable or absent access-session identities would break the
// AOP/ART/ACK binding the identifier exists to enforce.
func NewNHPSessionID() uint64 {
	id, err := readNHPSessionID(rand.Reader)
	if err != nil {
		panic("nhp: crypto/rand session ID unavailable: " + err.Error())
	}
	return id
}

func readNHPSessionID(reader io.Reader) (uint64, error) {
	if reader == nil {
		return 0, fmt.Errorf("nil entropy reader")
	}
	var buf [nhpSessionIDBytes]byte
	for {
		if _, err := io.ReadFull(reader, buf[:]); err != nil {
			return 0, err
		}
		if id := binary.BigEndian.Uint64(buf[:]); id != 0 {
			return id, nil
		}
	}
}
