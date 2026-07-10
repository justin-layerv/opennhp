package relay

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/utils"
	"github.com/layervai/nhp/internalauth"
)

// TestPubKeyFingerprintLockstepWithInternalauth fences the two Go copies of
// the public-key fingerprint against each other:
//
//   - nhp/utils PubKeyFingerprint — the nhp-repo copy; this relay uses it to
//     derive the /relay/{serverId} routing ids (config.go), and the js-agent
//     mirrors it in TypeScript.
//   - internalauth PubKeyFingerprint — the shared-module copy added for
//     NHP-native agent registration, consumed by qurl-service and
//     qurl-reverse-tunnel-server, which must derive the SAME id for an agent
//     static key without importing nhp packages (internalauth is deliberately
//     pure stdlib).
//
// Neither module can import the other (internalauth must stay stdlib-only;
// the nhp module does not depend on internalauth), so equality cannot be
// enforced by sharing code — this endpoints-module test is the only place
// both implementations are visible to one compiler, which is why it lives
// here rather than beside either copy. It runs in the full endpoints suite
// on every code PR (build-and-push.yml) and asserts equality over random
// inputs, so a one-sided change to hash, truncation length, or base64
// variant fails CI instead of silently splitting agent identities between
// nhp-server and qurl-service.
func TestPubKeyFingerprintLockstepWithInternalauth(t *testing.T) {
	// Realistic shape first: 100 random 32-byte keys (Curve25519 static key
	// size, the only size production hands these helpers).
	for i := 0; i < 100; i++ {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}

		nhpFP := utils.PubKeyFingerprint(key)
		sharedFP := internalauth.PubKeyFingerprint(key)
		if nhpFP != sharedFP {
			t.Fatalf("fingerprint drift on random key %d: nhp/utils=%q internalauth=%q (key=%s)",
				i, nhpFP, sharedFP, base64.StdEncoding.EncodeToString(key))
		}

		b64 := base64.StdEncoding.EncodeToString(key)
		nhpFromB64, nhpErr := utils.PubKeyFingerprintFromBase64(b64)
		sharedFromB64, sharedErr := internalauth.PubKeyFingerprintFromBase64(b64)
		if nhpErr != nil || sharedErr != nil {
			t.Fatalf("FromBase64 errored on valid input: nhp/utils=%v internalauth=%v", nhpErr, sharedErr)
		}
		if nhpFromB64 != sharedFP || sharedFromB64 != sharedFP {
			t.Fatalf("FromBase64 drift on random key %d: nhp/utils=%q internalauth=%q direct=%q",
				i, nhpFromB64, sharedFromB64, sharedFP)
		}
	}

	// Degenerate/edge inputs: the helpers hash whatever they are given, so the
	// copies must agree beyond the happy-path key size too.
	for _, edge := range [][]byte{
		nil,
		{},
		{0x00},
		make([]byte, 31),
		make([]byte, 33),
		make([]byte, 1024),
	} {
		if got, want := internalauth.PubKeyFingerprint(edge), utils.PubKeyFingerprint(edge); got != want {
			t.Fatalf("fingerprint drift on %d-byte input: internalauth=%q nhp/utils=%q", len(edge), got, want)
		}
	}

	// Invalid base64 must be an error on BOTH sides — a copy that started
	// tolerating bad encodings would mint fingerprints for garbage on one
	// side only.
	if _, err := utils.PubKeyFingerprintFromBase64("!!!not-base64!!!"); err == nil {
		t.Fatal("nhp/utils.PubKeyFingerprintFromBase64 accepted invalid base64")
	}
	if _, err := internalauth.PubKeyFingerprintFromBase64("!!!not-base64!!!"); err == nil {
		t.Fatal("internalauth.PubKeyFingerprintFromBase64 accepted invalid base64")
	}

	// Length contract pinned once on both sides.
	if utils.PubKeyFingerprintLen != internalauth.PubKeyFingerprintLen {
		t.Fatalf("PubKeyFingerprintLen drift: nhp/utils=%d internalauth=%d",
			utils.PubKeyFingerprintLen, internalauth.PubKeyFingerprintLen)
	}
}
