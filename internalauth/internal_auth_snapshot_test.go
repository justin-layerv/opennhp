package internalauth

import (
	"testing"
	"time"
)

// TestSign_Snapshot_FixedReferenceVector pins the EXACT wire-format
// bytes for a frozen (timestamp, method, path, body, secret) tuple.
// This is the cross-consumer contract anchor — every consumer
// (nhp-server, qurl-service, qurl-reverse-tunnel-server) compares
// HMACs computed by THIS module, so a change to the canonical
// signing string, scheme constant, or HMAC compute path that doesn't
// land identically across the rollout will break THIS test (in this
// module's CI) AND every signed request in production simultaneously.
//
// Recomputing the expected via signingString() inside this test would
// be a tautology (a bug in signingString would still pass). The hex
// was derived from first principles by feeding the canonical signing
// string through HMAC-SHA256 with the pinned secret. The same vector
// is mirrored in qurl-service's TestSign_StableHeaderShape so a
// drift on either side breaks both repos' CI in the same window.
//
// To re-derive if the scheme or vector changes (printf is portable;
// `echo -n` differs between bash and dash). The trailing awk strips
// the `(stdin)= ` prefix that openssl emits in -hex mode on most
// systems — without it, the printout has a leading `(stdin)= ` that
// can make a reviewer think they computed the wrong hash. The
// inner sha256 step uses openssl rather than `sha256sum` because
// `sha256sum` is GNU coreutils (Linux); macOS has `shasum -a 256`
// instead. openssl is on both:
//
//	printf 'NHPv1\n1700000000\nPOST\n/nhp/internal/knock\n%s' \
//	  "$(printf '{"req":1}' | openssl dgst -sha256 -hex | awk '{print $NF}')" | \
//	  openssl dgst -sha256 -hmac "shared-secret-bytes-padded-to-32-chars-min" -hex | \
//	  awk '{print $NF}'
func TestSign_Snapshot_FixedReferenceVector(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	// Test-only fixture: NOT a real secret pattern. The string is
	// guessable on purpose so the snapshot vector is reproducible
	// from the godoc recipe. Production secrets MUST come from a
	// CSPRNG (Terraform's `random_password` or AWS Secrets Manager's
	// `generate_secret_string`); MinSecretLength=32 only fences the
	// length floor, not the entropy floor.
	s, err := newWithClock("shared-secret-bytes-padded-to-32-chars-min", func() time.Time { return at })
	if err != nil {
		t.Fatalf("newWithClock: %v", err)
	}
	got := s.Sign("POST", "/nhp/internal/knock", []byte(`{"req":1}`))
	const want = "NHPv1 timestamp=1700000000,signature=cd56ab4ca9b0a1aa6e9da21cf5482f1615fa538be9f8b08267a1f5c4cf56a878"
	if got != want {
		t.Errorf("snapshot drift — every consumer's signed traffic just broke:\ngot:  %q\nwant: %q", got, want)
	}

	// Symmetric fence: the same vector must Verify clean against
	// the same signer. Without this, a regression where Sign produces
	// the correct bytes but Verify's compare logic drifted (constant-
	// time compare swapped to non-constant-time, hex decode introduced
	// a normalization step, etc.) would slip past the bytes-equality
	// check above. Round-trip is cheap; the symmetry catch is real.
	if err := s.Verify(want, "POST", "/nhp/internal/knock", []byte(`{"req":1}`), 0); err != nil {
		t.Errorf("snapshot vector failed Verify round-trip — Sign/Verify drifted:\nheader: %q\nerr: %v", want, err)
	}

	// Bypass-Sign fence: assert computeMAC(signingString(...)) directly
	// against the pinned hex. The Sign(...) and Verify(...) checks above
	// both go through the public surface; this row goes around it. If
	// a future committer "regenerates the snapshot" by running the
	// broken Sign and copy-pasting its output, this row would catch
	// the regression because the expected hex was derived externally
	// via the openssl recipe in the godoc above — NOT from
	// signingString itself. DO NOT regenerate this hex by running Sign;
	// re-derive via the recipe. The bypass also catches a bug class
	// where Sign and signingString drift in lockstep (both wrong, both
	// agree) — the externally-derived expected breaks both at once.
	const wantSig = "cd56ab4ca9b0a1aa6e9da21cf5482f1615fa538be9f8b08267a1f5c4cf56a878"
	if gotSig := s.computeMAC(signingString(1_700_000_000, "POST", "/nhp/internal/knock", []byte(`{"req":1}`))); gotSig != wantSig {
		t.Errorf("computeMAC(signingString(...)) drift — Sign output may match a broken signingString:\ngot:  %q\nwant: %q", gotSig, wantSig)
	}
}
