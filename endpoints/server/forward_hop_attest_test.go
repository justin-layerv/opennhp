package server

import (
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/layervai/nhp/internalauth"
)

// buildForwardHopAttestation constructs historical sender envelopes so the
// still-live receiver verifier remains interoperable during rollout overlap.
func buildForwardHopAttestation(selfEcdh core.Ecdh, selfPubB64, peerPubB64 string, hop int, now time.Time, source string, req *common.HttpKnockRequest) (*ForwardHopAttestation, error) {
	if selfEcdh == nil {
		return nil, fmt.Errorf("forward hop attest: nil self ecdh")
	}
	peerPub, err := base64.StdEncoding.DecodeString(peerPubB64)
	if err != nil {
		return nil, err
	}
	macKey := forwardHopMACKey(selfEcdh.SharedSecret(peerPub))
	if macKey == nil {
		return nil, errForwardHopECDHFailed
	}
	ts := now.Unix()
	return &ForwardHopAttestation{
		SenderPubKey: selfPubB64,
		Hop:          hop,
		Timestamp:    ts,
		MAC: internalauth.ComputeHMACHex(macKey,
			forwardHopSigningString(selfPubB64, hop, ts, source, forwardHopReqBind(req))),
	}, nil
}

// hopTestPeer is a server identity (ECDH keypair + base64 pubkey) used to
// exercise the per-pair MAC binding.
type hopTestPeer struct {
	ecdh core.Ecdh
	pub  string
}

func newHopTestPeer(t *testing.T) hopTestPeer {
	t.Helper()
	e, err := core.NewECDH(core.ECC_CURVE25519)
	if err != nil {
		t.Fatalf("NewECDH: %v", err)
	}
	return hopTestPeer{ecdh: e, pub: e.PublicKeyBase64()}
}

func hopTestReq() *common.HttpKnockRequest {
	return &common.HttpKnockRequest{
		AuthServiceId:  "asp-1",
		ResourceId:     "res-1",
		UserId:         "user-1",
		DeviceId:       "dev-1",
		OrganizationId: "org-1",
		SrcIp:          "203.0.113.7",
		Token:          "tok-abc",
	}
}

// known builds a trust-anchor set from the given pubkeys.
func known(pubs ...string) map[string]bool {
	s := make(map[string]bool, len(pubs))
	for _, p := range pubs {
		s[p] = true
	}
	return s
}

// TestForwardHop_RoundTrip is the happy path: server A attests a hop to B,
// B verifies with its own key and a trust set containing A.
func TestForwardHop_RoundTrip(t *testing.T) {
	a := newHopTestPeer(t)
	b := newHopTestPeer(t)
	now := time.Unix(1_700_000_000, 0)
	req := hopTestReq()

	att, err := buildForwardHopAttestation(a.ecdh, a.pub, b.pub, 1, now, "", req)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if att.SenderPubKey != a.pub || att.Hop != 1 {
		t.Fatalf("unexpected attestation fields: %+v", att)
	}
	if err := verifyForwardHopAttestation(b.ecdh, att, known(a.pub, b.pub), now, forwardHopMaxSkew, "", req); err != nil {
		t.Fatalf("verify should succeed, got %v", err)
	}
}

// TestForwardHop_ImpersonationResistant is the core #1127 property: a third
// compromised fleet member (evil) cannot forge an attestation that claims
// to come from A, because it cannot compute ECDH(privA, pubB). Even though
// evil signs a structurally valid attestation and stamps A's pubkey on it,
// B's verification — which derives the key from ECDH(privB, pubA) — fails.
func TestForwardHop_ImpersonationResistant(t *testing.T) {
	a := newHopTestPeer(t)
	b := newHopTestPeer(t)
	evil := newHopTestPeer(t)
	now := time.Unix(1_700_000_000, 0)
	req := hopTestReq()

	// evil mints an attestation under ITS key but claims to be A.
	forged, err := buildForwardHopAttestation(evil.ecdh, a.pub /* lie */, b.pub, 1, now, "", req)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if forged.SenderPubKey != a.pub {
		t.Fatalf("setup: forged sender should claim A's pubkey")
	}
	// A is a legitimate fleet member, so the trust anchor passes — the MAC
	// check is what must catch the impersonation.
	err = verifyForwardHopAttestation(b.ecdh, forged, known(a.pub, b.pub), now, forwardHopMaxSkew, "", req)
	if !errors.Is(err, errForwardHopBadMAC) {
		t.Fatalf("impersonation must fail with MAC mismatch, got %v", err)
	}
}

// TestForwardHop_UnknownPeerRejected: a valid self-signed attestation from
// a server not in the live fleet registry is refused — the attribution /
// revocation lever.
func TestForwardHop_UnknownPeerRejected(t *testing.T) {
	a := newHopTestPeer(t)
	b := newHopTestPeer(t)
	now := time.Unix(1_700_000_000, 0)
	req := hopTestReq()

	att, err := buildForwardHopAttestation(a.ecdh, a.pub, b.pub, 1, now, "", req)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// A absent from the trust set (e.g. revoked / never registered).
	err = verifyForwardHopAttestation(b.ecdh, att, known(b.pub), now, forwardHopMaxSkew, "", req)
	if !errors.Is(err, errForwardHopUnknownPeer) {
		t.Fatalf("unknown peer must be rejected, got %v", err)
	}
}

// TestForwardHop_WrongRecipientRejected: an attestation A built for B does
// not verify at a different recipient C (different per-pair key).
func TestForwardHop_WrongRecipientRejected(t *testing.T) {
	a := newHopTestPeer(t)
	b := newHopTestPeer(t)
	c := newHopTestPeer(t)
	now := time.Unix(1_700_000_000, 0)
	req := hopTestReq()

	att, err := buildForwardHopAttestation(a.ecdh, a.pub, b.pub, 1, now, "", req)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	err = verifyForwardHopAttestation(c.ecdh, att, known(a.pub, b.pub, c.pub), now, forwardHopMaxSkew, "", req)
	if !errors.Is(err, errForwardHopBadMAC) {
		t.Fatalf("wrong recipient must fail MAC, got %v", err)
	}
}

// TestForwardHop_TamperedFields: mutating any signed field after the fact
// breaks the MAC.
func TestForwardHop_TamperedFields(t *testing.T) {
	a := newHopTestPeer(t)
	b := newHopTestPeer(t)
	now := time.Unix(1_700_000_000, 0)
	req := hopTestReq()
	trust := known(a.pub, b.pub)

	base, err := buildForwardHopAttestation(a.ecdh, a.pub, b.pub, 1, now, "", req)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	t.Run("hop bumped within range", func(t *testing.T) {
		tampered := *base
		tampered.Hop = 2 // still <= maxForwardHops, so passes range check
		err := verifyForwardHopAttestation(b.ecdh, &tampered, trust, now, forwardHopMaxSkew, "", req)
		if !errors.Is(err, errForwardHopBadMAC) {
			t.Fatalf("hop tamper must fail MAC, got %v", err)
		}
	})

	t.Run("timestamp shifted within skew", func(t *testing.T) {
		tampered := *base
		tampered.Timestamp = now.Add(time.Minute).Unix()
		err := verifyForwardHopAttestation(b.ecdh, &tampered, trust, now, forwardHopMaxSkew, "", req)
		if !errors.Is(err, errForwardHopBadMAC) {
			t.Fatalf("ts tamper must fail MAC, got %v", err)
		}
	})

	t.Run("request swapped", func(t *testing.T) {
		other := hopTestReq()
		other.Token = "tok-different"
		err := verifyForwardHopAttestation(b.ecdh, base, trust, now, forwardHopMaxSkew, "", other)
		if !errors.Is(err, errForwardHopBadMAC) {
			t.Fatalf("request swap must fail MAC (reqBind), got %v", err)
		}
	})
}

// TestForwardHop_SourceBinding: the envelope Source is bound into the MAC,
// so a server-to-server attestation (built with Source="") cannot be
// replayed with Source flipped to "api" to dodge the re-forward block.
func TestForwardHop_SourceBinding(t *testing.T) {
	a := newHopTestPeer(t)
	b := newHopTestPeer(t)
	now := time.Unix(1_700_000_000, 0)
	req := hopTestReq()
	trust := known(a.pub, b.pub)

	att, err := buildForwardHopAttestation(a.ecdh, a.pub, b.pub, 1, now, "", req)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// Same Source ("") verifies.
	if err := verifyForwardHopAttestation(b.ecdh, att, trust, now, forwardHopMaxSkew, "", req); err != nil {
		t.Fatalf("matching source should verify, got %v", err)
	}
	// Flipped Source ("api") is a MAC mismatch.
	if err := verifyForwardHopAttestation(b.ecdh, att, trust, now, forwardHopMaxSkew, SourceAPI, req); !errors.Is(err, errForwardHopBadMAC) {
		t.Fatalf("flipped source must fail MAC, got %v", err)
	}
}

// TestForwardHop_HopRange enforces the loop ceiling regardless of MAC.
func TestForwardHop_HopRange(t *testing.T) {
	a := newHopTestPeer(t)
	b := newHopTestPeer(t)
	now := time.Unix(1_700_000_000, 0)
	req := hopTestReq()
	trust := known(a.pub, b.pub)

	for _, hop := range []int{0, -1, maxForwardHops + 1, 99} {
		att, err := buildForwardHopAttestation(a.ecdh, a.pub, b.pub, hop, now, "", req)
		if err != nil {
			t.Fatalf("build hop=%d: %v", hop, err)
		}
		err = verifyForwardHopAttestation(b.ecdh, att, trust, now, forwardHopMaxSkew, "", req)
		if !errors.Is(err, errForwardHopBadHop) {
			t.Fatalf("hop=%d must fail with bad-hop, got %v", hop, err)
		}
	}
}

// TestForwardHop_Stale rejects an attestation outside the freshness window.
func TestForwardHop_Stale(t *testing.T) {
	a := newHopTestPeer(t)
	b := newHopTestPeer(t)
	signedAt := time.Unix(1_700_000_000, 0)
	req := hopTestReq()

	att, err := buildForwardHopAttestation(a.ecdh, a.pub, b.pub, 1, signedAt, "", req)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// Verify 10 minutes later — beyond the 5-minute window.
	later := signedAt.Add(10 * time.Minute)
	err = verifyForwardHopAttestation(b.ecdh, att, known(a.pub, b.pub), later, forwardHopMaxSkew, "", req)
	if !errors.Is(err, errForwardHopStale) {
		t.Fatalf("stale attestation must be rejected, got %v", err)
	}
}

// TestForwardHop_Missing distinguishes a nil attestation so the handler can
// treat an API origin as benign.
func TestForwardHop_Missing(t *testing.T) {
	b := newHopTestPeer(t)
	err := verifyForwardHopAttestation(b.ecdh, nil, known(b.pub), time.Unix(1_700_000_000, 0), forwardHopMaxSkew, "", hopTestReq())
	if !errors.Is(err, errForwardHopMissing) {
		t.Fatalf("nil attestation must report missing, got %v", err)
	}
}

// TestForwardHop_StageClassification pins the log-token mapping.
func TestForwardHop_StageClassification(t *testing.T) {
	cases := map[error]string{
		nil:                      "none",
		errForwardHopMissing:     "missing",
		errForwardHopBadPubKey:   "pubkey",
		errForwardHopBadHop:      "hop",
		errForwardHopStale:       "skew",
		errForwardHopUnknownPeer: "unknown_peer",
		errForwardHopECDHFailed:  "ecdh",
		errForwardHopBadMAC:      "signature",
	}
	for err, want := range cases {
		if got := forwardHopStage(err); got != want {
			t.Errorf("forwardHopStage(%v) = %q, want %q", err, got, want)
		}
	}
}
