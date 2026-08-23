package server

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/nhp/core"
)

// hopKey returns a deterministic 32-byte X25519 private key for tests
// (X25519 clamps internally, so any 32 bytes is a valid private key).
func hopKey(seed byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = seed + byte(i)
	}
	return k
}

func hopEcdh(t *testing.T, seed byte) core.Ecdh {
	t.Helper()
	e, err := core.ECDHFromKey(core.ECC_CURVE25519, hopKey(seed))
	if err != nil {
		t.Fatalf("ECDHFromKey: %v", err)
	}
	return e
}

// newHopVerifyingServer wires a forwarding test server whose receiving
// identity is a real core.Device (so ECDH verification runs). The trust
// anchor is the receiver's own pubkey (auto-trusted) plus any extra
// trustedPeers, fed through a real fleetTrustAnchor with a static
// discovery source so the handler exercises the production trust path.
func newHopVerifyingServer(t *testing.T, require bool, trustedPeers ...string) (*HttpServer, *core.Device) {
	t.Helper()
	bDevice := core.NewDevice(core.NHP_SERVER, hopKey(100), nil)
	if bDevice == nil {
		t.Fatal("core.NewDevice returned nil")
	}
	discovered := make([]ServerInfo, 0, len(trustedPeers))
	for _, p := range trustedPeers {
		discovered = append(discovered, ServerInfo{PubKey: p})
	}
	hs := newInternalKnockTestServer()
	hs.udpServer.device = bDevice
	hs.forwardHopRequire = require
	hs.fleetTrust = newFleetTrustAnchor(
		func(context.Context) ([]ServerInfo, error) { return discovered, nil },
		bDevice.PublicKeyBase64,
	)
	if hs.hopVerifyEcdh() == nil {
		t.Fatal("hopVerifyEcdh should be non-nil with device + fleetTrust")
	}
	return hs, bDevice
}

// TestHandleInternalKnock_HopStrict_ValidAttestationProceeds: a strict-mode
// receiver accepts a well-formed server-to-server forward and proceeds past
// the gate (200, not 401/403).
func TestHandleInternalKnock_HopStrict_ValidAttestationProceeds(t *testing.T) {
	gin.SetMode(gin.TestMode)
	a := hopEcdh(t, 1)
	hs, b := newHopVerifyingServer(t, true, a.PublicKeyBase64())

	fwdReq := buildKnockRequest("")
	att, err := buildForwardHopAttestation(a, a.PublicKeyBase64(), b.PublicKeyBase64(), 1, time.Now(), "", fwdReq.Request)
	if err != nil {
		t.Fatalf("build attestation: %v", err)
	}
	fwdReq.Attestation = att

	w := callHandleInternalKnock(t, hs, fwdReq)
	if w.Code != http.StatusOK {
		t.Fatalf("valid attestation should proceed, got %d: %s", w.Code, w.Body.String())
	}
	assertRetiredHTTPAdmissionResponse(t, w.Code, w.Body.Bytes())
}

// TestHandleInternalKnock_HopStrict_MissingRejected: strict mode rejects a
// server-to-server forward with no attestation (401).
func TestHandleInternalKnock_HopStrict_MissingRejected(t *testing.T) {
	gin.SetMode(gin.TestMode)
	hs, _ := newHopVerifyingServer(t, true, hopEcdh(t, 1).PublicKeyBase64())

	w := callHandleInternalKnock(t, hs, buildKnockRequest("")) // no attestation
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("strict missing attestation should be 401, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandleInternalKnock_HopPermit_MissingAllowed: permit mode warns and
// allows a missing attestation, and emits the permit counter.
func TestHandleInternalKnock_HopPermit_MissingAllowed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	hs, _ := newHopVerifyingServer(t, false, hopEcdh(t, 1).PublicKeyBase64())

	var mu sync.Mutex
	counts := map[string]int{}
	hs.internalAuthEmit = func(name string) {
		mu.Lock()
		counts[name]++
		mu.Unlock()
	}

	w := callHandleInternalKnock(t, hs, buildKnockRequest(""))
	if w.Code != http.StatusOK {
		t.Fatalf("permit missing attestation should proceed, got %d: %s", w.Code, w.Body.String())
	}
	assertRetiredHTTPAdmissionResponse(t, w.Code, w.Body.Bytes())
	if counts[MetricForwardHopAttestPermit] != 1 {
		t.Fatalf("expected one ForwardHopAttestPermit, got %d", counts[MetricForwardHopAttestPermit])
	}
}

// TestHandleInternalKnock_HopAPIOriginNoAttestation: an API origin carries no
// attestation and is benign even in strict mode (200), with no permit/reject
// counter.
func TestHandleInternalKnock_HopAPIOriginNoAttestation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	hs, _ := newHopVerifyingServer(t, true, hopEcdh(t, 1).PublicKeyBase64())

	var mu sync.Mutex
	counts := map[string]int{}
	hs.internalAuthEmit = func(name string) {
		mu.Lock()
		counts[name]++
		mu.Unlock()
	}

	w := callHandleInternalKnock(t, hs, buildKnockRequest(SourceAPI))
	if w.Code != http.StatusOK {
		t.Fatalf("API origin without attestation should proceed, got %d: %s", w.Code, w.Body.String())
	}
	assertRetiredHTTPAdmissionResponse(t, w.Code, w.Body.Bytes())
	if counts[MetricForwardHopAttestPermit] != 0 || counts[MetricForwardHopAttestReject] != 0 {
		t.Fatalf("API origin should not emit permit/reject, got %+v", counts)
	}
}

// TestHandleInternalKnock_HopCeiling_HardReject: an attestation claiming a hop
// above the ceiling is rejected (403) regardless of rollout mode.
func TestHandleInternalKnock_HopCeiling_HardReject(t *testing.T) {
	gin.SetMode(gin.TestMode)
	a := hopEcdh(t, 1)
	// permit mode (require=false) — ceiling reject must fire anyway.
	hs, b := newHopVerifyingServer(t, false, a.PublicKeyBase64())

	var mu sync.Mutex
	counts := map[string]int{}
	hs.internalAuthEmit = func(name string) {
		mu.Lock()
		counts[name]++
		mu.Unlock()
	}

	fwdReq := buildKnockRequest("")
	att, err := buildForwardHopAttestation(a, a.PublicKeyBase64(), b.PublicKeyBase64(), maxForwardHops+1, time.Now(), "", fwdReq.Request)
	if err != nil {
		t.Fatalf("build attestation: %v", err)
	}
	fwdReq.Attestation = att

	w := callHandleInternalKnock(t, hs, fwdReq)
	if w.Code != http.StatusForbidden {
		t.Fatalf("over-ceiling hop should be 403 even in permit mode, got %d: %s", w.Code, w.Body.String())
	}
	// The ceiling reject must use its own counter, not the strict-reject one.
	if counts[MetricForwardHopCeilingReject] != 1 {
		t.Fatalf("want one ForwardHopCeilingReject, got %d", counts[MetricForwardHopCeilingReject])
	}
	if counts[MetricForwardHopAttestReject] != 0 {
		t.Fatalf("ceiling reject must not emit the strict-reject counter, got %d", counts[MetricForwardHopAttestReject])
	}
}

// TestHandleInternalKnock_HopStrict_UnknownPeerRejected: a self-signed
// attestation from a server absent from the trust anchor is rejected (401).
func TestHandleInternalKnock_HopStrict_UnknownPeerRejected(t *testing.T) {
	gin.SetMode(gin.TestMode)
	a := hopEcdh(t, 1)
	// Trust anchor deliberately omits A (revoked / unregistered) — only
	// the receiver's own pubkey is trusted.
	hs, b := newHopVerifyingServer(t, true)

	fwdReq := buildKnockRequest("")
	att, err := buildForwardHopAttestation(a, a.PublicKeyBase64(), b.PublicKeyBase64(), 1, time.Now(), "", fwdReq.Request)
	if err != nil {
		t.Fatalf("build attestation: %v", err)
	}
	fwdReq.Attestation = att

	w := callHandleInternalKnock(t, hs, fwdReq)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown peer should be 401 in strict mode, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandleInternalKnock_HopStrict_ImpersonationRejected: a compromised third
// server signs an attestation but stamps another server's pubkey on it. Even
// though that claimed server is a trusted fleet member, the MAC (keyed by the
// receiver↔claimed-sender pair) fails and the request is rejected (401). This
// is the core #1127 property end-to-end.
func TestHandleInternalKnock_HopStrict_ImpersonationRejected(t *testing.T) {
	gin.SetMode(gin.TestMode)
	a := hopEcdh(t, 1)    // legitimate fleet member A
	evil := hopEcdh(t, 7) // compromised member E
	hs, b := newHopVerifyingServer(t, true, a.PublicKeyBase64())

	fwdReq := buildKnockRequest("")
	// E mints the attestation under its own key but claims to be A.
	forged, err := buildForwardHopAttestation(evil, a.PublicKeyBase64() /* lie */, b.PublicKeyBase64(), 1, time.Now(), "", fwdReq.Request)
	if err != nil {
		t.Fatalf("build attestation: %v", err)
	}
	fwdReq.Attestation = forged

	w := callHandleInternalKnock(t, hs, fwdReq)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("impersonation should be 401, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandleInternalKnock_HopPermit_InvalidAllowed: in permit mode a
// present-but-invalid attestation (tampered MAC) is warned-and-allowed and
// increments the permit counter — the rollout-window behavior, distinct from
// the missing-attestation case.
func TestHandleInternalKnock_HopPermit_InvalidAllowed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	a := hopEcdh(t, 1)
	hs, b := newHopVerifyingServer(t, false, a.PublicKeyBase64()) // permit

	var mu sync.Mutex
	counts := map[string]int{}
	hs.internalAuthEmit = func(name string) {
		mu.Lock()
		counts[name]++
		mu.Unlock()
	}

	fwdReq := buildKnockRequest("")
	att, err := buildForwardHopAttestation(a, a.PublicKeyBase64(), b.PublicKeyBase64(), 1, time.Now(), "", fwdReq.Request)
	if err != nil {
		t.Fatalf("build attestation: %v", err)
	}
	// Tamper one hex digit so the MAC always changes. The old
	// "00"+att.MAC[2:] silently no-op'd whenever the time-keyed MAC already
	// began with "00" (~1/256 of seconds, since the MAC signs time.Now via
	// the signing string), letting the "corrupted" attestation verify clean,
	// take the success branch instead of permit, and flake this assertion
	// (#2558). '0'→'f' / else→'0' always differs from the original digit, so
	// the MAC can never accidentally stay valid regardless of runner timing.
	if att.MAC[0] == '0' {
		att.MAC = "f" + att.MAC[1:]
	} else {
		att.MAC = "0" + att.MAC[1:]
	}
	fwdReq.Attestation = att

	w := callHandleInternalKnock(t, hs, fwdReq)
	if w.Code != http.StatusOK {
		t.Fatalf("permit-mode invalid attestation should proceed, got %d: %s", w.Code, w.Body.String())
	}
	assertRetiredHTTPAdmissionResponse(t, w.Code, w.Body.Bytes())
	if counts[MetricForwardHopAttestPermit] != 1 {
		t.Fatalf("want one ForwardHopAttestPermit, got %d", counts[MetricForwardHopAttestPermit])
	}
	if counts[MetricForwardHopAttestReject] != 0 {
		t.Fatalf("permit mode must not emit the strict-reject counter, got %d", counts[MetricForwardHopAttestReject])
	}
}

// TestInitForwardHopAttestation guards the receiver trust anchor retained for
// rolling overlap with historical forwarding servers.
func TestInitForwardHopAttestation(t *testing.T) {
	dev := core.NewDevice(core.NHP_SERVER, hopKey(100), nil)
	if dev == nil {
		t.Fatal("core.NewDevice returned nil")
	}

	t.Run("cloud mode wires receiver", func(t *testing.T) {
		// A zero-value *CloudMapClient is enough — initForwardHopAttestation
		// only takes a method value off it (DiscoverServerInstances), never
		// calls it.
		us := &UdpServer{device: dev, cloudMap: &CloudMapClient{}}
		hs := &HttpServer{udpServer: us}
		hs.initForwardHopAttestation(us)
		if hs.fleetTrust == nil {
			t.Error("receiver trust anchor not wired in cloud mode")
		}
		if hs.hopVerifyEcdh() == nil {
			t.Error("hopVerifyEcdh nil after cloud-mode wiring")
		}
	})

	t.Run("no device disables receiver", func(t *testing.T) {
		us := &UdpServer{cloudMap: &CloudMapClient{}} // device nil
		hs := &HttpServer{udpServer: us}
		hs.initForwardHopAttestation(us)
		if hs.fleetTrust != nil {
			t.Error("trust anchor must stay nil without a device keypair")
		}
	})

	t.Run("no cloudMap leaves receiver disabled", func(t *testing.T) {
		us := &UdpServer{device: dev} // cloudMap nil
		hs := &HttpServer{udpServer: us}
		hs.initForwardHopAttestation(us)
		if hs.fleetTrust != nil {
			t.Error("trust anchor must stay nil without Cloud Map")
		}
		if hs.hopVerifyEcdh() != nil {
			t.Error("hopVerifyEcdh must be nil when fleetTrust is unset")
		}
	})
}
