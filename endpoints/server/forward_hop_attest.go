package server

// Cross-server forward hop attestation (issue #1127).
//
// The /nhp/internal/knock forward path previously prevented re-forward
// loops with a plaintext boolean (`Forwarded`) and an attacker-settable
// `Source` field. The shared HMAC gate added for #1122 authenticates
// "a party holding the shared NHP_INTERNAL_AUTH_SECRET" — but every
// fleet server holds that same secret, so a COMPROMISED server can forge
// the loop-breaking flag (set Source="api", mint Hop=0) exactly as a
// non-key-holder could before #1122. A shared-secret hop counter adds
// nothing against that threat: the compromised holder re-signs it.
//
// This file binds each server-to-server forward hop to the FORWARDING
// SERVER'S NHP IDENTITY using a per-pair MAC key derived from the X25519
// ECDH shared secret between the sender and the named recipient. Only the
// sender (holding its private key) and the recipient (holding its own)
// can compute that key, so:
//
//   - A third compromised fleet member CANNOT forge a hop that claims to
//     originate from some other server — it lacks both private keys.
//   - The recipient can ATTRIBUTE each hop to a specific server pubkey
//     and reject a sender whose pubkey is not in the live fleet registry
//     (the revocation lever: drop a server from Cloud Map → its forwards
//     fail fleet-wide, no fleet-wide secret rotation needed).
//   - maxForwardHops bounds any re-forward chain regardless of rollout
//     mode.
//
// Residual (documented, not closed): a single compromised fleet member
// can still emit its OWN attested hop=1 forwards — the MAC proves it is
// that server, not that the request is benign. That residual is bounded
// by maxForwardHops through honest servers and is revocable. Eliminating
// it entirely would require per-request authorization the forward path
// does not have. See docs/design/INTERNAL_FORWARD_HOP_ATTESTATION.md.
//
// Why this lives in endpoints/server and not the shared internalauth
// module: unlike the shared-secret internal-auth gate, this primitive
// depends on the nhp/core X25519 device keypair (ECDH) and the Cloud Map
// server registry — both nhp-server concepts. internalauth is deliberately
// pure-stdlib so cross-repo consumers (qurl-service, qurl-reverse-tunnel-
// server) keep CGO_ENABLED=0 and have no AWS/core dependency. Only
// nhp-servers attest hops (origins like qurl-service carry no
// attestation), so there is no cross-repo consumer to share with; the one
// genuinely shareable primitive (HMAC→hex) is reused via
// internalauth.ComputeHMACHex.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/layervai/nhp/internalauth"
)

const (
	// forwardHopScheme is the versioned domain tag baked into the
	// attestation signing string. Bumping it invalidates every in-flight
	// attestation in one coordinated step — same discipline as
	// internalauth.Scheme.
	forwardHopScheme = "NHP-FWD-HOP-v1"

	// forwardHopKDFInfo domain-separates the per-pair MAC key derived
	// from the raw ECDH secret. The same X25519 static keys back the NHP
	// Noise handshake; running the shared secret through an HMAC PRF with
	// this label keeps the hop-MAC key in a disjoint key space so neither
	// construction can be coaxed into producing the other's keystream.
	forwardHopKDFInfo = "nhp-internal-forward-hopbind-v1"

	// maxForwardHops is the hard ceiling on server-to-server forward
	// hops. Legitimate traffic forwards at most once (API origin = hop 0;
	// the single permitted server-to-server forward = hop 1), so the
	// ceiling of 2 is pure headroom that bounds any compromised- or
	// buggy-node re-forward chain. A request whose attested hop exceeds
	// this is refused regardless of rollout mode — it is a loop bound,
	// not an auth decision.
	maxForwardHops = 2

	// forwardHopFleetCacheTTL throttles Cloud Map discovery for the receiver
	// trust anchor. A newly joined rolling-overlap sender becomes trusted within
	// roughly one fleet-health window.
	forwardHopFleetCacheTTL = 30 * time.Second

	// forwardHopFleetErrorRetry is how soon discovery is retried after a
	// failed Cloud Map call, instead of waiting the full
	// forwardHopFleetCacheTTL. The refresh window is claimed before the RPC
	// runs, so without this a transient discovery error would defer the next
	// attempt a full cache-TTL even though no fresh data was obtained. Short
	// enough to recover promptly, long enough to still throttle during a
	// sustained Cloud Map outage (the 10-min sticky TTL keeps trust correct
	// meanwhile).
	forwardHopFleetErrorRetry = 5 * time.Second

	// forwardHopTrustTTL is the sticky window: a server pubkey stays
	// trusted this long after its last healthy Cloud Map sighting.
	// Cloud Map discovery is health-filtered, so without stickiness a
	// forwarder that transiently fails health checks during a deploy
	// would be rejected (strict) or permit-warned, and
	// ForwardHopAttestPermit would never settle to zero. 10 min comfortably
	// spans an instance-refresh health flap while bounding revocation
	// latency: a genuinely removed server is distrusted within this window
	// of its last sighting. Operators needing faster revocation of a
	// compromised peer should rotate the shared secret / terminate, not
	// rely on this window alone.
	forwardHopTrustTTL = 10 * time.Minute
)

// forwardHopMaxSkew bounds attestation freshness. Pinned to the same
// window as the rest of the internal surface so operators reason about
// one skew budget.
const forwardHopMaxSkew = internalauth.DefaultMaxClockSkew

// Verification failure causes. Kept as distinct sentinels so the handler
// can branch (origin-without-attestation is benign; hop-ceiling is a hard
// reject) and so forwardHopStage can log a one-token reason without
// echoing a sub-check oracle.
var (
	errForwardHopMissing     = errors.New("forward hop attest: missing attestation")
	errForwardHopBadPubKey   = errors.New("forward hop attest: malformed sender pubkey")
	errForwardHopBadHop      = errors.New("forward hop attest: hop out of range")
	errForwardHopStale       = errors.New("forward hop attest: timestamp outside freshness window")
	errForwardHopUnknownPeer = errors.New("forward hop attest: sender not a known fleet server")
	errForwardHopECDHFailed  = errors.New("forward hop attest: ECDH derivation failed")
	errForwardHopBadMAC      = errors.New("forward hop attest: MAC mismatch")
)

// forwardHopReqBind returns the canonical hex identity of a knock,
// binding an attestation to THIS specific request so a compromised peer
// cannot lift a valid attestation off one knock and replay it onto a
// different (malicious) knock inside the freshness window. The fields are
// the stable knock-intent identifiers; Token (the per-knock credential)
// makes the bind effectively unique per attempt. Forwarded/Ctx are
// deliberately excluded — Forwarded is mutated by the receiver after
// verification, and Ctx never crosses the wire.
//
// Fields are LENGTH-PREFIX framed (4-byte big-endian length + bytes), not
// "\n"-joined: the values are attacker-influenced (UserId/SrcIp/Token,
// etc.), and a value containing the separator could otherwise shift a field
// boundary so two distinct knocks hash to the same bind. Framing makes the
// encoding structurally unambiguous regardless of field contents — matching
// internalauth's fixed-width canonicalization discipline. The leading domain
// tag versions this bind format independently of the outer scheme.
func forwardHopReqBind(req *common.HttpKnockRequest) string {
	if req == nil {
		return "nil"
	}
	h := sha256.New()
	writeFramed := func(s string) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	for _, f := range []string{
		"nhp-fwd-hop-reqbind-v1",
		req.AuthServiceId,
		req.ResourceId,
		req.UserId,
		req.DeviceId,
		req.OrganizationId,
		req.SrcIp,
		req.Token,
	} {
		writeFramed(f)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// forwardHopSigningString is the canonical HMAC input. Newline-separated,
// no trailing newline (mirrors internalauth.signingString). senderPubB64
// is signed so the per-pair-symmetric MAC key — identical for A→B and
// B→A — cannot be abused to reflect a B→A attestation back as an A→B one:
// the signed sender identity differs.
//
// source is the envelope Source the attestation is bound to (empty for a
// server-to-server hop). Binding it prevents a captured server-to-server
// attestation from being resubmitted with Source flipped to "api" — which
// would otherwise keep Forwarded=false and induce one extra honest forward.
//
// Unlike forwardHopReqBind this uses "\n"-join, not length-prefix framing:
// of the six fields only `source` is variable-length, and it sits between a
// numeric `ts` and the fixed-64-hex `reqBindHex`, so no separator injection
// can shift a boundary into an ambiguous parse. (And a collision is moot
// regardless — producing a valid MAC requires the per-pair k_pair, which a
// non-fleet attacker cannot derive.) reqBind frames because ALL its inputs
// are attacker-influenced free-text; here the framing buys nothing.
func forwardHopSigningString(senderPubB64 string, hop int, ts int64, source, reqBindHex string) string {
	return strings.Join([]string{
		forwardHopScheme,
		senderPubB64,
		strconv.Itoa(hop),
		strconv.FormatInt(ts, 10),
		source,
		reqBindHex,
	}, "\n")
}

// forwardHopMACKey derives a 32-byte per-pair MAC key from the raw X25519
// ECDH shared secret with domain separation (HMAC-as-PRF, RFC 5869
// Extract style). Returns nil if the secret is unavailable (e.g. a
// malformed peer pubkey made SharedSecret return nil).
func forwardHopMACKey(ecdhSecret []byte) []byte {
	if len(ecdhSecret) == 0 {
		return nil
	}
	m := hmac.New(sha256.New, ecdhSecret)
	m.Write([]byte(forwardHopKDFInfo))
	return m.Sum(nil)
}

// verifyForwardHopAttestation checks a received hop attestation against
// the receiver's own key (selfEcdh) and the set of known fleet pubkeys.
// Returns nil iff the attestation is well-formed, within the hop ceiling,
// fresh, originates from a known fleet server, and carries a MAC valid
// under the per-pair key.
//
// Check order is deliberate: the structural / loop-bound checks (hop
// range, freshness) run BEFORE the trust-anchor and crypto checks so that
// errForwardHopBadHop is returned for any out-of-range hop regardless of
// whether the sender is a known peer — the handler treats that error as a
// hard loop reject independent of rollout mode. None of the early-return
// facts are secret, so the ordering leaks nothing useful.
func verifyForwardHopAttestation(selfEcdh core.Ecdh, att *ForwardHopAttestation, knownPubKeys map[string]bool, now time.Time, maxSkew time.Duration, source string, req *common.HttpKnockRequest) error {
	if att == nil {
		return errForwardHopMissing
	}
	if att.SenderPubKey == "" {
		return errForwardHopBadPubKey
	}
	// Hop ceiling — a real forward is hop >= 1; reject 0/negative and
	// anything above the loop ceiling. Checked first so the handler's
	// hard-reject branch fires for any over-hop attestation.
	if att.Hop < 1 || att.Hop > maxForwardHops {
		return errForwardHopBadHop
	}
	if maxSkew <= 0 {
		maxSkew = forwardHopMaxSkew
	}
	diff := now.Unix() - att.Timestamp
	if diff < 0 {
		diff = -diff
	}
	// Second-granularity comparison (ts is unix seconds). This assumes
	// maxSkew >= 1s; a sub-second maxSkew would truncate to 0 and reject
	// everything. Safe today — maxSkew is pinned to forwardHopMaxSkew
	// (5 min); the guard is here so a future sub-second value fails loudly
	// in review rather than silently in prod.
	if diff > int64(maxSkew/time.Second) {
		return errForwardHopStale
	}
	// Trust anchor: the sender pubkey must belong to a live fleet server.
	// A valid MAC alone only proves the sender holds the matching private
	// key; without this check a compromised member could present an
	// attacker-chosen keypair and self-attribute. This is also the
	// revocation lever.
	if !knownPubKeys[att.SenderPubKey] {
		return errForwardHopUnknownPeer
	}
	if selfEcdh == nil {
		return errForwardHopECDHFailed
	}
	peerPub, err := base64.StdEncoding.DecodeString(att.SenderPubKey)
	if err != nil {
		return errForwardHopBadPubKey
	}
	macKey := forwardHopMACKey(selfEcdh.SharedSecret(peerPub))
	if macKey == nil {
		return errForwardHopECDHFailed
	}
	expected := internalauth.ComputeHMACHex(macKey, forwardHopSigningString(att.SenderPubKey, att.Hop, att.Timestamp, source, forwardHopReqBind(req)))
	// Constant-time compare on the raw hex bytes — hmac.Equal is safe
	// against both length and content timing differences.
	if !hmac.Equal([]byte(expected), []byte(att.MAC)) {
		return errForwardHopBadMAC
	}
	return nil
}

// initForwardHopAttestation builds the receiver trust anchor for historical
// server-to-server HTTP envelopes during rollout overlap. Direct HTTP
// forwarding is retired, so this server no longer wires an outbound signer.
// It no-ops without a device keypair or Cloud Map fleet registry.
func (hs *HttpServer) initForwardHopAttestation(us *UdpServer) {
	if us == nil || us.device == nil {
		return
	}
	if us.cloudMap != nil {
		// Method values close over us.cloudMap / us.device, both fixed for
		// the server's lifetime.
		hs.fleetTrust = newFleetTrustAnchor(us.cloudMap.DiscoverServerInstances, us.device.PublicKeyBase64)
	}
}

// hopVerifyEcdh returns this server's static ECDH for hop-attestation
// verification, or nil when verification is inactive. Verification requires
// the server's own keypair (to derive the per-pair key) and a constructed
// trust anchor (the fleet pubkey source); without either — local/test or
// non-cloud deployments — it is skipped (the legacy posture, identical to
// the signer==nil branch of the shared-secret gate).
//
// A single nil/non-nil gate so the receiver fetches the ECDH exactly once.
// A constructed device always has a scheme-0 ECDH (core.NewDevice returns
// nil otherwise); the device-then-ECDH nil checks are defensive, and a nil
// result safely disables verification rather than strict-rejecting every
// forward. Sender and receiver both hardcode scheme 0.
func (hs *HttpServer) hopVerifyEcdh() core.Ecdh {
	if hs.udpServer == nil || hs.udpServer.device == nil || hs.fleetTrust == nil {
		return nil
	}
	return hs.udpServer.device.GetEcdhByCipherScheme(0)
}

// emitForwardHop emits a hop-attestation rollout counter, reusing the
// internal-auth metric emitter (nil-safe — no-op when unset, as in
// tests).
func (hs *HttpServer) emitForwardHop(metric string) {
	if hs.internalAuthEmit != nil {
		hs.internalAuthEmit(metric)
	}
}

// fleetTrustAnchor maintains the sticky set of fleet pubkeys trusted as
// hop-attestation senders. Extracted from HttpServer so the
// stickiness / eviction / throttle / discovery-error logic is unit-testable
// with an injected discovery source and clock (see
// fleet_trust_anchor_test.go).
//
// "Sticky" = a pubkey observed in any discovery stays trusted for
// forwardHopTrustTTL after its last sighting. This decouples trust from
// instantaneous health: Cloud Map discovery is health-filtered, so a
// forwarder that briefly fails health checks during a deploy must not be
// treated as un-attributable (which would flap ForwardHopAttestPermit and
// block the strict flip). Genuine removal (terminate/deregister) still
// revokes once the sticky window lapses.
type fleetTrustAnchor struct {
	mu      sync.Mutex
	seen    map[string]time.Time // pubkey → last healthy sighting
	refresh time.Time            // next discovery time (throttle)

	// discover returns the currently-healthy fleet servers. Production
	// wires CloudMapClient.DiscoverServerInstances; tests inject a fake.
	discover func(context.Context) ([]ServerInfo, error)
	// selfPub returns this server's own pubkey (always trusted), or "".
	selfPub func() string
	// now is the clock — time.Now in production, injected in tests.
	now func() time.Time
}

// newFleetTrustAnchor wires the production trust anchor. discover and
// selfPub must be non-nil; the clock defaults to time.Now.
func newFleetTrustAnchor(discover func(context.Context) ([]ServerInfo, error), selfPub func() string) *fleetTrustAnchor {
	return &fleetTrustAnchor{
		seen:     make(map[string]time.Time),
		discover: discover,
		selfPub:  selfPub,
		now:      time.Now,
	}
}

// known returns the trusted-sender set. Only the discovery RPC is throttled
// (at most once per forwardHopFleetCacheTTL); the set itself is rebuilt from
// the sticky map on every call (cheap at fleet scale, and only
// attestation-bearing forwarded knocks reach here). The discovery RPC runs
// WITHOUT mu held: a refreshing caller claims the next window under the lock,
// releases it for the network I/O, then re-acquires to merge — so a slow
// discovery can't serialize every concurrent /nhp/internal/knock verifier
// behind one round-trip. A discovery error preserves the existing sticky set
// (failing closed in strict mode on a transient blip is worse than a slightly
// stale set; the TTL still bounds staleness). The local server's own pubkey
// is always trusted.
func (a *fleetTrustAnchor) known(ctx context.Context) map[string]bool {
	now := a.now()

	// Claim the refresh window under the lock if due, so exactly one
	// caller per window performs discovery and the rest serve the cache.
	a.mu.Lock()
	doRefresh := now.After(a.refresh) && a.discover != nil
	if doRefresh {
		a.refresh = now.Add(forwardHopFleetCacheTTL)
	}
	a.mu.Unlock()

	// Network I/O without the lock. A discovery error leaves discovered
	// nil so the sticky set is served unchanged.
	var discovered []ServerInfo
	var discoverErr bool
	if doRefresh {
		instances, err := a.discover(ctx)
		if err != nil {
			discoverErr = true
			log.Warning("forward hop attest: fleet pubkey discovery failed: %v", err)
		} else {
			discovered = instances
		}
	}

	// Merge sightings, then a single pass that both evicts expired entries
	// (the revocation step) and builds the set returned to the caller.
	a.mu.Lock()
	defer a.mu.Unlock()
	if discoverErr {
		// The window was claimed (now+cacheTTL) before the failed RPC; pull
		// the next attempt in so a transient blip recovers within the
		// error-retry interval instead of the full cache TTL. Use a fresh
		// clock read rather than the pre-RPC `now`, so the retry floor holds
		// even when discovery was slow to fail (otherwise a failure taking
		// longer than the retry interval would land a.refresh in the past).
		a.refresh = a.now().Add(forwardHopFleetErrorRetry)
	}
	for _, inst := range discovered {
		if inst.PubKey != "" {
			a.seen[inst.PubKey] = now
		}
	}
	set := make(map[string]bool, len(a.seen)+1)
	for pub, seen := range a.seen {
		if now.Sub(seen) > forwardHopTrustTTL {
			delete(a.seen, pub)
			continue
		}
		set[pub] = true
	}
	// Self is trusted unconditionally — even before the first discovery
	// and regardless of its own health in Cloud Map.
	if a.selfPub != nil {
		if sp := a.selfPub(); sp != "" {
			set[sp] = true
		}
	}
	return set
}

// forwardHopStage maps a verification error to a one-token reason for
// operator logging, mirroring internalauth.ClassifyAuthFailure. Keeps the
// log line from echoing a sub-check oracle to anyone with log access.
func forwardHopStage(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, errForwardHopMissing):
		return "missing"
	case errors.Is(err, errForwardHopBadPubKey):
		return "pubkey"
	case errors.Is(err, errForwardHopBadHop):
		return "hop"
	case errors.Is(err, errForwardHopStale):
		return "skew"
	case errors.Is(err, errForwardHopUnknownPeer):
		return "unknown_peer"
	case errors.Is(err, errForwardHopECDHFailed):
		return "ecdh"
	case errors.Is(err, errForwardHopBadMAC):
		return "signature"
	default:
		return "other"
	}
}
