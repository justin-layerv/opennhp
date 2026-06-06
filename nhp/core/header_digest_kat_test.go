package core

import (
	"bytes"
	"hash"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// TestHeaderDigestKnownAnswer is a known-answer test (KAT) that locks the exact
// on-wire byte layout the header digest is computed over.
//
// TestCheckHeaderDigestDoesNotAllocateHashScratch already exercises compute +
// verify + tamper, but it derives its expected value dynamically, so it cannot
// detect a change to the absolute byte layout (a field reorder/offset/size
// change would recompute the "expected" the same wrong way and stay green).
// This test instead builds a fully deterministic header, computes the digest
// exactly as addHeaderDigest/checkHeaderDigest do (initial constant + responder
// static public key + header prefix [+ cookie for the NHP_RKN case]), and
// asserts the result equals a hardcoded golden. Any change to the field order,
// offsets, or sizes of curve.HeaderCurve shifts the hashed prefix and flips the
// golden, catching the wire-format regression the #2335 rename rests on. The
// goldens are also fed back through the production checkHeaderDigest verify path
// on all three of its branches (no cookie, current cookie, previous cookie), so
// the receiver's recomputation is locked to the same layout the digest is built
// over. See #2383.
func TestHeaderDigestKnownAnswer(t *testing.T) {
	ciphers := NewCipherSuite()

	// The goldens below are computed under BLAKE2s-256 (the default suite's hash,
	// whose 32-byte output is HashSize). Pin that assumption so a future change
	// to the default cipher suite fails here with a clear cause rather than a
	// bare golden mismatch. (The goldens also bake in PublicKeySize and
	// InitialHashString; those surface via the length guard below and the
	// regenerate note on the goldens.)
	if ciphers.HashType != HASH_BLAKE2S {
		t.Fatalf("goldens assume HASH_BLAKE2S; default suite hash is now %v — regenerate them", ciphers.HashType)
	}

	// The responder static public key is the second hash input (after the
	// initial constant); a fixed value keeps the goldens reproducible.
	var staticPubKey [PublicKeySize]byte
	for i := range staticPubKey {
		staticPubKey[i] = byte(0xA0 + i)
	}

	fill := func(b []byte, v byte) {
		for i := range b {
			b[i] = v
		}
	}

	// newDeterministicHeader builds a HeaderCurve whose every byte is fixed.
	// Each typed field is filled with a distinct constant *through its accessor*,
	// so the value at every offset is placed by the struct layout itself — a
	// field reorder/resize moves the constants and changes the hashed prefix.
	// SetTypeAndPayloadSize is intentionally avoided: it draws a random preamble
	// (utils.GetRandomUint32), which would make the digest non-deterministic.
	newDeterministicHeader := func() Header {
		var packetBuf PacketBuffer
		pkt := &Packet{
			Buf:        &packetBuf,
			Content:    packetBuf[:],
			HeaderType: NHP_KNK,
		}
		header := pkt.HeaderWithCipherScheme(common.CIPHER_SCHEME_CURVE)

		// Pre-fill the whole header with a HeaderCommon sentinel, then stamp each
		// typed field with a distinct constant through its accessor. The bytes
		// left at the sentinel are exactly the HeaderCommon block (the prefix not
		// reachable through a field accessor), so this needs no curve-package
		// internals or hardcoded offsets. The trailing HeaderDigest bytes also
		// get the sentinel, but they sit past the hashed prefix and are
		// overwritten with the golden below.
		fill(header.Bytes(), 0xC0)
		fill(header.EphermeralBytes(), 0xE1)
		fill(header.IdentityBytes(), 0x1D)
		fill(header.StaticBytes(), 0x57)
		fill(header.TimestampBytes(), 0x71)
		return header
	}

	// newSeededHash returns a hash pre-seeded with the responder's first two
	// digest inputs — the initial constant and the static public key — exactly as
	// addHeaderDigest/checkHeaderDigest seed before mixing in the header prefix.
	// checkHeaderDigest consumes and nils ppd.digestHash, so verify callers
	// reseed with this before each call.
	newSeededHash := func(t *testing.T) hash.Hash {
		h, err := NewHash(ciphers.HashType)
		if err != nil {
			t.Fatalf("NewHash failed: %v", err)
		}
		h.Write(initialHashBytes)
		h.Write(staticPubKey[:])
		return h
	}

	// computeDigest mirrors addHeaderDigest/checkHeaderDigest exactly: the seeded
	// hash, the header prefix, then (RKN only) the connection cookie. It
	// reimplements the computation rather than calling addHeaderDigest (which
	// needs a fully populated MsgAssemblerData) on purpose — the "verify accepts
	// golden" subtest routes each golden back through the production
	// checkHeaderDigest, which is what binds this reimplementation to production.
	computeDigest := func(t *testing.T, header Header, cookie []byte) []byte {
		h := newSeededHash(t)
		prefixLen := header.Size() - len(header.HeaderDigestBytes())
		h.Write(header.Bytes()[:prefixLen])
		if cookie != nil {
			h.Write(cookie)
		}
		return h.Sum(nil)
	}

	// Golden digests — the lock. They bake in every input to the header hash: the
	// HeaderCurve field layout, the fixed field-fill constants in
	// newDeterministicHeader (0xC0/0xE1/0x1D/0x57/0x71), the cookie fill patterns
	// below (currCookie[i]=i, prevCookie[i]=0x80+i) for the two RKN goldens,
	// InitialHashString, the responder static pubkey (PublicKeySize bytes), and
	// the default suite's BLAKE2s hash. Regenerate ONLY on an intentional change
	// to one of those, and explain it in the commit — run the test and copy the
	// %#v value the failing assertion prints. A diff here means the bytes fed to
	// the header hash moved.
	wantNoCookie := []byte{
		0x53, 0x60, 0x91, 0xd2, 0x00, 0x2e, 0xc9, 0x3b,
		0x89, 0x41, 0x0e, 0x4e, 0x7e, 0x6f, 0x19, 0xeb,
		0xdd, 0xb4, 0x76, 0x68, 0xba, 0x00, 0x62, 0x8f,
		0x18, 0xcd, 0x9a, 0xf7, 0x2a, 0x72, 0x4d, 0x33,
	}
	wantCurrCookie := []byte{
		0x1f, 0xf8, 0x45, 0x95, 0x44, 0x35, 0x85, 0xfe,
		0xbc, 0x28, 0xa3, 0x13, 0x87, 0x65, 0x31, 0x33,
		0x7d, 0x47, 0x79, 0x39, 0x24, 0xea, 0x6f, 0x69,
		0x07, 0x9e, 0x7c, 0x51, 0x25, 0xbe, 0xdb, 0xfd,
	}
	wantPrevCookie := []byte{
		0x13, 0xe3, 0xf9, 0x16, 0xf2, 0x9d, 0xfc, 0xa0,
		0x21, 0xf7, 0x57, 0x84, 0xc2, 0xc3, 0x18, 0x02,
		0x6b, 0x3e, 0x68, 0x76, 0xdc, 0x89, 0x39, 0xa3,
		0xde, 0x53, 0xbf, 0x5b, 0xf0, 0x7d, 0x06, 0xa3,
	}

	// Each golden is a full digest, so it must be HashSize bytes. A HashSize
	// change would otherwise surface only as a bare length-mismatched golden
	// diff; name the cause here instead.
	for _, g := range [][]byte{wantNoCookie, wantCurrCookie, wantPrevCookie} {
		if len(g) != HashSize {
			t.Fatalf("golden length = %d, want HashSize (%d) — regenerate the goldens", len(g), HashSize)
		}
	}

	// The three goldens must be mutually distinct, else a curr/prev (or
	// cookie/no-cookie) collapse could slip past the verify subtest by hashing to
	// a shared value. Lock distinctness at the golden layer too.
	if bytes.Equal(wantNoCookie, wantCurrCookie) ||
		bytes.Equal(wantNoCookie, wantPrevCookie) ||
		bytes.Equal(wantCurrCookie, wantPrevCookie) {
		t.Fatal("goldens must be mutually distinct; two collapsed to the same value")
	}

	// Deterministic cookies for the NHP_RKN path: distinct current/previous
	// values so the golden detects a curr/prev mix-up.
	var currCookie, prevCookie [CookieSize]byte
	for i := range currCookie {
		currCookie[i] = byte(i)
		prevCookie[i] = byte(0x80 + i)
	}

	// Each subtest builds its own header so there is no cross-subtest ordering
	// dependency (the mutation case below corrupts the header it uses).

	t.Run("golden", func(t *testing.T) {
		header := newDeterministicHeader()
		if got := computeDigest(t, header, nil); !bytes.Equal(got, wantNoCookie) {
			t.Fatalf("no-cookie digest = %#v, want golden %#v", got, wantNoCookie)
		}
		if got := computeDigest(t, header, currCookie[:]); !bytes.Equal(got, wantCurrCookie) {
			t.Fatalf("current-cookie digest = %#v, want golden %#v", got, wantCurrCookie)
		}
		if got := computeDigest(t, header, prevCookie[:]); !bytes.Equal(got, wantPrevCookie) {
			t.Fatalf("previous-cookie digest = %#v, want golden %#v", got, wantPrevCookie)
		}
	})

	t.Run("verify accepts golden", func(t *testing.T) {
		header := newDeterministicHeader()
		ppd := &PacketParserData{header: header}
		accept := func(sumCookie bool, golden []byte, what string) {
			copy(header.HeaderDigestBytes(), golden)
			ppd.digestHash = newSeededHash(t)
			if !ppd.checkHeaderDigest(sumCookie) {
				t.Fatalf("checkHeaderDigest(%v) rejected the golden %s digest", sumCookie, what)
			}
		}

		accept(false, wantNoCookie, "no-cookie")

		// Cookie branch selection keys off LocalInitTime vs LastCookieTime + RTT
		// (strict <): above the threshold → CurrCookie, below it → PrevCookie.
		ppd.ConnData = &ConnectionData{CookieStore: &CookieStore{
			CurrCookie:     currCookie,
			PrevCookie:     prevCookie,
			LastCookieTime: 1,
		}}
		ppd.LocalInitTime = 1 << 60
		accept(true, wantCurrCookie, "current-cookie")
		ppd.LocalInitTime = 0
		accept(true, wantPrevCookie, "previous-cookie")
	})

	t.Run("verify rejects a tampered field", func(t *testing.T) {
		// The production verifier must reject a header carrying the no-cookie
		// golden once any prefix byte is tampered — confirming no field is left
		// out of checkHeaderDigest's hashed region. (The golden subtest already
		// locks the *computed* digest over the full prefix; this locks the
		// *verify* side.) Probe one byte per field, including the HeaderCommon and
		// Timestamp ends, so coverage spans the whole prefix, not one offset.
		mutations := []struct {
			name   string
			mutate func(h Header)
		}{
			{"HeaderCommon", func(h Header) { h.Bytes()[0] ^= 0xff }},
			{"Ephermeral", func(h Header) { h.EphermeralBytes()[0] ^= 0xff }},
			{"Identity", func(h Header) { h.IdentityBytes()[0] ^= 0xff }},
			{"Static", func(h Header) { h.StaticBytes()[0] ^= 0xff }},
			{"Timestamp", func(h Header) { b := h.TimestampBytes(); b[len(b)-1] ^= 0xff }},
		}
		for _, m := range mutations {
			t.Run(m.name, func(t *testing.T) {
				header := newDeterministicHeader()
				copy(header.HeaderDigestBytes(), wantNoCookie) // valid for the untampered header
				m.mutate(header)                               // ...now stale

				ppd := &PacketParserData{header: header}
				ppd.digestHash = newSeededHash(t)
				if ppd.checkHeaderDigest(false) {
					t.Fatalf("checkHeaderDigest accepted a header tampered in %s", m.name)
				}
			})
		}

		// Symmetry with "verify accepts golden": the cookie branch hashes the same
		// prefix before mixing the cookie, so a tampered prefix must be rejected on
		// both cookie selections too. One field probe per selection suffices — the
		// per-field coverage above is branch-independent; here we just exercise
		// each cookie branch of the verifier.
		cookieProbes := []struct {
			name          string
			golden        []byte
			localInitTime int64 // vs LastCookieTime+RTT: above → CurrCookie, below → PrevCookie
		}{
			{"current cookie", wantCurrCookie, 1 << 60},
			{"previous cookie", wantPrevCookie, 0},
		}
		for _, c := range cookieProbes {
			t.Run(c.name, func(t *testing.T) {
				header := newDeterministicHeader()
				copy(header.HeaderDigestBytes(), c.golden) // valid for the untampered header
				header.StaticBytes()[0] ^= 0xff            // ...now stale
				ppd := &PacketParserData{
					header: header,
					ConnData: &ConnectionData{CookieStore: &CookieStore{
						CurrCookie:     currCookie,
						PrevCookie:     prevCookie,
						LastCookieTime: 1,
					}},
				}
				ppd.LocalInitTime = c.localInitTime
				ppd.digestHash = newSeededHash(t)
				if ppd.checkHeaderDigest(true) {
					t.Fatalf("checkHeaderDigest(true) accepted a header tampered in Static on the %s branch", c.name)
				}
			})
		}
	})
}
