package qurlv2

import (
	"errors"
	"strings"
	"testing"
)

// Fuzz targets for the hand-rolled strict parser. A token-walk parser over
// attacker-controlled, unauthenticated input is exactly where fuzzing pays off:
// the only invariant asserted here is that parsing NEVER panics (it must always
// return a value or an error, never crash). Behavior correctness is covered by
// the table tests; this guards the robustness of the structural walk, the
// container drain, the base64url decode, and the key-length checks against
// pathological byte sequences.

// FuzzParseClaims fuzzes the decoded-claims-JSON parser directly (the bytes that
// come out of base64url-decoding fragment Part 1).
func FuzzParseClaims(f *testing.F) {
	// Seed with a valid object and a spread of adversarial shapes the table tests
	// already name, so the fuzzer starts from interesting structure.
	f.Add([]byte(`{"v":2,"iss":"qurl-service","kid":"k","iat":1,"nbf":1,"exp":2,"jti":"j","cell_public_key_b64":"AAAA","cell_id":"c","relay_url":"https://r","resource_public_key_b64":"AAAA","qurl_user_public_key_b64":"AAAA"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"v":2,"v":2}`))                   // duplicate key
	f.Add([]byte(`{"exp":1e9}`))                     // exponent number
	f.Add([]byte(`{"exp":1.5}`))                     // fractional number
	f.Add([]byte(`{"jti":["x"]}`))                   // array-for-scalar
	f.Add([]byte(`{"cell_id":{"a":{"b":[1,2,3]}}}`)) // nested container drain
	f.Add([]byte(`{"unknown":1}`))                   // unknown field
	f.Add([]byte(`{"v":null}`))                      // null value
	f.Add([]byte(`{} trailing`))                     // trailing data
	f.Add([]byte(``))                                // empty
	f.Add([]byte(`{"v":2,"iss":"qurl-service"`))     // truncated

	f.Fuzz(func(_ *testing.T, raw []byte) {
		// Must not panic. The result is intentionally ignored — both a parsed
		// value and an error are acceptable outcomes for arbitrary input.
		_, _ = parseClaims(raw)
		_, _ = parseSecret(raw)
	})
}

// FuzzParseFragment fuzzes the full fragment parser (prefix + 3 base64url parts),
// the layer that runs first on an unauthenticated URL fragment.
func FuzzParseFragment(f *testing.F) {
	f.Add("qv2.AAAA.BBBB.CCCC")
	f.Add("#qv2.AAAA.BBBB.CCCC")
	f.Add("qv2..BBBB.CCCC")          // empty claims part
	f.Add("qv1.AAAA.BBBB.CCCC")      // wrong prefix
	f.Add("qv2.AAAA.BBBB")           // too few parts
	f.Add("qv2.AAAA.BBBB.CCCC.DDDD") // too many parts
	f.Add("qv2.AA==.BBBB.CCCC")      // padded base64
	f.Add("qv2.A*A.BBBB.CCCC")       // non-base64url char
	f.Add(strings.Repeat(".", 100))  // many empty parts
	f.Add("")                        // empty

	f.Fuzz(func(_ *testing.T, fragment string) {
		// Must not panic. ParseFragment is the unauthenticated entrypoint.
		_, _ = ParseFragment(fragment)
	})
}

// FuzzDecodeTransport exercises the unauthenticated outer-fragment framing
// boundary. An error must never leak partial canonical output; an accept must
// stay inside the total bound and reconstruct only a qv2 body.
func FuzzDecodeTransport(f *testing.F) {
	f.Add("qv2t1.1.1.1.A.B.C")
	f.Add("qv2.A.B.C")
	f.Add(strings.Repeat("A", TransportMaxLength+1))

	f.Fuzz(func(t *testing.T, body string) {
		canonical, err := DecodeTransport(body)
		if err != nil {
			if canonical != "" {
				t.Fatalf("DecodeTransport returned output %q with error %v", canonical, err)
			}
			return
		}
		if len(body) > TransportMaxLength {
			t.Fatalf("oversize transport unexpectedly accepted: %d", len(body))
		}
		if !strings.HasPrefix(canonical, FragmentPrefix+".") {
			t.Fatalf("accepted transport returned non-canonical prefix: %q", canonical)
		}
	})
}

// FuzzDecodeB64Canonical asserts the security-critical canonicality property of
// decodeB64: it accepts a string ONLY if that string is the unique canonical
// encoding of the bytes it decodes to. If decode succeeds, re-encoding the bytes
// (through the same encodeB64 the decoder checks against) must reproduce the exact
// input — otherwise a non-canonical variant of a signed part (notably one with
// embedded '\r'/'\n', which Go's base64 decoder silently skips) would be accepted,
// making fragments malleable.
func FuzzDecodeB64Canonical(f *testing.F) {
	f.Add("")
	f.Add("AAAA")
	f.Add("AQID")
	f.Add("_-_-")
	f.Add("A")    // length 1 mod 4
	f.Add("AAA=") // padding
	f.Add("AAB")  // non-canonical trailing bits
	f.Add("\r")   // bare CR: Go's decoder skips it; must be rejected as non-canonical
	f.Add("\n")   // bare LF: same
	f.Add("A\nA") // embedded LF inside otherwise-valid base64

	f.Fuzz(func(t *testing.T, s string) {
		raw, err := decodeB64(s)
		if err != nil {
			if !errors.Is(err, ErrEncoding) {
				t.Fatalf("decodeB64 rejected %q with non-ErrEncoding error: %v", s, err)
			}
			return
		}
		if got := encodeB64(raw); got != s {
			t.Fatalf("decodeB64 accepted non-canonical %q (canonical form is %q)", s, got)
		}
	})
}
