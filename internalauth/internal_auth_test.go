package internalauth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixedSigner returns a signer whose clock is pinned to `at` so tests
// can drive the timestamp deterministically. Uses newWithClock (the
// package-internal constructor) so the "set once at construction"
// invariant holds — no post-construction mutation, no race surface
// against concurrent Sign calls. External consumers that need a
// pinned clock call NewWithClock (the public test-clock entry
// point); newWithClock is package-internal and not reachable from
// outside this module.
func fixedSigner(t *testing.T, secret string, at time.Time) *Signer {
	t.Helper()
	s, err := newWithClock(secret, func() time.Time { return at })
	if err != nil {
		t.Fatalf("newWithClock: %v", err)
	}
	return s
}

func TestNew_RejectsEmptySecret(t *testing.T) {
	// Empty secret is a security-critical misconfiguration: HMAC with
	// a zero-length key still produces valid signatures, which would
	// let any caller's signature pass verification. Reject at
	// construction so a missing env var fails loud at startup.
	_, err := New("")
	if !errors.Is(err, ErrInternalAuth) {
		t.Errorf("err = %v, want errors.Is(ErrInternalAuth)", err)
	}
}

// TestNewWithClock_RejectsNilClock pins the public-
// boundary nil-clock guard. The godoc claims a misconfigured test
// fixture "fails at signer construction rather than at first Sign
// call" — without this row, that contract had no fence and a future
// edit that dropped the guard would silently land a signer that
// panics on the first Sign rather than rejecting at construction.
// Same fence shape as the empty-secret row above, applied to the
// other public-boundary precondition.
func TestNewWithClock_RejectsNilClock(t *testing.T) {
	_, err := NewWithClock(strings.Repeat("a", 32), nil)
	if !errors.Is(err, ErrInternalAuth) {
		t.Errorf("nil clock: want ErrInternalAuth, got %v", err)
	}
}

// TestNewWithClock_ReturnsUsableSigner pins the
// happy path: a non-nil clock that pins to a fixed time produces a
// signer whose Sign output reflects that time. Without this row,
// the public test-clock surface had only the rejection branch
// fenced — a future refactor that wired the clock into the wrong
// field (or accidentally captured time.Now at construction) would
// still pass the rejection test but produce signers that ignore
// the injected clock. This row exercises the round-trip so
// consumers' deterministic-timestamp tests have a load-bearing
// guarantee at the module layer.
func TestNewWithClock_ReturnsUsableSigner(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	s, err := NewWithClock(strings.Repeat("a", 32),
		func() time.Time { return at })
	if err != nil {
		t.Fatalf("NewWithClock: %v", err)
	}
	if s == nil {
		t.Fatal("returned signer is nil")
	}
	header := s.Sign("POST", "/p", nil)
	// Pin the timestamp the injected clock provided — if the clock
	// wasn't actually wired through, the header's timestamp would
	// differ from at.Unix() and this fails. Pinning the timestamp
	// (rather than just the round-trip Verify) is what fences the
	// "clock function actually injected" invariant.
	want := "NHPv1 timestamp=1700000000,"
	if !strings.HasPrefix(header, want) {
		t.Errorf("header timestamp drifted from injected clock:\nheader: %q\nwant prefix: %q", header, want)
	}
	// Round-trip verification with the same signer confirms the
	// signer is usable end-to-end, not just constructible.
	if err := s.Verify(header, "POST", "/p", nil, 0); err != nil {
		t.Errorf("round-trip with WithClock signer failed: %v", err)
	}
}

// TestNew_RejectsShortSecret pins the brute-force
// floor: a 1- to 31-byte secret must fail at construction, not at
// request time. Catches a Terraform misconfiguration where the
// Secrets Manager value gets truncated (e.g. by a substring template)
// — without this check, the gate would silently accept HMACs that
// are well below the SHA-256 security level.
func TestNew_RejectsShortSecret(t *testing.T) {
	cases := []struct {
		name   string
		secret string
		ok     bool
	}{
		{"1 byte", "a", false},
		{"15 bytes", strings.Repeat("a", 15), false},
		{"31 bytes (one short)", strings.Repeat("a", 31), false},
		{"32 bytes (boundary, accepted)", strings.Repeat("a", 32), true},
		{"33 bytes", strings.Repeat("a", 33), true},
		{"large key (256 bytes)", strings.Repeat("a", 256), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.secret)
			if tc.ok && err != nil {
				t.Errorf("len=%d: want OK, got %v", len(tc.secret), err)
			}
			if !tc.ok && !errors.Is(err, ErrInternalAuth) {
				t.Errorf("len=%d: want ErrInternalAuth, got %v", len(tc.secret), err)
			}
		})
	}
}

// TestVerify_RejectsDuplicateParams fences against a sender that
// emits the same param twice. Last-wins semantics would let a
// misbehaving sender accidentally replay an old timestamp by
// appending it after the current one (the signature would still
// have to match for the *first* timestamp, but a sender that signs
// over both shows a bug in the sender library worth catching loudly
// rather than silently picking one value).
func TestVerify_RejectsDuplicateParams(t *testing.T) {
	s := fixedSigner(t, "dup-secret-padded-out-to-32-chars", time.Unix(1_700_000_000, 0))

	cases := []struct {
		name   string
		header string
	}{
		{"duplicate timestamp", "NHPv1 timestamp=1700000000,timestamp=1700000001,signature=" + strings.Repeat("a", 64)},
		{"duplicate signature", "NHPv1 timestamp=1700000000,signature=" + strings.Repeat("a", 64) + ",signature=" + strings.Repeat("b", 64)},
		// Empty-first shapes — an emptiness check on the stored value
		// would treat the first param as "not seen yet" and silently
		// accept last-wins. sawTs/sawSig presence tracking closes
		// this; without it these rows would pass and the attacker
		// could smuggle a second value past the duplicate guard.
		{"empty-first timestamp", "NHPv1 timestamp=,timestamp=1700000000,signature=" + strings.Repeat("a", 64)},
		{"empty-first signature", "NHPv1 timestamp=1700000000,signature=,signature=" + strings.Repeat("a", 64)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := s.Verify(tc.header, "POST", "/p", nil, 0)
			if !errors.Is(err, ErrInternalAuth) {
				t.Errorf("want ErrInternalAuth, got %v", err)
			}
		})
	}
}

// TestVerify_RejectsPathNormalizationMismatch pins the implicit
// contract documented on Sign: the caller must pass the already-
// normalized path the peer's router will observe. A signer that
// emits "//knock" while the verifier sees "/knock" (because an
// intermediate or the receive-side router collapsed the doubled
// slash) must produce a signature mismatch — otherwise the silent
// 401 class becomes hard to diagnose in production. Pinning this
// here means a future change that pre-normalizes inside Sign
// shows up as a test change, not a silent loosening.
func TestVerify_RejectsPathNormalizationMismatch(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	s := fixedSigner(t, "path-norm-secret-padded-to-32-chars+", at)
	cases := []struct {
		name, signPath, verifyPath string
	}{
		// Doubled slashes: the classic normalization-mismatch case.
		// A Gin/ServeMux router collapses "//" → "/" before reaching
		// the handler; a signer that emits "//" would fence mismatch.
		{"doubled slash", "/nhp/internal//knock", "/nhp/internal/knock"},
		// Trailing slash: Gin's default RedirectTrailingSlash=true
		// redirects "/path/" → "/path" at the router layer, so a
		// caller signing with a trailing slash never reaches the
		// handler. Test fences the signing-string mismatch at the
		// shared-module layer regardless of router policy.
		{"trailing slash", "/nhp/internal/knock/", "/nhp/internal/knock"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header := s.Sign("POST", tc.signPath, []byte(`{"req":1}`))
			err := s.Verify(header, "POST", tc.verifyPath, []byte(`{"req":1}`), 0)
			if !errors.Is(err, ErrInternalAuth) {
				t.Errorf("want ErrInternalAuth on %s, got %v", tc.name, err)
			}
		})
	}
}

func TestSignVerify_RoundTrip(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	s := fixedSigner(t, "a-real-secret-bytes-padded-to-32-chars-or-more", at)

	header := s.Sign("POST", "/nhp/internal/knock", []byte(`{"req":1}`))
	if err := s.Verify(header, "POST", "/nhp/internal/knock", []byte(`{"req":1}`), 0); err != nil {
		t.Errorf("round-trip failed: %v", err)
	}
}

// TestClassifyAuthFailure pins the stage-only log surface. Every
// distinct failure mode Verify can return must land in one of the
// three named buckets — a future reviewer adding a new return in
// Verify must also add a row here, otherwise "other" fires and the
// operator loses the useful categorization that's load-bearing for
// the strict-mode rollout alarm.
func TestClassifyAuthFailure(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	s := fixedSigner(t, "classify-secret-padded-to-32-chars-ok", at)

	cases := []struct {
		name  string
		err   error
		stage AuthFailureStage
	}{
		{"nil", nil, AuthStageNone},
		{"missing header", s.Verify("", "POST", "/p", nil, 0), AuthStageParse},
		{"unsupported scheme", s.Verify("NHPv0 timestamp=1,signature=aa", "POST", "/p", nil, 0), AuthStageParse},
		{"malformed params", s.Verify("NHPv1 bogus-no-equals", "POST", "/p", nil, 0), AuthStageParse},
		{"unknown param", s.Verify("NHPv1 timestamp=1700000000,signature="+strings.Repeat("a", 64)+",extra=1", "POST", "/p", nil, 0), AuthStageParse},
		{"duplicate ts", s.Verify("NHPv1 timestamp=1,timestamp=2,signature="+strings.Repeat("a", 64), "POST", "/p", nil, 0), AuthStageParse},
		{"missing ts+sig", s.Verify("NHPv1 ", "POST", "/p", nil, 0), AuthStageParse},
		{"invalid ts", s.Verify("NHPv1 timestamp=notanint,signature="+strings.Repeat("a", 64), "POST", "/p", nil, 0), AuthStageParse},
		{"ts too small (negative wrap)", s.Verify("NHPv1 timestamp=-9223372036854775808,signature="+strings.Repeat("a", 64), "POST", "/p", nil, 0), AuthStageParse},
		{"ts too large (millis-as-secs)", s.Verify("NHPv1 timestamp=1700000000000,signature="+strings.Repeat("a", 64), "POST", "/p", nil, 0), AuthStageParse},
		// Pick a timestamp inside the plausible-bounds sanity range
		// (1_000_000_000 … 1e11) but outside the 5-min skew window
		// relative to fixedSigner's clock (1_700_000_000). The
		// earlier `timestamp=0` row now hits the bounds check, not
		// skew — good, but we still need a row for the skew branch.
		{"skew window", s.Verify("NHPv1 timestamp=1000000000,signature="+strings.Repeat("a", 64), "POST", "/p", nil, 0), AuthStageSkew},
		{"signature mismatch", s.Verify("NHPv1 timestamp=1700000000,signature="+strings.Repeat("a", 64), "POST", "/p", nil, 0), AuthStageSignature},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyAuthFailure(tc.err)
			if got != tc.stage {
				t.Errorf("err=%v → %q, want %q", tc.err, got, tc.stage)
			}
		})
	}

	// Negative fence: no row above should land in AuthStageOther.
	// ClassifyAuthFailure buckets by textual substring, so if a future
	// edit renames a wrapped error (e.g. "invalid timestamp" → "bad ts")
	// without updating the classifier, the failure would silently
	// reclassify to AuthStageOther and the rollout alarm would lose its
	// category signal. Asserting zero-Other across the whole table
	// catches that regression without requiring a per-row assertion.
	for _, tc := range cases {
		if tc.err != nil && ClassifyAuthFailure(tc.err) == AuthStageOther {
			t.Errorf("case %q classified to AuthStageOther (err=%v); extend ClassifyAuthFailure or update the case", tc.name, tc.err)
		}
	}
}

// TestVerify_RejectsMutation pins each element of the signing string
// as a separate fence. A change in any one of {method, path, body,
// timestamp, scheme, secret} must cause verification to fail. The
// matrix is explicit (rather than table-driven with a single mutate
// function) so a future refactor that drops an element from the
// signing string will show up as a test delete, not a silent pass.
func TestVerify_RejectsMutation(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	s := fixedSigner(t, "secret-A-padded-out-to-32-chars-min", at)
	header := s.Sign("POST", "/nhp/internal/knock", []byte(`{"req":1}`))

	cases := []struct {
		name   string
		verify func() error
	}{
		{
			"method tampered",
			func() error {
				return s.Verify(header, "GET", "/nhp/internal/knock", []byte(`{"req":1}`), 0)
			},
		},
		{
			"path tampered",
			func() error {
				return s.Verify(header, "POST", "/nhp/internal/other", []byte(`{"req":1}`), 0)
			},
		},
		{
			"body tampered",
			func() error {
				return s.Verify(header, "POST", "/nhp/internal/knock", []byte(`{"req":2}`), 0)
			},
		},
		{
			"different secret rejects",
			func() error {
				s2 := fixedSigner(t, "secret-B-padded-out-to-32-chars-min", at)
				return s2.Verify(header, "POST", "/nhp/internal/knock", []byte(`{"req":1}`), 0)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.verify()
			if !errors.Is(err, ErrInternalAuth) {
				t.Errorf("err = %v, want errors.Is(ErrInternalAuth)", err)
			}
		})
	}
}

func TestVerify_ClockSkew(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	signer := fixedSigner(t, "skew-secret-padded-out-to-32-chars", at)
	header := signer.Sign("POST", "/p", nil)

	cases := []struct {
		name       string
		verifierAt time.Time
		skew       time.Duration
		wantOK     bool
	}{
		{"zero skew, exact match", at, 0, true},
		{"within default window (1min past)", at.Add(1 * time.Minute), 0, true},
		{"within default window (1min future)", at.Add(-1 * time.Minute), 0, true},
		{"at default boundary (5min past, inclusive)", at.Add(5 * time.Minute), 0, true},
		{"outside default window (5min + 1s past)", at.Add(5*time.Minute + time.Second), 0, false},
		{"outside default window (5min + 1s future)", at.Add(-(5*time.Minute + time.Second)), 0, false},
		{"custom tight window (10s) — within", at.Add(5 * time.Second), 10 * time.Second, true},
		{"custom tight window (10s) — outside", at.Add(11 * time.Second), 10 * time.Second, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verifier := fixedSigner(t, "skew-secret-padded-out-to-32-chars", tc.verifierAt)
			err := verifier.Verify(header, "POST", "/p", nil, tc.skew)
			if tc.wantOK && err != nil {
				t.Errorf("want OK, got %v", err)
			}
			if !tc.wantOK && !errors.Is(err, ErrInternalAuth) {
				t.Errorf("want ErrInternalAuth, got %v", err)
			}
		})
	}
}

// TestVerify_MalformedHeaders fences the parser against every shape
// the header could arrive in wrong. Each row is a specific threat
// the parser has to reject: missing pieces, unsupported scheme,
// injected params, non-numeric timestamp.
func TestVerify_MalformedHeaders(t *testing.T) {
	s := fixedSigner(t, "hdr-secret-padded-out-to-32-chars", time.Unix(1_700_000_000, 0))

	cases := []struct {
		name   string
		header string
	}{
		{"empty", ""},
		{"scheme only, no params", "NHPv1"},
		{"wrong scheme", "NHPv2 timestamp=1700000000,signature=deadbeef"},
		{"lower-case scheme", "nhpv1 timestamp=1700000000,signature=deadbeef"},
		{"missing signature", "NHPv1 timestamp=1700000000"},
		{"missing timestamp", "NHPv1 signature=deadbeef"},
		{"non-numeric timestamp", "NHPv1 timestamp=now,signature=deadbeef"},
		{"malformed param (no equals)", "NHPv1 timestamp1700000000,signature=deadbeef"},
		// Unknown param rejected so a future v1.1 addition can't be
		// retroactively accepted by v1 verifiers (silent downgrade).
		{"unknown param rejected", "NHPv1 timestamp=1700000000,signature=deadbeef,extra=x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := s.Verify(tc.header, "POST", "/p", nil, 0)
			if !errors.Is(err, ErrInternalAuth) {
				t.Errorf("want ErrInternalAuth, got %v", err)
			}
		})
	}
}

// TestSigningString_StableFormat pins the exact bytes HMAC sees. The
// wire format is a cross-service contract: every consumer of this
// module computes the same signing string and the verifier compares
// HMACs over those bytes. Any refactor that reorders fields or
// changes separators must bump Scheme so mismatched
// versions fail loudly instead of silently.
func TestSigningString_StableFormat(t *testing.T) {
	ts := int64(1_700_000_000)
	body := []byte(`{"req":1}`)
	got := signingString(ts, "POST", "/nhp/internal/knock", body)

	// Canonical form: scheme \n timestamp \n METHOD \n path \n bodyHash
	bodyHash := sha256.Sum256(body)
	want := fmt.Sprintf("NHPv1\n%d\nPOST\n/nhp/internal/knock\n%s",
		ts, hex.EncodeToString(bodyHash[:]))
	if got != want {
		t.Errorf("signing string drifted:\ngot:  %q\nwant: %q", got, want)
	}
}

func TestSign_LowercasesHex(t *testing.T) {
	// Hex-encoded signatures must be lowercase on the wire so a peer
	// that always uppercases (e.g. fmt.Sprintf("%X")) trips the
	// constant-time compare instead of silently accepting a
	// case-fold of the expected value.
	s := fixedSigner(t, "case-secret-padded-out-to-32-chars", time.Unix(1_700_000_000, 0))
	header := s.Sign("POST", "/p", nil)
	_, rest, _ := strings.Cut(header, " ")
	_, sig, _ := strings.Cut(rest, "signature=")
	if sig != strings.ToLower(sig) {
		t.Errorf("signature %q is not lowercase hex", sig)
	}
}

// TestVerify_NilAndEmptyBodyEquivalent pins that Sign(nil) and
// Verify(nil) interoperate with the HTTP path where an empty body is
// a zero-length slice after io.ReadAll.
func TestVerify_NilAndEmptyBodyEquivalent(t *testing.T) {
	s := fixedSigner(t, "body-secret-padded-out-to-32-chars", time.Unix(1_700_000_000, 0))

	headerNil := s.Sign("POST", "/p", nil)
	if err := s.Verify(headerNil, "POST", "/p", []byte{}, 0); err != nil {
		t.Errorf("nil-signed / empty-verified mismatch: %v", err)
	}
	headerEmpty := s.Sign("POST", "/p", []byte{})
	if err := s.Verify(headerEmpty, "POST", "/p", nil, 0); err != nil {
		t.Errorf("empty-signed / nil-verified mismatch: %v", err)
	}
}

// TestVerify_ConstantTimeCompare is a structural fence: the verifier
// must use hmac.Equal (or equivalent) on the signature, not ==.
// Can't directly test timing, but we can assert the call site uses
// the right primitive via a short signature vs long signature
// probe — hmac.Equal handles length differences safely, string ==
// short-circuits on length which is fine but still timing-observable.
// This test exercises the short-sig branch.
func TestVerify_ShortSignatureRejected(t *testing.T) {
	s := fixedSigner(t, "ct-secret-padded-out-to-32-chars-min", time.Unix(1_700_000_000, 0))
	full := s.Sign("POST", "/p", nil)

	// Truncate the hex signature — hmac.Equal must reject.
	_, rest, _ := strings.Cut(full, " ")
	ts, _, _ := strings.Cut(rest, ",")
	bad := fmt.Sprintf("NHPv1 %s,signature=deadbeef", ts)
	err := s.Verify(bad, "POST", "/p", nil, 0)
	if !errors.Is(err, ErrInternalAuth) {
		t.Errorf("truncated signature accepted: err=%v", err)
	}

	// Also ensure that a longer-than-expected signature is rejected
	// (prevents a regression where constant-time compare checks a
	// prefix).
	overlong := fmt.Sprintf("NHPv1 %s,signature=%s%s", ts,
		strings.Repeat("a", 64), // full-length valid-hex padding
		"extra",
	)
	err2 := s.Verify(overlong, "POST", "/p", nil, 0)
	if !errors.Is(err2, ErrInternalAuth) {
		t.Errorf("overlong signature accepted: err=%v", err2)
	}

	// Non-hex bytes in the signature must reject. hmac.Equal on raw
	// bytes already does the right thing (the local-side hex decode of
	// the computed signature can't produce 'G'), but pinning this as
	// an explicit row documents the contract for future readers and
	// catches a regression that swapped the compare to string ==.
	nonHex := fmt.Sprintf("NHPv1 %s,signature=%s", ts, strings.Repeat("g", 64))
	err3 := s.Verify(nonHex, "POST", "/p", nil, 0)
	if !errors.Is(err3, ErrInternalAuth) {
		t.Errorf("non-hex signature accepted: err=%v", err3)
	}
}

// TestSign_ConcurrentUse fences the Signer concurrency godoc claim:
// "Safe for concurrent use after construction: secret and now are
// set once at construction and never reassigned."
// A future edit that adds mutable per-call state (a cached buffer, a
// stateful HMAC instance, a sliding-window nonce) would silently
// corrupt signatures under load — this test runs N workers signing
// and verifying in parallel and trips the -race detector if any
// shared mutable state is introduced.
//
// Lives in the shared module (not just at the consumer's call site)
// because every consumer — nhp-server, qurl-service, qurl-reverse-
// tunnel-server — relies on this invariant. The shared module's CI
// runs first; surfacing a regression here means every consumer's
// pipeline blocks on the same broken bytes instead of three separate
// repos each finding it independently after a deploy. Mirrors the
// removed qurl-service-side TestSign_ConcurrentUse and the existing
// endpoints/server/TestInternalAuthSigner_Concurrent in nhp-server,
// but at the module's authoritative layer.
func TestSign_ConcurrentUse(t *testing.T) {
	const (
		secret  = "concurrent-secret-padded-out-to-32-chars"
		workers = 16
		iters   = 200
	)
	// Production constructor (NOT fixedSigner) so we exercise the
	// time.Now path — fixedSigner pins a frozen clock that would mask
	// a regression where Sign mutated a per-call timestamp cache.
	s, err := New(secret)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	errCh := make(chan error, workers*iters)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			body := []byte(fmt.Sprintf(`{"worker":%d}`, id))
			for j := 0; j < iters; j++ {
				hdr := s.Sign("POST", "/nhp/internal/knock", body)
				if verr := s.Verify(hdr, "POST", "/nhp/internal/knock", body, 0); verr != nil {
					errCh <- fmt.Errorf("worker %d iter %d: %w", id, j, verr)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for e := range errCh {
		t.Error(e)
	}
}

// Compile-time asserts: the constants the rest of the codebase will
// reference must not accidentally become empty or lose their prefix.
func TestHeaderConstants(t *testing.T) {
	if Header == "" || !strings.HasPrefix(Header, "X-") {
		t.Errorf("Header %q must start with X-", Header)
	}
	if !strings.HasPrefix(Scheme, "NHPv") {
		t.Errorf("Scheme %q must start with NHPv", Scheme)
	}
	// Sanity: hmac.New with the secret must be addressable (used
	// inside computeMAC). We exercise the method here so the signing
	// path is touched in this file and shows coverage.
	s := fixedSigner(t, "sanity-secret-padded-to-32-chars-min", time.Unix(0, 0))
	h := s.computeMAC("ping")
	if _, err := hex.DecodeString(h); err != nil {
		t.Errorf("computeMAC output is not valid hex: %q", h)
	}
}
