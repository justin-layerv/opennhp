// Package internalauth implements the HMAC canonicalization used by
// every server↔server and service↔server HTTP call on the VPC-internal
// /nhp/internal/* surface.
//
// Why this is its own module (and not an internal package): qurl-service,
// qurl-reverse-tunnel-server, and nhp-server all need byte-identical
// signing. Two hand-copies (the original setup) drifted at review-time
// risk; one shared module with a snapshot test means a change to the
// canonical signing string breaks every consumer's CI in lockstep
// instead of breaking signatures silently in production. The module is
// pure stdlib (crypto/hmac, crypto/sha256, encoding/hex, errors, fmt,
// strconv, strings, time) so consumers preserve CGO_ENABLED=0 builds.
//
// Scheme (X-Nhp-Auth header value):
//
//	NHPv1 timestamp=<unix>,signature=<hex-lower>
//
// Signed content (fields separated by "\n"; no trailing newline):
//
//	NHPv1\n<timestamp>\n<METHOD>\n<path>\n<sha256-hex-lower of body>
//
// Hex MUST be lowercase on the wire. The verifier compares hex bytes
// directly (constant-time, length-safe via hmac.Equal); a peer that
// uppercases its signature will fail verification. This is a strict
// format contract — TestSign_LowercasesHex pins the sender, and any
// future alternative encoder must continue to emit lowercase to
// interoperate with deployed verifiers.
//
// Replay protection is a bounded timestamp window enforced server-side
// (DefaultMaxClockSkew by default). The secret is loaded from env at
// process start, held in memory as []byte, and never logged.
//
// The scheme is distinct from endpoints/server/staticplugins/passcode/
// hmac_auth.go in the nhp repo — that one signs only the timestamp and
// is used for an end-user passcode flow, not internal service auth.
// Keeping them separate (instead of generalizing the passcode signer)
// avoids accidental cross-use: a secret leak on one surface does not
// authenticate the other.
package internalauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	// Header is the HTTP header carrying the signed auth.
	Header = "X-Nhp-Auth"
	// Scheme prefixes the header value and is part of the
	// signed string — bumping to v2 invalidates every v1 signer/verifier
	// in a single coordinated step.
	Scheme = "NHPv1"
	// DefaultMaxClockSkew bounds replay without requiring strict clock
	// sync. 5 minutes is long enough to tolerate VM pause / NTP drift
	// during fleet deploys and short enough that a captured header is
	// useless by the time the attacker can meaningfully replay it.
	DefaultMaxClockSkew = 5 * time.Minute
	// MinSecretLength is the minimum byte length accepted at signer
	// construction. HMAC-SHA256 is brute-forceable with a short key;
	// a misconfigured Terraform reference (e.g. a truncated Secrets
	// Manager value) that produced a 1- or 2-byte secret would pass
	// the empty-secret check but produce trivially-weak signatures.
	//
	// This is a minimum LENGTH, not a minimum entropy. A 32-character
	// all-`a` string passes and is trivially guessable — upstream
	// provisioning (Terraform's `random_password`, Secrets Manager's
	// `generate_secret_string`, etc.) is responsible for producing
	// random material. The floor only fences the class of bugs where a
	// substitution pipeline silently produces an empty or truncated
	// value, not the class where an operator hand-types a weak secret.
	MinSecretLength = 32
)

// ErrInternalAuth is the fixed sentinel returned on any auth failure.
// Callers log the underlying cause (via fmt.Errorf %w or a leaf err)
// at the server boundary; the header-level 401 response echoes only
// this sentinel so the attacker learns nothing about which arm of the
// check failed.
var ErrInternalAuth = errors.New("internal auth failed")

// AuthFailureStage classifies a Verify failure into a coarse category
// for operator logging. Exposed so handlers can log a one-token stage
// ("parse", "skew", "signature") instead of the full wrapped error —
// the latter would let an attacker with read access to the log
// aggregation stack distinguish signature-mismatch from stale-
// timestamp, partially undoing the sentinel-only response body.
type AuthFailureStage string

const (
	AuthStageNone      AuthFailureStage = "none"      // nil err — no failure; caller should not log
	AuthStageParse     AuthFailureStage = "parse"     // header missing/malformed, unknown/duplicate params, bad ts format
	AuthStageSkew      AuthFailureStage = "skew"      // timestamp outside the clock-skew window
	AuthStageSignature AuthFailureStage = "signature" // HMAC comparison failed
	AuthStageOther     AuthFailureStage = "other"     // unrecognized (shouldn't fire; defensive default)
)

// ClassifyAuthFailure bucketizes the error returned by Verify into one
// of the stages above. Use at the log site to avoid echoing the full
// wrapped error — attackers with log visibility must not be able to
// tell signature-mismatch apart from skew-rejection, which would
// recreate the oracle the 401 body was shaped to close.
//
// A nil error maps to AuthStageNone, not AuthStageOther — this
// distinguishes "no failure to classify" from "unknown failure
// shape". Callers generally guard with `if err != nil` before
// classifying, but the explicit None keeps "success" from
// accidentally looking like "other" if the guard is dropped.
//
// Implementation note: today this is suffix-prefix matching against
// Verify's error strings (the suffix after the ErrInternalAuth wrap).
// TestClassifyAuthFailure pins every current shape, so a regression
// shows up in CI — but the coupling is textual, not compile-time.
// The sturdier shape (typed sentinel errors wrapped via %w,
// classified via errors.Is) is tracked as follow-up #1230. Choosing
// to defer because: (a) the test suite already fences every return,
// (b) the scheme constant baked into the signing string means any
// subsequent refactor can land non-breaking, (c) the suffix-prefix
// match below tightens the coupling vs the original strings.Contains
// (which would silently re-bucket if a future error string contained
// "missing" or "duplicate" inadvertently — see #1838-class concern
// raised in PR-2b' round-8 cr review). Explicit choice, not
// oversight.
func ClassifyAuthFailure(err error) AuthFailureStage {
	if err == nil {
		return AuthStageNone
	}
	// Strip the ErrInternalAuth wrap once so each case below pins the
	// reason suffix at the start of the remaining string. This tightens
	// the coupling vs strings.Contains: a future return like "signature
	// missing required hex chars" now lands in the signature bucket
	// (correct), not silently in the parse bucket because it contained
	// the substring "missing" anywhere. Each prefix below corresponds
	// to exactly one fmt.Errorf call site in Verify.
	msg := err.Error()
	const wrap = "internal auth failed: "
	suffix := strings.TrimPrefix(msg, wrap)
	switch {
	case strings.HasPrefix(suffix, "signature mismatch"):
		return AuthStageSignature
	case strings.HasPrefix(suffix, "timestamp outside clock-skew window"):
		return AuthStageSkew
	case strings.HasPrefix(suffix, "missing "),
		strings.HasPrefix(suffix, "header missing "),
		strings.HasPrefix(suffix, "unsupported scheme"),
		strings.HasPrefix(suffix, "malformed "),
		strings.HasPrefix(suffix, "duplicate "),
		strings.HasPrefix(suffix, "unknown header param"),
		strings.HasPrefix(suffix, "invalid timestamp"),
		strings.HasPrefix(suffix, "timestamp outside plausible bounds"):
		return AuthStageParse
	default:
		return AuthStageOther
	}
}

// Signer signs and verifies internal-auth headers. The secret is
// captured by value at construction; rotation means constructing a
// new signer and swapping the handle, not mutating an existing one.
// Zero-length and short secrets are rejected at construction so a
// misconfigured env can't silently produce a verifier that accepts
// any signature.
//
// Replay window: the signed string binds (scheme, timestamp, method,
// path, body) but NO per-request nonce. Within the server-enforced
// maxSkew window (DefaultMaxClockSkew, 5 min), a VPC-local observer
// who captures a valid signed request can replay it against the
// same (method, path, body) tuple. For idempotent endpoints like
// the current /nhp/internal/knock (re-authorizes the same srcIP
// the original caller already authorized) this is self-limiting.
// Endpoints with non-idempotent side effects must add a nonce layer
// (server-side replay cache keyed on signing-string hash, or a
// nonce field bumping Scheme to v2) before they rely
// on this signer for replay protection — see layervai/nhp#1223.
//
// Safe for concurrent use after construction: secret and now are
// set once at construction and never reassigned. A future change
// that adds shared state (counter, sliding-window nonce, cached
// HMAC instance) would need to add explicit synchronization or
// document the unsafe semantics here. Tests that need to drive the
// clock construct a fresh signer per scenario via newWithClock
// rather than mutating an existing one.
type Signer struct {
	secret []byte
	// now is injected so tests can drive the clock without touching
	// time.Now globally. Production construction sets it to time.Now.
	// now must be safe for concurrent use — Sign and Verify fire
	// from many request goroutines. time.Now is safe; a test-time
	// closure over a mutable *time.Time would not be.
	now func() time.Time
}

// New returns a signer or an error. Empty and
// short secrets are rejected — a zero-length HMAC key produces valid
// signatures (HMAC(key="", msg) is well-defined) and a 1- to 31-byte
// key reduces the brute-force cost below the SHA-256 security level.
// The 32-byte minimum matches MinSecretLength (boundary inclusive,
// fenced by TestNew_RejectsShortSecret's 32-byte row); surface a
// config-shaped error so a Terraform misconfiguration fails at
// startup with a clear message instead of silently producing weak
// signatures.
func New(secret string) (*Signer, error) {
	return newWithClock(secret, time.Now)
}

// NewWithClock is the test-only constructor that pins the clock
// function. Production code MUST use New. Exposed (rather than
// mutating a `now` field on an existing signer post-construction)
// so the signer's "all fields set once at construction" invariant
// holds across every consumer's deterministic-timestamp tests,
// eliminating any data-race surface between concurrent Sign calls
// and a test's clock reassignment. clock must be non-nil; passing
// nil returns a wrapped ErrInternalAuth so a misconfigured test
// fixture fails at signer construction rather than at first Sign
// call.
func NewWithClock(secret string, clock func() time.Time) (*Signer, error) {
	if clock == nil {
		return nil, fmt.Errorf("%w: clock must be non-nil", ErrInternalAuth)
	}
	return newWithClock(secret, clock)
}

// newWithClock is the package-internal constructor used by both
// New (which wires time.Now) and NewWithClock (the public test-
// clock path that external consumers like qurl-service call to pin
// the clock in their own test suites). The nil-clock guard is
// enforced only at the public boundary (NewWithClock); package-
// internal callers already pass a non-nil clock literal (or
// time.Now) so a duplicate guard here would be defensive bloat
// without adding fence value. External consumers cannot call
// newWithClock and must use NewWithClock; the public boundary is
// the only supported escape hatch for deterministic-timestamp
// tests.
func newWithClock(secret string, clock func() time.Time) (*Signer, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("%w: secret must be non-empty", ErrInternalAuth)
	}
	if len(secret) < MinSecretLength {
		// Don't echo the actual length — in hostile deploy-log
		// forwarding setups (shared aggregator, Splunk fan-out)
		// an attacker who reads the log learns a secret-fingerprint
		// fact they shouldn't. Just say "too short".
		return nil, fmt.Errorf("%w: secret length below minimum (want >= %d bytes)", ErrInternalAuth, MinSecretLength)
	}
	return &Signer{
		secret: []byte(secret),
		now:    clock,
	}, nil
}

// Sign returns the X-Nhp-Auth header value for the given request.
// body may be nil for empty-body requests; the body hash is computed
// over an empty byte slice in that case (same as sha256("")).
//
// path must be the already-normalized path the peer's router will
// observe. Callers that build the URL by string concat must collapse
// doubled "/" themselves — the verifier receives ctx.Request.URL.Path
// which Gin has already normalized via its http.ServeMux layer. A
// signer that emits "//knock" against a verifier that sees "/knock"
// will produce a silent 401.
//
// Path contract: ASCII bytes only, no percent-encoded segments. Both
// the signer and verifier read URL.Path in its decoded form, so a
// request containing `%2F` inside a path component is ambiguous — the
// decoded form on either side may or may not match depending on how
// each side's HTTP framework handles percent-decoded slashes. The
// only callers of this endpoint today (the forwarder and qurl-service)
// use a fixed literal path (`/nhp/internal/knock`), so this is a
// documented contract rather than an enforced check. Adding a
// percent-encoded segment to the URL on either side is a breaking
// change that needs a coordinated rollout, not a silent deploy.
func (s *Signer) Sign(method, path string, body []byte) string {
	ts := s.now().Unix()
	signString := signingString(ts, method, path, body)
	sig := s.computeMAC(signString)
	return fmt.Sprintf("%s timestamp=%d,signature=%s", Scheme, ts, sig)
}

// Verify parses and checks the header. Returns nil on success, a
// wrapped ErrInternalAuth on any failure. maxSkew bounds the
// tolerated offset between the caller's timestamp and the server's
// clock; pass 0 (or any non-positive value) to use DefaultMaxClockSkew.
func (s *Signer) Verify(header, method, path string, body []byte, maxSkew time.Duration) error {
	if maxSkew <= 0 {
		maxSkew = DefaultMaxClockSkew
	}
	if header == "" {
		return fmt.Errorf("%w: missing %s header", ErrInternalAuth, Header)
	}

	scheme, rest, ok := strings.Cut(header, " ")
	if !ok || scheme != Scheme {
		return fmt.Errorf("%w: unsupported scheme", ErrInternalAuth)
	}

	// Track presence separately from value so an empty-first-then-real
	// duplicate (e.g. "signature=,signature=<real>") is rejected — an
	// emptiness check would treat the first empty value as "not yet
	// seen" and silently accept last-wins.
	var (
		tsStr, sigStr string
		sawTs, sawSig bool
	)
	for _, part := range strings.Split(rest, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return fmt.Errorf("%w: malformed header params", ErrInternalAuth)
		}
		switch k {
		case "timestamp":
			// Reject duplicate keys — last-wins semantics would let
			// a misbehaving sender accidentally replay an old
			// timestamp by appending it after the current one. Same
			// rationale applies to signature.
			if sawTs {
				return fmt.Errorf("%w: duplicate timestamp param", ErrInternalAuth)
			}
			sawTs = true
			tsStr = v
		case "signature":
			if sawSig {
				return fmt.Errorf("%w: duplicate signature param", ErrInternalAuth)
			}
			sawSig = true
			sigStr = v
		default:
			// Unknown keys are rejected — a future v1.1 that adds a
			// new key must bump the scheme to invalidate old verifiers
			// in lockstep. Silently accepting them would let a
			// downgrade attack land.
			return fmt.Errorf("%w: unknown header param %q", ErrInternalAuth, k)
		}
	}
	if tsStr == "" || sigStr == "" {
		return fmt.Errorf("%w: header missing timestamp or signature", ErrInternalAuth)
	}

	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: invalid timestamp", ErrInternalAuth)
	}
	// Sanity range: reject timestamps outside plausible bounds
	// BEFORE the skew subtraction. Without this, a pathological
	// `timestamp=-9223372036854775808` overflows two's complement
	// in (now - ts). Still not exploitable (the attacker needs a
	// valid signature for that timestamp), but also catches a
	// misconfigured peer sending millisecond-since-epoch instead
	// of seconds — currently those would fail the skew check
	// after wraparound with a confusing error message.
	//
	// Lower: 2001-09-09 (Unix second 1_000_000_000) — comfortably
	// before the NHP protocol exists, so any real clock producing
	// something smaller is already broken. Upper: 5138 (Unix
	// second 1e11) — ~3000 years out; leaves room for a time
	// source that's incorrectly set to a far-future date.
	const (
		minPlausibleTs = int64(1_000_000_000)
		maxPlausibleTs = int64(100_000_000_000)
	)
	if ts < minPlausibleTs || ts > maxPlausibleTs {
		return fmt.Errorf("%w: timestamp outside plausible bounds", ErrInternalAuth)
	}

	now := s.now().Unix()
	diff := now - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > int64(maxSkew/time.Second) {
		return fmt.Errorf("%w: timestamp outside clock-skew window (%ds)", ErrInternalAuth, diff)
	}

	expected := s.computeMAC(signingString(ts, method, path, body))
	// Constant-time compare on the raw hex bytes — hmac.Equal is safe
	// against both length and content timing differences.
	if !hmac.Equal([]byte(expected), []byte(sigStr)) {
		return fmt.Errorf("%w: signature mismatch", ErrInternalAuth)
	}
	return nil
}

// computeMAC runs HMAC-SHA256(secret, data) and returns lowercase hex.
// Named deliberately to not shadow the crypto/hmac package imported
// into this file — `s.hmac(...)` next to `hmac.New(...)` inside the
// same method body reads ambiguously to a skimming reviewer.
func (s *Signer) computeMAC(data string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

// signingString is the canonical input to HMAC. Test vectors that
// pin the wire format across signer/verifier versions exercise it
// through Sign/Verify end-to-end; the snapshot test in
// internal_auth_snapshot_test.go also pins the exact bytes for a
// fixed reference vector, so a refactor that reorders fields or
// changes separators must bump Scheme and land
// identically on every consumer.
func signingString(ts int64, method, path string, body []byte) string {
	bodyHash := sha256.Sum256(body)
	return fmt.Sprintf("%s\n%d\n%s\n%s\n%s",
		Scheme,
		ts,
		strings.ToUpper(method),
		path,
		hex.EncodeToString(bodyHash[:]),
	)
}
