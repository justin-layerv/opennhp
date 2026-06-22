package qurlv2

import (
	"fmt"
	"time"
)

// Liveness (clock-dependent) checks for the admission path.
//
// The strict parser deliberately enforces only the CLOCK-FREE ordering bounds
// (iat<=exp, nbf<=exp) because this package has no trusted clock and the design
// assigns expiry/liveness to admission. VerifyClaims therefore returns Claims
// that may already be expired or not-yet-valid. The NHP server admission caller
// MUST run this check (with the agreed clock-skew allowance) BEFORE it calls
// qurl-service prepare or opens any AC — it is part of the integrity boundary's
// fail-fast, not a substitute for qurl-service's authoritative DDB liveness.

// ErrExpired is returned when exp is in the past (beyond the skew allowance).
var ErrExpired = fmt.Errorf("qurlv2: claims expired")

// ErrNotYetValid is returned when nbf is in the future (beyond the skew
// allowance).
var ErrNotYetValid = fmt.Errorf("qurlv2: claims not yet valid (nbf in the future)")

// CheckLiveness rejects a claim that is expired or not-yet-valid relative to now,
// allowing skew of clock skew on each side. exp and nbf are integer Unix seconds
// (already range/ordering-validated by the strict parser). skew is clamped to >= 0.
//
// Semantics (with s = skew, t = now):
//   - not-yet-valid iff nbf > t + s  (nbf is in the future beyond skew);
//   - expired       iff exp < t - s  (exp is in the past beyond skew).
//
// The boundaries are inclusive: exactly-at-exp (within skew) and exactly-at-nbf
// are still live, matching the design's "fail-fast on stale links" intent without
// rejecting a claim the instant it reaches exp.
func CheckLiveness(c *Claims, now time.Time, skew time.Duration) error {
	if c == nil {
		return fmt.Errorf("%w: nil claims", ErrStrictParse)
	}
	if skew < 0 {
		skew = 0
	}
	nowUnix := now.Unix()
	skewSecs := int64(skew / time.Second)

	if c.Nbf > nowUnix+skewSecs {
		return fmt.Errorf("%w: nbf=%d now=%d skew=%ds", ErrNotYetValid, c.Nbf, nowUnix, skewSecs)
	}
	if c.Exp < nowUnix-skewSecs {
		return fmt.Errorf("%w: exp=%d now=%d skew=%ds", ErrExpired, c.Exp, nowUnix, skewSecs)
	}
	return nil
}
