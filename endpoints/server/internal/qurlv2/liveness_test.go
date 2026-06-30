package qurlv2

import (
	"errors"
	"testing"
	"time"
)

func livenessClaims(nbf, exp int64) *Claims {
	return &Claims{Nbf: nbf, Exp: exp}
}

func TestCheckLiveness(t *testing.T) {
	now := time.Unix(1_781_910_150, 0) // mid-window for baselineClaims (nbf 1781910000, exp 1781910300)

	tests := []struct {
		name    string
		nbf     int64
		exp     int64
		skew    time.Duration
		wantErr error
	}{
		{name: "live mid-window", nbf: 1781910000, exp: 1781910300, skew: 0, wantErr: nil},
		{name: "exactly at nbf is live", nbf: now.Unix(), exp: now.Unix() + 100, skew: 0, wantErr: nil},
		{name: "exactly at exp is live", nbf: now.Unix() - 100, exp: now.Unix(), skew: 0, wantErr: nil},
		{name: "expired beyond skew", nbf: now.Unix() - 100, exp: now.Unix() - 31, skew: 30 * time.Second, wantErr: ErrExpired},
		{name: "expired but within skew is live", nbf: now.Unix() - 100, exp: now.Unix() - 30, skew: 30 * time.Second, wantErr: nil},
		{name: "not yet valid beyond skew", nbf: now.Unix() + 31, exp: now.Unix() + 100, skew: 30 * time.Second, wantErr: ErrNotYetValid},
		{name: "not yet valid but within skew is live", nbf: now.Unix() + 30, exp: now.Unix() + 100, skew: 30 * time.Second, wantErr: nil},
		{name: "negative skew clamps to zero (expired)", nbf: now.Unix() - 100, exp: now.Unix() - 1, skew: -5 * time.Second, wantErr: ErrExpired},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckLiveness(livenessClaims(tt.nbf, tt.exp), now, tt.skew)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("want live, got %v", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("want %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestCheckLiveness_NilClaims(t *testing.T) {
	if err := CheckLiveness(nil, time.Now(), 0); !errors.Is(err, ErrStrictParse) {
		t.Fatalf("nil claims must error, got %v", err)
	}
}
