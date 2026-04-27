package ac

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// TestGenerateAccessToken_DecodesTo32Bytes pins the cross-component
// wire contract: a token issued by GenerateAccessToken, when decoded
// as base64.StdEncoding, must yield exactly 32 bytes. The HTTP /refresh
// handler at endpoints/ac/httpac.go enforces `len(buf) == 32` after
// decode, so a regression that flips the encoding to RawURLEncoding
// (43 chars, no padding) or changes the byte budget would pass every
// other test in this PR but fail at runtime when an agent presents a
// real token. Smoke-tier coverage of the live wire shape is tracked
// in #1417.
func TestGenerateAccessToken_DecodesTo32Bytes(t *testing.T) {
	a := &UdpAC{tokenStore: common.NewTokenStore[*AccessEntry]()}
	entry := &AccessEntry{User: &common.AgentUser{UserId: "u"}, OpenTime: 60}

	token := a.GenerateAccessToken(entry)
	buf, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("token does not decode as base64.StdEncoding: %v (token=%q)", err, token)
	}
	if len(buf) != 32 {
		// Wire contract: the AC's /refresh handler in endpoints/ac/httpac.go
		// rejects tokens whose base64-StdEncoding decode is not 32 bytes.
		// (Line number deliberately omitted — line numbers drift; the
		// `len(buf) != 32` check is the searchable invariant.)
		t.Fatalf("decoded token length = %d, want 32 (token=%q) — wire contract with httpac.go broken",
			len(buf), token)
	}
}

// TestGenerateAccessToken_Uniqueness asserts that 10_000 AC tokens issued
// for the same User are all unique and round-trip through VerifyAccessToken.
// Token generation must not depend on entry metadata; setting only
// tokenStore here is deliberate — adding a config field would mask a
// future regression that re-introduces metadata into the token derivation.
func TestGenerateAccessToken_Uniqueness(t *testing.T) {
	a := &UdpAC{
		tokenStore: common.NewTokenStore[*AccessEntry](),
	}

	const n = 10_000
	user := &common.AgentUser{
		UserId:         "user-1",
		DeviceId:       "device-1",
		OrganizationId: "org-1",
		AuthServiceId:  "asp-1",
	}

	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		entry := &AccessEntry{User: user, OpenTime: 60}
		token := a.GenerateAccessToken(entry)
		if _, dup := seen[token]; dup {
			t.Fatalf("collision after %d tokens: %q", i, token)
		}
		seen[token] = struct{}{}

		got := a.VerifyAccessToken(token)
		if got != entry {
			t.Fatalf("VerifyAccessToken did not return the issued entry for token %d", i)
		}
		if got.User != user {
			t.Fatalf("VerifyAccessToken returned an entry with the wrong User pointer for token %d", i)
		}
	}
}

// TestIssueACTokenIfSuccess_GatesOnErrCode fences the threat-model fix:
// post-nhp#1124 the access token is the entire auth secret, so a token
// issued alongside ErrCode != success would only ever appear in leaky
// %+v error logs on the server (endpoints/server/udpserver.go:1862,
// :2150). The gate must use STRICT success-code equality, not the more
// permissive common.IsSuccessErrCode (which treats empty string as
// success) — bare-return paths in HandleAccessControl can leave ErrCode
// == "" with err != nil, and the server's leak logger treats those as
// failures. Issuing a token under those conditions would re-open the
// exact path the gate exists to close.
func TestIssueACTokenIfSuccess_GatesOnErrCode(t *testing.T) {
	cases := []struct {
		name        string
		errCode     string
		wantIssued  bool
		description string
	}{
		{
			name:        "empty_errcode_no_token",
			errCode:     "",
			wantIssued:  false,
			description: "empty ErrCode is the bare-return / err-set-but-no-errcode case from HandleAccessControl (e.g. EBPFXDP EbpfRuleAdd failure at msghandler.go:478) — server's leak logger treats it as failure, gate must too",
		},
		{
			name:        "explicit_success_code_issues",
			errCode:     common.ErrSuccess.ErrorCode(),
			wantIssued:  true,
			description: "the only ErrCode value that should mint a token",
		},
		{
			name:        "failure_code_no_token",
			errCode:     "5001",
			wantIssued:  false,
			description: "any explicit non-success code suppresses issuance",
		},
		{
			name:        "ac_op_failed_no_token",
			errCode:     common.ErrACOperationFailed.ErrorCode(),
			wantIssued:  false,
			description: "ErrACOperationFailed — the most common AC failure surface",
		},
		{
			name:        "ac_empty_pass_address_no_token",
			errCode:     common.ErrACEmptyPassAddress.ErrorCode(),
			wantIssued:  false,
			description: "ErrACEmptyPassAddress — fired by setArtMsgError at msghandler.go's empty-srcAddrs path",
		},
		{
			name:        "ac_ipset_not_found_no_token",
			errCode:     common.ErrACIPSetNotFound.ErrorCode(),
			wantIssued:  false,
			description: "ErrACIPSetNotFound — fired when iptables ipset is nil",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &UdpAC{tokenStore: common.NewTokenStore[*AccessEntry]()}
			artMsg := &common.ACOpsResultMsg{ErrCode: tc.errCode}
			entry := &AccessEntry{
				User:     &common.AgentUser{UserId: "u"},
				OpenTime: 60,
			}

			a.IssueACTokenIfSuccess(artMsg, entry)

			if tc.wantIssued {
				if artMsg.ACToken == "" {
					t.Fatalf("%s: expected ACToken to be populated", tc.description)
				}
				if got := a.VerifyAccessToken(artMsg.ACToken); got != entry {
					t.Fatalf("%s: token did not round-trip through tokenStore", tc.description)
				}
			} else {
				if artMsg.ACToken != "" {
					t.Fatalf("%s: expected ACToken to stay empty, got %q", tc.description, artMsg.ACToken)
				}
				if a.tokenStore.Size() != 0 {
					t.Fatalf("%s: expected tokenStore to stay empty, got size %d", tc.description, a.tokenStore.Size())
				}
			}
		})
	}
}

// TestGenerateAccessToken_LatePacketBuffer fences the
// accessTokenLatePacketBufferSeconds extension. The AC issues tokens with
// ExpireTime = now + OpenTime + buffer to keep iptables/ipset entries
// matchable for late-arriving packets after the client thinks the window
// is closed. A regression that drops the +buffer (a tempting "tighten
// the contract" cleanup) would silently shorten the late-packet window
// and cause sporadic refused-traffic incidents that don't reproduce
// outside production timing.
func TestGenerateAccessToken_LatePacketBuffer(t *testing.T) {
	a := &UdpAC{
		tokenStore: common.NewTokenStore[*AccessEntry](),
	}

	const openTime = 60
	entry := &AccessEntry{
		User:     &common.AgentUser{UserId: "user-1"},
		OpenTime: openTime,
	}

	before := time.Now()
	a.GenerateAccessToken(entry)
	after := time.Now()

	wantMin := before.Add(time.Duration(openTime+accessTokenLatePacketBufferSeconds) * time.Second)
	wantMax := after.Add(time.Duration(openTime+accessTokenLatePacketBufferSeconds) * time.Second)

	if entry.ExpireTime.Before(wantMin) {
		t.Fatalf("ExpireTime %v earlier than expected lower bound %v (lost late-packet buffer?)",
			entry.ExpireTime, wantMin)
	}
	if entry.ExpireTime.After(wantMax) {
		t.Fatalf("ExpireTime %v later than expected upper bound %v",
			entry.ExpireTime, wantMax)
	}

	// Strictly-non-zero buffer assertion: catches a regression that drops
	// BOTH the constant AND the addition (e.g., a "simplification" that
	// rewrites the entire ExpireTime line to `before.Add(OpenTime * sec)`).
	// The bracket assertions above catch a buffer-shrinks-to-N regression;
	// this one catches a buffer-disappears-entirely regression.
	expireAtOpenTimeBoundary := before.Add(time.Duration(openTime) * time.Second)
	if !entry.ExpireTime.After(expireAtOpenTimeBoundary) {
		t.Fatalf("ExpireTime %v is not strictly later than now+OpenTime %v — late-packet buffer is zero",
			entry.ExpireTime, expireAtOpenTimeBoundary)
	}
}
