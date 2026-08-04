package test

import (
	"testing"

	core "github.com/OpenNHP/opennhp/nhp/core"
)

// The tests in this file pin the on-the-wire message type registry: the integer
// value of every header type, its HeaderTypeToString label, and the device type
// that HeaderTypeToDeviceType resolves it to. These values are part of the
// protocol contract, so any accidental change (reordering a constant, inserting
// a new one in the middle, editing a label) shows up here as a failing test
// instead of silently breaking interoperability with already-deployed peers.
//
// Synced from upstream OpenNHP 9deb506b (refs upstream #1579) and extended to
// cover this fork's LayerV message types. The fork APPENDS its extensions after
// upstream's DHP_KNK (27) rather than interleaving them, which is what keeps
// values 0-27 wire-compatible with upstream peers — this table is the fence for
// that property. Insert a new fork message type at the END of the iota block
// and the END of nhpHeaderTypeStrings, never in the middle.

type headerTypeCase struct {
	headerType int
	value      int
	label      string
	deviceType int
}

// Expected values reflect the current registry in nhp/core/packet.go. Update
// this table deliberately, in lockstep with a compatibility note, if the
// registry ever changes.
//
// The DHP block (17-26) uses UNDERSCORE labels ("NHP_DRG") while everything
// else uses hyphens ("NHP-KPL"). That looks like a typo and is pinned here on
// purpose rather than corrected: these strings are emitted by
// HeaderTypeToString into operator-facing logs, upstream carries the identical
// labels, and the repo already fences several log substrings (see
// ErrPeerNotFound in nhp/core/errors.go). "Fixing" the spelling would diverge
// from upstream, churn any log tooling keyed on them, and buy nothing on the
// wire — the integer is the contract, the label is a display string.
var headerTypeRegistry = []headerTypeCase{
	// Upstream OpenNHP range (0-27) — must stay identical to upstream.
	{core.NHP_KPL, 0, "NHP-KPL", core.NHP_NO_DEVICE},
	{core.NHP_KNK, 1, "NHP-KNK", core.NHP_AGENT},
	{core.NHP_ACK, 2, "NHP-ACK", core.NHP_SERVER},
	{core.NHP_AOP, 3, "NHP-AOP", core.NHP_SERVER},
	{core.NHP_ART, 4, "NHP-ART", core.NHP_AC},
	{core.NHP_LST, 5, "NHP-LST", core.NHP_AGENT},
	{core.NHP_LRT, 6, "NHP-LRT", core.NHP_SERVER},
	{core.NHP_COK, 7, "NHP-COK", core.NHP_SERVER},
	{core.NHP_RKN, 8, "NHP-RKN", core.NHP_AGENT},
	{core.NHP_RLY, 9, "NHP-RLY", core.NHP_RELAY},
	{core.NHP_AOL, 10, "NHP-AOL", core.NHP_AC},
	{core.NHP_AAK, 11, "NHP-AAK", core.NHP_SERVER},
	{core.NHP_OTP, 12, "NHP-OTP", core.NHP_AGENT},
	{core.NHP_REG, 13, "NHP-REG", core.NHP_AGENT},
	{core.NHP_RAK, 14, "NHP-RAK", core.NHP_SERVER},
	{core.NHP_ACC, 15, "NHP-ACC", core.NHP_AGENT},
	{core.NHP_EXT, 16, "NHP-EXT", core.NHP_AGENT},
	{core.NHP_DRG, 17, "NHP_DRG", core.NHP_DB},
	{core.NHP_DAK, 18, "NHP_DAK", core.NHP_SERVER},
	{core.NHP_DAR, 19, "NHP_DAR", core.DHP_AGENT},
	{core.NHP_DAG, 20, "NHP_DAG", core.NHP_SERVER},
	{core.NHP_DSA, 21, "NHP_DSA", core.NHP_SERVER},
	{core.NHP_DAV, 22, "NHP_DAV", core.DHP_AGENT},
	{core.NHP_DWR, 23, "NHP_DWR", core.NHP_SERVER},
	{core.NHP_DWA, 24, "NHP_DWA", core.NHP_DB},
	{core.NHP_DOL, 25, "NHP_DOL", core.NHP_DB},
	{core.NHP_DBA, 26, "NHP_DBA", core.NHP_SERVER},
	{core.DHP_KNK, 27, "DHP-KNK", core.DHP_AGENT},

	// LayerV fork extensions (28+). Per-AC server assignment (Phase 2) and the
	// qURL v2 revocation pair (P4e, #2793).
	{core.NHP_FWD, 28, "NHP-FWD", core.NHP_SERVER},
	{core.NHP_FRT, 29, "NHP-FRT", core.NHP_SERVER},
	{core.NHP_ARD, 30, "NHP-ARD", core.NHP_SERVER},
	{core.NHP_REV, 31, "NHP-REV", core.NHP_SERVER},
	{core.NHP_RVA, 32, "NHP-RVA", core.NHP_AC},
}

func TestHeaderTypeValues(t *testing.T) {
	for _, tc := range headerTypeRegistry {
		if tc.headerType != tc.value {
			t.Errorf("header type %q: got value %d, want %d", tc.label, tc.headerType, tc.value)
		}
	}
}

func TestHeaderTypeToString(t *testing.T) {
	for _, tc := range headerTypeRegistry {
		if got := core.HeaderTypeToString(tc.headerType); got != tc.label {
			t.Errorf("HeaderTypeToString(%d) = %q, want %q", tc.headerType, got, tc.label)
		}
	}
}

func TestHeaderTypeToStringOutOfRange(t *testing.T) {
	for _, tp := range []int{-1, len(headerTypeRegistry), 1000} {
		if got := core.HeaderTypeToString(tp); got != "UNKNOWN" {
			t.Errorf("HeaderTypeToString(%d) = %q, want %q", tp, got, "UNKNOWN")
		}
	}
}

func TestHeaderTypeToDeviceType(t *testing.T) {
	for _, tc := range headerTypeRegistry {
		if got := core.HeaderTypeToDeviceType(tc.headerType); got != tc.deviceType {
			t.Errorf("HeaderTypeToDeviceType(%q) = %d, want %d", tc.label, got, tc.deviceType)
		}
	}
}

// The registry must stay contiguous starting at zero; a gap would mean a
// constant was removed without renumbering the rest, which shifts every value
// after it on the wire.
func TestHeaderTypeRegistryContiguous(t *testing.T) {
	for i, tc := range headerTypeRegistry {
		if tc.value != i {
			t.Fatalf("registry not contiguous at index %d: %q has value %d", i, tc.label, tc.value)
		}
	}
}

// TestHeaderTypeRegistryCoversEveryHeaderType keeps the table exhaustive. The
// out-of-range case above uses len(headerTypeRegistry) as the first invalid
// value, so a header type appended to nhpHeaderTypeStrings without a table row
// would otherwise turn that assertion into a false "UNKNOWN" expectation and
// leave the new type completely unpinned.
func TestHeaderTypeRegistryCoversEveryHeaderType(t *testing.T) {
	if got := core.HeaderTypeToString(len(headerTypeRegistry) - 1); got == "UNKNOWN" {
		t.Fatalf("registry table has %d rows but HeaderTypeToString(%d) = UNKNOWN — table is longer than the registry",
			len(headerTypeRegistry), len(headerTypeRegistry)-1)
	}
	if got := core.HeaderTypeToString(len(headerTypeRegistry)); got != "UNKNOWN" {
		t.Fatalf("HeaderTypeToString(%d) = %q, want UNKNOWN — a header type was added to nhpHeaderTypeStrings without a row in headerTypeRegistry",
			len(headerTypeRegistry), got)
	}
}
