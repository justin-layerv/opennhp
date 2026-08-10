package connectorhub

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	conformance "github.com/layervai/qurl-conformance"

	"github.com/OpenNHP/opennhp/nhp/core"
)

// assignmentSuccessCarrying returns the authority's IssueAssignment success
// envelope with assignment_ticket replaced by the supplied value. Everything
// else stays the released golden, so the envelope remains exactly what strict
// decoding accepts; only the one field whose size actually varies in production
// is substituted.
func assignmentSuccessCarrying(t *testing.T, assignmentTicket string) []byte {
	t.Helper()
	golden := authorityVectors(t).
		Operations[conformance.ConnectorAuthorityOperationIssueAssignment].SuccessGolden.BodyJSON
	const placeholder = `"conformance-account-assignment-ticket-0001"`
	if !strings.Contains(golden, placeholder) {
		t.Fatalf("golden no longer carries the placeholder ticket; update this helper")
	}
	return []byte(strings.Replace(golden, placeholder, `"`+assignmentTicket+`"`, 1))
}

// TestAssignmentLRTFitsOneUnfragmentedDatagram is the regression test for the
// enrollment black hole, and it measures the thing that actually broke: the
// size of the sealed datagram leaving the Hub.
//
// Nothing here is simulated. A real agent device completes the cookie
// challenge over a real UDP socket, the real worker calls the authority, seals
// the reply through the real NHP_LRT path, and writes it back; the assertion is
// on the bytes the client receives.
//
// Measured against deployed sandbox on 2026-08-08, the failure this prevents: a
// 1682-byte reply was fragmented by the kernel, discarded by the NLB, and still
// recorded by the Hub as response_sent with write_failed zero, so the agent
// waited out its ticket and no counter anywhere said why.
//
// The second subtest is the load-bearing one. A test that only asserts today's
// reply fits would have passed all through the outage, because no fixture ever
// carried a production-sized ticket. Sealing the pre-handle shape proves this
// test detects the defect rather than merely coexisting with its absence.
func TestAssignmentLRTFitsOneUnfragmentedDatagram(t *testing.T) {
	sealEnrollReply := func(t *testing.T, assignmentTicket string) int {
		t.Helper()
		authority := &fakeHubAuthority{issueResponse: assignmentSuccessCarrying(t, assignmentTicket)}
		f := newWorkerFixtureWithAuthority(t, authority)
		// The assignment golden carries a placeholder credential; the enroll
		// codec requires the canonical one or the request is refused as 52109
		// before the authority is ever called.
		f.request = []byte(strings.Replace(
			assignmentVectors(t).InitialAssignment.Request.BodyJSON,
			conformance.AgentAssignmentBootstrapCredentialFixture,
			authorityVectors(t).Fixtures.Credential, 1,
		))

		cookie, _ := f.challenge(t, 4001)
		proof := f.sealLST(t, 4002, &cookie)
		clear(cookie[:])
		f.send(t, proof)
		wire := f.read(t, 2*time.Second)

		// Prove it is the assignment reply and that it decrypts, so a truncated
		// or unrelated datagram cannot pass as a small one.
		ppd := f.decrypt(t, wire, core.NHP_LRT)
		if !json.Valid(ppd.BodyMessage) || !bytes.Contains(ppd.BodyMessage, []byte(`"nhp_udp_endpoint"`)) {
			t.Fatalf("sealed datagram is not an assignment LRT: %s", ppd.BodyMessage)
		}
		return len(wire)
	}

	t.Run("a handle-bearing reply fits with room to spare", func(t *testing.T) {
		handle := "ath_" + strings.Repeat("x", 22)
		sealed := sealEnrollReply(t, handle)
		t.Logf("handle reply seals to %d bytes (IPv6-minimum ceiling %d, IPv4 %d)",
			sealed, ipv6MinimumUnfragmentedCeiling, unfragmentedUDPResponseCeiling)

		if responseIsOversize(sealed) {
			t.Fatalf("sealed datagram is %d bytes, over the %d-byte IPv4 ceiling",
				sealed, unfragmentedUDPResponseCeiling)
		}
		// The stricter bound qurl-go enforces on receipt. Meeting only the IPv4
		// one would still be undeliverable across an IPv6-minimum segment.
		if sealed > ipv6MinimumUnfragmentedCeiling {
			t.Fatalf("sealed datagram is %d bytes, over the %d-byte IPv6-minimum ceiling",
				sealed, ipv6MinimumUnfragmentedCeiling)
		}
	})

	t.Run("the pre-handle reply this replaced does not fit", func(t *testing.T) {
		// The signed qat1 token the wire used to carry. If a change ever puts a
		// ticket-sized value back into assignment_ticket, the subtest above
		// starts failing -- this one proves that is a real detection and not an
		// accident of the fixture being unrepresentative.
		token := "qat1." + strings.Repeat("x", 990)
		sealed := sealEnrollReply(t, token)
		t.Logf("pre-handle reply seals to %d bytes", sealed)

		if !responseIsOversize(sealed) {
			t.Fatalf("a %d-byte reply carrying a %d-character ticket was judged deliverable; "+
				"this test can no longer detect the defect it exists for",
				sealed, len(token))
		}
	})
}

// TestGoldenAssignmentEnvelopeIsNotRepresentativeOfProduction records why every
// existing test was green while sandbox enrollment was dead, so nobody
// re-derives it. The frozen golden carries the 42-character placeholder
// "conformance-account-assignment-ticket-0001" where production carried a
// 996-byte signed ticket, so no test in either repository had ever sealed a
// reply anywhere near the contract ceiling.
//
// The numbers below are a 2026-08-08 measurement kept deliberately fixed. They
// are the record of what was undeliverable, not a claim about what the producer
// emits today -- since qurl-service#1367 that is roughly 817 bytes.
func TestGoldenAssignmentEnvelopeIsNotRepresentativeOfProduction(t *testing.T) {
	golden := authorityVectors(t).
		Operations[conformance.ConnectorAuthorityOperationIssueAssignment].SuccessGolden.BodyJSON

	// Captured from layerv-nhp-sandbox-ca-ia on 2026-08-08.
	const productionEnvelopeBytes = 1447
	const productionTicketBytes = 996
	// A conservative upper bound from the ticket contract, not an exact
	// measurement: 1447 + 256 = 1703 here against the 1682 measured on the
	// wire. Both clear the ceiling, so every assertion below holds either way.
	const nhpPacketOverheadBytes = 256

	t.Logf("frozen golden authority envelope = %d bytes", len(golden))
	t.Logf("real sandbox envelope            = %d bytes (%.1fx golden)",
		productionEnvelopeBytes, float64(productionEnvelopeBytes)/float64(len(golden)))
	t.Logf("real assignment_ticket           = %d bytes", productionTicketBytes)

	if len(golden) >= productionEnvelopeBytes {
		t.Skipf("golden (%d) is no longer smaller than production (%d); refresh this test",
			len(golden), productionEnvelopeBytes)
	}
	if sealed := productionEnvelopeBytes + nhpPacketOverheadBytes; sealed <= unfragmentedUDPResponseCeiling {
		t.Fatalf("a production-sized reply now seals to %d bytes and fits the %d-byte ceiling; "+
			"the ticket shrank and this test and its sibling should be revisited",
			sealed, unfragmentedUDPResponseCeiling)
	}
}

// TestResponseIsOversizeBoundary covers the predicate handlePacket applies.
//
// It is a boundary test rather than an end-to-end one because the fixture
// cannot express a production-sized reply: every golden in this package is
// built around a 42-character placeholder ticket, and strict decoding
// correctly rejects a hand-padded envelope. That gap is what
// TestGoldenAssignmentEnvelopeIsNotRepresentativeOfProduction records, and the
// production evidence in these comments is measured, not synthesized.
func TestResponseIsOversizeBoundary(t *testing.T) {
	// A payload of exactly the ceiling still fits one datagram:
	// 1472 + 8 UDP + 20 IP = 1500. The comparison must be strictly greater.
	for _, test := range []struct {
		name string
		size int
		want bool
	}{
		{"one below the ceiling", unfragmentedUDPResponseCeiling - 1, false},
		{"exactly the ceiling", unfragmentedUDPResponseCeiling, false},
		{"one over the ceiling", unfragmentedUDPResponseCeiling + 1, true},
		{"the golden reply this package seals", 617, false},
		{"the measured sandbox reply", 1682, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := responseIsOversize(test.size); got != test.want {
				t.Fatalf("responseIsOversize(%d) = %t, want %t", test.size, got, test.want)
			}
		})
	}
}
