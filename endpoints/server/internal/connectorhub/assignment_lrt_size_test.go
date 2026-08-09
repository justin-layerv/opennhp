package connectorhub

import (
	"testing"

	conformance "github.com/layervai/qurl-conformance"
)

// TestAssignmentLRTSizeBudgetIsDeliverable is the regression test for the
// sandbox enrollment black hole, asserted where the defect lives: the wire
// contract, not either implementation.
//
// Measured against the deployed sandbox Hub on 2026-08-08. A client sent 14
// datagrams; the Hub recorded 4 challenge_sent, 5 response_sent, 5
// replay_rejected, every other outcome zero, write_failed zero. A null control
// window with no probe traffic recorded zero on every outcome, so that
// accounting is exact. The client received all four challenges (340-342 bytes)
// and none of the five replies. An unregistered credential over the identical
// path got its 302-byte 52106 rejection back immediately.
//
// The live IssueAssignment body is 1426 bytes, 996 of it assignment_ticket,
// sealing to roughly 1682 bytes on the wire. The Hub sits behind a Network Load
// Balancer, and an NLB does not forward fragmented UDP. The kernel fragments,
// the middle discards it, and the write still succeeds — which is exactly why
// the Hub records response_sent with write_failed zero while nothing arrives.
//
// Both implementations conform. qurl-go and nhp/core interoperate cleanly on
// loopback (8/8 unique packets, 4/4 cookie proofs accepted) and agree on the
// proof flag and both pinned KATs. What is wrong is that the contract licenses
// an LRT packet far larger than the deployed transport can carry.
//
// The delivery failure itself is fixed, on the producer side: layervai/qurl-
// service#1367 moved the signed ticket off the wire behind a short handle and
// made the Connector Authority refuse to encode a reply over the unfragmented
// bound, so a real reply now seals to about 817 bytes.
//
// What this test asserts is not fixed. The CONTRACT still licenses a 4096-byte
// LRT packet, which means the deliverability of an assignment reply rests
// entirely on one producer choosing to check its own output. A second producer,
// or a regression in that check, reopens exactly this hole. Closing it needs
// qurl-conformance to lower NHPPacketMaxBytes to the unfragmented bound.
//
// It stays SKIPPED rather than red because it would fail on a contract this
// repository does not own. Un-skip it in the change that lowers that ceiling.
func TestAssignmentLRTSizeBudgetIsDeliverable(t *testing.T) {
	t.Skip("KNOWN GAP: the assignment contract permits a 4096-byte LRT packet against " +
		"a 1472-byte IPv4 unfragmented ceiling. The producer now enforces the bound " +
		"itself (qurl-service#1367); un-skip when qurl-conformance lowers the contract.")

	file, err := conformance.AssignmentTicket()
	if err != nil {
		t.Fatalf("load assignment-ticket contract: %v", err)
	}
	maxPacket := file.Contract.NHPPacketMaxBytes

	t.Logf("contract NHP packet max   = %d bytes", maxPacket)
	t.Logf("IPv4 unfragmented ceiling = %d bytes", unfragmentedUDPResponseCeiling)

	if maxPacket > unfragmentedUDPResponseCeiling {
		t.Fatalf("the assignment contract permits a %d-byte LRT packet, %d bytes beyond the "+
			"%d-byte IPv4 unfragmented ceiling.\n"+
			"A conforming producer may therefore emit a reply an NLB silently discards while "+
			"its own write succeeds and it records response_sent. Either lower the contract "+
			"ceiling to the unfragmented bound, or stop fronting the Hub with a transport "+
			"that drops fragments.",
			maxPacket, maxPacket-unfragmentedUDPResponseCeiling, unfragmentedUDPResponseCeiling)
	}
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
