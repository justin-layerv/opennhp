package ac

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/OpenNHP/opennhp/endpoints/metrics"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
)

// Regression fence for issue #1680. The 2026-05-06 prod cell0 incident: ACs
// stuck in a re-registration loop because the previous async cleanup worker
// was evicting peers that re-appeared in the new assignment. The fix replaced
// that machinery with a synchronous reconcile (reconcileDevicePeers) that
// only removes (pubkey, address) entries absent from the new assignment.
//
// The bug only manifests with shared-pubkey ASGs: the device peerMap entry
// is a *core.PeerGroup, AddPeer replaces members by address, and
// RemovePeerByAddress matches the just-installed new peer at that address.
// Tests using distinct pubkeys per server would pass even with the bug present.

// countDimCountersWithPrefix returns the number of dim-counter entries
// for the EXACT metric name, plus the sum of their values across all
// dim sets. metrics.Publisher's dim-counter keys are
// <metric_name>\x00<dim>=<val>… — anchoring on the \x00 field
// separator preempts a name-prefix collision (e.g., a future
// MetricReconcileOverlapMutating that would silently match
// MetricReconcileOverlap's prefix-search and inflate every overlap
// test's totals).
func countDimCountersWithPrefix(t *testing.T, reg *ACRegistration, prefix string) (matches int, total float64) {
	t.Helper()
	anchored := prefix + "\x00"
	_, dimCounters := reg.metrics.CountersForTest(t)
	for k, v := range dimCounters {
		if strings.HasPrefix(k, anchored) {
			matches++
			total += v
		}
	}
	return matches, total
}

// newACRegistrationWithDevice builds an ACRegistration backed by a real
// core.Device so reconcileDevicePeers can be observed end-to-end.
func newACRegistrationWithDevice(t *testing.T) (*ACRegistration, *core.Device) {
	t.Helper()
	device := core.NewDevice(core.NHP_AC, testPrivateKey(), nil)
	if device == nil {
		t.Fatal("Failed to create device")
	}
	ac := &UdpAC{
		config: &Config{ACId: "test-ac-1680", ServerEndpoint: "server.nhp.test.internal"},
		device: device,
	}
	return mustNewACRegistration(t, ac), device
}

// TestACRegistration_ReconcileDevicePeers_PreservesSharedAddress is the
// end-to-end fence: with two servers behind a shared pubkey, re-registration
// returning the same assignment must leave the device peer pool intact.
// Without the fix, RemovePeerByAddress would empty the PeerGroup and delete
// the peerMap entry, causing the next NHP_AAK to fail ErrPeerNotFound.
func TestACRegistration_ReconcileDevicePeers_PreservesSharedAddress(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	const sharedPubKey = "c2hhcmVkLXNlcnZlci1wdWJrZXk="

	// Prior assignment installed two members under the shared pubkey.
	priorPeer1 := &core.UdpPeer{Ip: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	priorPeer2 := &core.UdpPeer{Ip: "10.0.0.2", Port: DefaultServerPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	device.AddPeer(priorPeer1)
	device.AddPeer(priorPeer2)

	// Re-registration installed fresh structs at the same addresses. AddPeer's
	// same-address branch replaces the PeerGroup member, so the prior pointers
	// are no longer in peerMap, but their addresses alias the new members.
	newPeer1 := &core.UdpPeer{Ip: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	newPeer2 := &core.UdpPeer{Ip: "10.0.0.2", Port: DefaultServerPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	device.AddPeer(newPeer1)
	device.AddPeer(newPeer2)

	pubKeyBytes := newPeer1.PublicKey()
	if device.LookupPeer(pubKeyBytes) == nil {
		t.Fatal("test setup: pubkey should resolve before reconcile")
	}

	priorServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: sharedPubKey}, Peer: priorPeer1},
		{Target: common.RedirectTarget{IP: "10.0.0.2", Port: DefaultServerPort, PubKeyBase64: sharedPubKey}, Peer: priorPeer2},
	}
	newServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: sharedPubKey}, Peer: newPeer1, Connected: true},
		{Target: common.RedirectTarget{IP: "10.0.0.2", Port: DefaultServerPort, PubKeyBase64: sharedPubKey}, Peer: newPeer2, Connected: true},
	}

	reg.reconcileDevicePeers(priorServers, newServers)

	if device.LookupPeer(pubKeyBytes) == nil {
		t.Fatal("regression #1680: reconcile evicted the active peer for a shared-pubkey PeerGroup")
	}
}

// TestACRegistration_ReconcileDevicePeers_IPHostnameCombo covers the case
// where targets carry both IP and Hostname under a shared pubkey: the
// active-set key uses IP form and the device peer's Host() returns the
// Hostname form. Reconcile must still match correctly across that asymmetry.
// PeerGroup.RemoveMember matches on m.Ip == addr || m.Host() == addr, so
// passing peer.Host() at remove time finds the member via the Host() form
// regardless of which form targetActiveKey used for membership.
func TestACRegistration_ReconcileDevicePeers_IPHostnameCombo(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	const sharedPubKey = "Y29tYm8tcHVia2V5LWluLXNoYXJlZA=="

	priorPeer1 := &core.UdpPeer{Ip: "10.0.0.1", Hostname: "a.nhp.test.internal", Port: DefaultServerPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	priorPeer2 := &core.UdpPeer{Ip: "10.0.0.2", Hostname: "b.nhp.test.internal", Port: DefaultServerPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	device.AddPeer(priorPeer1)
	device.AddPeer(priorPeer2)

	pubKeyBytes := priorPeer1.PublicKey()
	if device.LookupPeer(pubKeyBytes) == nil {
		t.Fatal("test setup: pubkey should resolve before reconcile")
	}

	priorServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Hostname: "a.nhp.test.internal", Port: DefaultServerPort, PubKeyBase64: sharedPubKey}, Peer: priorPeer1},
		{Target: common.RedirectTarget{IP: "10.0.0.2", Hostname: "b.nhp.test.internal", Port: DefaultServerPort, PubKeyBase64: sharedPubKey}, Peer: priorPeer2},
	}
	newServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.2", Hostname: "b.nhp.test.internal", Port: DefaultServerPort, PubKeyBase64: sharedPubKey}, Peer: priorPeer2, Connected: true},
	}

	reg.reconcileDevicePeers(priorServers, newServers)

	peer := device.LookupPeer(pubKeyBytes)
	if peer == nil {
		t.Fatal("PeerGroup entry should still resolve: B remains in the assignment")
	}
	if group, isGroup := peer.(*core.PeerGroup); isGroup {
		members := group.Members()
		if len(members) != 1 {
			t.Errorf("PeerGroup should have 1 member after IP+Hostname partial retirement, got %d", len(members))
		}
		// Pointer-identity assertion: catches a regression that retains a
		// member at the right address but the wrong *UdpPeer instance.
		if len(members) > 0 && members[0] != priorPeer2 {
			t.Errorf("remaining member should be priorPeer2 pointer (Ip=%s), got pointer with Ip=%s", priorPeer2.Ip, members[0].Ip)
		}
	} else if udp, ok := peer.(*core.UdpPeer); ok {
		if udp != priorPeer2 {
			t.Errorf("demoted peer should be priorPeer2 pointer (Ip=%s), got pointer with Ip=%s", priorPeer2.Ip, udp.Ip)
		}
	} else {
		t.Fatalf("unexpected peer type %T after IP+Hostname partial retirement", peer)
	}
}

// TestACRegistration_ReconcileDevicePeers_DirectAAKShape fences the new
// reconcile call site in handleRegistrationResponse's direct-AAK branch
// (#1685). Pre-PR, that path replaced r.assignedServers without touching the
// device peer pool, leaking prior peers until process GC. Now reconcile
// runs there with the same semantics as HandleRedispatch's redispatch path.
//
// The shape exercised here is what the live path produces: prior=[A] on a
// distinct pubkey (the previous assigned server), new=[B] on a different
// pubkey (the registration server returning NHP_AAK with no peer list).
// A must leave the pool; B must remain.
func TestACRegistration_ReconcileDevicePeers_DirectAAKShape(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)

	priorPeer := &core.UdpPeer{Ip: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: "cHJpb3ItYXNzaWduZWQtcHVia2V5", Type: core.NHP_SERVER}
	newPeer := &core.UdpPeer{Ip: "10.0.0.2", Port: DefaultServerPort, PubKeyBase64: "bmV3LXJlZ2lzdHJhdGlvbi1wdWJrZXk=", Type: core.NHP_SERVER}
	device.AddPeer(priorPeer)
	device.AddPeer(newPeer)

	priorKey := priorPeer.PublicKey()
	newKey := newPeer.PublicKey()
	if device.LookupPeer(priorKey) == nil || device.LookupPeer(newKey) == nil {
		t.Fatal("test setup: both peers should resolve before reconcile")
	}

	priorServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: priorPeer.Ip, Port: priorPeer.Port, PubKeyBase64: priorPeer.PubKeyBase64}, Peer: priorPeer},
	}
	newServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: newPeer.Ip, Port: newPeer.Port, PubKeyBase64: newPeer.PubKeyBase64}, Peer: newPeer, Connected: true},
	}

	reg.reconcileDevicePeers(priorServers, newServers)

	if device.LookupPeer(priorKey) != nil {
		t.Error("prior assigned server should have been evicted on direct-AAK reconcile")
	}
	if device.LookupPeer(newKey) == nil {
		t.Error("new registration server should remain in the pool")
	}
}

// TestACRegistration_ReconcileDevicePeers_DirectAAKShape_SharedPubKey
// fences the same direct-AAK reconcile call site under shared-pubkey ASGs:
// prior at A and new at B, both under one pubkey (the device peerMap entry
// is a *core.PeerGroup). The fix's two invariants must hold here too —
// removal is by address, the active member at B is preserved, and the
// retired member at A is evicted without collapsing the PeerGroup entry.
// Catches a future direct-AAK NHP_AAK landing during a shared-pubkey ASG
// transition before it can resurface the original incident's bug class.
func TestACRegistration_ReconcileDevicePeers_DirectAAKShape_SharedPubKey(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	const sharedPubKey = "ZGlyZWN0LWFhay1zaGFyZWQtcHVia2V5"

	priorPeer := &core.UdpPeer{Ip: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	newPeer := &core.UdpPeer{Ip: "10.0.0.2", Port: DefaultServerPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	device.AddPeer(priorPeer)
	device.AddPeer(newPeer)

	pubKeyBytes := newPeer.PublicKey()
	if device.LookupPeer(pubKeyBytes) == nil {
		t.Fatal("test setup: pubkey should resolve before reconcile")
	}

	priorServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: sharedPubKey}, Peer: priorPeer},
	}
	newServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.2", Port: DefaultServerPort, PubKeyBase64: sharedPubKey}, Peer: newPeer, Connected: true},
	}

	reg.reconcileDevicePeers(priorServers, newServers)

	peer := device.LookupPeer(pubKeyBytes)
	if peer == nil {
		t.Fatal("PeerGroup entry should still resolve: B remains in the assignment")
	}
	switch entry := peer.(type) {
	case *core.PeerGroup:
		members := entry.Members()
		if len(members) != 1 {
			t.Errorf("PeerGroup should have 1 member after direct-AAK retirement, got %d", len(members))
		}
		if len(members) > 0 && members[0].Ip != "10.0.0.2" {
			t.Errorf("remaining member should be at 10.0.0.2, got %s", members[0].Ip)
		}
	case *core.UdpPeer:
		if entry.Ip != "10.0.0.2" {
			t.Errorf("demoted peer should be at 10.0.0.2, got %s", entry.Ip)
		}
	default:
		t.Fatalf("unexpected peer type %T after direct-AAK shared-pubkey retirement", peer)
	}
}

// TestACRegistration_ReconcileDevicePeers_PartialPeerGroupRetirement covers
// the middle case the bug taught us about: prior contains members at A and B
// under a *shared* pubkey (so the device peerMap entry is a *core.PeerGroup);
// new contains only B. Reconcile must remove A's member, retain B as the
// sole member, and leave the pubkey resolvable.
func TestACRegistration_ReconcileDevicePeers_PartialPeerGroupRetirement(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	const sharedPubKey = "c2hhcmVkLXNlcnZlci1wdWJrZXk="

	priorPeerA := &core.UdpPeer{Ip: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	priorPeerB := &core.UdpPeer{Ip: "10.0.0.2", Port: DefaultServerPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	device.AddPeer(priorPeerA)
	device.AddPeer(priorPeerB)

	pubKeyBytes := priorPeerA.PublicKey()
	if device.LookupPeer(pubKeyBytes) == nil {
		t.Fatal("test setup: pubkey should resolve before reconcile")
	}

	priorServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: sharedPubKey}, Peer: priorPeerA},
		{Target: common.RedirectTarget{IP: "10.0.0.2", Port: DefaultServerPort, PubKeyBase64: sharedPubKey}, Peer: priorPeerB},
	}
	newServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.2", Port: DefaultServerPort, PubKeyBase64: sharedPubKey}, Peer: priorPeerB, Connected: true},
	}

	reg.reconcileDevicePeers(priorServers, newServers)

	peer := device.LookupPeer(pubKeyBytes)
	if peer == nil {
		t.Fatal("PeerGroup entry should still be findable: B remains in the assignment")
	}
	group, isGroup := peer.(*core.PeerGroup)
	if isGroup {
		members := group.Members()
		if len(members) != 1 {
			t.Errorf("PeerGroup should have 1 member after partial retirement, got %d", len(members))
		}
		if len(members) > 0 && members[0].Ip != "10.0.0.2" {
			t.Errorf("remaining member should be at 10.0.0.2, got %s", members[0].Ip)
		}
	} else {
		// PeerGroup demotes to single peer when it falls to one member —
		// either form satisfies the "B remains, A is gone" invariant.
		udp, ok := peer.(*core.UdpPeer)
		if !ok {
			t.Fatalf("unexpected peer type %T after partial retirement", peer)
		}
		if udp.Ip != "10.0.0.2" {
			t.Errorf("demoted peer should be at 10.0.0.2, got %s", udp.Ip)
		}
	}
}

// TestACRegistration_ReconcileDevicePeers_RemovesRetiredAddress verifies the
// reconcile does not over-correct. An address present in priorServers but
// absent from newServers is a genuine retirement and must leave the pool.
func TestACRegistration_ReconcileDevicePeers_RemovesRetiredAddress(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	const distinctPubKey = "cmV0aXJlZC1wZWVyLXB1YmtleQ=="

	retiredPeer := &core.UdpPeer{Ip: "10.0.0.99", Port: DefaultServerPort, PubKeyBase64: distinctPubKey, Type: core.NHP_SERVER}
	device.AddPeer(retiredPeer)
	pubKeyBytes := retiredPeer.PublicKey()
	if device.LookupPeer(pubKeyBytes) == nil {
		t.Fatal("test setup: retired peer should be in device before reconcile")
	}

	priorServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.99", Port: DefaultServerPort, PubKeyBase64: distinctPubKey}, Peer: retiredPeer},
	}
	newServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: "ZGlmZmVyZW50LXBlZXItcHVia2V5"}},
	}

	reg.reconcileDevicePeers(priorServers, newServers)

	if device.LookupPeer(pubKeyBytes) != nil {
		t.Error("retired peer should have been removed but is still in device")
	}
}

// TestACRegistration_ReconcileDevicePeers_RemovesAllRetiredOnDisjoint
// drives the multi-element disjoint case: priorServers and newServers
// have no key overlap, every prior must leave. Fences the loop's set-
// difference math more explicitly than the len-1 _RemovesRetiredAddress
// case — a regression that, e.g., aliased the activeKeys map across
// loop iterations would still pass _RemovesRetiredAddress but fail here.
func TestACRegistration_ReconcileDevicePeers_RemovesAllRetiredOnDisjoint(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)

	priorPubA := "cHJpb3ItYS1wdWJrZXk="
	priorPubB := "cHJpb3ItYi1wdWJrZXk="
	priorPubC := "cHJpb3ItYy1wdWJrZXk="

	priorPeerA := &core.UdpPeer{Ip: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: priorPubA, Type: core.NHP_SERVER}
	priorPeerB := &core.UdpPeer{Ip: "10.0.0.2", Port: DefaultServerPort, PubKeyBase64: priorPubB, Type: core.NHP_SERVER}
	priorPeerC := &core.UdpPeer{Ip: "10.0.0.3", Port: DefaultServerPort, PubKeyBase64: priorPubC, Type: core.NHP_SERVER}
	device.AddPeer(priorPeerA)
	device.AddPeer(priorPeerB)
	device.AddPeer(priorPeerC)

	for _, p := range []*core.UdpPeer{priorPeerA, priorPeerB, priorPeerC} {
		if device.LookupPeer(p.PublicKey()) == nil {
			t.Fatalf("test setup: %s should resolve before reconcile", p.PubKeyBase64)
		}
	}

	priorServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: priorPubA}, Peer: priorPeerA},
		{Target: common.RedirectTarget{IP: "10.0.0.2", Port: DefaultServerPort, PubKeyBase64: priorPubB}, Peer: priorPeerB},
		{Target: common.RedirectTarget{IP: "10.0.0.3", Port: DefaultServerPort, PubKeyBase64: priorPubC}, Peer: priorPeerC},
	}
	newServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.1.0.1", Port: DefaultServerPort, PubKeyBase64: "bmV3LWEtcHVia2V5"}},
		{Target: common.RedirectTarget{IP: "10.1.0.2", Port: DefaultServerPort, PubKeyBase64: "bmV3LWItcHVia2V5"}},
	}

	reg.reconcileDevicePeers(priorServers, newServers)

	for _, p := range []*core.UdpPeer{priorPeerA, priorPeerB, priorPeerC} {
		if device.LookupPeer(p.PublicKey()) != nil {
			t.Errorf("regression: prior peer %s should have been evicted on disjoint-priors reconcile", p.PubKeyBase64)
		}
	}
}

// TestACRegistration_ReconcileDevicePeers_IPToHostnameTransition fences
// the cross-redispatch transition where a prior target was IP-only and
// the new target for the same peer is Hostname-only.
//
// DEFENSE-IN-DEPTH (not production path). RedirectTarget.Validate (#832)
// requires IP and explicitly rejects hostname-only targets, so this
// transition cannot happen via the normal NHP_ARD ingress path —
// drain-redirect (#1239) targets must resolve Hostname to IP before
// Validate. This test reaches reconcileDevicePeers directly with a
// hostname-only target to fence the targetActiveKey Hostname-fallback
// branch: if a future code path constructs a target that bypasses
// Validate (or if Validate regresses), the fallback's set-difference
// behavior must still preserve the active member. The keys differ
// across forms (IP|10.x.y.z:port vs Hostname|drain.foo:port), so
// reconcile evicts the prior. That's the correct outcome: the new
// peer is at a different resolved address and is in newServers via
// its own AddPeer, so the active member is preserved while the stale
// one drops.
//
// Distinct from _IPHostnameCombo (which exercises both fields set on
// the SAME target). This test fences the transition shape explicitly.
func TestACRegistration_ReconcileDevicePeers_IPToHostnameTransition(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	const pubKey = "dHJhbnNpdGlvbi1wdWJrZXk="

	// Prior: IP-only target, peer with Ip set.
	priorPeer := &core.UdpPeer{Ip: "10.0.0.42", Port: DefaultServerPort, PubKeyBase64: pubKey, Type: core.NHP_SERVER}
	device.AddPeer(priorPeer)
	priorKey := priorPeer.PublicKey()
	if device.LookupPeer(priorKey) == nil {
		t.Fatal("test setup: prior IP-only peer should resolve before reconcile")
	}

	// New: Hostname-only target for the same logical peer (different
	// address). Config flip simulates the drain-redirect form.
	newPeer := &core.UdpPeer{Hostname: "drain.nhp.internal", Port: DefaultServerPort, PubKeyBase64: pubKey, Type: core.NHP_SERVER}
	device.AddPeer(newPeer)

	priorServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.42", Port: DefaultServerPort, PubKeyBase64: pubKey}, Peer: priorPeer},
	}
	newServers := []*AssignedServer{
		{Target: common.RedirectTarget{Hostname: "drain.nhp.internal", Port: DefaultServerPort, PubKeyBase64: pubKey}, Peer: newPeer},
	}

	reg.reconcileDevicePeers(priorServers, newServers)

	// The new (hostname-form) peer should still be in the device pool —
	// AddPeer'd it above and reconcile should not have evicted it (its
	// address isn't in priorServers' active key set, and the prior's
	// IP-form key is the disjoint one that gets removed).
	if device.LookupPeer(priorKey) == nil {
		t.Error("regression: hostname-form peer was wiped — IP→Hostname transition should preserve the new peer")
	}
}

// TestACRegistration_TargetActiveKey covers the address-form fallback the
// reconcile relies on: an IP-bearing target keys on IP, a hostname-only
// target (NLB drain redirect form) keys on hostname. The sentinel case
// pins the bool return that reconcileDevicePeers reads to bump
// MetricUnaddressedTarget — without that signal an unreachable-by-design
// branch would re-key entries silently if RedirectTarget.Validate (#832)
// regressed.
func TestTargetActiveKey(t *testing.T) {
	cases := []struct {
		name         string
		target       common.RedirectTarget
		want         string
		wantSentinel bool
	}{
		{
			name:   "ip form",
			target: common.RedirectTarget{PubKeyBase64: "k", IP: "10.0.0.1", Port: 62206},
			want:   "k\x0010.0.0.1:62206",
		},
		{
			name:   "hostname form",
			target: common.RedirectTarget{PubKeyBase64: "k", Hostname: "drain.nhp.internal", Port: 62206},
			want:   "k\x00drain.nhp.internal:62206",
		},
		{
			name:   "ip wins when both set",
			target: common.RedirectTarget{PubKeyBase64: "k", IP: "10.0.0.1", Hostname: "ignored", Port: 62206},
			want:   "k\x0010.0.0.1:62206",
		},
		{
			name:         "unaddressed sentinel",
			target:       common.RedirectTarget{PubKeyBase64: "k", Port: 62206},
			want:         "k\x00<unaddressed>:62206",
			wantSentinel: true,
		},
		{
			name:   "hostname with pipe is unambiguous (cr round-38 #8)",
			target: common.RedirectTarget{PubKeyBase64: "k", Hostname: "host|with|pipes", Port: 62206},
			want:   "k\x00host|with|pipes:62206",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, gotSentinel := targetActiveKey(c.target)
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
			if gotSentinel != c.wantSentinel {
				t.Errorf("sentinel: got %v, want %v", gotSentinel, c.wantSentinel)
			}
		})
	}
}

// TestACRegistration_ReconcileDevicePeers_EmitsUnaddressedMetric fences
// the alarm path for a Validate (#832) regression: a target without IP
// and without Hostname must surface to alarms via
// MetricUnaddressedTarget, not just to log-grep. The metric is
// incremented inside reconcileDevicePeers per sentinel observation
// (the per-pass aggregation sums sentinel hits across both newServers
// and priorServers loops; AddCounterWithDims with the count gives a
// per-observation time-series).
func TestACRegistration_ReconcileDevicePeers_EmitsUnaddressedMetric(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	reg.metrics = metrics.NewPublisherForTest(t)

	priorPeer := &core.UdpPeer{Ip: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: "cHJpb3ItcHVia2V5", Type: core.NHP_SERVER}
	device.AddPeer(priorPeer)

	priorServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: "cHJpb3ItcHVia2V5"}, Peer: priorPeer},
	}
	// New target has no IP and no Hostname — the <unaddressed> sentinel branch.
	newServers := []*AssignedServer{
		{Target: common.RedirectTarget{PubKeyBase64: "bmV3LXB1YmtleQ==", Port: DefaultServerPort}},
	}

	reg.reconcileDevicePeers(priorServers, newServers)

	matches, total := countDimCountersWithPrefix(t, reg, MetricUnaddressedTarget)
	if matches != 1 {
		t.Errorf("expected exactly 1 MetricUnaddressedTarget dim entry, got %d", matches)
	}
	if total != 1.0 {
		t.Errorf("expected MetricUnaddressedTarget total to be 1.0 (one sentinel hit), got %v", total)
	}
}

// TestACRegistration_ReconcileDevicePeers_LookupPeerDefenseSkipsReplaced
// fences the defense-in-depth branch in reconcileDevicePeers:
// when the device's current entry for a prior peer's pubkey is a different
// *core.UdpPeer than the one captured at snapshot time, the function must
// skip RemovePeerByAddress rather than wholesale-delete peerMap[K]. Without
// this guard, core.Device.RemovePeerByAddress's non-PeerGroup branch would
// evict the sibling-installed replacement.
//
// Scenario: a prior assignment installed a peer; a sibling AddPeer at the
// same pubkey + same address replaced the peerMap entry pointer (via
// AddPeer's same-address-replace branch); reconcile runs with the original
// prior in priorServers, expects to evict it, finds the replacement instead,
// and must skip the device call.
func TestACRegistration_ReconcileDevicePeers_LookupPeerDefenseSkipsReplaced(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	const sharedPubKey = "ZGVmZW5zZS1pbi1kZXB0aC1wdWJrZXk="

	priorPeer := &core.UdpPeer{Ip: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	device.AddPeer(priorPeer)

	// Sibling AddPeer at the same (pubkey, address) replaces peerMap[K]'s
	// pointer in-place via udpPeersShareAddress's same-address-replace
	// branch. After this, peerMap[K] points at replacementPeer, not priorPeer.
	replacementPeer := &core.UdpPeer{Ip: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	device.AddPeer(replacementPeer)

	pubKeyBytes := replacementPeer.PublicKey()
	current := device.LookupPeer(pubKeyBytes)
	if current == nil {
		t.Fatal("test setup: pubkey should resolve before reconcile")
	}
	if udp, ok := current.(*core.UdpPeer); !ok || udp == priorPeer {
		t.Fatalf("test setup: peerMap[K] should be replacementPeer, got %T (priorPeer match=%v)", current, udp == priorPeer)
	}

	priorServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: priorPeer.Ip, Port: priorPeer.Port, PubKeyBase64: priorPeer.PubKeyBase64}, Peer: priorPeer},
	}
	newServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.99", Port: DefaultServerPort, PubKeyBase64: "b3RoZXItcHVia2V5LWZvci1uZXc="}},
	}

	reg.reconcileDevicePeers(priorServers, newServers)

	// Defense fired: replacement still in the pool because the LookupPeer
	// identity check saw udp != srv.Peer and skipped RemovePeerByAddress.
	if device.LookupPeer(pubKeyBytes) == nil {
		t.Fatal("regression: LookupPeer defense should have skipped removal — replacement was wiped along with the prior")
	}
}

// TestACRegistration_HandleRedispatch_AllConnectsFail_EvictsPriorPeers
// fences the evict-all-priors branch in HandleRedispatch's
// successCount == 0 path. Pre-PR this
// path leaked prior peers in the device pool until process restart;
// post-PR it calls reconcileDevicePeers(priorServers, nil) so the
// genuinely-retired priors leave the pool, restoring Stop()'s invariant
// that assignedServers is the only place peers are referenced.
//
// Drives the failure path without network mocking: UdpAC.IsRunning()
// returns false by default (running atomic.Bool zero value), and
// connectToServer's IsRunning gate fires before the sendMsgCh send,
// so every connect returns "AC not running" without touching the
// network. successCount == 0 → the new reconcile call evicts priors.
func TestACRegistration_HandleRedispatch_AllConnectsFail_EvictsPriorPeers(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	// reg.ac.running stays false (default atomic.Bool zero value), which
	// drives connectToServer's IsRunning gate to fail fast WITHOUT
	// touching the network — every connect returns "AC not running"
	// before the sendMsgCh send. This is what makes successCount == 0
	// reachable without mocking. Implementation note: if connectToServer
	// is ever refactored to fast-fail via a different mechanism (e.g.,
	// moving the IsRunning check earlier, or replacing it with a
	// context-cancellation gate), this test could silently start
	// exercising the new path — which may or may not still drive the
	// successCount == 0 branch. Verify the failure mechanism is
	// equivalent before relying on this harness for new test cases.
	reg.metrics = metrics.NewPublisherForTest(t)

	// Harness pre-condition fence. The successCount == 0 branch this test
	// drives is reached by connectToServer's IsRunning gate fast-failing
	// every connect (registration.go:1582). That gate reads
	// reg.ac.running.Load(); if running is true (or if the gate is
	// removed entirely), connectToServer no longer fast-fails on this
	// harness alone and the test would silently start exercising a
	// different path. Assert the precondition explicitly so a refactor
	// of the gate breaks here, with a pointer at the gate site, rather
	// than further downstream where the failure is harder to diagnose.
	if reg.ac.IsRunning() {
		t.Fatal("harness regression: reg.ac should NOT be running at test start — the successCount==0 branch is reached via connectToServer's IsRunning gate (registration.go:1582). If IsRunning() is now true here, either the harness needs updating or connectToServer's gate has moved.")
	}

	priorPeer := &core.UdpPeer{Ip: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: "cHJpb3ItYXNzaWduZWQtcGVlcg==", Type: core.NHP_SERVER}
	device.AddPeer(priorPeer)
	priorKey := priorPeer.PublicKey()
	if device.LookupPeer(priorKey) == nil {
		t.Fatal("test setup: prior peer should resolve before HandleRedispatch")
	}

	reg.mu.Lock()
	reg.assignedServers = []*AssignedServer{
		{Target: common.RedirectTarget{IP: priorPeer.Ip, Port: priorPeer.Port, PubKeyBase64: priorPeer.PubKeyBase64}, Peer: priorPeer, Connected: true},
	}
	reg.mu.Unlock()

	err := reg.HandleRedispatch(&common.ACRedispatchMsg{
		Targets: []common.RedirectTarget{
			{IP: "127.0.0.1", Port: 1, PubKeyBase64: "bmV3LXVucmVhY2hhYmxlLXBlZXI=", AZ: "us-east-2a"},
		},
	})

	if err == nil {
		t.Fatal("expected error from HandleRedispatch when all connects fail")
	}
	if !strings.Contains(err.Error(), "failed to connect") {
		t.Errorf("unexpected error: %v", err)
	}

	if device.LookupPeer(priorKey) != nil {
		t.Error("regression: prior peer should have been evicted by successCount==0 reconcile, but is still in the device pool")
	}

	// Fence the cr round-33 #1 fix in connectToServer's IsRunning gate:
	// pre-fix the just-AddPeer'd new peer (pubkey "bmV3LXVucmVhY2hhYmxlLXBlZXI=")
	// would leak into the device pool when IsRunning returned false. The
	// reconcile call doesn't catch it (different pubkey from priors), so
	// connectToServer's IsRunning branch must clean up itself, mirroring
	// the timeout/cancel branches below.
	leakedPubKey, _ := base64.StdEncoding.DecodeString("bmV3LXVucmVhY2hhYmxlLXBlZXI=")
	if device.LookupPeer(leakedPubKey) != nil {
		t.Error("regression: connectToServer's IsRunning early-return must call RemovePeerByAddress on the just-AddPeer'd peer (cr round-33 #1)")
	}

	// Fence MetricNilNewServersReconcile emission — the all-fail branch must
	// surface to soak observation as a separate signal from MetricReconcileOverlap
	// so #1693's threshold authoring can distinguish overlap-during-incident
	// from steady-state overlap.
	matches, _ := countDimCountersWithPrefix(t, reg, MetricNilNewServersReconcile)
	if matches != 1 {
		t.Errorf("expected exactly 1 MetricNilNewServersReconcile dim entry, got %d", matches)
	}

	// Fragility-fence: the harness assumes connectToServer's IsRunning gate
	// drives the failure. Assert MetricServerConnectionFailure was actually
	// emitted — if a future refactor moves the gate or makes it succeed,
	// this assertion fails loudly instead of silently exercising a different
	// code path.
	connectFailures, _ := countDimCountersWithPrefix(t, reg, MetricServerConnectionFailure)
	if connectFailures < 1 {
		t.Errorf("harness regression: expected MetricServerConnectionFailure >= 1 (the IsRunning gate should have failed at least one connect), got %d — connectToServer may have started succeeding, in which case this test no longer exercises the successCount==0 branch", connectFailures)
	}
}

// TestACRegistration_ReconcileDevicePeers_NilSafe verifies nil entries do not
// panic and an empty prior set is a no-op.
func TestACRegistration_ReconcileDevicePeers_NilSafe(t *testing.T) {
	reg, _ := newACRegistrationWithDevice(t)

	reg.reconcileDevicePeers(nil, nil)

	priorServers := []*AssignedServer{
		nil,
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: "k"}, Peer: nil},
	}
	newServers := []*AssignedServer{
		nil,
	}
	reg.reconcileDevicePeers(priorServers, newServers)
}

// TestACRegistration_ReconcileDevicePeers_AllPeerNilPriors_NoOp fences the
// srv.Peer == nil guard explicitly. Drives reconcile with a non-empty prior
// slice where EVERY entry has .Peer == nil — the documented post-condition
// of HandleRedispatch's all-fail path before its successCount==0 reconcile
// runs. The loop must skip every prior (no LookupPeer, no
// RemovePeerByAddress) and the device pool must be unchanged.
//
// Catches a regression that, e.g., tightened the guard to only `srv == nil`
// or moved the guard below the LookupPeer call — both would panic on
// srv.Peer.PublicKey() or pass through to the device call with a nil peer.
func TestACRegistration_ReconcileDevicePeers_AllPeerNilPriors_NoOp(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)

	// Plant an unrelated peer in the device pool. If reconcile incorrectly
	// touched it, the test would fail.
	bystander := &core.UdpPeer{Ip: "10.0.0.99", Port: DefaultServerPort, PubKeyBase64: "Ynlz", Type: core.NHP_SERVER}
	device.AddPeer(bystander)
	bystanderKey := bystander.PublicKey()
	if device.LookupPeer(bystanderKey) == nil {
		t.Fatal("test setup: bystander should resolve before reconcile")
	}

	priorServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: "k1"}, Peer: nil},
		{Target: common.RedirectTarget{IP: "10.0.0.2", Port: DefaultServerPort, PubKeyBase64: "k2"}, Peer: nil},
		{Target: common.RedirectTarget{IP: "10.0.0.3", Port: DefaultServerPort, PubKeyBase64: "k3"}, Peer: nil},
	}
	newServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.1.0.1", Port: DefaultServerPort, PubKeyBase64: "newpk"}},
	}

	reg.reconcileDevicePeers(priorServers, newServers)

	if device.LookupPeer(bystanderKey) == nil {
		t.Error("regression: reconcile should be a no-op on all-Peer-nil priors but bystander was evicted")
	}
}

// TestACRegistration_ReconcileDevicePeers_MetricsAccumulateAcrossCalls
// fences the cumulative counter behavior across multiple reconcile calls
// on the same ACRegistration. Catches a regression where someone resets
// metric state between calls (e.g., adding a per-call publisher reset for
// some "isolation" reason). Drives two reconciles with sentinel-bearing
// targets and asserts MetricUnaddressedTarget totals across both calls,
// not just the most recent.
func TestACRegistration_ReconcileDevicePeers_MetricsAccumulateAcrossCalls(t *testing.T) {
	reg, _ := newACRegistrationWithDevice(t)
	reg.metrics = metrics.NewPublisherForTest(t)

	// Each call has 1 sentinel hit (newServers contains a target with
	// neither IP nor Hostname). After two calls, the total should be 2.
	priors := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: "p1"}, Peer: &core.UdpPeer{Ip: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: "p1", Type: core.NHP_SERVER}},
	}
	sentinelNew := []*AssignedServer{
		{Target: common.RedirectTarget{PubKeyBase64: "broken", Port: DefaultServerPort}}, // no IP, no Hostname
	}

	reg.reconcileDevicePeers(priors, sentinelNew)
	reg.reconcileDevicePeers(priors, sentinelNew)

	matches, total := countDimCountersWithPrefix(t, reg, MetricUnaddressedTarget)
	if matches != 1 {
		t.Errorf("expected exactly 1 MetricUnaddressedTarget dim entry across both calls, got %d", matches)
	}
	if total != 2.0 {
		t.Errorf("expected MetricUnaddressedTarget total to be 2.0 (one sentinel hit per call × 2 calls), got %v", total)
	}
}

// TestACRegistration_ReconcileInFlightCounter_ValidationEarlyReturns asserts
// that validation-only error returns from HandleRedispatch do NOT touch the
// in-flight counter. The counter (and its MetricReconcileOverlap signal) is
// scoped to the post-validation path that actually mutates peer-pool state.
// Validation early-returns are no-ops and would be metric noise — they're
// excluded by the recordReconcileEntry placement.
func TestACRegistration_ReconcileInFlightCounter_ValidationEarlyReturns(t *testing.T) {
	ac := &UdpAC{
		config: &Config{ACId: "test-ac-1680", ServerEndpoint: "server.nhp.test.internal"},
	}
	reg := mustNewACRegistration(t, ac)

	cases := []struct {
		name   string
		ardMsg *common.ACRedispatchMsg
	}{
		{name: "error code set", ardMsg: &common.ACRedispatchMsg{ErrCode: "LICENSE_EXPIRED", ErrMsg: "x"}},
		{name: "no targets", ardMsg: &common.ACRedispatchMsg{Targets: nil}},
		{name: "all targets filtered", ardMsg: &common.ACRedispatchMsg{Targets: []common.RedirectTarget{{IP: "", Hostname: "", Port: 0}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := reg.reconcileInFlight.Load(); got != 0 {
				t.Fatalf("precondition: counter should be 0, got %d", got)
			}
			_ = reg.HandleRedispatch(c.ardMsg)
			if got := reg.reconcileInFlight.Load(); got != 0 {
				t.Errorf("validation early-return for %s touched the counter: got %d, want 0", c.name, got)
			}
		})
	}
}

// TestACRegistration_ReconcileInFlightCounter_StoppedEarlyReturn asserts
// the stopped-manager early return at the top of HandleRedispatch does NOT
// touch the in-flight counter. recordReconcileEntry is gated on actual
// peer-pool work; the post-Stop fast path runs no work at all.
func TestACRegistration_ReconcileInFlightCounter_StoppedEarlyReturn(t *testing.T) {
	ac := &UdpAC{
		config: &Config{ACId: "test-ac-1680", ServerEndpoint: "server.nhp.test.internal"},
	}
	reg := mustNewACRegistration(t, ac)
	reg.stopped.Store(true)

	if got := reg.reconcileInFlight.Load(); got != 0 {
		t.Fatalf("precondition: counter should be 0, got %d", got)
	}

	err := reg.HandleRedispatch(&common.ACRedispatchMsg{Targets: []common.RedirectTarget{{IP: "10.0.0.1", Port: DefaultServerPort, PubKeyBase64: "k"}}})
	if err == nil {
		t.Error("HandleRedispatch on stopped manager should return ErrRegistrationStopped")
	}
	if got := reg.reconcileInFlight.Load(); got != 0 {
		t.Errorf("stopped early-return touched the counter: got %d, want 0", got)
	}
}

// TestACRegistration_RecordReconcileEntry covers the helper used by
// HandleRedispatch to track in-flight count and surface
// MetricReconcileOverlap. Drives the helper directly because the success
// path that exercises the post-validation increment from inside
// HandleRedispatch requires a live network for connectToServer.
func TestACRegistration_RecordReconcileEntry(t *testing.T) {
	ac := &UdpAC{
		config: &Config{ACId: "test-ac-1680", ServerEndpoint: "server.nhp.test.internal"},
	}
	reg := mustNewACRegistration(t, ac)

	t.Run("solo entry increments and decrements symmetrically", func(t *testing.T) {
		// Match the overlap subtest's harness — inject the in-memory publisher
		// so this subtest doesn't accidentally exercise the real CloudWatch-
		// bound publisher. Both subtests now share the same shape.
		reg.metrics = metrics.NewPublisherForTest(t)

		exit := reg.recordReconcileEntry()
		if got := reg.reconcileInFlight.Load(); got != 1 {
			t.Errorf("after entry: counter should be 1, got %d", got)
		}
		exit()
		if got := reg.reconcileInFlight.Load(); got != 0 {
			t.Errorf("after exit: counter should return to 0, got %d", got)
		}
	})

	t.Run("overlap entry exits to held baseline and emits MetricReconcileOverlap", func(t *testing.T) {
		// Inject a real *metrics.Publisher that records counter emissions
		// in memory (no AWS, no flush goroutine). With this we can assert
		// not just counter symmetry but that MetricReconcileOverlap was
		// actually emitted on the inFlight > 1 branch — symmetric tests
		// alone would pass even if the if-condition silently broke.
		reg.metrics = metrics.NewPublisherForTest(t)

		reg.reconcileInFlight.Add(1)
		t.Cleanup(func() { reg.reconcileInFlight.Add(-1) })

		exit := reg.recordReconcileEntry()
		if got := reg.reconcileInFlight.Load(); got != 2 {
			t.Errorf("overlap entry: counter should be 2, got %d", got)
		}
		exit()
		if got := reg.reconcileInFlight.Load(); got != 1 {
			t.Errorf("overlap exit: counter should return to held baseline 1, got %d", got)
		}

		matches, total := countDimCountersWithPrefix(t, reg, MetricReconcileOverlap)
		if matches != 1 {
			t.Errorf("expected exactly 1 MetricReconcileOverlap dim entry, got %d", matches)
		}
		if total != 1.0 {
			t.Errorf("expected MetricReconcileOverlap total to be 1.0 (one overlap), got %v", total)
		}
	})

	t.Run("solo entry does not emit MetricReconcileOverlap", func(t *testing.T) {
		reg.metrics = metrics.NewPublisherForTest(t)
		if got := reg.reconcileInFlight.Load(); got != 0 {
			t.Fatalf("precondition: counter should be 0, got %d", got)
		}

		exit := reg.recordReconcileEntry()
		exit()

		if matches, _ := countDimCountersWithPrefix(t, reg, MetricReconcileOverlap); matches != 0 {
			t.Errorf("solo entry should not emit MetricReconcileOverlap; got %d match(es)", matches)
		}
	})

	// Makes the Stop() comment's "metric drop semantics" contract executable:
	// an in-flight reconcile bumping IncrCounterWithDims after r.metrics.Stop()
	// must not panic, hang, or deadlock — the bump is silently dropped and
	// the goroutine returns. Without this fence, a future change to
	// metrics.Publisher.Stop that, e.g., closed a channel that
	// IncrCounterWithDims sends on would crash dying-AC goroutines.
	t.Run("overlap entry after Stop is panic-safe (drop semantics)", func(t *testing.T) {
		reg.metrics = metrics.NewPublisherForTest(t)
		reg.metrics.Stop() // simulate the AC dying mid-reconcile

		// Drive the overlap branch: pre-increment to force inFlight > 1
		// inside recordReconcileEntry's atomic compare.
		reg.reconcileInFlight.Add(1)
		t.Cleanup(func() { reg.reconcileInFlight.Add(-1) })

		// If IncrCounterWithDims-after-Stop panics or blocks, this test
		// fails (panic propagates) or times out (default Go test deadline).
		exit := reg.recordReconcileEntry()
		exit()

		// Sanity: counter symmetry held even on the dying-process path.
		if got := reg.reconcileInFlight.Load(); got != 1 {
			t.Errorf("counter symmetry after Stop+overlap: expected 1, got %d", got)
		}
	})
}

// TestACRegistration_SmokeLogSubstringsPresent fences the load-bearing
// log wording the smoke fence tests/smoke/09_ac_redispatch_loop_test.go
// substring-matches against. The smoke test runs against deployed
// instances and only fails on regression; this test runs at unit-level
// build/lint time so a wording refactor breaks fast, before deploy.
//
// #1714 tracks adding stable structured tags to the emission sites,
// after which this fence becomes redundant.
func TestACRegistration_SmokeLogSubstringsPresent(t *testing.T) {
	// Resolve paths relative to this test file so the fence works from
	// any go test invocation cwd (cr round-34 #1: don't depend on the
	// implicit cwd-is-package-dir assumption that os.ReadFile bare-name
	// would impose).
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed; cannot resolve test file path")
	}
	pkgDir := filepath.Dir(thisFile)

	// (filepath, required substrings) pairs. Each substring is part of
	// a smoke regex in tests/smoke/09_ac_redispatch_loop_test.go and a
	// rename in either file would silently zero out the smoke query.
	// Both files MUST stay in lockstep with the smoke regexes until
	// #1714's structured-tag replacement lands.
	cases := []struct {
		path     string // relative to pkgDir
		required []string
	}{
		{
			path: "registration.go", // emission site
			required: []string{
				"servers appear down, triggering re-registration", // checkAllUnconnected branch
				"Refresh NHP_AOL to ",                             // handleRefreshResponse error branch
				"failed: ",                                        // joins the NHP_AOL emission with ErrPeerNotFound's message
			},
		},
		{
			path: "../../nhp/core/errors.go", // ErrPeerNotFound's message text
			required: []string{
				"peer not found in peer pool", // smoke regex: /Refresh NHP_AOL to .* failed: peer not found in peer pool/
			},
		},
	}

	for _, c := range cases {
		full := filepath.Join(pkgDir, c.path)
		src, err := os.ReadFile(full)
		if err != nil {
			t.Fatalf("read %s: %v", full, err)
		}
		source := string(src)
		for _, s := range c.required {
			if !strings.Contains(source, s) {
				t.Errorf("smoke fence regression: %s no longer contains substring %q — the smoke test's CloudWatch Logs Insights query will silently zero out. Either restore the wording or land #1714's structured-tag replacement and update tests/smoke/09_ac_redispatch_loop_test.go's queries in lockstep.", c.path, s)
			}
		}
	}
}
