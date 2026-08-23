package ac

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

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

func devicePeerIPs(t *testing.T, device *core.Device, pubKey []byte) map[string]bool {
	t.Helper()
	peer := device.LookupPeer(pubKey)
	if peer == nil {
		t.Fatal("device peer entry is absent")
	}
	memberIPs := make(map[string]bool)
	switch p := peer.(type) {
	case *core.UdpPeer:
		memberIPs[p.Ip] = true
	case *core.PeerGroup:
		for _, member := range p.Members() {
			memberIPs[member.Ip] = true
		}
	default:
		t.Fatalf("device peer entry = %T, want *core.UdpPeer or *core.PeerGroup", peer)
	}
	return memberIPs
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON fixture: %v", err)
	}
	return body
}

// TestACRegistration_HandleRedispatch_PrunesRetiredPeersBeforeConnect fences
// the 2026-07-18 sandbox failure where a periodic NLB refresh reached a
// shared-key PeerGroup at MaxPeerGroupSize. Three retired server members still
// occupied the group; one live replacement filled the last slot and AddPeer
// refused the other two. Their NHP_AOP replies then failed address validation
// and surfaced as 52005.
//
// HandleRedispatch must apply the new authoritative assignment's set
// difference before connectToServer adds its members. Keeping the unrelated
// NLB member makes the capacity pressure realistic: only retiring the stale
// assigned servers creates enough slots for all live replacements.
func TestACRegistration_HandleRedispatch_PrunesRetiredPeersBeforeConnect(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	reg.ac.sendMsgCh = make(chan *core.MsgData, 3)
	reg.ac.running.Store(true)
	defer reg.Stop()

	sharedKeyBytes := bytes.Repeat([]byte{0x42}, core.PublicKeySize)
	sharedPubKey := base64.StdEncoding.EncodeToString(sharedKeyBytes)
	newPeerIPs := []string{"10.100.10.103", "10.100.11.144", "10.100.12.145"}

	priorServers := make([]*AssignedServer, 0, 3)
	for _, ip := range []string{"10.100.10.10", "10.100.11.11", "10.100.12.12"} {
		peer := &core.UdpPeer{Ip: ip, Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
		device.AddPeer(peer)
		priorServers = append(priorServers, &AssignedServer{
			Target: common.RedirectTarget{IP: ip, Port: testServerListenPort, PubKeyBase64: sharedPubKey},
			Peer:   peer,
		})
	}
	// The NLB registration peer shares the key but is not part of the prior
	// assignment, so reconcile must leave it alone. Together with the three
	// retired peers it leaves exactly one slot before refresh: without the
	// pre-connect prune, one new server wins the race and the other two are
	// refused at MaxPeerGroupSize.
	registrationPeer := &core.UdpPeer{Ip: "10.100.20.20", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	device.AddPeer(registrationPeer)

	reg.mu.Lock()
	reg.assignedServers = priorServers
	reg.mu.Unlock()

	targets := make([]common.RedirectTarget, 0, len(newPeerIPs))
	for _, ip := range newPeerIPs {
		targets = append(targets, common.RedirectTarget{
			IP: ip, Port: testServerListenPort, PubKeyBase64: sharedPubKey,
		})
	}

	result := make(chan error, 1)
	go func() {
		result <- reg.handleRedispatch(&common.ACRedispatchMsg{
			ErrCode: common.ErrSuccess.ErrorCode(),
			Targets: targets,
		}, registrationPeer)
	}()

	requests := make([]*core.MsgData, 0, len(newPeerIPs))
	for range newPeerIPs {
		select {
		case md := <-reg.ac.sendMsgCh:
			requests = append(requests, md)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for redispatch connection request")
		}
	}

	memberIPs := devicePeerIPs(t, device, sharedKeyBytes)
	livePeersInstalled := true
	for _, ip := range newPeerIPs {
		livePeersInstalled = livePeersInstalled && memberIPs[ip]
	}

	aakBody, err := json.Marshal(common.ServerACAckMsg{
		ErrCode: common.ErrSuccess.ErrorCode(),
	})
	if err != nil {
		t.Fatalf("marshal NHP_AAK: %v", err)
	}
	for _, md := range requests {
		md.ResponseMsgCh <- successfulTestAAKPacket(reg.ac, aakBody)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("HandleRedispatch: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for HandleRedispatch")
	}

	if !livePeersInstalled {
		t.Fatalf("live replacement peers were absent before their replies; member IPs: %v", memberIPs)
	}

	for _, server := range priorServers {
		if memberIPs[server.Target.IP] {
			t.Errorf("retired peer %s still occupied a shared-key slot before replies", server.Target.IP)
		}
	}
	for _, ip := range newPeerIPs {
		if !memberIPs[ip] {
			t.Errorf("live peer %s was refused despite retired capacity", ip)
		}
	}
	if !memberIPs[registrationPeer.Ip] {
		t.Errorf("in-flight registration peer %s was not preserved", registrationPeer.Ip)
	}
}

// TestACRegistration_HandleRedispatch_RotatingSharedKeyConvergesActualGroup
// fences #2123's cross-epoch leak. The setup starts from the live failure
// shape: one blue server remains in PeerGroup even though the most-recent
// priorServers slice has already forgotten it. Eight three-server assignments
// then rotate across blue and green fleets sharing one key. Every epoch must
// converge the actual group to exactly the three assigned servers plus the
// in-flight NLB registration peer; a priorServers-only delta fails on epoch 1.
func TestACRegistration_HandleRedispatch_RotatingSharedKeyConvergesActualGroup(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	reg.ac.sendMsgCh = make(chan *core.MsgData, 3)
	reg.ac.running.Store(true)
	defer reg.Stop()

	sharedKeyBytes := bytes.Repeat([]byte{0x43}, core.PublicKeySize)
	sharedPubKey := base64.StdEncoding.EncodeToString(sharedKeyBytes)
	registrationPeer := &core.UdpPeer{Ip: "10.100.20.20", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	device.AddPeer(registrationPeer)

	blue := []string{"10.100.10.10", "10.100.11.11", "10.100.12.12"}
	green := []string{"10.100.10.103", "10.100.11.144", "10.100.12.145"}
	bluePeers := make([]*core.UdpPeer, 0, len(blue))
	for _, ip := range blue {
		peer := &core.UdpPeer{Ip: ip, Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
		reg.addAssignmentPeer(peer)
		bluePeers = append(bluePeers, peer)
	}
	// blue[2] is deliberately absent from priorServers: it models a member
	// forgotten across earlier rotating-subset epochs while still resident in
	// the actual PeerGroup.
	reg.mu.Lock()
	reg.assignedServers = []*AssignedServer{
		{Target: common.RedirectTarget{IP: blue[0], Port: testServerListenPort, PubKeyBase64: sharedPubKey}, Peer: bluePeers[0]},
		{Target: common.RedirectTarget{IP: blue[1], Port: testServerListenPort, PubKeyBase64: sharedPubKey}, Peer: bluePeers[1]},
	}
	reg.mu.Unlock()

	epochs := [][]string{
		{green[0], green[1], green[2]},
		{green[1], green[2], blue[0]},
		{green[2], blue[0], blue[1]},
		{blue[0], blue[1], blue[2]},
		{green[0], blue[1], blue[2]},
		{green[0], green[1], blue[2]},
		{green[0], green[1], green[2]},
		{blue[0], blue[1], blue[2]},
	}
	aakBody, err := json.Marshal(common.ServerACAckMsg{ErrCode: common.ErrSuccess.ErrorCode()})
	if err != nil {
		t.Fatalf("marshal NHP_AAK: %v", err)
	}

	for epoch, ips := range epochs {
		targets := make([]common.RedirectTarget, 0, len(ips))
		for _, ip := range ips {
			targets = append(targets, common.RedirectTarget{IP: ip, Port: testServerListenPort, PubKeyBase64: sharedPubKey})
		}

		result := make(chan error, 1)
		go func() {
			result <- reg.handleRedispatch(&common.ACRedispatchMsg{
				ErrCode: common.ErrSuccess.ErrorCode(),
				Targets: targets,
			}, registrationPeer)
		}()

		requests := make([]*core.MsgData, 0, len(ips))
		for range ips {
			select {
			case md := <-reg.ac.sendMsgCh:
				requests = append(requests, md)
			case <-time.After(time.Second):
				t.Fatalf("epoch %d: timed out waiting for redispatch request", epoch+1)
			}
		}
		memberIPs := devicePeerIPs(t, device, sharedKeyBytes)
		for _, md := range requests {
			md.ResponseMsgCh <- successfulTestAAKPacket(reg.ac, aakBody)
		}
		select {
		case err := <-result:
			if err != nil {
				t.Fatalf("epoch %d: HandleRedispatch: %v", epoch+1, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("epoch %d: timed out waiting for HandleRedispatch", epoch+1)
		}

		if len(memberIPs) != len(ips)+1 {
			t.Fatalf("epoch %d: member IPs = %v, want exactly assignment + registration peer", epoch+1, memberIPs)
		}
		if !memberIPs[registrationPeer.Ip] {
			t.Errorf("epoch %d: registration peer %s was not preserved", epoch+1, registrationPeer.Ip)
		}
		for _, ip := range ips {
			if !memberIPs[ip] {
				t.Errorf("epoch %d: assigned peer %s is absent; member IPs: %v", epoch+1, ip, memberIPs)
			}
		}
	}
}

// TestACRegistration_AuthoritativeTransitionsSerialize proves that a second
// assignment cannot begin peer installation while the first is blocked on its
// UDP acknowledgements. Once the first completes, the later assignment runs
// and owns the final shared-key membership.
func TestACRegistration_AuthoritativeTransitionsSerialize(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	reg.ac.sendMsgCh = make(chan *core.MsgData, 3)
	reg.ac.running.Store(true)
	defer reg.Stop()

	sharedKeyBytes := bytes.Repeat([]byte{0x45}, core.PublicKeySize)
	sharedPubKey := base64.StdEncoding.EncodeToString(sharedKeyBytes)
	blue := []string{"10.100.10.10", "10.100.11.11", "10.100.12.12"}
	green := []string{"10.100.10.103", "10.100.11.144", "10.100.12.145"}
	targets := func(ips []string) []common.RedirectTarget {
		out := make([]common.RedirectTarget, 0, len(ips))
		for _, ip := range ips {
			out = append(out, common.RedirectTarget{IP: ip, Port: testServerListenPort, PubKeyBase64: sharedPubKey})
		}
		return out
	}

	firstResult := make(chan error, 1)
	go func() {
		firstResult <- reg.HandleRedispatch(&common.ACRedispatchMsg{
			ErrCode: common.ErrSuccess.ErrorCode(),
			Targets: targets(blue),
		})
	}()

	firstRequests := make([]*core.MsgData, 0, len(blue))
	for range blue {
		select {
		case md := <-reg.ac.sendMsgCh:
			firstRequests = append(firstRequests, md)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for first assignment request")
		}
	}
	if reg.transitionMu.TryLock() {
		reg.transitionMu.Unlock()
		t.Fatal("first assignment did not hold transitionMu while awaiting UDP acknowledgements")
	}

	secondAcquired := make(chan struct{})
	releaseSecond := make(chan struct{})
	defer func() {
		select {
		case <-releaseSecond:
		default:
			close(releaseSecond)
		}
	}()
	reg.afterRedispatchTransitionLock = func() {
		close(secondAcquired)
		<-releaseSecond
	}
	secondResult := make(chan error, 1)
	go func() {
		secondResult <- reg.HandleRedispatch(&common.ACRedispatchMsg{
			ErrCode: common.ErrSuccess.ErrorCode(),
			Targets: targets(green),
		})
	}()

	aakBody, err := json.Marshal(common.ServerACAckMsg{ErrCode: common.ErrSuccess.ErrorCode()})
	if err != nil {
		t.Fatalf("marshal NHP_AAK: %v", err)
	}
	for _, md := range firstRequests {
		md.ResponseMsgCh <- successfulTestAAKPacket(reg.ac, aakBody)
	}
	select {
	case err := <-firstResult:
		if err != nil {
			t.Fatalf("first HandleRedispatch: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first assignment")
	}
	select {
	case <-secondAcquired:
	case <-time.After(time.Second):
		t.Fatal("second assignment did not acquire transitionMu after first completed")
	}
	close(releaseSecond)

	secondRequests := make([]*core.MsgData, 0, len(green))
	for range green {
		select {
		case md := <-reg.ac.sendMsgCh:
			secondRequests = append(secondRequests, md)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for second assignment request")
		}
	}
	for _, md := range secondRequests {
		md.ResponseMsgCh <- successfulTestAAKPacket(reg.ac, aakBody)
	}
	select {
	case err := <-secondResult:
		if err != nil {
			t.Fatalf("second HandleRedispatch: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for second assignment")
	}

	memberIPs := devicePeerIPs(t, device, sharedKeyBytes)
	if len(memberIPs) != len(green) {
		t.Fatalf("final member IPs = %v, want later assignment %v", memberIPs, green)
	}
	for _, ip := range green {
		if !memberIPs[ip] {
			t.Errorf("later assigned peer %s is absent; member IPs: %v", ip, memberIPs)
		}
	}
}

func TestACRegistration_StopCancelsPrefenceAuthoritativeResponse(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	sharedKeyBytes := bytes.Repeat([]byte{0x4d}, core.PublicKeySize)
	sharedPubKey := base64.StdEncoding.EncodeToString(sharedKeyBytes)
	pending := &core.UdpPeer{Ip: "10.100.20.20", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	if err := reg.beginRegistrationAttempt(pending); err != nil {
		t.Fatalf("beginRegistrationAttempt: %v", err)
	}

	responseEntered := make(chan struct{})
	reg.afterRegistrationTransitionLock = func() {
		close(responseEntered)
		<-reg.stopCh
	}
	responseResult := make(chan error, 1)
	go func() {
		responseResult <- handleTestRegistrationResponse(reg, &core.PacketParserData{
			HeaderType:  core.NHP_AAK,
			BodyMessage: []byte(`{"errCode":"0","registered":true}`),
		}, pending)
	}()
	<-responseEntered

	stopDone := make(chan struct{})
	go func() {
		reg.Stop()
		close(stopDone)
	}()
	select {
	case err := <-responseResult:
		if !errors.Is(err, ErrRegistrationStopped) {
			t.Fatalf("pre-fence response error = %v, want ErrRegistrationStopped", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Stop did not close stopCh while response held transitionMu")
	}
	select {
	case <-stopDone:
	case <-time.After(time.Second):
		t.Fatal("Stop did not complete after pre-fence response")
	}

	if got := reg.GetAssignedServers(); len(got) != 0 {
		t.Fatalf("Stop left assigned servers after pre-fence response: %v", got)
	}
	if got := device.LookupPeer(sharedKeyBytes); got != nil {
		t.Fatalf("Stop left device peer after pre-fence response: %T", got)
	}
}

func TestACRegistration_StopCancelsInFlightRedispatchConnect(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	reg.ac.sendMsgCh = make(chan *core.MsgData)
	reg.ac.running.Store(true)
	sharedKeyBytes := bytes.Repeat([]byte{0x4e}, core.PublicKeySize)
	sharedPubKey := base64.StdEncoding.EncodeToString(sharedKeyBytes)

	result := make(chan error, 1)
	go func() {
		result <- reg.HandleRedispatch(&common.ACRedispatchMsg{
			ErrCode: common.ErrSuccess.ErrorCode(),
			Targets: []common.RedirectTarget{{
				IP: "10.100.10.103", Port: testServerListenPort, PubKeyBase64: sharedPubKey,
			}},
		})
	}()

	deadline := time.Now().Add(time.Second)
	for len(reg.assignmentPeersSnapshot()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for redispatch peer admission")
		}
		time.Sleep(time.Millisecond)
	}
	// connectToServer is blocked publishing to the unbuffered sendMsgCh while
	// transitionMu is held. Stop must close stopCh before trying to acquire that
	// mutex, and the send itself must select on stopCh rather than block forever.

	stopDone := make(chan struct{})
	go func() {
		reg.Stop()
		close(stopDone)
	}()
	select {
	case <-stopDone:
	case <-time.After(time.Second):
		t.Fatal("Stop waited for connection timeout instead of canceling through stopCh")
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrRegistrationStopped) {
			t.Fatalf("canceled redispatch error = %v, want ErrRegistrationStopped", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled redispatch did not return")
	}
	if got := device.LookupPeer(sharedKeyBytes); got != nil {
		t.Fatalf("Stop left canceled assignment peer in Device: %T", got)
	}
	for _, metricName := range []string{
		MetricServerConnectionFailure,
		MetricServerConnections,
		MetricRegistrationSuccess,
	} {
		_, total := countDimCountersWithPrefix(t, reg, metricName)
		if total != 0 {
			t.Errorf("Stop cancellation emitted %s = %v, want 0", metricName, total)
		}
	}
}

func TestACRegistration_StopCancellationDoesNotDegradeEmbeddedAAKToSuccess(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	reg.ac.sendMsgCh = make(chan *core.MsgData, 1)
	reg.ac.running.Store(true)
	sharedKeyBytes := bytes.Repeat([]byte{0x58}, core.PublicKeySize)
	sharedPubKey := base64.StdEncoding.EncodeToString(sharedKeyBytes)
	registrationPeer := &core.UdpPeer{Ip: "10.100.20.20", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	device.AddPeer(registrationPeer)
	aakBody := mustJSON(t, common.ServerACAckMsg{
		ErrCode:    common.ErrSuccess.ErrorCode(),
		Registered: true,
		Peers: []common.RedirectTarget{{
			IP: "10.100.10.103", Port: testServerListenPort, PubKeyBase64: sharedPubKey,
		}},
	})

	result := make(chan error, 1)
	go func() {
		result <- handleTestRegistrationResponse(reg, &core.PacketParserData{
			HeaderType:  core.NHP_AAK,
			BodyMessage: aakBody,
		}, registrationPeer)
	}()
	select {
	case <-reg.ac.sendMsgCh:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for embedded-AAK connection request")
	}

	stopDone := make(chan struct{})
	go func() {
		reg.Stop()
		close(stopDone)
	}()
	select {
	case err := <-result:
		if !errors.Is(err, ErrRegistrationStopped) {
			t.Fatalf("embedded-AAK cancellation error = %v, want ErrRegistrationStopped", err)
		}
	case <-time.After(time.Second):
		t.Fatal("embedded-AAK cancellation did not return")
	}
	select {
	case <-stopDone:
	case <-time.After(time.Second):
		t.Fatal("Stop did not complete after embedded-AAK cancellation")
	}

	for _, metricName := range []string{
		MetricServerConnectionFailure,
		MetricServerConnections,
		MetricRegistrationSuccess,
	} {
		_, total := countDimCountersWithPrefix(t, reg, metricName)
		if total != 0 {
			t.Errorf("embedded-AAK cancellation emitted %s = %v, want 0", metricName, total)
		}
	}
	if got := device.LookupPeer(sharedKeyBytes); got != nil {
		t.Fatalf("Stop left embedded-AAK peer state in Device: %T", got)
	}
}

func TestACRegistration_LateAuthoritativeResponseCannotRepopulateAfterStop(t *testing.T) {
	sharedKeyBytes := bytes.Repeat([]byte{0x49}, core.PublicKeySize)
	sharedPubKey := base64.StdEncoding.EncodeToString(sharedKeyBytes)
	tests := []struct {
		name string
		ppd  *core.PacketParserData
	}{
		{
			name: "direct AAK",
			ppd: &core.PacketParserData{
				HeaderType:  core.NHP_AAK,
				BodyMessage: []byte(`{"errCode":"0","registered":true}`),
			},
		},
		{
			name: "redispatch ARD",
			ppd: &core.PacketParserData{
				HeaderType: core.NHP_ARD,
				BodyMessage: mustJSON(t, common.ACRedispatchMsg{
					ErrCode: common.ErrSuccess.ErrorCode(),
					Targets: []common.RedirectTarget{{IP: "10.100.10.103", Port: testServerListenPort, PubKeyBase64: sharedPubKey}},
				}),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg, device := newACRegistrationWithDevice(t)
			pending := &core.UdpPeer{Ip: "10.100.20.20", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
			if err := reg.beginRegistrationAttempt(pending); err != nil {
				t.Fatalf("beginRegistrationAttempt: %v", err)
			}

			reg.Stop()
			err := handleTestRegistrationResponse(reg, tt.ppd, pending)
			if !errors.Is(err, ErrRegistrationStopped) {
				t.Fatalf("late response error = %v, want ErrRegistrationStopped", err)
			}
			if got := reg.GetAssignedServers(); len(got) != 0 {
				t.Fatalf("late response repopulated assigned servers: %v", got)
			}
			reg.mu.RLock()
			registrationPeer := reg.registrationPeer
			pendingPeer := reg.pendingRegistrationPeer
			reg.mu.RUnlock()
			if registrationPeer != nil || pendingPeer != nil {
				t.Fatalf("late response repopulated peer state: registration=%v pending=%v", registrationPeer, pendingPeer)
			}
			if got := device.LookupPeer(sharedKeyBytes); got != nil {
				t.Fatalf("late response repopulated device: %T", got)
			}
		})
	}
}

func TestACRegistration_MalformedARDCleansPendingPeer(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	sharedKeyBytes := bytes.Repeat([]byte{0x4a}, core.PublicKeySize)
	sharedPubKey := base64.StdEncoding.EncodeToString(sharedKeyBytes)
	pending := &core.UdpPeer{Ip: "10.100.20.20", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	if err := reg.beginRegistrationAttempt(pending); err != nil {
		t.Fatalf("beginRegistrationAttempt: %v", err)
	}

	err := handleTestRegistrationResponse(reg, &core.PacketParserData{
		HeaderType:  core.NHP_ARD,
		BodyMessage: []byte(`{not-json`),
	}, pending)
	if err == nil || !strings.Contains(err.Error(), "failed to parse NHP_ARD") {
		t.Fatalf("malformed ARD error = %v", err)
	}
	reg.mu.RLock()
	pendingPeer := reg.pendingRegistrationPeer
	reg.mu.RUnlock()
	if pendingPeer != nil {
		t.Fatalf("malformed ARD left pending marker: %v", pendingPeer)
	}
	if got := device.LookupPeer(sharedKeyBytes); got != nil {
		t.Fatalf("malformed ARD left temporary device peer: %T", got)
	}
}

// TestACRegistration_HandleRedispatch_PreservesPendingRegistrationPeer fences
// the overlap introduced by sweeping actual PeerGroup members. While an AOL is
// awaiting its response, an out-of-band redispatch must retain the temporary
// NLB peer even though that peer is absent from the assigned-server targets.
func TestACRegistration_HandleRedispatch_PreservesPendingRegistrationPeer(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	reg.ac.sendMsgCh = make(chan *core.MsgData, 3)
	reg.ac.running.Store(true)
	defer reg.Stop()

	sharedKeyBytes := bytes.Repeat([]byte{0x46}, core.PublicKeySize)
	sharedPubKey := base64.StdEncoding.EncodeToString(sharedKeyBytes)
	pendingPeer := &core.UdpPeer{Ip: "10.100.20.20", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	if err := reg.beginRegistrationAttempt(pendingPeer); err != nil {
		t.Fatalf("beginRegistrationAttempt: %v", err)
	}

	assigned := []string{"10.100.10.103", "10.100.11.144", "10.100.12.145"}
	targets := make([]common.RedirectTarget, 0, len(assigned))
	for _, ip := range assigned {
		targets = append(targets, common.RedirectTarget{IP: ip, Port: testServerListenPort, PubKeyBase64: sharedPubKey})
	}

	result := make(chan error, 1)
	go func() {
		result <- reg.HandleRedispatch(&common.ACRedispatchMsg{
			ErrCode: common.ErrSuccess.ErrorCode(),
			Targets: targets,
		})
	}()

	requests := make([]*core.MsgData, 0, len(assigned))
	for range assigned {
		select {
		case md := <-reg.ac.sendMsgCh:
			requests = append(requests, md)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for out-of-band redispatch request")
		}
	}
	memberIPs := devicePeerIPs(t, device, sharedKeyBytes)
	if !memberIPs[pendingPeer.Ip] {
		t.Fatalf("pending NLB peer was removed during blocked redispatch: %v", memberIPs)
	}

	aakBody, err := json.Marshal(common.ServerACAckMsg{ErrCode: common.ErrSuccess.ErrorCode()})
	if err != nil {
		t.Fatalf("marshal NHP_AAK: %v", err)
	}
	for _, md := range requests {
		md.ResponseMsgCh <- successfulTestAAKPacket(reg.ac, aakBody)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("HandleRedispatch: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for out-of-band redispatch")
	}

	if err := handleTestRegistrationResponse(reg, &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(`{"errCode":"0","registered":true}`),
	}, pendingPeer); err != nil {
		t.Fatalf("handleRegistrationResponse: %v", err)
	}
	memberIPs = devicePeerIPs(t, device, sharedKeyBytes)
	if len(memberIPs) != 1 || !memberIPs[pendingPeer.Ip] {
		t.Fatalf("later direct AAK did not become authoritative: %v", memberIPs)
	}
	reg.mu.RLock()
	pending := reg.pendingRegistrationPeer
	reg.mu.RUnlock()
	if pending != nil {
		t.Fatalf("pending registration marker was not cleared: %v", pending)
	}
}

func TestACRegistration_BeginRegistrationAttemptDrainsFullSharedKeyGroup(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	sharedKeyBytes := bytes.Repeat([]byte{0x48}, core.PublicKeySize)
	sharedPubKey := base64.StdEncoding.EncodeToString(sharedKeyBytes)
	for _, ip := range []string{"10.100.10.10", "10.100.11.11", "10.100.12.12", "10.100.20.20", "10.100.21.21"} {
		reg.addAssignmentPeer(&core.UdpPeer{Ip: ip, Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER})
	}
	pending := &core.UdpPeer{Ip: "10.100.30.30", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}

	if err := reg.beginRegistrationAttempt(pending); err != nil {
		t.Fatalf("beginRegistrationAttempt: %v", err)
	}
	memberIPs := devicePeerIPs(t, device, sharedKeyBytes)
	if len(memberIPs) != 1 || !memberIPs[pending.Ip] {
		t.Fatalf("pending NLB peer did not replace stale full group: %v", memberIPs)
	}

	reg.discardRegistrationAttempt(pending)
}

func TestACRegistration_BeginRegistrationAttemptRejectsFullStaticGroup(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	sharedKeyBytes := bytes.Repeat([]byte{0x4a}, core.PublicKeySize)
	sharedPubKey := base64.StdEncoding.EncodeToString(sharedKeyBytes)
	staticPeers := make([]*core.UdpPeer, 0, core.MaxPeerGroupSize)
	for _, ip := range []string{"10.100.10.10", "10.100.11.11", "10.100.12.12", "10.100.20.20", "10.100.21.21"} {
		peer := &core.UdpPeer{Ip: ip, Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
		staticPeers = append(staticPeers, peer)
		device.AddPeer(peer)
	}
	reg.ac.config.Servers = staticPeers
	reg.ac.serverPeerMap = map[string]*core.UdpPeer{sharedPubKey: staticPeers[0]}
	pending := &core.UdpPeer{Ip: "10.100.30.30", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}

	err := reg.beginRegistrationAttempt(pending)
	if err == nil || !strings.Contains(err.Error(), "at capacity") {
		t.Fatalf("beginRegistrationAttempt error = %v, want explicit capacity failure", err)
	}
	reg.mu.RLock()
	pendingMarker := reg.pendingRegistrationPeer
	reg.mu.RUnlock()
	if pendingMarker != nil {
		t.Fatalf("rejected registration left pending marker: %p", pendingMarker)
	}
	members := devicePeerIPs(t, device, sharedKeyBytes)
	if len(members) != core.MaxPeerGroupSize || members[pending.Ip] {
		t.Fatalf("rejected registration changed full static group: %v", members)
	}
}

func TestACRegistration_DiscardRegistrationRestoresSameAddressStaticPeer(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	sharedKeyBytes := bytes.Repeat([]byte{0x52}, core.PublicKeySize)
	sharedPubKey := base64.StdEncoding.EncodeToString(sharedKeyBytes)
	staticPeer := &core.UdpPeer{Ip: "10.100.30.30", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	pendingPeer := &core.UdpPeer{Ip: staticPeer.Ip, Port: staticPeer.Port, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	device.AddPeer(staticPeer)
	reg.ac.config.Servers = []*core.UdpPeer{staticPeer}
	reg.ac.serverPeerMap = map[string]*core.UdpPeer{sharedPubKey: staticPeer}

	if err := reg.beginRegistrationAttempt(pendingPeer); err != nil {
		t.Fatalf("beginRegistrationAttempt: %v", err)
	}
	if got := device.LookupPeer(sharedKeyBytes); got != pendingPeer {
		t.Fatalf("pending peer did not replace same-address static pointer: got %p want %p", got, pendingPeer)
	}

	reg.discardRegistrationAttempt(pendingPeer)
	if got := device.LookupPeer(sharedKeyBytes); got != staticPeer {
		t.Fatalf("discard did not restore static pointer: got %T %p want %p", got, got, staticPeer)
	}
}

func TestACRegistration_FailedAssignmentRestoresSameAddressStaticPeer(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	sharedKeyBytes := bytes.Repeat([]byte{0x53}, core.PublicKeySize)
	sharedPubKey := base64.StdEncoding.EncodeToString(sharedKeyBytes)
	staticPeer := &core.UdpPeer{Ip: "10.100.30.30", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	device.AddPeer(staticPeer)
	reg.ac.config.Servers = []*core.UdpPeer{staticPeer}
	reg.ac.serverPeerMap = map[string]*core.UdpPeer{sharedPubKey: staticPeer}
	server := &AssignedServer{Target: common.RedirectTarget{
		IP: staticPeer.Ip, Port: staticPeer.Port, PubKeyBase64: sharedPubKey,
	}}

	// running=false fails after the dynamic pointer has replaced the static one.
	if err := reg.connectToServer(server); err == nil || !strings.Contains(err.Error(), "AC not running") {
		t.Fatalf("connectToServer error = %v, want AC not running", err)
	}
	if got := device.LookupPeer(sharedKeyBytes); got != staticPeer {
		t.Fatalf("failed assignment did not restore static pointer: got %T %p want %p", got, got, staticPeer)
	}
	if owned := reg.assignmentPeersSnapshot(); len(owned) != 0 {
		t.Fatalf("failed assignment retained dynamic ownership: %v", owned)
	}
}

func TestACRegistration_BeginRegistrationAttemptRejectsSupersession(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	sharedKeyBytes := bytes.Repeat([]byte{0x47}, core.PublicKeySize)
	sharedPubKey := base64.StdEncoding.EncodeToString(sharedKeyBytes)
	first := &core.UdpPeer{Ip: "10.100.20.20", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	second := &core.UdpPeer{Ip: "10.100.21.21", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}

	if err := reg.beginRegistrationAttempt(first); err != nil {
		t.Fatalf("first beginRegistrationAttempt: %v", err)
	}
	if err := reg.beginRegistrationAttempt(second); err == nil {
		t.Fatal("second beginRegistrationAttempt unexpectedly superseded the pending peer")
	}
	memberIPs := devicePeerIPs(t, device, sharedKeyBytes)
	if len(memberIPs) != 1 || !memberIPs[first.Ip] || memberIPs[second.Ip] {
		t.Fatalf("rejected registration attempt changed device membership: %v", memberIPs)
	}
	reg.mu.RLock()
	pending := reg.pendingRegistrationPeer
	reg.mu.RUnlock()
	if pending != first {
		t.Fatalf("pending peer = %p, want first peer %p", pending, first)
	}

	reg.discardRegistrationAttempt(first)
	if got := device.LookupPeer(sharedKeyBytes); got != nil {
		t.Fatalf("discard left pending peer in device: %T", got)
	}
}

func TestACRegistration_ReconcilePreservesStaticSameKeyReloadReplacement(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	sharedKeyBytes := bytes.Repeat([]byte{0x4b}, core.PublicKeySize)
	sharedPubKey := base64.StdEncoding.EncodeToString(sharedKeyBytes)
	staticOld := &core.UdpPeer{Ip: "10.100.30.30", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	forgottenOwned := &core.UdpPeer{Ip: "10.100.10.10", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	priorOwned := &core.UdpPeer{Ip: "10.100.11.11", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	device.AddPeer(staticOld)
	reg.addAssignmentPeer(forgottenOwned)
	reg.addAssignmentPeer(priorOwned)

	// A config reload replaces the same static address with a new pointer. The
	// registration manager never owned either pointer.
	staticReloaded := &core.UdpPeer{Ip: staticOld.Ip, Port: staticOld.Port, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	device.AddPeer(staticReloaded)
	reg.ac.config.Servers = []*core.UdpPeer{staticReloaded}
	reg.ac.serverPeerMap = map[string]*core.UdpPeer{sharedPubKey: staticReloaded}
	priorServers := []*AssignedServer{{
		Target: common.RedirectTarget{IP: priorOwned.Ip, Port: priorOwned.Port, PubKeyBase64: sharedPubKey},
		Peer:   priorOwned,
	}}
	newServers := []*AssignedServer{{
		Target: common.RedirectTarget{IP: "10.100.12.12", Port: testServerListenPort, PubKeyBase64: sharedPubKey},
	}}

	reg.reconcileDevicePeers(priorServers, newServers)
	got := device.LookupPeer(sharedKeyBytes)
	if got != staticReloaded {
		t.Fatalf("reconcile removed or replaced static reload peer: got %T %p, want %p", got, got, staticReloaded)
	}
	if owned := reg.assignmentPeersSnapshot(); len(owned) != 0 {
		t.Fatalf("retired assignment ownership was not drained: %v", owned)
	}

	// A later dynamic assignment can replace the exact static address in
	// Device. While config still owns that endpoint, assignment reconciliation
	// must preserve the current pointer even when the dynamic assignment rotates
	// away; otherwise it would erase the statically configured route too.
	dynamicSameAddress := &core.UdpPeer{Ip: staticReloaded.Ip, Port: staticReloaded.Port, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	reg.addAssignmentPeer(dynamicSameAddress)
	reg.reconcileDevicePeers([]*AssignedServer{{
		Target: common.RedirectTarget{IP: dynamicSameAddress.Ip, Port: dynamicSameAddress.Port, PubKeyBase64: sharedPubKey},
		Peer:   dynamicSameAddress,
	}}, newServers)
	if got := device.LookupPeer(sharedKeyBytes); got != dynamicSameAddress {
		t.Fatalf("reconcile removed static-owned address after dynamic replacement: got %T %p, want %p", got, got, dynamicSameAddress)
	}

	// Once config relinquishes the endpoint, the next assignment transition
	// may retire the AC-owned replacement normally.
	reg.ac.config.Servers = nil
	reg.ac.serverPeerMap = nil
	reg.reconcileDevicePeers([]*AssignedServer{{
		Target: common.RedirectTarget{IP: dynamicSameAddress.Ip, Port: dynamicSameAddress.Port, PubKeyBase64: sharedPubKey},
		Peer:   dynamicSameAddress,
	}}, newServers)
	if got := device.LookupPeer(sharedKeyBytes); got != nil {
		t.Fatalf("reconcile retained AC-owned peer after static config removal: %T %p", got, got)
	}
	if owned := reg.assignmentPeersSnapshot(); len(owned) != 0 {
		t.Fatalf("retired static-address replacement ownership was not drained: %v", owned)
	}
}

func TestACRegistration_RefusedAssignmentPeerDoesNotLeakOwnership(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	sharedKeyBytes := bytes.Repeat([]byte{0x4c}, core.PublicKeySize)
	sharedPubKey := base64.StdEncoding.EncodeToString(sharedKeyBytes)
	for _, ip := range []string{"10.100.10.10", "10.100.11.11", "10.100.12.12", "10.100.20.20", "10.100.21.21"} {
		device.AddPeer(&core.UdpPeer{Ip: ip, Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER})
	}
	server := &AssignedServer{Target: common.RedirectTarget{
		IP: "10.100.30.30", Port: testServerListenPort, PubKeyBase64: sharedPubKey,
	}}

	// The group is full, so admission fails before connectToServer can send to
	// a peer the Device would reject.
	if err := reg.connectToServer(server); err == nil {
		t.Fatal("connectToServer unexpectedly succeeded")
	}
	if owned := reg.assignmentPeersSnapshot(); len(owned) != 0 {
		t.Fatalf("refused assignment attempt leaked ownership: %v", owned)
	}
	memberIPs := devicePeerIPs(t, device, sharedKeyBytes)
	if len(memberIPs) != core.MaxPeerGroupSize || memberIPs[server.Target.IP] {
		t.Fatalf("refused assignment changed static group: %v", memberIPs)
	}
}

// TestACRegistration_DirectAAK_ConvergesFullSharedKeyGroup covers the direct
// (no embedded peers) sibling of #2123 and #1720. The incoming peer's initial
// AddPeer is refused because five stale same-key members already fill the
// group. Direct-AAK reconciliation must drain every unassigned actual member
// and then idempotently re-add the authoritative peer.
func TestACRegistration_DirectAAK_ConvergesFullSharedKeyGroup(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	sharedKeyBytes := bytes.Repeat([]byte{0x44}, core.PublicKeySize)
	sharedPubKey := base64.StdEncoding.EncodeToString(sharedKeyBytes)

	oldPeer := &core.UdpPeer{Ip: "10.100.10.10", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	reg.addAssignmentPeer(oldPeer)
	for _, ip := range []string{"10.100.11.11", "10.100.12.12", "10.100.20.20", "10.100.21.21"} {
		reg.addAssignmentPeer(&core.UdpPeer{Ip: ip, Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER})
	}
	reg.registrationPeer = oldPeer
	reg.assignedServers = []*AssignedServer{
		{Target: common.RedirectTarget{IP: oldPeer.Ip, Port: oldPeer.Port, PubKeyBase64: sharedPubKey}, Peer: oldPeer, Connected: true},
	}

	newPeer := &core.UdpPeer{Ip: "10.100.10.103", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	// Mirrors register(): AddPeer runs before handleRegistrationResponse and is
	// refused at the cap in this setup.
	device.AddPeer(newPeer)
	before := devicePeerIPs(t, device, sharedKeyBytes)
	if before[newPeer.Ip] {
		t.Fatal("test setup: new direct peer unexpectedly entered the full group")
	}

	err := handleTestRegistrationResponse(reg, &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(`{"errCode":"0","registered":true}`),
	}, newPeer)
	if err != nil {
		t.Fatalf("handleRegistrationResponse: %v", err)
	}

	after := devicePeerIPs(t, device, sharedKeyBytes)
	if len(after) != 1 || !after[newPeer.Ip] {
		t.Fatalf("direct AAK peer group did not converge to authoritative peer: %v", after)
	}
}

func TestACRegistration_DirectAAK_RejectsFullStaticGroup(t *testing.T) {
	for _, tt := range []struct {
		name       string
		serverAddr string
	}{
		{name: "direct server address", serverAddr: "8.8.8.8:62206"},
		{name: "non-routable pubkey rewrite", serverAddr: "10.0.0.5:62206"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reg, device := newACRegistrationWithDevice(t)
			sharedKeyBytes := bytes.Repeat([]byte{0x4c}, core.PublicKeySize)
			sharedPubKey := base64.StdEncoding.EncodeToString(sharedKeyBytes)
			staticPeers := make([]*core.UdpPeer, 0, core.MaxPeerGroupSize)
			for _, ip := range []string{"10.100.10.10", "10.100.11.11", "10.100.12.12", "10.100.20.20", "10.100.21.21"} {
				peer := &core.UdpPeer{Ip: ip, Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
				staticPeers = append(staticPeers, peer)
				device.AddPeer(peer)
			}
			reg.ac.config.Servers = staticPeers
			reg.ac.serverPeerMap = map[string]*core.UdpPeer{sharedPubKey: staticPeers[0]}

			registrationKeyBytes := bytes.Repeat([]byte{0x4d}, core.PublicKeySize)
			registrationPeer := &core.UdpPeer{
				Ip: "9.9.9.9", Port: testServerListenPort,
				PubKeyBase64: base64.StdEncoding.EncodeToString(registrationKeyBytes), Type: core.NHP_SERVER,
			}
			device.AddPeer(registrationPeer)
			err := handleTestRegistrationResponse(reg, &core.PacketParserData{
				HeaderType: core.NHP_AAK,
				BodyMessage: mustJSON(t, common.ServerACAckMsg{
					ErrCode:      common.ErrSuccess.ErrorCode(),
					Registered:   true,
					ServerAddr:   tt.serverAddr,
					ServerPubKey: sharedPubKey,
				}),
			}, registrationPeer)
			if err == nil || !strings.Contains(err.Error(), "remained at capacity") {
				t.Fatalf("handleRegistrationResponse error = %v, want explicit capacity failure", err)
			}

			if got := reg.GetAssignedServers(); len(got) != 0 {
				t.Fatalf("capacity failure published unreachable assignment: %#v", got)
			}
			reg.mu.RLock()
			retainedRegistrationPeer := reg.registrationPeer
			reg.mu.RUnlock()
			if retainedRegistrationPeer != nil {
				t.Fatalf("capacity failure retained unreachable registration peer: %p", retainedRegistrationPeer)
			}
			if owned := reg.assignmentPeersSnapshot(); len(owned) != 0 {
				t.Fatalf("capacity failure retained assignment ownership: %v", owned)
			}
			members := devicePeerIPs(t, device, sharedKeyBytes)
			if len(members) != core.MaxPeerGroupSize {
				t.Fatalf("capacity failure changed static group: %v", members)
			}
			if got := device.LookupPeer(registrationKeyBytes); got != nil {
				t.Fatalf("obsolete registration-key peer survived pubkey transition: %T", got)
			}
		})
	}
}

func TestACRegistration_DirectAAK_CleansRetainedNilAddressPeer(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	sharedKeyBytes := bytes.Repeat([]byte{0x45}, core.PublicKeySize)
	sharedPubKey := base64.StdEncoding.EncodeToString(sharedKeyBytes)
	staticPeer := &core.UdpPeer{Ip: "10.100.30.30", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	retainedPeer := &core.UdpPeer{Ip: "not-an-ip", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	device.AddPeer(staticPeer)
	device.AddPeer(retainedPeer)
	reg.ac.config.Servers = []*core.UdpPeer{staticPeer}
	reg.ac.serverPeerMap = map[string]*core.UdpPeer{sharedPubKey: staticPeer}

	// The legacy direct AAK accepts a peer whose address cannot currently
	// resolve but omits it from assignedServers. Its ownership must still be
	// recorded, or no later priorServers delta can discover it.
	if err := handleTestRegistrationResponse(reg, &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(`{"errCode":"0","registered":true}`),
	}, retainedPeer); err != nil {
		t.Fatalf("retain nil-address peer: %v", err)
	}
	reg.mu.RLock()
	assignedCount := len(reg.assignedServers)
	registrationPeer := reg.registrationPeer
	reg.mu.RUnlock()
	if assignedCount != 0 || registrationPeer != retainedPeer {
		t.Fatalf("nil-address AAK state = assigned %d registration %p, want 0 and %p", assignedCount, registrationPeer, retainedPeer)
	}
	if owned := reg.assignmentPeersSnapshot(); owned[udpPeerActiveKey(retainedPeer)] != retainedPeer {
		t.Fatalf("nil-address peer ownership not retained: %v", owned)
	}

	// A later same-key direct assignment has no priorServers entry for the
	// retained peer. Reconciliation must find it through the ownership map,
	// remove it, and preserve the statically configured same-key endpoint.
	newPeer := &core.UdpPeer{Ip: "10.100.10.103", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	device.AddPeer(newPeer)
	if err := handleTestRegistrationResponse(reg, &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(`{"errCode":"0","registered":true}`),
	}, newPeer); err != nil {
		t.Fatalf("replace nil-address peer: %v", err)
	}

	after := devicePeerIPs(t, device, sharedKeyBytes)
	if len(after) != 2 || !after[staticPeer.Ip] || !after[newPeer.Ip] || after[retainedPeer.Ip] {
		t.Fatalf("same-key direct AAK did not retire only the retained peer: %v", after)
	}
	owned := reg.assignmentPeersSnapshot()
	if len(owned) != 1 || owned[udpPeerActiveKey(newPeer)] != newPeer {
		t.Fatalf("assignment ownership did not converge to new peer: %v", owned)
	}
}

func TestACRegistration_RedispatchCleansRetainedNilAddressPeerAcrossKeys(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	reg.ac.sendMsgCh = make(chan *core.MsgData, 1)
	reg.ac.running.Store(true)
	defer reg.Stop()

	oldKeyBytes := bytes.Repeat([]byte{0x54}, core.PublicKeySize)
	oldPubKey := base64.StdEncoding.EncodeToString(oldKeyBytes)
	oldPeer := &core.UdpPeer{Ip: "not-an-ip", Port: testServerListenPort, PubKeyBase64: oldPubKey, Type: core.NHP_SERVER}
	device.AddPeer(oldPeer)
	if err := handleTestRegistrationResponse(reg, &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(`{"errCode":"0","registered":true}`),
	}, oldPeer); err != nil {
		t.Fatalf("retain nil-address peer: %v", err)
	}

	newKeyBytes := bytes.Repeat([]byte{0x55}, core.PublicKeySize)
	newPubKey := base64.StdEncoding.EncodeToString(newKeyBytes)
	result := make(chan error, 1)
	go func() {
		result <- reg.HandleRedispatch(&common.ACRedispatchMsg{
			ErrCode: common.ErrSuccess.ErrorCode(),
			Targets: []common.RedirectTarget{{
				IP: "10.100.10.103", Port: testServerListenPort, PubKeyBase64: newPubKey,
			}},
		})
	}()
	var request *core.MsgData
	select {
	case request = <-reg.ac.sendMsgCh:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for cross-key redispatch request")
	}
	request.ResponseMsgCh <- successfulTestAAKPacket(reg.ac, []byte(`{"errCode":"0"}`))
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("cross-key redispatch: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for cross-key redispatch")
	}

	if got := device.LookupPeer(oldKeyBytes); got != nil {
		t.Fatalf("cross-key redispatch retained nil-address peer: %T", got)
	}
	if got := device.LookupPeer(newKeyBytes); got == nil {
		t.Fatal("cross-key redispatch did not install new assignment peer")
	}
	reg.mu.RLock()
	registrationPeer := reg.registrationPeer
	reg.mu.RUnlock()
	if registrationPeer != nil {
		t.Fatalf("cross-key redispatch retained registrationPeer: %p", registrationPeer)
	}
	owned := reg.assignmentPeersSnapshot()
	if len(owned) != 1 {
		t.Fatalf("cross-key redispatch ownership did not converge: %v", owned)
	}
}

func TestACRegistration_FailedRedispatchClearsSupersededRegistrationPeer(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	oldKeyBytes := bytes.Repeat([]byte{0x56}, core.PublicKeySize)
	oldPubKey := base64.StdEncoding.EncodeToString(oldKeyBytes)
	oldPeer := &core.UdpPeer{Ip: "not-an-ip", Port: testServerListenPort, PubKeyBase64: oldPubKey, Type: core.NHP_SERVER}
	device.AddPeer(oldPeer)
	if err := handleTestRegistrationResponse(reg, &core.PacketParserData{
		HeaderType:  core.NHP_AAK,
		BodyMessage: []byte(`{"errCode":"0","registered":true}`),
	}, oldPeer); err != nil {
		t.Fatalf("retain nil-address peer: %v", err)
	}

	newPubKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x57}, core.PublicKeySize))
	err := reg.HandleRedispatch(&common.ACRedispatchMsg{
		ErrCode: common.ErrSuccess.ErrorCode(),
		Targets: []common.RedirectTarget{{
			IP: "10.100.10.103", Port: testServerListenPort, PubKeyBase64: newPubKey,
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "failed to connect to any assigned servers") {
		t.Fatalf("failed redispatch error = %v", err)
	}
	if got := device.LookupPeer(oldKeyBytes); got != nil {
		t.Fatalf("failed cross-key redispatch retained old Device peer: %T", got)
	}
	reg.mu.RLock()
	registrationPeer := reg.registrationPeer
	reg.mu.RUnlock()
	if registrationPeer != nil {
		t.Fatalf("failed cross-key redispatch retained registrationPeer: %p", registrationPeer)
	}
	if owned := reg.assignmentPeersSnapshot(); len(owned) != 0 {
		t.Fatalf("failed cross-key redispatch retained assignment ownership: %v", owned)
	}
}

func TestACRegistration_EmbeddedPeersFailureRetainsUsableResponsePeer(t *testing.T) {
	for _, tt := range []struct {
		name         string
		directServer bool
	}{
		{name: "registration peer fallback"},
		{name: "direct server peer", directServer: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reg, device := newACRegistrationWithDevice(t)
			sharedKeyBytes := bytes.Repeat([]byte{0x46}, core.PublicKeySize)
			sharedPubKey := base64.StdEncoding.EncodeToString(sharedKeyBytes)
			registrationPubKey := sharedPubKey
			if tt.directServer {
				registrationPubKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x47}, core.PublicKeySize))
			}
			staticPeer := &core.UdpPeer{Ip: "10.100.30.30", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
			registrationPeer := &core.UdpPeer{Ip: "10.100.40.40", Port: testServerListenPort, PubKeyBase64: registrationPubKey, Type: core.NHP_SERVER}
			device.AddPeer(staticPeer)
			device.AddPeer(registrationPeer)
			reg.ac.config.Servers = []*core.UdpPeer{staticPeer}
			reg.ac.serverPeerMap = map[string]*core.UdpPeer{sharedPubKey: staticPeer}

			aak := common.ServerACAckMsg{
				ErrCode:    common.ErrSuccess.ErrorCode(),
				Registered: true,
				Peers: []common.RedirectTarget{{
					IP: "10.100.50.50", Port: testServerListenPort, PubKeyBase64: sharedPubKey,
				}},
			}
			expectedPeer := registrationPeer
			if tt.directServer {
				aak.ServerAddr = "8.8.8.8:62206"
				aak.ServerPubKey = sharedPubKey
				expectedPeer = &core.UdpPeer{Ip: "8.8.8.8", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
			}

			// running=false makes every embedded-peer connection fail after its
			// temporary Device add. The response handler deliberately degrades to
			// the viable response peer instead of failing registration.
			if err := handleTestRegistrationResponse(reg, &core.PacketParserData{
				HeaderType:  core.NHP_AAK,
				BodyMessage: mustJSON(t, aak),
			}, registrationPeer); err != nil {
				t.Fatalf("handleRegistrationResponse: %v", err)
			}

			reg.mu.RLock()
			retainedPeer := reg.registrationPeer
			reg.mu.RUnlock()
			if retainedPeer == nil || udpPeerActiveKey(retainedPeer) != udpPeerActiveKey(expectedPeer) {
				t.Fatalf("retained response peer = %#v, want %s", retainedPeer, expectedPeer.Host())
			}
			members := devicePeerIPs(t, device, sharedKeyBytes)
			if len(members) != 2 || !members[staticPeer.Ip] || !members[expectedPeer.Ip] || members[aak.Peers[0].IP] {
				t.Fatalf("degraded response peer/static membership = %v", members)
			}
			owned := reg.assignmentPeersSnapshot()
			if len(owned) != 1 || owned[udpPeerActiveKey(retainedPeer)] != retainedPeer {
				t.Fatalf("degraded response peer ownership = %v", owned)
			}
			fallbackServers := reg.GetAssignedServers()
			if len(fallbackServers) != 1 || fallbackServers[0].Peer != retainedPeer || !fallbackServers[0].IsConnected() {
				t.Fatalf("degraded response peer is not keepalive-visible as the connected fallback assignment: %#v", fallbackServers)
			}
			if got := fallbackServers[0].Target.IP; got != expectedPeer.Ip {
				t.Fatalf("fallback assignment IP = %q, want %q", got, expectedPeer.Ip)
			}
			if fallbackServers[0].GetLastSeen().IsZero() {
				t.Fatal("fallback assignment has zero LastSeen and would immediately fail health checks")
			}
		})
	}
}

func TestACRegistration_EmbeddedPeersSuccessRetiresOnlyResponsePeer(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	reg.ac.sendMsgCh = make(chan *core.MsgData, 1)
	reg.ac.running.Store(true)
	defer reg.Stop()

	sharedKeyBytes := bytes.Repeat([]byte{0x48}, core.PublicKeySize)
	sharedPubKey := base64.StdEncoding.EncodeToString(sharedKeyBytes)
	registrationPubKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x49}, core.PublicKeySize))
	staticPeer := &core.UdpPeer{Ip: "10.100.30.30", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	registrationPeer := &core.UdpPeer{Ip: "10.100.40.40", Port: testServerListenPort, PubKeyBase64: registrationPubKey, Type: core.NHP_SERVER}
	oldDirectPeer := &core.UdpPeer{Ip: "8.8.8.9", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	target := common.RedirectTarget{IP: "8.8.4.4", Port: testServerListenPort, PubKeyBase64: sharedPubKey}
	device.AddPeer(staticPeer)
	device.AddPeer(registrationPeer)
	if !reg.addAssignmentPeer(oldDirectPeer) {
		t.Fatal("test setup: old direct assignment was not admitted")
	}
	reg.registrationPeer = oldDirectPeer
	reg.assignedServers = []*AssignedServer{{
		Target:    common.RedirectTarget{IP: oldDirectPeer.Ip, Port: oldDirectPeer.Port, PubKeyBase64: sharedPubKey},
		Peer:      oldDirectPeer,
		Connected: true,
		LastSeen:  time.Now(),
	}}
	reg.ac.config.Servers = []*core.UdpPeer{staticPeer}
	reg.ac.serverPeerMap = map[string]*core.UdpPeer{sharedPubKey: staticPeer}
	aakBody := mustJSON(t, common.ServerACAckMsg{
		ErrCode:      common.ErrSuccess.ErrorCode(),
		Registered:   true,
		ServerAddr:   "8.8.8.8:62206",
		ServerPubKey: sharedPubKey,
		Peers:        []common.RedirectTarget{target},
	})
	peerAAKBody := mustJSON(t, common.ServerACAckMsg{ErrCode: common.ErrSuccess.ErrorCode()})

	result := make(chan error, 1)
	go func() {
		result <- handleTestRegistrationResponse(reg, &core.PacketParserData{
			HeaderType:  core.NHP_AAK,
			BodyMessage: aakBody,
		}, registrationPeer)
	}()

	var request *core.MsgData
	select {
	case request = <-reg.ac.sendMsgCh:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for embedded-peer connection request")
	}
	request.ResponseMsgCh <- successfulTestAAKPacket(reg.ac, peerAAKBody)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("handleRegistrationResponse: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for embedded-peer response handling")
	}

	members := devicePeerIPs(t, device, sharedKeyBytes)
	if len(members) != 2 || !members[staticPeer.Ip] || !members[target.IP] || members["8.8.8.8"] || members[oldDirectPeer.Ip] {
		t.Fatalf("successful embedded assignment membership = %v", members)
	}
	reg.mu.RLock()
	staleRegistrationPeer := reg.registrationPeer
	reg.mu.RUnlock()
	if staleRegistrationPeer != nil {
		t.Fatalf("successful embedded assignment retained stale direct registration peer: %p", staleRegistrationPeer)
	}
	owned := reg.assignmentPeersSnapshot()
	if len(owned) != 1 {
		t.Fatalf("successful embedded assignment ownership = %v", owned)
	}
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
	priorPeer1 := &core.UdpPeer{Ip: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	priorPeer2 := &core.UdpPeer{Ip: "10.0.0.2", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	device.AddPeer(priorPeer1)
	device.AddPeer(priorPeer2)

	// Re-registration installed fresh structs at the same addresses. AddPeer's
	// same-address branch replaces the PeerGroup member, so the prior pointers
	// are no longer in peerMap, but their addresses alias the new members.
	newPeer1 := &core.UdpPeer{Ip: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	newPeer2 := &core.UdpPeer{Ip: "10.0.0.2", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	device.AddPeer(newPeer1)
	device.AddPeer(newPeer2)

	pubKeyBytes := newPeer1.PublicKey()
	if device.LookupPeer(pubKeyBytes) == nil {
		t.Fatal("test setup: pubkey should resolve before reconcile")
	}

	priorServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: sharedPubKey}, Peer: priorPeer1},
		{Target: common.RedirectTarget{IP: "10.0.0.2", Port: testServerListenPort, PubKeyBase64: sharedPubKey}, Peer: priorPeer2},
	}
	newServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: sharedPubKey}, Peer: newPeer1, Connected: true},
		{Target: common.RedirectTarget{IP: "10.0.0.2", Port: testServerListenPort, PubKeyBase64: sharedPubKey}, Peer: newPeer2, Connected: true},
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

	priorPeer1 := &core.UdpPeer{Ip: "10.0.0.1", Hostname: "a.nhp.test.internal", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	priorPeer2 := &core.UdpPeer{Ip: "10.0.0.2", Hostname: "b.nhp.test.internal", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	device.AddPeer(priorPeer1)
	device.AddPeer(priorPeer2)

	pubKeyBytes := priorPeer1.PublicKey()
	if device.LookupPeer(pubKeyBytes) == nil {
		t.Fatal("test setup: pubkey should resolve before reconcile")
	}

	priorServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Hostname: "a.nhp.test.internal", Port: testServerListenPort, PubKeyBase64: sharedPubKey}, Peer: priorPeer1},
		{Target: common.RedirectTarget{IP: "10.0.0.2", Hostname: "b.nhp.test.internal", Port: testServerListenPort, PubKeyBase64: sharedPubKey}, Peer: priorPeer2},
	}
	newServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.2", Hostname: "b.nhp.test.internal", Port: testServerListenPort, PubKeyBase64: sharedPubKey}, Peer: priorPeer2, Connected: true},
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

	priorPeer := &core.UdpPeer{Ip: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: "cHJpb3ItYXNzaWduZWQtcHVia2V5", Type: core.NHP_SERVER}
	newPeer := &core.UdpPeer{Ip: "10.0.0.2", Port: testServerListenPort, PubKeyBase64: "bmV3LXJlZ2lzdHJhdGlvbi1wdWJrZXk=", Type: core.NHP_SERVER}
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

	priorPeer := &core.UdpPeer{Ip: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	newPeer := &core.UdpPeer{Ip: "10.0.0.2", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	device.AddPeer(priorPeer)
	device.AddPeer(newPeer)

	pubKeyBytes := newPeer.PublicKey()
	if device.LookupPeer(pubKeyBytes) == nil {
		t.Fatal("test setup: pubkey should resolve before reconcile")
	}

	priorServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: sharedPubKey}, Peer: priorPeer},
	}
	newServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.2", Port: testServerListenPort, PubKeyBase64: sharedPubKey}, Peer: newPeer, Connected: true},
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

	priorPeerA := &core.UdpPeer{Ip: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	priorPeerB := &core.UdpPeer{Ip: "10.0.0.2", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	device.AddPeer(priorPeerA)
	device.AddPeer(priorPeerB)

	pubKeyBytes := priorPeerA.PublicKey()
	if device.LookupPeer(pubKeyBytes) == nil {
		t.Fatal("test setup: pubkey should resolve before reconcile")
	}

	priorServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: sharedPubKey}, Peer: priorPeerA},
		{Target: common.RedirectTarget{IP: "10.0.0.2", Port: testServerListenPort, PubKeyBase64: sharedPubKey}, Peer: priorPeerB},
	}
	newServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.2", Port: testServerListenPort, PubKeyBase64: sharedPubKey}, Peer: priorPeerB, Connected: true},
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

	retiredPeer := &core.UdpPeer{Ip: "10.0.0.99", Port: testServerListenPort, PubKeyBase64: distinctPubKey, Type: core.NHP_SERVER}
	device.AddPeer(retiredPeer)
	pubKeyBytes := retiredPeer.PublicKey()
	if device.LookupPeer(pubKeyBytes) == nil {
		t.Fatal("test setup: retired peer should be in device before reconcile")
	}

	priorServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.99", Port: testServerListenPort, PubKeyBase64: distinctPubKey}, Peer: retiredPeer},
	}
	newServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: "ZGlmZmVyZW50LXBlZXItcHVia2V5"}},
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

	priorPeerA := &core.UdpPeer{Ip: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: priorPubA, Type: core.NHP_SERVER}
	priorPeerB := &core.UdpPeer{Ip: "10.0.0.2", Port: testServerListenPort, PubKeyBase64: priorPubB, Type: core.NHP_SERVER}
	priorPeerC := &core.UdpPeer{Ip: "10.0.0.3", Port: testServerListenPort, PubKeyBase64: priorPubC, Type: core.NHP_SERVER}
	device.AddPeer(priorPeerA)
	device.AddPeer(priorPeerB)
	device.AddPeer(priorPeerC)

	for _, p := range []*core.UdpPeer{priorPeerA, priorPeerB, priorPeerC} {
		if device.LookupPeer(p.PublicKey()) == nil {
			t.Fatalf("test setup: %s should resolve before reconcile", p.PubKeyBase64)
		}
	}

	priorServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: priorPubA}, Peer: priorPeerA},
		{Target: common.RedirectTarget{IP: "10.0.0.2", Port: testServerListenPort, PubKeyBase64: priorPubB}, Peer: priorPeerB},
		{Target: common.RedirectTarget{IP: "10.0.0.3", Port: testServerListenPort, PubKeyBase64: priorPubC}, Peer: priorPeerC},
	}
	newServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.1.0.1", Port: testServerListenPort, PubKeyBase64: "bmV3LWEtcHVia2V5"}},
		{Target: common.RedirectTarget{IP: "10.1.0.2", Port: testServerListenPort, PubKeyBase64: "bmV3LWItcHVia2V5"}},
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
	priorPeer := &core.UdpPeer{Ip: "10.0.0.42", Port: testServerListenPort, PubKeyBase64: pubKey, Type: core.NHP_SERVER}
	device.AddPeer(priorPeer)
	priorKey := priorPeer.PublicKey()
	if device.LookupPeer(priorKey) == nil {
		t.Fatal("test setup: prior IP-only peer should resolve before reconcile")
	}

	// New: Hostname-only target for the same logical peer (different
	// address). Config flip simulates the drain-redirect form.
	newPeer := &core.UdpPeer{Hostname: "drain.nhp.internal", Port: testServerListenPort, PubKeyBase64: pubKey, Type: core.NHP_SERVER}
	device.AddPeer(newPeer)

	priorServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.42", Port: testServerListenPort, PubKeyBase64: pubKey}, Peer: priorPeer},
	}
	newServers := []*AssignedServer{
		{Target: common.RedirectTarget{Hostname: "drain.nhp.internal", Port: testServerListenPort, PubKeyBase64: pubKey}, Peer: newPeer},
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
			name:   "ipv6 form",
			target: common.RedirectTarget{PubKeyBase64: "k", IP: "2001:db8::1", Port: 62206},
			want:   "k\x00[2001:db8::1]:62206",
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
			name:   "hostname with pipe is unambiguous",
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

	ipv6Peer := &core.UdpPeer{Ip: "2001:db8::1", Port: 62206, PubKeyBase64: "k"}
	if got, want := udpPeerActiveKey(ipv6Peer), "k\x00[2001:db8::1]:62206"; got != want {
		t.Fatalf("udpPeerActiveKey IPv6 framing = %q, want %q", got, want)
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

	priorPeer := &core.UdpPeer{Ip: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: "cHJpb3ItcHVia2V5", Type: core.NHP_SERVER}
	device.AddPeer(priorPeer)

	priorServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: "cHJpb3ItcHVia2V5"}, Peer: priorPeer},
	}
	// New target has no IP and no Hostname — the <unaddressed> sentinel branch.
	newServers := []*AssignedServer{
		{Target: common.RedirectTarget{PubKeyBase64: "bmV3LXB1YmtleQ==", Port: testServerListenPort}},
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

// TestACRegistration_ReconcileDevicePeers_InstanceRemovalPreservesReplaced
// fences exact-pointer removal in reconcileDevicePeers. When the device's
// current entry for a prior peer's pubkey is a different *core.UdpPeer than
// the one captured at snapshot time, RemovePeerInstance must preserve it.
//
// Scenario: a prior assignment installed a peer; a sibling AddPeer at the
// same pubkey + same address replaced the peerMap entry pointer (via
// AddPeer's same-address-replace branch); reconcile runs with the original
// prior in priorServers, expects to evict it, finds the replacement instead,
// and must skip the device call.
func TestACRegistration_ReconcileDevicePeers_InstanceRemovalPreservesReplaced(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	const sharedPubKey = "ZGVmZW5zZS1pbi1kZXB0aC1wdWJrZXk="

	priorPeer := &core.UdpPeer{Ip: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
	device.AddPeer(priorPeer)

	// Sibling AddPeer at the same (pubkey, address) replaces peerMap[K]'s
	// pointer in-place via udpPeersShareAddress's same-address-replace
	// branch. After this, peerMap[K] points at replacementPeer, not priorPeer.
	replacementPeer := &core.UdpPeer{Ip: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: sharedPubKey, Type: core.NHP_SERVER}
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
		{Target: common.RedirectTarget{IP: "10.0.0.99", Port: testServerListenPort, PubKeyBase64: "b3RoZXItcHVia2V5LWZvci1uZXc="}},
	}

	reg.reconcileDevicePeers(priorServers, newServers)

	// Exact-pointer removal leaves the replacement in the pool.
	if device.LookupPeer(pubKeyBytes) == nil {
		t.Fatal("regression: exact-pointer removal wiped the replacement along with the prior")
	}
}

// TestACRegistration_HandleRedispatch_AllConnectsFail_EvictsPriorPeers verifies
// the all-fail path removes both the prior assignment and the newly admitted
// peer. Leaving the test AC stopped makes every connect fail before network I/O.
func TestACRegistration_HandleRedispatch_AllConnectsFail_EvictsPriorPeers(t *testing.T) {
	reg, device := newACRegistrationWithDevice(t)
	reg.metrics = metrics.NewPublisherForTest(t)

	if reg.ac.IsRunning() {
		t.Fatal("test AC must be stopped to exercise the all-connects-fail path")
	}

	priorPeer := &core.UdpPeer{Ip: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: "cHJpb3ItYXNzaWduZWQtcGVlcg==", Type: core.NHP_SERVER}
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
		t.Fatalf("HandleRedispatch error = %v, want connection failure", err)
	}

	if device.LookupPeer(priorKey) != nil {
		t.Error("all-fail reconcile retained the prior peer")
	}

	// connectToServer must remove the peer it admitted before IsRunning failed.
	leakedPubKey, _ := base64.StdEncoding.DecodeString("bmV3LXVucmVhY2hhYmxlLXBlZXI=")
	if device.LookupPeer(leakedPubKey) != nil {
		t.Error("failed connect retained the newly admitted peer")
	}

	// Fence MetricNilNewServersReconcile emission: the all-fail branch reports
	// one event when either cleanup pass removed a prior peer.
	matches, _ := countDimCountersWithPrefix(t, reg, MetricNilNewServersReconcile)
	if matches != 1 {
		t.Errorf("expected exactly 1 MetricNilNewServersReconcile dim entry, got %d", matches)
	}

	// Confirm the test reached the operational connection-failure path.
	connectFailures, _ := countDimCountersWithPrefix(t, reg, MetricServerConnectionFailure)
	if connectFailures < 1 {
		t.Errorf("MetricServerConnectionFailure entries = %d, want at least 1", connectFailures)
	}
}

// TestACRegistration_ReconcileDevicePeers_NilSafe verifies nil entries do not
// panic and an empty prior set is a no-op.
func TestACRegistration_ReconcileDevicePeers_NilSafe(t *testing.T) {
	reg, _ := newACRegistrationWithDevice(t)

	reg.reconcileDevicePeers(nil, nil)

	priorServers := []*AssignedServer{
		nil,
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: "k"}, Peer: nil},
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
	bystander := &core.UdpPeer{Ip: "10.0.0.99", Port: testServerListenPort, PubKeyBase64: "Ynlz", Type: core.NHP_SERVER}
	device.AddPeer(bystander)
	bystanderKey := bystander.PublicKey()
	if device.LookupPeer(bystanderKey) == nil {
		t.Fatal("test setup: bystander should resolve before reconcile")
	}

	priorServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: "k1"}, Peer: nil},
		{Target: common.RedirectTarget{IP: "10.0.0.2", Port: testServerListenPort, PubKeyBase64: "k2"}, Peer: nil},
		{Target: common.RedirectTarget{IP: "10.0.0.3", Port: testServerListenPort, PubKeyBase64: "k3"}, Peer: nil},
	}
	newServers := []*AssignedServer{
		{Target: common.RedirectTarget{IP: "10.1.0.1", Port: testServerListenPort, PubKeyBase64: "newpk"}},
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
		{Target: common.RedirectTarget{IP: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: "p1"}, Peer: &core.UdpPeer{Ip: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: "p1", Type: core.NHP_SERVER}},
	}
	sentinelNew := []*AssignedServer{
		{Target: common.RedirectTarget{PubKeyBase64: "broken", Port: testServerListenPort}}, // no IP, no Hostname
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
// in-flight counter. The invariant detector is scoped to the post-validation
// path that actually mutates peer-pool state.
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

	err := reg.HandleRedispatch(&common.ACRedispatchMsg{Targets: []common.RedirectTarget{{IP: "10.0.0.1", Port: testServerListenPort, PubKeyBase64: "k"}}})
	if err == nil {
		t.Error("HandleRedispatch on stopped manager should return ErrRegistrationStopped")
	}
	if got := reg.reconcileInFlight.Load(); got != 0 {
		t.Errorf("stopped early-return touched the counter: got %d, want 0", got)
	}
}

// TestACRegistration_RecordReconcileEntry covers the invariant detector used
// by reconcileDevicePeers. It drives the helper directly so the metric branch
// can be tested without manufacturing an unsafe production call-site bypass.
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
	// (filepath, required substrings) pairs. Each substring is part of
	// a smoke regex in tests/smoke/09_ac_redispatch_loop_test.go and a
	// rename in either file would silently zero out the smoke query.
	// Both files MUST stay in lockstep with the smoke regexes until
	// #1714's structured-tag replacement lands.
	cases := []struct {
		path     string // relative to package dir
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
		source := string(pkgFileBytes(t, c.path))
		for _, s := range c.required {
			if !strings.Contains(source, s) {
				t.Errorf("smoke fence regression: %s no longer contains substring %q — the smoke test's CloudWatch Logs Insights query will silently zero out. Either restore the wording or land #1714's structured-tag replacement and update tests/smoke/09_ac_redispatch_loop_test.go's queries in lockstep.", c.path, s)
			}
		}
	}
}
