package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// ============================================================================
// NHP-Relay forward handling (#2208)
//
//	Browser JS-Agent -> NHP-Relay (internet-facing) -> private NHP-Server -> AC
//
// The relay terminates TLS, observes the real client IP at its edge, wraps the
// agent's opaque inner NHP packet in a RelayForwardMsg{SourceAddr, InnerPacket}
// and sends it to the (private) server as an NHP_RLY packet.
//
// HandleRelayForward decrypts the inner packet with the shared server key (the
// relay cannot read it — inner crypto is end-to-end agent<->server) and
// DISPATCHES BY INNER TYPE (agent-registration N2):
//   - KNK / RKN / EXT → the knock pipeline (buildKnockAck), reply NHP_ACK.
//   - NHP_OTP         → the OTP dispatch (dispatchOTP). FIRE-AND-FORGET: no reply
//                       (the relay already answered the browser HTTP 202; there
//                       is no parked reply-waiter to receive one).
//   - NHP_REG         → the register dispatch (buildRegisterAck), reply NHP_RAK.
//
// A reply (NHP_ACK or NHP_RAK) is:
//   - encrypted for the AGENT (from the inner packet's cipher state),
//   - correlated to the INNER request counter,
//   - but transported back to the RELAY's address, which forwards the opaque
//     bytes to the browser.
//
// The reply rides the inner packet's cipher state via the EncryptedPktCh divert
// + a manual WriteToUDP to the relay (NOT forwardToTransaction — there is no
// RemoteTransaction for a synthetically-decrypted inner packet); sendRelayReply
// generalizes that divert to a header type. This avoids the core ConnectionData
// surgery (RealRemoteAddr + a per-relay connection map) that upstream uses; the
// round-trip is fenced by relay_ack_roundtrip_spike_test.go.
//
// Trust model: the relay is authenticated by Noise IK while the OUTER NHP_RLY
// packet is decrypted — it cannot complete the handshake without the fleet
// private key, regardless of the DisableRelayPeerValidation setting. The #2208
// shared-keypair fleet runs DisableRelayPeerValidation=true (its per-AZ
// instances share one keypair but present distinct source IPs, so the
// responder's CheckRecvAddress pin must be off), which makes the lookupRelayPeer
// gate below load-bearing rather than belt-and-suspenders. With validation on
// (legacy/default) the responder additionally requires a registered NHP_RELAY
// peer and pins its source address. Either way SourceAddr is asserted by a
// Noise-authenticated, relay.toml-registered relay and is the SOLE trusted
// source of the AC-pinhole client IP. See docs/design/NHP_RELAY_TOPOLOGY.md.
//
// Deployment assumption: this path needs CLOUD-MODE agent resolution
// (DisableAgentPeerValidation=true, which cloud mode forces). The INNER knock is
// decrypted onto a synthetic ConnData whose RemoteAddr is the relay-reported
// CLIENT IP; in a legacy etcd/file deployment with agent validation enabled,
// validatePeer would run CheckRecvAddress against that client IP for an agent
// that isn't a registered peer at all, so the decrypt fails closed
// (ErrPeerNotFound / ErrPeerAddressMismatch) and the forward drops as a
// RelayForwardReject. The relay is a cloud browser feature, so that's the
// intended outcome — noted here to save an on-prem debugging session.
// ============================================================================

// relayInnerMinPacketSize is the smallest plausible decoded inner NHP packet (a
// bare common header). Mirrors forward.go's minPacketSize.
const relayInnerMinPacketSize = 24

// relayInnerMaxBase64Len bounds the base64 InnerPacket BEFORE decoding so a
// malicious relay (or a corrupted forward) cannot force an oversized
// allocation. A valid inner packet must fit a single pool buffer
// (core.PacketBufferSize), so its base64 form cannot exceed this length.
var relayInnerMaxBase64Len = base64.StdEncoding.EncodedLen(core.PacketBufferSize)

// lookupRelayPeer returns the registered NHP_RELAY peer for pubKeyBase64, or nil
// if absent. Mirrors lookupAgentPeer; tolerates a nil relayPeerMap (a server
// booted without relay.toml).
func (s *UdpServer) lookupRelayPeer(pubKeyBase64 string) *core.UdpPeer {
	s.relayPeerMapMutex.Lock()
	defer s.relayPeerMapMutex.Unlock()
	return s.relayPeerMap[pubKeyBase64]
}

// HandleRelayForward processes an NHP_RLY packet: an agent knock forwarded by a
// relay. outerPpd is the already-decrypted NHP_RLY (the relay is authenticated
// by the standard Noise pipeline before dispatch reaches here).
func (s *UdpServer) HandleRelayForward(outerPpd *core.PacketParserData) {
	s.wg.Add(1)
	defer s.wg.Done()

	s.metrics.IncrCounter(MetricRelayForward)

	relayAddr := outerPpd.ConnData.RemoteAddr
	relayPubKey := base64.StdEncoding.EncodeToString(outerPpd.RemotePubKey)

	// Authorization gate: require the sender to be a specifically registered
	// NHP_RELAY peer before trusting its SourceAddr to open an AC pinhole.
	//   - #2208 shared-keypair fleet (DisableRelayPeerValidation=true): the core
	//     responder skipped its peer-validation block entirely, so THIS is the
	//     sole gate authorizing the (Noise-IK-authenticated) relay pubkey.
	//   - validation on (legacy/default): the responder's validatePeer already
	//     rejected unknown pubkeys via LookupPeer, but does NOT check
	//     peer.DeviceType()==NHP_RELAY, so a registered AC/agent pubkey could
	//     otherwise inject an NHP_RLY with a spoofed SourceAddr — this closes that
	//     by requiring specifically a relay peer.
	// Also the sole gate for a future dynamic relay registry (see #2541).
	if s.lookupRelayPeer(relayPubKey) == nil {
		s.metrics.IncrCounter(MetricRelayForwardReject)
		log.Error("server-relay(@%s)[HandleRelayForward] sender pubkey_b64_prefix=%q is not a registered NHP_RELAY peer; dropping",
			relayAddr, pubkeyLogPrefix(relayPubKey))
		return
	}

	rlyMsg := &common.RelayForwardMsg{}
	if err := json.Unmarshal(outerPpd.BodyMessage, rlyMsg); err != nil {
		s.metrics.IncrCounter(MetricRelayForwardReject)
		log.Error("server-relay(@%s)[HandleRelayForward] failed to parse RelayForwardMsg: %v", relayAddr, err)
		return
	}

	// SYNTACTIC source-address validation for ALL inner types: the source address
	// becomes the synthetic ConnData.RemoteAddr the inner packet is decrypted
	// against (decryptRelayInnerKnock), so it must be well-formed before the inner
	// type is even known. The stricter ROUTABLE-PUBLIC gate is TYPE-DEPENDENT and
	// applied later, inside the dispatch switch, ONLY for the AC-pinhole-opening
	// knock types (KNK/RKN/EXT) — NOT for the registration types (OTP/REG), which
	// open no pinhole and whose SourceAddr is purely informational/audit. See the
	// dispatch switch for the full rationale.
	sourceAddr, err := validateRelaySourceAddrSyntactic(rlyMsg.SourceAddr)
	if err != nil {
		s.metrics.IncrCounter(MetricRelayForwardReject)
		log.Error("server-relay(@%s)[HandleRelayForward] rejecting malformed relay-reported source address: %v", relayAddr, err)
		return
	}

	innerBytes, err := decodeRelayInnerPacket(rlyMsg.InnerPacket)
	if err != nil {
		s.metrics.IncrCounter(MetricRelayForwardReject)
		log.Error("server-relay(@%s src=%s)[HandleRelayForward] invalid inner packet: %v", relayAddr, sourceAddr, err)
		return
	}

	// Decrypt the inner knock against the shared server key, stamping the
	// relay-reported client IP as the synthetic ConnData.RemoteAddr so the whole
	// downstream pipeline (AC pinhole source, echoed AgentAddr, log tags)
	// attributes the real client and never the relay. Mirrors forward.go
	// decryptForwardedKnock.
	innerPpd, err := s.decryptRelayInnerKnock(innerBytes, sourceAddr)
	if err != nil {
		s.metrics.IncrCounter(MetricRelayForwardReject)
		log.Error("server-relay(@%s src=%s)[HandleRelayForward] inner knock decrypt failed: %v", relayAddr, sourceAddr, err)
		return
	}

	// CRYPTO-AUTH BOUNDARY: the inner decrypt above authenticated the agent
	// (Noise populated innerPpd.RemotePubKey). This is NOT yet the reply-vs-drop
	// boundary — two PRE-REPLY fail-closed guards still remain below (the
	// missing-pubkey fail-safe and the inner header-type dispatch's default arm);
	// they drop WITHOUT a reply because a packet with no agent key, or an
	// unrelayable type, yields no reply to build. Past those, each dispatch arm
	// decides its own reply contract: KNK/RKN/EXT and REG DELIVER their verdict as
	// an ack/RAK (the verdict rides in the bytes; only a marshal/encrypt failure
	// drops silently), while NHP_OTP is fire-and-forget and intentionally replies
	// with nothing. Every drop ABOVE the decrypt is pre-auth — no authenticated
	// agent to encrypt a reply for.

	// Fail closed if the responder did not populate the agent's static key (the
	// inner knock must authenticate the agent before its src IP can steer an AC
	// pinhole). Mirrors forward.go's forwardedAgentPubKey guard. A successful
	// PacketToMsg always sets a 32-byte RemotePubKey (responder.go populates it
	// regardless of DisableAgentPeerValidation), so this is a fail-safe against a
	// future responder regression — effectively unreachable via a real decrypt,
	// hence no direct test.
	if len(innerPpd.RemotePubKey) != 32 {
		s.metrics.IncrCounter(MetricRelayForwardReject)
		log.Error("server-relay(@%s src=%s)[HandleRelayForward] inner knock missing authenticated agent pubkey (len=%d); dropping",
			relayAddr, sourceAddr, len(innerPpd.RemotePubKey))
		return
	}

	// Inner header-type DISPATCH. Unlike upstream (which injects the inner packet
	// into a generic connection routine that dispatches by type), we route each
	// admitted inner type to the matching server handler here:
	//
	//   NHP_KNK / NHP_RKN / NHP_EXT  → the knock pipeline (buildKnockAck), reply
	//                                  NHP_ACK via sendRelayAck (unchanged).
	//   NHP_OTP                      → the OTP dispatch (dispatchOTP), reply
	//                                  NOTHING — OTP is FIRE-AND-FORGET per the CSA
	//                                  NHP spec, and the relay already answered the
	//                                  browser 202 Accepted without parking a
	//                                  reply-waiter. Sending anything here would
	//                                  have no waiter to receive it.
	//   NHP_REG                      → the register dispatch (buildRegisterAck),
	//                                  reply NHP_RAK via sendRelayReply. buildRegisterAck
	//                                  fails CLOSED: while the agent plugin is
	//                                  stubbed (N3 pending) the RAK carries a mapped
	//                                  registration errCode rather than dropping.
	//   default                      → reject + MetricRelayForwardReject (DHP_KNK
	//                                  and every non-registration/non-knock type
	//                                  are not a relay use case).
	//
	// All handlers read innerPpd.ConnData.RemoteAddr (= sourceAddr, the real
	// client) for src attribution / AC pinhole, never the relay address.
	//
	// TYPE-DEPENDENT SOURCE-ADDRESS GATE: the knock arm (KNK/RKN/EXT) additionally
	// requires sourceAddr to be a ROUTABLE PUBLIC IP, because that address opens an
	// AC pinhole — a spoofable/private/loopback source there is a real security
	// concern. The registration arms (OTP/REG) do NOT re-check that: registration
	// opens NO AC pinhole (SourceAddr is purely informational/audit for OTP/REG),
	// so a loopback or RFC1918 relay source — same-host smoke tests, a dev relay —
	// MUST be accepted. Rejecting a private source on the registration path would
	// make it silently drop AFTER the relay already returned HTTP 202, i.e. a
	// registration that looks accepted but never processed. Only the syntactic
	// check (validateRelaySourceAddrSyntactic, applied above for every type) gates
	// OTP/REG.
	switch innerPpd.HeaderType {
	case core.NHP_KNK, core.NHP_RKN, core.NHP_EXT:
		// Routable-public gate — knock-path only (opens an AC pinhole). Reject a
		// non-routable source here even though it passed the syntactic check above.
		// Inline isRoutablePublicIP against the ALREADY-PARSED sourceAddr (from the
		// syntactic check at ~line 134) — no second parse/alloc on this hot path.
		// The routable-public logic is unit-tested directly (TestIsRoutablePublicIP),
		// and the shipped rejection is covered end-to-end by
		// TestHandleRelayForward_PrivateSource_RegistrationAcceptedKnockRejected
		// (a private source ⇒ KNK rejected, OTP/REG accepted) — so shipped == tested
		// without a combined helper.
		if !isRoutablePublicIP(sourceAddr.IP) {
			s.metrics.IncrCounter(MetricRelayForwardReject)
			log.Error("server-relay(@%s src=%s)[HandleRelayForward] non-routable source ip for knock type %s (opens an AC pinhole); dropping",
				relayAddr, sourceAddr, core.HeaderTypeToString(innerPpd.HeaderType))
			return
		}
		ackBytes, userID, buildErr := s.buildKnockAck(innerPpd)
		if buildErr != nil {
			// Marshal failure only — an auth reject returns nil error with the
			// verdict in ackBytes and is sent below.
			log.Error("server-relay(@%s src=%s user=%s)[HandleRelayForward] failed to build knock ack: %v",
				relayAddr, sourceAddr, userID, buildErr)
			return
		}
		if err := s.sendRelayAck(innerPpd, relayAddr, ackBytes); err != nil {
			log.Error("server-relay(@%s src=%s user=%s)[HandleRelayForward] failed to send relayed ack: %v",
				relayAddr, sourceAddr, userID, err)
			return
		}
		log.Info("server-relay(@%s src=%s user=%s)[HandleRelayForward] delivered relayed ack", relayAddr, sourceAddr, userID)

	case core.NHP_OTP:
		// Fire-and-forget: run the shared OTP dispatch and send NOTHING. Errors
		// (including the expected ErrPluginNotRegistered while N3 is pending, and
		// a rate-limit drop) are logged inside dispatchOTP and swallowed here —
		// there is no reply channel for an OTP.
		s.metrics.IncrCounter(MetricRelayOTP)
		if otpErr := s.dispatchOTP(innerPpd); otpErr != nil {
			keyPrefix := pubkeyLogPrefix(base64.StdEncoding.EncodeToString(innerPpd.RemotePubKey))
			log.Error("server-relay(@%s src=%s key=%s)[HandleRelayForward] relayed OTP dispatch error (swallowed, fire-and-forget): %v",
				relayAddr, sourceAddr, keyPrefix, otpErr)
		}

	case core.NHP_REG:
		s.metrics.IncrCounter(MetricRelayRegister)
		keyPrefix := pubkeyLogPrefix(base64.StdEncoding.EncodeToString(innerPpd.RemotePubKey))
		rakBytes, buildErr := s.buildRegisterAck(innerPpd)
		if buildErr != nil {
			// Marshal failure only — a plugin/auth reject is carried IN the RAK
			// bytes (fail-closed errCode), not returned here. Nothing to deliver.
			log.Error("server-relay(@%s src=%s key=%s)[HandleRelayForward] failed to build relayed RAK: %v",
				relayAddr, sourceAddr, keyPrefix, buildErr)
			return
		}
		if err := s.sendRelayReply(innerPpd, relayAddr, core.NHP_RAK, rakBytes); err != nil {
			log.Error("server-relay(@%s src=%s key=%s)[HandleRelayForward] failed to send relayed RAK: %v",
				relayAddr, sourceAddr, keyPrefix, err)
			return
		}
		log.Info("server-relay(@%s src=%s key=%s)[HandleRelayForward] delivered relayed RAK",
			relayAddr, sourceAddr, keyPrefix)

	default:
		s.metrics.IncrCounter(MetricRelayForwardReject)
		log.Error("server-relay(@%s src=%s)[HandleRelayForward] inner packet header=%s is not a relayable type; dropping",
			relayAddr, sourceAddr, core.HeaderTypeToString(innerPpd.HeaderType))
		return
	}
}

// decryptRelayInnerKnock decrypts a forwarded inner NHP packet against the
// shared server key using a synthetic ConnectionData whose RemoteAddr is the
// relay-reported client address. Mirrors forward.go decryptForwardedKnock; the
// synthetic ConnData is used only for decryption and never to transmit.
func (s *UdpServer) decryptRelayInnerKnock(innerBytes []byte, sourceAddr *net.UDPAddr) (*core.PacketParserData, error) {
	now := time.Now().UnixNano()
	pd := &core.PacketData{
		BasePacket: &core.Packet{Content: innerBytes},
		ConnData: &core.ConnectionData{
			Device:     s.device,
			RemoteAddr: sourceAddr,
			InitTime:   now,
		},
		InitTime: now,
	}
	innerPpd, err := s.device.PacketToMsg(pd)
	if err != nil {
		return nil, err
	}
	if innerPpd == nil {
		return nil, fmt.Errorf("decryption returned no parsed packet")
	}
	if innerPpd.Error != nil {
		return nil, innerPpd.Error
	}
	return innerPpd, nil
}

// sendRelayReply encrypts a reply of the given header type from the inner
// packet's cipher state (so the AGENT can decrypt it and it correlates to the
// inner request counter) and writes the bytes to the RELAY's address, which
// forwards them to the browser.
//
// THE DIVERT: this uses the EncryptedPktCh divert + a manual WriteToUDP rather
// than forwardToTransaction, because the inner packet was decrypted onto a
// SYNTHETIC ConnData (decryptRelayInnerKnock) and therefore has no
// RemoteTransaction to forward a reply through. makeMsgData(innerPpd, ...) still
// carries the inner packet's cipher state (PrevParserData) and SenderTrxId, so
// the encrypted reply is end-to-end for the agent and counter-correlated; we
// just place the finished bytes on the wire toward the relay ourselves. The
// architecture spike that proves an agent can decrypt such a divert-built reply
// is relay_ack_roundtrip_spike_test.go.
//
// headerType is the ONLY per-reply-kind variable: NHP_ACK for a relayed knock
// reply, NHP_RAK for a relayed register reply. OTP is fire-and-forget and never
// calls this.
func (s *UdpServer) sendRelayReply(innerPpd *core.PacketParserData, relayAddr *net.UDPAddr, headerType int, body []byte) error {
	replyMd := makeMsgData(innerPpd, headerType, body)
	encCh := make(chan *core.MsgAssemblerData, 1)
	replyMd.EncryptedPktCh = encCh
	s.device.SendMsgToPacket(replyMd)

	select {
	case mad := <-encCh:
		if mad.Error != nil {
			return mad.Error
		}
		packet := slices.Clone(mad.BasePacket.Content)
		mad.Destroy()
		if _, err := s.listenConn.WriteToUDP(packet, relayAddr); err != nil {
			return err
		}
		return nil
	case <-time.After(ForwardTimeout):
		// The encryption worker may still deliver a mad to the buffered channel
		// after we stop waiting; release its pool packet in the background so it
		// isn't leaked. Bounded by a second ForwardTimeout so a dead worker
		// (e.g. device stopping) can't leak this goroutine.
		go func() {
			select {
			case mad := <-encCh:
				if mad != nil {
					mad.Destroy()
				}
			case <-time.After(ForwardTimeout):
			}
		}()
		return fmt.Errorf("timeout encrypting relayed reply")
	}
}

// sendRelayAck is the thin NHP_ACK wrapper over sendRelayReply, kept so the
// existing knock-reply call site (and the relay_ack_roundtrip_spike_test.go
// harness) don't churn when the reply mechanism generalized to a header type.
func (s *UdpServer) sendRelayAck(innerPpd *core.PacketParserData, relayAddr *net.UDPAddr, ackBytes []byte) error {
	return s.sendRelayReply(innerPpd, relayAddr, core.NHP_ACK, ackBytes)
}

// validateRelaySourceAddrSyntactic validates ONLY the SHAPE of the
// relay-reported client address — non-nil, a parseable IP, and a valid port —
// and returns it as a *net.UDPAddr. It deliberately does NOT assert the IP is
// routable/public.
//
// This is the check applied to EVERY forwarded inner type, because the source
// address becomes the synthetic ConnData.RemoteAddr the inner packet is
// decrypted against (decryptRelayInnerKnock), so it must at least be well-formed
// before the type is even known. The stricter routable-public assertion is
// layered on top ONLY for the AC-pinhole-opening knock types, as an inline
// isRoutablePublicIP check in HandleRelayForward's knock dispatch arm (see the
// type-dependent gate there) — the registration types (NHP_OTP / NHP_REG) use
// ONLY this syntactic check.
func validateRelaySourceAddrSyntactic(addr *common.NetAddress) (*net.UDPAddr, error) {
	if addr == nil {
		return nil, fmt.Errorf("missing source address")
	}
	if addr.Port <= 0 || addr.Port > 65535 {
		return nil, fmt.Errorf("invalid source port %d", addr.Port)
	}
	ip := net.ParseIP(addr.Ip)
	if ip == nil {
		return nil, fmt.Errorf("unparseable source ip %q", addr.Ip)
	}
	return &net.UDPAddr{IP: ip, Port: addr.Port}, nil
}

// isRoutablePublicIP reports whether ip is a plausible routable public client
// address. Rejects unspecified / loopback / multicast / link-local / private
// (RFC1918) and CGNAT shared space (100.64.0.0/10). Ported from upstream.
//
// It does NOT reject IANA documentation/benchmark ranges (192.0.2.0/24,
// 198.18.0.0/15, 203.0.113.0/24, 2001:db8::/32) — those pass as "public" (the
// tests use 203.0.113.x as the example client). Matches upstream and is low
// risk because SourceAddr is asserted by an already-authenticated relay, not an
// arbitrary peer; the name promises a touch more than it strictly enforces.
func isRoutablePublicIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() ||
		ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsPrivate() {
		return false
	}
	// Carrier-grade NAT shared address space (RFC 6598, 100.64.0.0/10) is not a
	// routable public client IP.
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
		return false
	}
	return true
}

// decodeRelayInnerPacket bounds (pre- and post-decode) and base64-decodes the
// inner packet field.
func decodeRelayInnerPacket(innerB64 string) ([]byte, error) {
	if len(innerB64) == 0 {
		return nil, fmt.Errorf("empty inner packet")
	}
	if len(innerB64) > relayInnerMaxBase64Len {
		return nil, fmt.Errorf("inner packet base64 too large: %d chars (max %d)", len(innerB64), relayInnerMaxBase64Len)
	}
	innerBytes, err := base64.StdEncoding.DecodeString(innerB64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	if len(innerBytes) < relayInnerMinPacketSize {
		return nil, fmt.Errorf("inner packet too short: %d bytes (min %d)", len(innerBytes), relayInnerMinPacketSize)
	}
	if len(innerBytes) > core.PacketBufferSize {
		return nil, fmt.Errorf("inner packet too large: %d bytes (max %d)", len(innerBytes), core.PacketBufferSize)
	}
	return innerBytes, nil
}
