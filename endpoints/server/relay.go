package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// ============================================================================
// NHP-Relay forward handling (#2208)
//
//	Browser JS-Agent -> HTTPS NHP-Relay -> internal NHP-Server NLB -> AC
//
// The relay observes the real client address at its HTTPS edge,
// wraps the agent's opaque inner NHP packet in a RelayForwardMsg, and sends it
// to the server's internal endpoint as an authenticated NHP_RLY packet.
//
// HandleRelayForward decrypts the inner packet with the server key (the relay
// cannot read it — inner crypto is end-to-end agent<->server), dispatches it by
// authenticated inner type, and encrypts ACK/COK/RAK/LRT replies for the agent
// from that inner cipher state. It then places those still-opaque bytes in an
// authenticated server->relay RelayReturnMsg carrying the random RequestID.
//
// Both encryption layers use EncryptedPktCh because a synthetically decrypted
// inner packet has no RemoteTransaction to forward through. The server sends
// the outer return to the authenticated NHP_RLY packet's source; the relay
// validates the server key and request ID before delivering the inner reply.
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
// RelayForwardReject. Browser relay ingress is therefore a cloud-mode feature;
// native UDP SDKs bypass this path and connect to their assigned cell's public
// NHP NLB. Legacy/on-prem relay deployments fail closed rather than weakening
// peer validation.
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

// HandleRelayForward processes an NHP_RLY packet: an agent packet forwarded by a
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
	if err := common.DecodeRelayJSONStrict(outerPpd.BodyMessage, rlyMsg); err != nil {
		s.metrics.IncrCounter(MetricRelayForwardReject)
		log.Error("server-relay(@%s)[HandleRelayForward] failed to parse RelayForwardMsg: %v", relayAddr, err)
		return
	}
	if !common.ValidRelayRequestID(rlyMsg.RequestID) {
		s.metrics.IncrCounter(MetricRelayForwardReject)
		log.Error("server-relay(@%s)[HandleRelayForward] missing or invalid request ID", relayAddr)
		return
	}

	// Every relayed type needs a syntactically valid source for its synthetic
	// connection. Only knock types are required to be publicly routable because
	// only those types can open an AC pinhole; OTP/REG/LST also need to work from
	// private and loopback addresses in development and same-host smoke tests.
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
	innerPpd, cookieBytes, innerConn, err := s.decryptRelayInnerKnock(innerBytes, sourceAddr)
	if innerConn != nil {
		defer innerConn.Close()
	}
	if err != nil {
		s.metrics.IncrCounter(MetricRelayForwardReject)
		log.Error("server-relay(@%s src=%s)[HandleRelayForward] inner knock decrypt failed: %v", relayAddr, sourceAddr, err)
		return
	}
	if len(cookieBytes) > 0 {
		if err := s.sendRelayReturn(outerPpd, rlyMsg.RequestID, cookieBytes); err != nil {
			log.Error("server-relay(@%s src=%s)[HandleRelayForward] failed to return overload cookie: %v", relayAddr, sourceAddr, err)
		}
		return
	}

	// CRYPTO-AUTH BOUNDARY: the inner decrypt above authenticated the agent
	// (Noise populated innerPpd.RemotePubKey). This is NOT yet the ack-vs-drop
	// boundary — two PRE-ACK fail-closed guards still remain below (the
	// missing-pubkey fail-safe and the inner header-type gate); they drop
	// WITHOUT an ack because a packet with no agent key, or a non-knock type,
	// yields no knock-ack to build. The ack-vs-drop boundary is buildKnockAck:
	// from there an auth REJECT is DELIVERED as an ack (the verdict rides in the
	// bytes) and only a marshal/encrypt failure drops silently. Every drop ABOVE
	// the decrypt is pre-auth — no authenticated agent to encrypt an ack for.

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

	// Dispatch through the same handlers used by direct traffic. RequestID only
	// changes the authenticated relay return transport; it must not fork direct
	// OTP/REG/LST semantics, rate limits, plugin loading, metrics, or error mapping.
	switch innerPpd.HeaderType {
	case core.NHP_KNK, core.NHP_RKN, core.NHP_EXT:
		if !isRoutablePublicIP(sourceAddr.IP) {
			s.metrics.IncrCounter(MetricRelayForwardReject)
			log.Error("server-relay(@%s src=%s)[HandleRelayForward] non-routable source ip for knock type %s (opens an AC pinhole); dropping",
				relayAddr, sourceAddr, core.HeaderTypeToString(innerPpd.HeaderType))
			return
		}
	case core.DHP_KNK:
		// The current browser HTTPS relay rejects DHP_KNK before forwarding, so
		// this arm is unreachable from that ingress today. Retain it as
		// defense-in-depth for any future authenticated NHP_RLY ingress: DHP uses
		// the shared knock/ACK crypto pipeline below, but only appraises device
		// evidence and does not open an AC pinhole. Keep the syntactic source
		// check without imposing the public-IP knock gate.
	case core.NHP_OTP:
		// Fire-and-forget: the relay has no pending waiter for OTP.
		s.metrics.IncrCounter(MetricRelayOTP)
		if otpErr := s.dispatchOTP(innerPpd); otpErr != nil {
			keyPrefix := pubkeyLogPrefix(base64.StdEncoding.EncodeToString(innerPpd.RemotePubKey))
			log.Error("server-relay(@%s src=%s key=%s)[HandleRelayForward] relayed OTP dispatch error (swallowed, fire-and-forget): %v",
				relayAddr, sourceAddr, keyPrefix, otpErr)
		}
		return
	case core.NHP_REG:
		s.metrics.IncrCounter(MetricRelayRegister)
		keyPrefix := pubkeyLogPrefix(base64.StdEncoding.EncodeToString(innerPpd.RemotePubKey))
		rakBytes, buildErr := s.buildRegisterAck(innerPpd)
		if buildErr != nil {
			log.Error("server-relay(@%s src=%s key=%s)[HandleRelayForward] failed to build relayed RAK: %v",
				relayAddr, sourceAddr, keyPrefix, buildErr)
			return
		}
		innerReply, encryptErr := s.buildRelayInnerReply(innerPpd, core.NHP_RAK, rakBytes)
		if encryptErr != nil {
			log.Error("server-relay(@%s src=%s key=%s)[HandleRelayForward] failed to encrypt relayed RAK: %v",
				relayAddr, sourceAddr, keyPrefix, encryptErr)
			return
		}
		if returnErr := s.sendRelayReturn(outerPpd, rlyMsg.RequestID, innerReply); returnErr != nil {
			log.Error("server-relay(@%s src=%s key=%s)[HandleRelayForward] failed to return relayed RAK: %v",
				relayAddr, sourceAddr, keyPrefix, returnErr)
		}
		return
	case core.NHP_LST:
		lrtBytes, userID, listErr := s.buildListResult(innerPpd)
		// Logical/plugin failures are encoded in a populated LRT and must reach
		// the agent. Nil alone means the LRT verdict could not be marshaled.
		if lrtBytes == nil {
			log.Error("server-relay(@%s src=%s user=%s)[HandleRelayForward] failed to build relayed LRT: %v",
				relayAddr, sourceAddr, userID, listErr)
			return
		}
		innerReply, encryptErr := s.buildRelayInnerReply(innerPpd, core.NHP_LRT, lrtBytes)
		if encryptErr != nil {
			log.Error("server-relay(@%s src=%s user=%s)[HandleRelayForward] failed to encrypt relayed LRT: %v",
				relayAddr, sourceAddr, userID, encryptErr)
			return
		}
		if returnErr := s.sendRelayReturn(outerPpd, rlyMsg.RequestID, innerReply); returnErr != nil {
			log.Error("server-relay(@%s src=%s user=%s)[HandleRelayForward] failed to return relayed LRT: %v",
				relayAddr, sourceAddr, userID, returnErr)
		}
		return
	default:
		s.metrics.IncrCounter(MetricRelayForwardReject)
		log.Error("server-relay(@%s src=%s)[HandleRelayForward] inner packet header=%s is not a relayable type; dropping",
			relayAddr, sourceAddr, core.HeaderTypeToString(innerPpd.HeaderType))
		return
	}

	// Run the exact knock pipeline. buildKnockAck reads ppd.ConnData.RemoteAddr
	// (= sourceAddr) for the AC pinhole and AgentAddr, so the AC opens for the
	// real client, never the relay.
	ackBytes, userID, buildErr := s.buildKnockAck(innerPpd)
	if buildErr != nil {
		// Marshal failure only — an auth reject returns nil error with the
		// verdict in ackBytes and is sent below.
		log.Error("server-relay(@%s src=%s user=%s)[HandleRelayForward] failed to build knock ack: %v",
			relayAddr, sourceAddr, userID, buildErr)
		return
	}

	innerReply, err := s.buildRelayInnerReply(innerPpd, core.NHP_ACK, ackBytes)
	if err != nil {
		log.Error("server-relay(@%s src=%s user=%s)[HandleRelayForward] failed to encrypt relayed ack: %v",
			relayAddr, sourceAddr, userID, err)
		return
	}
	if err := s.sendRelayReturn(outerPpd, rlyMsg.RequestID, innerReply); err != nil {
		log.Error("server-relay(@%s src=%s user=%s)[HandleRelayForward] failed to send relayed ack: %v",
			relayAddr, sourceAddr, userID, err)
		return
	}
	log.Info("server-relay(@%s src=%s user=%s)[HandleRelayForward] delivered relayed ack", relayAddr, sourceAddr, userID)
}

// decryptRelayInnerKnock decrypts a forwarded inner NHP packet against the
// shared server key using a synthetic ConnectionData whose RemoteAddr is the
// relay-reported client address. Mirrors forward.go decryptForwardedKnock; the
// synthetic ConnData is used only for decryption and never to transmit. A new
// one per forward intentionally carries no per-connection replay/flood history;
// timestamp validation plus the relay's edge admission and in-flight bounds are
// the authoritative controls for this relayed path.
func (s *UdpServer) decryptRelayInnerKnock(innerBytes []byte, sourceAddr *net.UDPAddr) (*core.PacketParserData, []byte, *core.ConnectionData, error) {
	now := time.Now().UnixNano()
	conn := &core.ConnectionData{
		Device:               s.device,
		RemoteAddr:           sourceAddr,
		InitTime:             now,
		CookieStore:          &core.CookieStore{},
		SendQueue:            make(chan *core.Packet, 1),
		RecvQueue:            make(chan *core.Packet, 1),
		BlockSignal:          make(chan struct{}, 1),
		SetTimeoutSignal:     make(chan struct{}, 1),
		StopSignal:           make(chan struct{}),
		RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
	}
	pd := &core.PacketData{
		BasePacket: &core.Packet{Content: innerBytes},
		ConnData:   conn,
		InitTime:   now,
	}
	innerPpd, err := s.device.PacketToMsg(pd)
	if err != nil {
		if errors.Is(err, core.ErrServerRejectWithCookie) {
			select {
			case packet := <-conn.SendQueue:
				cookie := append([]byte(nil), packet.Content...)
				s.device.ReleasePoolPacket(packet)
				return nil, cookie, conn, nil
			case <-time.After(ForwardTimeout):
				return nil, nil, conn, fmt.Errorf("timeout waiting for overload cookie")
			}
		}
		return nil, nil, conn, err
	}
	if innerPpd == nil {
		return nil, nil, conn, fmt.Errorf("decryption returned no parsed packet")
	}
	if innerPpd.Error != nil {
		return nil, nil, conn, innerPpd.Error
	}
	return innerPpd, nil, conn, nil
}

// buildRelayInnerReply encrypts the end-to-end agent reply but does not put its
// raw bytes on the relay transport. The caller wraps them in RelayReturnMsg so
// the relay can correlate by random request ID rather than colliding counters.
func (s *UdpServer) buildRelayInnerReply(innerPpd *core.PacketParserData, headerType int, body []byte) ([]byte, error) {
	md := makeMsgData(innerPpd, headerType, body)
	encCh := make(chan *core.MsgAssemblerData, 1)
	md.EncryptedPktCh = encCh
	s.device.SendMsgToPacket(md)

	select {
	case mad := <-encCh:
		return core.ConsumeEncryptedPacket(mad)
	case <-time.After(ForwardTimeout):
		// The encryption worker may still deliver a mad to the buffered channel
		// after we stop waiting; release its pool packet in the background so it
		// isn't leaked. Bounded by a second ForwardTimeout so a dead worker
		// (e.g. device stopping) can't leak this goroutine.
		s.reapLateEncryptedPacket(encCh, ForwardTimeout)
		return nil, fmt.Errorf("timeout encrypting relayed inner reply")
	}
}

// reapLateEncryptedPacket makes the bounded late-result drain part of graceful
// shutdown. The dispatch wrapper owns a wg slot before the handler starts, and
// this nested Add happens synchronously before the handler returns, so Stop
// cannot enter wg.Wait before the drain is registered.
func (s *UdpServer) reapLateEncryptedPacket(encCh <-chan *core.MsgAssemblerData, timeout time.Duration) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		select {
		case mad := <-encCh:
			if mad != nil {
				mad.Destroy()
			}
		case <-time.After(timeout):
		}
	}()
}

// sendRelayReturn wraps an opaque agent reply in an authenticated server->relay
// NHP_ACK envelope. The outer ACK is encrypted to the registered relay static
// key; the inner bytes remain encrypted to the agent.
func (s *UdpServer) sendRelayReturn(outerPpd *core.PacketParserData, requestID string, inner []byte) error {
	body, err := json.Marshal(&common.RelayReturnMsg{
		RequestID:   requestID,
		InnerPacket: base64.StdEncoding.EncodeToString(inner),
	})
	if err != nil {
		return fmt.Errorf("marshal RelayReturnMsg: %w", err)
	}
	encCh := make(chan *core.MsgAssemblerData, 1)
	md := makeMsgData(outerPpd, core.NHP_ACK, body)
	// The authenticated return contains a complete standard NHP packet. Give
	// only this outer transport a larger buffer; direct NHP replies remain capped
	// by core.PacketBufferSize.
	md.Compress = false
	md.ExternalPacket = s.device.AllocateRelayPacket()
	md.EncryptedPktCh = encCh
	s.device.SendMsgToPacket(md)
	select {
	case mad := <-encCh:
		packet, err := core.ConsumeEncryptedPacket(mad)
		if err != nil {
			return err
		}
		_, err = s.listenConn.WriteToUDP(packet, outerPpd.ConnData.RemoteAddr)
		return err
	case <-time.After(ForwardTimeout):
		// The encryption worker owns the pooled outer packet until it delivers;
		// releasing it here would race that worker. Drain a normal late result.
		// A permanently stuck worker can retain one 6 KiB buffer, bounded by the
		// server's fixed receive/encryption queues rather than by packet volume.
		s.reapLateEncryptedPacket(encCh, ForwardTimeout)
		return fmt.Errorf("timeout encrypting relay return envelope")
	}
}

// validateRelaySourceAddrSyntactic validates the shape of the relay-reported
// client address. Routability is checked separately for knock types, the only
// relayed requests that use this address to open an AC pinhole.
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
