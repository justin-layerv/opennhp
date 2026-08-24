package core

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"

	common "github.com/OpenNHP/opennhp/nhp/common"
	log "github.com/OpenNHP/opennhp/nhp/log"
)

func cookieRemoteKey(connData *ConnectionData) string {
	if connData == nil {
		return ""
	}
	addr := connData.RealRemoteAddr
	if addr == nil {
		addr = connData.RemoteAddr
	}
	if addr == nil || addr.IP == nil {
		log.Debug("cookieRemoteKey: missing remote address; stateless cookie will fail closed")
		return ""
	}
	if v4 := addr.IP.To4(); v4 != nil {
		return v4.String()
	}
	return addr.IP.String()
}

// Stateless cookies are opaque 32-byte HMAC-SHA256 outputs. CookieSize must
// stay pinned to sha256.Size because agents round-trip COK bytes through a
// fixed [CookieSize] buffer before stamping the RKN header digest.
var _ [CookieSize - sha256.Size]byte
var _ [sha256.Size - CookieSize]byte

const (
	statelessCookieDomain       = "nhp-overload-cookie-v1\x00"
	maxStatelessCookieRemoteKey = 64
	maxStatelessCookieInput     = len(statelessCookieDomain) + 4 + maxStatelessCookieRemoteKey + 4 + PublicKeySize + 8
)

const (
	// HubLSTCookieWindowSeconds is frozen by connector_hub_lst_cookie_v1.
	// Verifiers accept the current and immediately previous window only.
	HubLSTCookieWindowSeconds int64 = 30
	hubLSTCookieDomain              = "nhp-connector-hub-lst-cookie-v1\x00"
	hubLSTCookieIPv4Family    byte  = 0x04
	hubLSTCookieIPv6Family    byte  = 0x06
	hubLSTCookieBase64Size          = (CookieSize + 2) / 3 * 4
)

// canonicalHubLSTSourceIP returns the worker-observed source IP in the exact
// binary form frozen by connector_hub_lst_cookie_v1. The UDP port is excluded
// so NAT rebinding and address-fallback retries do not invalidate proof. A
// relay-provided RealRemoteAddr is deliberately ignored: the dedicated public
// Hub binds the return route it directly observed.
func canonicalHubLSTSourceIP(connData *ConnectionData) (family byte, raw []byte, ok bool) {
	if connData == nil || connData.RemoteAddr == nil || connData.RemoteAddr.IP == nil || connData.RemoteAddr.Zone != "" {
		return 0, nil, false
	}
	addr, ok := netip.AddrFromSlice(connData.RemoteAddr.IP)
	if !ok {
		return 0, nil, false
	}
	addr = addr.Unmap()
	if addr.Is4() {
		v4 := addr.As4()
		return hubLSTCookieIPv4Family, v4[:], true
	}
	if addr.Is6() {
		v6 := addr.As16()
		return hubLSTCookieIPv6Family, v6[:], true
	}
	return 0, nil, false
}

// deriveHubLSTCookieInto implements the exact cross-repo HMAC framing:
// domain || family || u32be(ip length) || ip || u32be(peer length) || peer ||
// u64be(window index). The domain constant already includes its NUL separator.
func deriveHubLSTCookieInto(out *[CookieSize]byte, signingKey []byte, family byte, sourceIP, peerPk []byte, windowIndex int64) {
	mac := hmac.New(sha256.New, signingKey)
	_, _ = io.WriteString(mac, hubLSTCookieDomain)
	mac.Write([]byte{family})
	var framed [8]byte
	binary.BigEndian.PutUint32(framed[:4], uint32(len(sourceIP)))
	mac.Write(framed[:4])
	mac.Write(sourceIP)
	binary.BigEndian.PutUint32(framed[:4], uint32(len(peerPk)))
	mac.Write(framed[:4])
	mac.Write(peerPk)
	binary.BigEndian.PutUint64(framed[:], uint64(windowIndex))
	mac.Write(framed[:])
	mac.Sum(out[:0])
	SetZero(framed[:])
}

// deriveStatelessCookieInto is a stack-only HMAC-SHA256 implementation for the
// overloaded RKN flood path so cookie checks add no steady-state heap pressure
// while a server is already shedding work. Keep it byte-for-byte with
// TestDeriveStatelessCookieIntoMatchesReferenceHMAC.
func deriveStatelessCookieInto(out *[CookieSize]byte, signingKey []byte, remoteKey string, peerPk []byte, windowIndex int64) {
	if len(remoteKey) > maxStatelessCookieRemoteKey || len(peerPk) > PublicKeySize {
		deriveStatelessCookieHMACInto(out, signingKey, remoteKey, peerPk, windowIndex)
		return
	}

	var msg [maxStatelessCookieInput]byte
	n := copy(msg[:], statelessCookieDomain)
	binary.BigEndian.PutUint32(msg[n:n+4], uint32(len(remoteKey)))
	n += 4
	n += copy(msg[n:], remoteKey)
	binary.BigEndian.PutUint32(msg[n:n+4], uint32(len(peerPk)))
	n += 4
	n += copy(msg[n:], peerPk)
	binary.BigEndian.PutUint64(msg[n:n+8], uint64(windowIndex))
	n += 8

	var ipad, opad [sha256.BlockSize]byte
	var keyHash [sha256.Size]byte
	key := signingKey
	if len(key) > sha256.BlockSize {
		keyHash = sha256.Sum256(key)
		key = keyHash[:]
	}
	copy(ipad[:], key)
	copy(opad[:], key)
	for i := range ipad {
		ipad[i] ^= 0x36
		opad[i] ^= 0x5c
	}

	var innerInput [sha256.BlockSize + maxStatelessCookieInput]byte
	copy(innerInput[:sha256.BlockSize], ipad[:])
	copy(innerInput[sha256.BlockSize:], msg[:n])
	inner := sha256.Sum256(innerInput[:sha256.BlockSize+n])

	var outerInput [sha256.BlockSize + sha256.Size]byte
	copy(outerInput[:sha256.BlockSize], opad[:])
	copy(outerInput[sha256.BlockSize:], inner[:])
	sum := sha256.Sum256(outerInput[:])
	copy(out[:], sum[:])

	SetZero(keyHash[:])
	SetZero(ipad[:])
	SetZero(opad[:])
	SetZero(innerInput[:])
	SetZero(outerInput[:])
	SetZero(inner[:])
	SetZero(sum[:])
}

func deriveStatelessCookieHMACInto(out *[CookieSize]byte, signingKey []byte, remoteKey string, peerPk []byte, windowIndex int64) {
	mac := hmac.New(sha256.New, signingKey)
	_, _ = io.WriteString(mac, statelessCookieDomain)
	var rb [4]byte
	binary.BigEndian.PutUint32(rb[:], uint32(len(remoteKey)))
	mac.Write(rb[:])
	_, _ = io.WriteString(mac, remoteKey)
	binary.BigEndian.PutUint32(rb[:], uint32(len(peerPk)))
	mac.Write(rb[:])
	mac.Write(peerPk)
	var wb [8]byte
	binary.BigEndian.PutUint64(wb[:], uint64(windowIndex))
	mac.Write(wb[:])
	mac.Sum(out[:0])
}

// decryptInitiatorStaticPubKey advances the normal Noise IK transcript through
// the initiator-static decrypt and caches the result. Overload RKN cookie
// verification calls this before validatePeer, so validatePeer must reuse the
// cached key instead of replaying the ECDH. TestCookieVerifyEndToEnd is the
// load-bearing regression for that handoff. Failure may partially advance the
// transcript; callers must reject the packet and discard the ppd.
func (ppd *PacketParserData) decryptInitiatorStaticPubKey() ([]byte, error) {
	if ppd.peerStaticPubKeyDecrypted {
		return ppd.RemotePubKey, nil
	}

	// evolve chain hash ChainHash0 -> ChainHash1
	ppd.chainHash.Write(ppd.deviceEcdh.PublicKey())
	ppd.chainHash.Write(ppd.header.EphermeralBytes())

	// evolve chain key ChainKey0 -> ChainKey1
	ppd.noise.MixKey(&ppd.chainKey, ppd.chainKey[:], ppd.header.EphermeralBytes())

	// get ephermeral shared key
	ess := ppd.deviceEcdh.SharedSecret(ppd.header.EphermeralBytes())
	if ess == nil {
		return nil, ErrDeviceECDHEphermalFailed
	}
	defer SetZero(ess[:])

	var key [SymmetricKeySize]byte
	defer SetZero(key[:])
	ppd.noise.KeyGen2(&ppd.chainKey, &key, ppd.chainKey[:], ess[:])

	aead, err := AeadFromKey(ppd.Ciphers.GcmType, &key)
	if err != nil {
		return nil, fmt.Errorf("decryptInitiatorStaticPubKey: aead: %w", err)
	}
	peerPk, err := aead.Open(ppd.remotePubKeyBuf[:0], ppd.header.NonceBytes(), ppd.header.StaticBytes(), ppd.chainHash.Sum(ppd.hashBuf[:0]))
	if err != nil {
		return nil, fmt.Errorf("decryptInitiatorStaticPubKey: open: %w", err)
	}
	if len(peerPk) != PublicKeySize {
		return nil, fmt.Errorf("decryptInitiatorStaticPubKey: expected %d-byte pubkey, got %d", PublicKeySize, len(peerPk))
	}

	ppd.RemotePubKey = ppd.remotePubKeyBuf[:]
	ppd.peerStaticPubKeyDecrypted = true
	return peerPk, nil
}

type CookieStore struct {
	CurrCookie     [CookieSize]byte
	PrevCookie     [CookieSize]byte
	LastCookieTime int64
}

func (cs *CookieStore) Set(cookie []byte) {
	copy(cs.PrevCookie[:], cs.CurrCookie[:])
	copy(cs.CurrCookie[:], cookie)
}

func (cs *CookieStore) Clear() {
	SetZero(cs.CurrCookie[:])
	SetZero(cs.PrevCookie[:])
}

type PacketData struct {
	BasePacket             *Packet
	ConnData               *ConnectionData
	PrevAssemblerData      *MsgAssemblerData
	ConnLastRemoteSendTime *int64
	ConnCookieStore        *CookieStore
	ConnPeerPublicKey      *[PublicKeySizeEx]byte
	InitTime               int64
	DecryptedMsgCh         chan *PacketParserData
}

type PacketParserData struct {
	device     *Device
	basePacket *Packet
	// owningRemoteTransaction is the exact responder transaction created for
	// this request. It is immutable after packet-to-message dispatch installs it
	// and lets specialized handlers retire their own transaction without a
	// transaction-id lookup that could resolve a newer same-id request.
	owningRemoteTransaction *RemoteTransaction
	// originalContent is a pristine snapshot of basePacket.Content captured
	// before decryptBody's in-place AEAD Open overwrites the body region with
	// plaintext. BasePacketContent() returns it so cross-server knock
	// forwarding re-sends the ORIGINAL ciphertext that the assigned server can
	// re-decrypt with the shared registration key (issue #2651). It is a
	// separate heap slice, so it stays valid after Destroy() releases
	// basePacket to the pool (the knock path reads it post-Destroy, like
	// remotePubKeyBuf), and it is ciphertext, not key material, so it is
	// intentionally not zeroed on Destroy.
	originalContent []byte
	ConnData        *ConnectionData
	CipherScheme    int
	Ciphers         *CipherSuite

	deviceEcdh Ecdh
	header     Header
	digestHash hash.Hash
	chainHash  hash.Hash
	bodyAead   cipher.AEAD
	chainKey   [SymmetricKeySize]byte
	// hashBuf avoids per-Sum result allocation. HashSize coverage is checked in crypto.go.
	hashBuf [HashSize]byte

	LocalInitTime int64
	SenderTrxId   uint64
	// RemoteSendTime is the AEAD-authenticated wall-clock send time
	// the sender stamped into the packet header (nanos), populated
	// after the timestamp passes the applicable skew/staleness and
	// per-connection LastRemoteSendTime gates. Downstream handlers
	// (e.g., AC AOP dedupe in endpoints/ac/aop_replay_cache.go) use
	// it to distinguish a captured-and-replayed packet (same
	// timestamp) from a fresh post-restart packet that happens to
	// reuse the sender's in-memory counter (different timestamp).
	// Zero value means "not populated" (e.g., AEAD failed before the
	// timestamp gate); callers that key on it must not invoke before
	// AEAD verification has succeeded.
	RemoteSendTime int64
	// ReceivedFrom is trusted, immutable receive-transport metadata. It is not
	// carried in protocol bytes. UDP endpoints may use it only after successful
	// peer authentication to return a message to the datagram's actual source
	// when ConnectionData.RemoteAddr names an intermediary such as an NLB.
	ReceivedFrom netip.AddrPort

	noise        NoiseFactory // int
	HeaderType   int
	BodySize     int
	HeaderFlag   uint16
	BodyCompress bool
	Overload     bool
	// hubLSTPublicPath pins the exact admission mode selected when this packet
	// parser is created. Device options can be reloaded while workers are live;
	// every gate for one packet must observe the same mode or a mid-packet
	// option flip could separate the unregistered-peer bypass from its mandatory
	// return-routability proof.
	hubLSTPublicPath bool

	SenderIdentity            []byte
	SenderMidPublicKey        []byte
	ConnLastRemoteSendTime    *int64
	ConnCookieStore           *CookieStore
	ConnPeerPublicKey         *[PublicKeySizeEx]byte
	RemotePubKey              []byte
	peerStaticPubKeyDecrypted bool
	// remotePubKeyBuf lives inside the PacketParserData allocation; it avoids
	// a separate heap object for RemotePubKey. Because RemotePubKey slices into
	// this array, downstream aliases extend this struct's lifetime. See Destroy
	// for why the buffer is left intact.
	remotePubKeyBuf [PublicKeySize]byte
	BodyMessage     []byte

	decryptedMsgCh chan<- *PacketParserData //Plaintext payload dispatched (Decryption cycle completed)
	feedbackMsgCh  chan<- *PacketParserData
	Error          error
}

// OwningRemoteTransaction returns the exact responder transaction created for
// this parsed request. Synthetic packets that do not enter the core responder
// lifecycle (for example relay-inner dispatch) return nil.
func (ppd *PacketParserData) OwningRemoteTransaction() *RemoteTransaction {
	if ppd == nil {
		return nil
	}
	return ppd.owningRemoteTransaction
}

func (ppd *PacketParserData) isHubLSTPublicPath() bool {
	return ppd != nil && ppd.hubLSTPublicPath
}

func (d *Device) isHubLSTPublicHeader(headerType int) bool {
	if d == nil || d.deviceType != NHP_SERVER || headerType != NHP_LST {
		return false
	}
	d.optionMutex.Lock()
	option := d.option
	d.optionMutex.Unlock()
	return !option.DisableAgentPeerValidation && option.AllowUnregisteredAgentLST
}

func (ppd *PacketParserData) hasHubLSTCookieProof() bool {
	return ppd.isHubLSTPublicPath() && ppd.HeaderFlag == common.NHP_FLAG_HUB_LST_COOKIE_PROOF
}

func (d *Device) createPacketParserData(pd *PacketData) (ppd *PacketParserData, err error) {
	// Returns a non-nil ppd even on err so the callers' err paths
	// (device.go packetToMsgRoutine, RecvPacketToMsg) can route through
	// ppd.Error / ppd.feedbackMsgCh / ppd.decryptedMsgCh and Destroy
	// the pool packet. Lifecycle is the caller's.
	if pd.PrevAssemblerData != nil {
		ppd = pd.PrevAssemblerData.derivePacketParserData(pd.BasePacket, pd.InitTime)
	} else {
		ppd = &PacketParserData{}
		ppd.device = d
		ppd.basePacket = pd.BasePacket
		ppd.ConnData = pd.ConnData
		ppd.ReceivedFrom = pd.BasePacket.ReceivedFrom
		ppd.ConnCookieStore = pd.ConnCookieStore
		ppd.LocalInitTime = pd.InitTime
		ppd.ConnLastRemoteSendTime = pd.ConnLastRemoteSendTime
		ppd.ConnPeerPublicKey = pd.ConnPeerPublicKey

		// init header and init device ecdh
		ppd.HeaderFlag = ppd.basePacket.Flag()
		ppd.header = ppd.basePacket.Header()
		ppd.CipherScheme = ppd.header.CipherScheme()
		ppd.Ciphers = NewCipherSuite()
		ppd.deviceEcdh = d.GetEcdhByCipherScheme(ppd.CipherScheme)
	}

	// Populate caller channel before the first fallible call below so
	// the err defer in device.go packetToMsgRoutine can deliver the
	// err. One place rather than per-branch.
	ppd.decryptedMsgCh = pd.DecryptedMsgCh

	// Version gate, ahead of every key agreement. A sender below 1.1 does not
	// fold the HeaderCommon into the body AAD, so its body tag can never verify
	// here; reporting that as a version mismatch rather than an AEAD failure is
	// what makes a staged rollout diagnosable.
	//
	// THIS GATE IS A DIAGNOSABILITY AID, NOT A SECURITY BOUNDARY. The version
	// lives in HeaderCommon, which is read here before anything authenticates
	// it. On a packet that carries a body the fold below makes any edit fail the
	// Open, so the gate is backed. On an EMPTY-BODY packet nothing is: no AEAD
	// runs, so an off-path attacker holding only the responder's static PUBLIC
	// key can set any admitted version and re-stamp the unkeyed digest — exactly
	// what restampHeaderDigest does in responder_test.go. Do not later treat a
	// passing version check as evidence of anything about an empty-body packet.
	// Containment there is the CheckRecvHeaderType allowlist and the counter's
	// binding as the GCM nonce; see the residual-gap note in initiator.go
	// encryptBody.
	//
	// NHP_KPL never reaches this function and carries no AEAD, so keepalives
	// from an older peer are unaffected. Two separate mechanisms hold that:
	// the synchronous entry point short-circuits it directly (device.go
	// PacketToMsg, on the RecvPrecheck type), and on the asynchronous path every
	// endpoint receive loop drops it before RecvPacketToMsg ever queues it
	// (endpoints/{agent/udpagent,server/udpserver,ac/udpac,db/udpdevice}.go).
	// packetToMsgRoutine itself does NOT re-check, so a new caller that queues
	// raw datagrams must drop NHP_KPL itself.
	if major, minor := ppd.header.Version(); major != ProtocolVersionMajor || minor < MinimumRecvProtocolVersionMinor {
		err = ErrUnsupportedProtocolVersion
		// bare return: caller's err defer expects named ppd populated
		return
	}

	// init chain hash -> ChainHash0
	// Always reset per packet; intermediate chain-key carry-over was
	// removed (Go-Go agreed on zeros, JS-Go did not). Ported from
	// OpenNHP commit 03619015e. Invariant: this block runs for both
	// branches above — deriveMsgAssemblerData deliberately leaves
	// chain state alone, relying on this re-init.
	ppd.chainHash, err = NewHash(ppd.Ciphers.HashType)
	if err != nil {
		err = fmt.Errorf("failed to create chain hash: %w", err)
		return
	}
	ppd.chainHash.Write(initialHashBytes)

	// init chain key -> ChainKey0
	ppd.noise.HashType = ppd.Ciphers.HashType
	ppd.noise.MixKey(&ppd.chainKey, ppd.chainHash.Sum(ppd.hashBuf[:0]), initialChainKeyBytes)

	ppd.HeaderType, ppd.BodySize = ppd.header.TypeAndPayloadSize()
	ppd.hubLSTPublicPath = d.isHubLSTPublicHeader(ppd.HeaderType)
	if !ppd.isHubLSTPublicPath() {
		log.Debug("start decryption using CIPHER_SCHEME_CURVE")
	}

	// The dedicated public Hub accepts exactly the two assignment-LST flag
	// states frozen by conformance: initial (0) or cookie proof (0x0004).
	// COMPRESS is rejected before body decryption/inflation, and every unknown
	// bit fails closed. Other NHP roles retain their historical flag behavior.
	if ppd.isHubLSTPublicPath() && ppd.HeaderFlag != 0 && ppd.HeaderFlag != common.NHP_FLAG_HUB_LST_COOKIE_PROOF {
		return ppd, ErrInvalidHubLSTFlags
	}

	// init header digest hash -> DigestHash0
	ppd.digestHash, err = NewHash(ppd.Ciphers.HashType)
	if err != nil {
		err = fmt.Errorf("failed to create header digest hash: %w", err)
		return
	}
	ppd.digestHash.Write(initialHashBytes)

	// evolve header digest hash DigestHash0 -> DigestHash1
	ppd.digestHash.Write(ppd.deviceEcdh.PublicKey())

	// check header digest
	if ppd.device.deviceType == NHP_SERVER {
		// server overload handling
		overload := ppd.device.IsOverload()
		if overload {
			// overload, further discard unwanted packet type
			ppd.Overload = true
			if !ppd.IsAllowedAtOverload() {
				if !ppd.isHubLSTPublicPath() {
					log.Critical("discard packet type %d due to overload", ppd.HeaderType)
				}
				err = ErrServerOverload
				return
			}
		}

		// Agents stamp overload cookies into every RKN digest. When stateless
		// params are configured, verify that cookie even if this replica has
		// already recovered below its local overload threshold; otherwise a COK
		// minted by a hot sibling can be rejected by a cooler verifier. Servers
		// install stateless params at startup; the CookieStore path remains for
		// embedded/tests that intentionally leave the params disabled.
		sumCookie := ppd.HeaderType == NHP_RKN && (overload || ppd.device.statelessCookieParamsConfigured())
		digestOK := false
		if ppd.hasHubLSTCookieProof() {
			digestOK = ppd.checkHubLSTCookieProofDigest()
		} else {
			digestOK = ppd.checkHeaderDigest(sumCookie)
		}
		if !digestOK {
			// "HMAC" string kept deliberately (#1126): operator-facing log
			// breadcrumb, matches the preserved ErrServer... message + terraform.
			if !ppd.isHubLSTPublicPath() {
				log.Error("HMAC validation failed on server side. sumCookie: %v", sumCookie)
			}
			err = ErrServerHeaderDigestCheckFailed
			// bare return: caller's err defer expects named ppd populated
			return
		}

	} else {
		if !ppd.checkHeaderDigest(false) {
			// "HMAC" string kept deliberately (#1126) — see note above.
			log.Error("HMAC validation failed.")
			err = ErrHeaderDigestCheckFailed
			// bare return: caller's err defer expects named ppd populated
			return
		}
	}

	// get sender id
	ppd.SenderTrxId = ppd.header.Counter()

	// init body message
	ppd.BodyCompress = ppd.HeaderFlag&common.NHP_FLAG_COMPRESS != 0
	ppd.BodyMessage = nil

	return ppd, nil
}

func (ppd *PacketParserData) deriveMsgAssemblerData(t int, compress bool, message []byte, externalPacket *Packet) (mad *MsgAssemblerData) {
	mad = &MsgAssemblerData{}
	mad.device = ppd.device
	mad.connData = ppd.ConnData
	mad.HeaderType = t
	mad.ciphers = ppd.Ciphers
	mad.CipherScheme = ppd.CipherScheme
	mad.RemotePubKey = ppd.RemotePubKey
	mad.BodyCompress = compress
	mad.bodyMessage = message

	// init packet buffer
	if externalPacket != nil {
		mad.BasePacket = externalPacket
	} else {
		mad.BasePacket = mad.device.AllocatePoolPacket()
	}
	mad.BasePacket.HeaderType = t

	// create header and init device ecdh
	mad.header = mad.BasePacket.HeaderWithCipherScheme(mad.CipherScheme)
	mad.deviceEcdh = mad.device.GetEcdhByCipherScheme(mad.CipherScheme)

	// init version
	//
	// The with-prev branch of createMsgAssemblerData skips the fresh-assembler
	// init, so without this every in-transaction reply (ACK, COK, LRT, RAK, AOP,
	// ART) shipped whatever bytes 8-9 the recycled pool buffer happened to hold.
	// Nothing read the field before, so the garbage was invisible; the receive
	// gate added in createPacketParserData reads it, and a reply must not be
	// rejected for a version its sender never wrote.
	mad.header.SetVersion(ProtocolVersionMajor, ProtocolVersionMinor)

	// continue with the sender's counter
	mad.header.SetCounter(ppd.SenderTrxId)

	// chain hash/key are reinitialized per packet by
	// initiator.go createMsgAssemblerData (OpenNHP 03619015e).

	return mad
}

// shouldCheckRecvAttack gates the per-connection LastRemoteSendTime
// *replay* check (timestamp regression), split from shouldCheckFlood
// (#1123 round-7) so a type can be replay-gated without also taking the
// 20 ms flood interval.
//
// It now returns true for every (deviceType, peerType, msgType): the
// replay gate has NO exemptions — both historical ones are gone (NHP_AOP
// under #1123, NHP_ART under #1457). The predicate is kept rather than
// inlined as the tested invariant anchor (re-introducing an exemption
// must consciously edit this function and its pins in responder_test.go)
// and to stay parallel with its still-selective siblings shouldCheckFlood
// / shouldEscalateStale.
//
// Two caveats: (1) the strict less-than rejects even a benign reorder of
// two µs-spaced packets as a "replay" — reachable for bursty types (AOP,
// ART) with NO network reorder, because send timestamps are stamped by the
// concurrent msgToPacketRoutine workers. The drop is unconditional, but
// whether it ALSO escalates toward a connection block is gated per type by
// shouldEscalateReplay (ART and AOP are drop-only, #1457/#2518).
// (2) it only sees in-connection replays — the cross-connection ones
// (restart / failover / NAT flush reset the state) are caught by the
// endpoint dedupe caches (endpoints/ac/aop_replay_cache.go,
// endpoints/server/art_replay_cache.go).
func shouldCheckRecvAttack(deviceType int, peerType int, msgType int) bool {
	return true
}

// shouldEscalateReplay reports whether a dropped in-connection replay (a
// timestamp regression caught by shouldCheckRecvAttack) should ALSO
// escalate toward a connection block — bump ConnData.RecvThreatCount and,
// past ThreatCountBeforeBlock, SendBlockSignal. The replay packet is
// dropped either way; this gates only the punitive escalation, mirroring
// shouldEscalateStale for the stale gate.
//
// NHP_ART (AC→server) is exempt (#1457). ART send timestamps are stamped
// inside the concurrent msgToPacketRoutine workers
// (initiator.createMsgAssemblerData sets mad.LocalInitTime), so during a
// knock burst the AC can emit ARTs whose timestamps are non-monotonic
// relative to arrival order WITHOUT any network reorder. With
// ThreatCountBeforeBlock = 1, a >=2-in-a-row regression (e.g. a burst
// arriving t3, t2, t1) would otherwise cross the threshold and
// SendBlockSignal, severing the trusted AEAD-authenticated AC->server
// connection — far worse than the single dropped packet the regression
// actually represents. The drop still rejects the replay, and the real
// cross-connection defense is the dedupe cache
// (endpoints/server/art_replay_cache.go), not this per-connection block.
//
// NHP_AOP (server->AC) is exempt for the symmetric reason (#2518): its
// send timestamp is stamped by the same concurrent msgToPacketRoutine
// workers, so a server knock burst can deliver AOPs whose timestamps are
// non-monotonic relative to arrival order with NO network reorder, and a
// >=2-in-a-row regression would otherwise cross ThreatCountBeforeBlock and
// SendBlockSignal — severing the trusted AEAD-authenticated server->AC
// connection that the flood- and stale-escalation exemptions
// (shouldCheckFlood, shouldEscalateStale) already protect. The drop still
// rejects the replay; the cross-connection AC dedupe cache
// (endpoints/ac/aop_replay_cache.go) is the real cross-connection defense.
// #1461 deliberately deferred this symmetric step; #2518 takes it, removing
// AOP's last per-connection auto-block. Every other (deviceType, peerType,
// msgType) keeps the default escalation. The exact unregistered-LST Hub path
// is separately drop-only at the validatePeer call site because it has no
// registry-backed source binding.
func shouldEscalateReplay(deviceType int, peerType int, msgType int) bool {
	if deviceType == NHP_SERVER && peerType == NHP_AC && msgType == NHP_ART {
		return false
	}
	if deviceType == NHP_AC && peerType == NHP_SERVER && msgType == NHP_AOP {
		return false
	}
	return true
}

// shouldCheckFlood gates the per-connection MinimalRecvIntervalMs
// flood check (two consecutive packets within 20 ms trip
// RecvThreatCount and, past ThreatCountBeforeBlock, fire
// SendBlockSignal on the connection).
//
// NHP_AOP (server → AC) is exempt because the server legitimately
// emits AOPs in tight succession to the same AC during knock
// bursts: each successful agent knock against the server produces
// one AOP per AC that needs an ipset entry, and timestamps on
// back-to-back sends differ by µs. Subjecting AOP to the 20 ms
// floor would false-flood-block a connection during routine burst
// load. The replay gate (shouldCheckRecvAttack) still catches any
// timestamp regression.
//
// NHP_ART (AC → server) is flood-exempt for the symmetric reason:
// during a knock burst the server sends back-to-back AOPs to one AC,
// so the AC's ARTs (one per AOP) leave µs apart and would
// false-flood-block the trusted AC→server connection under the 20 ms
// floor. Note the asymmetry with the replay gate: ART is NO LONGER
// replay-exempt (#1457 removed that), so shouldCheckRecvAttack still
// catches an ART timestamp regression — only the 20 ms rate floor is
// waived here, exactly as for AOP.
func shouldCheckFlood(deviceType int, peerType int, msgType int) bool {
	if deviceType == NHP_AC && peerType == NHP_SERVER && msgType == NHP_AOP {
		return false
	}
	if deviceType == NHP_SERVER && peerType == NHP_AC && msgType == NHP_ART {
		return false
	}
	return true
}

// recvStalenessFloor returns the maximum age (as a nanosecond
// duration) a received packet's AEAD-authenticated send timestamp
// may lag the local receive time before it is rejected as stale.
//
// NHP_AOP (server → AC) gets a tighter floor than the historical
// 600 s default (#1464). The AC's in-process AOP dedupe cache
// (endpoints/ac/aop_replay_cache.go) catches replays within a single
// process lifetime, but an AC restart — process restart, blue/green
// deploy, or failover — wipes that cache, so a captured AOP whose
// timestamp is still inside the staleness floor can replay against a
// fresh-cache AC and re-open the original (src,dst) ipset entry. The
// staleness floor is the only replay gate that survives a cache wipe,
// so tightening it for AOP shrinks that window uniformly across every
// restart class. Every other (deviceType, peerType, msgType) keeps
// the default floor, so agent→server knock paths are unchanged. The
// chosen value and its clock-skew budget live on the
// AOPRecvStalenessFloorSeconds constant — tune there.
//
// Re-tuning caution — for a stale drop that DOES escalate (see
// shouldEscalateStale), the branch also bumps ConnData.RecvThreatCount
// and, past ThreatCountBeforeBlock, fires SendBlockSignal, blocking
// the whole connection rather than dropping one packet. AOP is exempt
// from that escalation (shouldEscalateStale returns false), so a
// clock-skew false-reject of a legitimate AOP is a recoverable drop,
// not a connection block — but AOPRecvStalenessFloorSeconds is still
// kept well above realistic NTP skew so legitimate AOPs are not
// dropped at all in steady state.
//
// Co-located with shouldCheckRecvAttack / shouldCheckFlood so the
// AOP-specific responder gates stay in one place; a future refactor
// that widens this floor for AOP must revisit the cross-restart
// replay analysis in aop_replay_cache.go.
func recvStalenessFloor(deviceType int, peerType int, msgType int) int64 {
	if deviceType == NHP_AC && peerType == NHP_SERVER && msgType == NHP_AOP {
		return AOPRecvStalenessFloorSeconds * int64(time.Second)
	}
	return DefaultRecvStalenessFloorSeconds * int64(time.Second)
}

// shouldEscalateStale reports whether dropping a stale packet should
// also escalate it as a threat — bump ConnData.RecvThreatCount and,
// past ThreatCountBeforeBlock, fire SendBlockSignal to close and block
// the connection. The stale packet is dropped either way; this only
// gates the punitive escalation.
//
// NHP_AOP (server → AC) is exempt (#1464). It mirrors the existing
// shouldCheckFlood exemption: AOP already does NOT escalate on the
// 20 ms flood gate, precisely so a legitimate server's bursty AOPs
// cannot self-inflict a connection block. The staleness gate is the
// only block-trigger AOP was still subject to, and tightening the AOP
// floor (recvStalenessFloor) makes a benign clock-skew false-reject
// more reachable — so a stale AOP, which on a fresh/post-restart
// connection is far more likely a clock-skew artifact than an attack,
// must not be allowed to sever the trusted, AEAD-authenticated
// server→AC connection. It also removes a small DoS lever: an in-VPC
// attacker replaying one captured AOP after it ages past the floor
// could otherwise trip the block on a fresh connection. The packet is
// still dropped (ErrStalePacketReceived) and genuine in-connection
// timestamp regressions are still caught + escalated by the replay
// gate (shouldCheckRecvAttack, which AOP remains subject to), and a
// replayed AOP is independently dropped by the AC dedupe cache
// (endpoints/ac/aop_replay_cache.go), so the lost escalation is only a
// weak rate-limit on a low-payoff stale-AOP flood — already largely
// forgone by the flood-gate exemption.
//
// Accepted residual — AOP is exempt from the flood gate
// (shouldCheckFlood) and the stale gate (this predicate), and now also
// from the replay-gate escalation (shouldEscalateReplay, #2518), so AOP
// has NO remaining per-connection auto-block trigger: the replay gate
// (shouldCheckRecvAttack) still DROPS an in-connection timestamp
// regression, but no longer escalates it. An in-connection regression or
// a replay flood on a *fresh* connection (LastRemoteSendTime == 0, no
// regression) therefore can no longer be source-blocked by any gate —
// but every such packet is still dropped (ErrReplayPacketReceived, no
// authz bypass), the attacker is bounded by their finite captured
// packets (each costing one already-required AEAD decrypt), and the
// cross-connection AC dedupe cache (endpoints/ac/aop_replay_cache.go)
// remains AOP's real replay defense. This is a deliberate trade, not a
// side effect.
//
// NHP_ART (AC → server) keeps the default escalation: it is exempt
// from the replay/flood gates but a genuinely stale ART is not an
// expected legitimate event, so there is no false-reject motivation to
// suppress the block. The exact unregistered-LST Hub path bypasses this
// predicate at the validatePeer call site because its source is not bound.
func shouldEscalateStale(deviceType int, peerType int, msgType int) bool {
	if deviceType == NHP_AC && peerType == NHP_SERVER && msgType == NHP_AOP {
		return false
	}
	return true
}

// unregisteredLSTFutureSkewLimit bounds how far a public Hub request may lead
// the Hub's receive clock. Without this exact-path bound, a valid initiator can
// stamp an arbitrarily future time and extend the captured packet's
// cross-connection replay eligibility far beyond the past-staleness floor. It
// is deliberately not a global clock-policy change: on servers without this
// option, registered peers retain the historical behavior plus registry and
// source-address binding. A Hub enabling the option skips those checks for
// every LST, even if its key is registered, so it must not host registered LST
// peers. The 600-second past floor stays unchanged until the Hub
// application-envelope expiry contract is fixed under #3227.
const unregisteredLSTFutureSkewLimit = HubLSTFutureSkewLimitSeconds * time.Second

func (ppd *PacketParserData) validatePeer() (err error) {
	publicHubLST := ppd.isHubLSTPublicPath()
	peerPk, err := ppd.decryptInitiatorStaticPubKey()
	if err != nil {
		if !publicHubLST {
			log.Error("failed to decrypt peer pubkey: %v", err)
		}
		return err
	}

	//log.Debug("decrypted pubkey: %v, input: %v", peerPk, ppd.header.StaticBytes())

	// validate peer public key if they already exists in peer pool
	// also validate peer address if it has been changed
	// NOTE: to relieve ac from managing arbitrary agent peers,
	// ac does not validate nor store agent public key. Related msgtype: NHP_ACC.
	var peer Peer
	var toValidate bool
	var peerDeviceType int

	ppd.device.optionMutex.Lock()
	option := ppd.device.option
	ppd.device.optionMutex.Unlock()

	peerDeviceType = HeaderTypeToDeviceType(ppd.HeaderType)
	allowUnregisteredLST := publicHubLST
	switch peerDeviceType {
	case NHP_AGENT:
		toValidate = !option.DisableAgentPeerValidation && !allowUnregisteredLST

	case NHP_SERVER:
		toValidate = !option.DisableServerPeerValidation

	case NHP_AC:
		toValidate = !option.DisableACPeerValidation

	case NHP_RELAY:
		toValidate = !option.DisableRelayPeerValidation
	case NHP_DB:
		toValidate = !option.DisableDePeerValidation
	case DHP_AGENT:
		toValidate = !option.DisableAgentPeerValidation
	}

	if toValidate {
		peer = ppd.device.LookupPeer(peerPk)
		if peer == nil {
			log.Error("peer not found in peer pool")
			err = ErrPeerNotFound
			return err
		}

		if peer.IsExpired() {
			log.Error("peer expired")
			err = ErrPeerExpired
			return err
		}

		if !peer.CheckRecvAddress(ppd.LocalInitTime, ppd.ConnData.RemoteAddr) {
			log.Error("peer does not match its previous address")
			err = ErrPeerAddressMismatch
			return err
		}
		peer.UpdateRecv(ppd.LocalInitTime, ppd.ConnData.RemoteAddr)
	}

	if ppd.ConnPeerPublicKey != nil {
		copy((*ppd.ConnPeerPublicKey)[:], peerPk)
	}

	// evolve chainhash ChainHash1 -> ChainHash2
	ppd.chainHash.Write(ppd.header.StaticBytes())

	// init shared key
	ss := ppd.deviceEcdh.SharedSecret(peerPk)
	if ss == nil {
		if !publicHubLST {
			log.Error("device ECDH failed with obtained peer")
		}
		err = ErrDeviceECDHObtainedPeerFailed
		return err
	}

	// prepare key for aead
	var key [SymmetricKeySize]byte
	var aead cipher.AEAD

	// generate gcm key and decrypt timestamp ChainKey2 -> ChainKey3
	ppd.noise.KeyGen2(&ppd.chainKey, &key, ppd.chainKey[:], ss[:])
	SetZero(ss[:])

	var tsBytes [TimestampSize]byte
	aead, err = AeadFromKey(ppd.Ciphers.GcmType, &key)
	if err != nil {
		if !publicHubLST {
			log.Error("failed to create AEAD for timestamp decryption: %v", err)
		}
		return err
	}
	_, err = aead.Open(tsBytes[:0], ppd.header.NonceBytes(), ppd.header.TimestampBytes(), ppd.chainHash.Sum(ppd.hashBuf[:0]))
	if err != nil {
		if !publicHubLST {
			log.Error("failed to decrypt timestamp")
		}
		return err
	}

	remoteSendTime := int64(binary.BigEndian.Uint64(tsBytes[:]))
	if allowUnregisteredLST && remoteSendTime > ppd.LocalInitTime+int64(unregisteredLSTFutureSkewLimit) {
		// Do not escalate: a legitimate fast clock must not self-block; the Hub worker (#3227) must rate-limit abuse.
		return ErrStalePacketReceived
	}

	lastRemoteSendTime := atomic.LoadInt64(&ppd.ConnData.LastRemoteSendTime)
	if shouldCheckRecvAttack(ppd.device.deviceType, peerDeviceType, ppd.HeaderType) {
		// The public Hub waives the coarse 20 ms floor below so the mandatory
		// one-resend proof can return immediately. Its proof header must be fresh,
		// so equality is an exact replay there; ordinary NHP paths retain their
		// historical strict-regression check and flood floor.
		replayed := remoteSendTime < lastRemoteSendTime ||
			(publicHubLST && lastRemoteSendTime != 0 && remoteSendTime == lastRemoteSendTime)
		if replayed {
			// replay packet, drop. Escalate the drop toward a connection
			// block only where an in-connection timestamp regression is an
			// attack signal rather than a likely benign reorder. NHP_ART
			// (AC→server, #1457) and NHP_AOP (server→AC, #2518) are both
			// exempt: their send timestamps are stamped inside the concurrent
			// msgToPacketRoutine workers (initiator.createMsgAssemblerData), so
			// a knock burst can deliver regressed ARTs/AOPs with NO network
			// reorder at all, and a >=2-in-a-row regression would otherwise
			// cross ThreatCountBeforeBlock and SendBlockSignal — severing the
			// trusted, AEAD-authenticated AC↔server connection. The packet is
			// still dropped (the replay is rejected) and the cross-connection
			// dedupe caches are the real cross-connection defense; only the
			// punitive block is waived. See shouldEscalateReplay.
			if !allowUnregisteredLST {
				escalate := shouldEscalateReplay(ppd.device.deviceType, peerDeviceType, ppd.HeaderType)
				// Log severity tracks the escalation decision: for the drop-only
				// exempt types an in-connection regression is an EXPECTED benign
				// burst-reorder, so log at Warning to avoid Critical-level spam on
				// healthy bursty connections (the AC dedupe cache already uses
				// Warning for the same benign-retry reason); for escalating types
				// the regression is a genuine attack signal and stays Critical.
				if escalate {
					log.Critical("received replay packet from %s, drop packet", ppd.ConnData.RemoteAddr.String())
					// threat plus 1
					threat := atomic.AddInt32(&ppd.ConnData.RecvThreatCount, 1)
					// with high queue number, the device may use ConnData channels when conn is already closed
					if threat > ThreatCountBeforeBlock && !ppd.ConnData.IsClosed() {
						// clamp threat count to avoid overflow
						atomic.StoreInt32(&ppd.ConnData.RecvThreatCount, ThreatCountBeforeBlock)
						// block source address
						ppd.ConnData.SendBlockSignal()
					}
				} else {
					log.Warning("received replay packet from %s, drop packet (drop-only type, not escalated)", ppd.ConnData.RemoteAddr.String())
				}
			}
			err = ErrReplayPacketReceived
			return err
		}
	}
	// A valid Hub proof is a protocol-mandated second LST and may arrive well
	// inside the inherited 20 ms per-connection floor. The exact-replay check
	// above plus the Hub worker's bounded admission/replay layer remain active.
	if !publicHubLST && shouldCheckFlood(ppd.device.deviceType, peerDeviceType, ppd.HeaderType) {
		if remoteSendTime < lastRemoteSendTime+MinimalRecvIntervalMs*int64(time.Millisecond) {
			// flood packet, drop
			if !allowUnregisteredLST {
				log.Critical("received flood packet from %s, drop packet", ppd.ConnData.RemoteAddr.String())
				// threat plus 1
				threat := atomic.AddInt32(&ppd.ConnData.RecvThreatCount, 1)
				if threat > ThreatCountBeforeBlock && !ppd.ConnData.IsClosed() {
					// clamp threat count to avoid overflow
					atomic.StoreInt32(&ppd.ConnData.RecvThreatCount, ThreatCountBeforeBlock)
					// block source address
					ppd.ConnData.SendBlockSignal()
				}
			}
			err = ErrFloodPacketReceived
			return err
		}
	}
	if remoteSendTime < (ppd.LocalInitTime - recvStalenessFloor(ppd.device.deviceType, peerDeviceType, ppd.HeaderType)) {
		// send remote timestamp is too old than receive local time, drop
		// note there might be time calibration error between remote and local devices.
		// AOP (server→AC) uses a tighter floor than the 600 s default to
		// bound the cross-restart replay window (#1464) — see
		// recvStalenessFloor.
		if !allowUnregisteredLST {
			log.Critical("received stale packet from %s, drop packet", ppd.ConnData.RemoteAddr.String())
			// Escalate to threat/block only for message types where a stale
			// packet is an attack signal rather than a likely clock-skew
			// artifact. AOP (server→AC) is exempt (#1464) so a benign
			// skew/boot-clock false-reject is a recoverable drop, not a
			// connection block — see shouldEscalateStale.
			if shouldEscalateStale(ppd.device.deviceType, peerDeviceType, ppd.HeaderType) {
				threat := atomic.AddInt32(&ppd.ConnData.RecvThreatCount, 1)
				if threat > ThreatCountBeforeBlock && !ppd.ConnData.IsClosed() {
					// clamp threat count to avoid overflow
					atomic.StoreInt32(&ppd.ConnData.RecvThreatCount, ThreatCountBeforeBlock)
					// block source address
					ppd.ConnData.SendBlockSignal()
				}
			}
		}
		err = ErrStalePacketReceived
		return err
	}

	// update remote last send time
	atomic.StoreInt64(&ppd.ConnData.LastRemoteSendTime, remoteSendTime)
	// Surface the AEAD-authenticated per-packet timestamp to
	// downstream handlers — set here unconditionally, on every
	// accepted packet, so both endpoint replay caches get a populated
	// value: the AC AOP dedupe (endpoints/ac/aop_replay_cache.go) and
	// the server ART dedupe (endpoints/server/art_replay_cache.go,
	// invoked via the Device recvReplayDedupe hook). It is assigned
	// after the gate branches above rather than inside any one of them,
	// so the value is populated even on a path a gate lets through.
	//
	// Cross-package contract: both replay caches key on this field. A
	// refactor that moves or skips this assignment silently degrades
	// either dedupe to (pubkey, txid, 0) keying — the post-restart
	// counter-collision regression tests in aop_replay_cache_test.go /
	// art_replay_cache_test.go fence the cache layer but not the
	// responder wire-up. Issue #1468 tracks an integration-style test
	// that drives a real packet through validatePeer to fence this
	// assignment end-to-end (a minimal-fixture unit test would require
	// the full noise-handshake context — Device, Peer, ECDH, AEAD
	// chain — substantively heavier than this assignment justifies as a
	// unit test). Until #1468 lands, the next reviewer of validatePeer
	// must catch any reordering here.
	ppd.RemoteSendTime = remoteSendTime
	// clear threat
	atomic.StoreInt32(&ppd.ConnData.RecvThreatCount, 0)

	// handle knock packet at overload before going into body decryption
	if ppd.device.deviceType == NHP_SERVER && ppd.Overload && (ppd.HeaderType == NHP_KNK || ppd.HeaderType == DHP_KNK) {
		ppd.sendCookie()
		return ErrServerRejectWithCookie
	}

	// evolve chainhash ChainHash2 -> ChainHash3
	ppd.chainHash.Write(ppd.header.TimestampBytes())

	// generate gcm key for body decryption ChainKey3 -> ChainKey4
	ppd.noise.KeyGen2(&ppd.chainKey, &key, ppd.chainKey[:], ppd.header.TimestampBytes())
	ppd.bodyAead, err = AeadFromKey(ppd.Ciphers.GcmType, &key)
	if err != nil {
		if !publicHubLST {
			log.Error("failed to create AEAD for body decryption: %v", err)
		}
		return err
	}

	return nil
}

// lastDecompressWarnNano throttles the near-ceiling decompression warning
// below to at most one line per decompressWarnInterval, process-wide. The
// throttle is deliberate and global: decryptBody is a per-packet path, this
// deployment ships logs to files with no downstream sampling to lean on, and
// the signal is an anomalous-ratio canary rather than a per-peer event — a
// hard-ceiling breach already logs Critical and fails the decode on every
// occurrence. The warning reports size only, matching that sibling Critical:
// decryptBody is a pure decoder intentionally decoupled from connection
// identity, so its unit tests can drive it without a full ConnData.
var lastDecompressWarnNano atomic.Int64

const decompressWarnInterval = int64(time.Minute)

// decompressWarnAllowed reports whether the near-ceiling warning may log at
// nowNano, CAS-claiming the throttle slot so at most one caller per
// decompressWarnInterval wins. Split out so the throttle gate is unit-testable
// without log capture or wall-clock timing (TestDecompressWarnAllowedThrottle).
func decompressWarnAllowed(nowNano int64) bool {
	last := lastDecompressWarnNano.Load()
	return nowNano-last >= decompressWarnInterval && lastDecompressWarnNano.CompareAndSwap(last, nowNano)
}

func (ppd *PacketParserData) decryptBody() (err error) {
	defer func() {
		// clear secrets
		ppd.chainHash.Reset()
		ppd.chainHash = nil
		SetZero(ppd.chainKey[:])
		SetZero(ppd.hashBuf[:])
	}()

	// message body is empty, skip decryption. No AEAD runs, so the HeaderCommon
	// binding folded below never applies to this packet — see the matching note
	// in initiator.go encryptBody for why that residual gap is contained.
	if len(ppd.basePacket.Content) == ppd.header.Size() {
		return nil
	}

	// Snapshot the original ciphertext before the in-place AEAD Open below
	// overwrites the body region with plaintext (see the originalContent field
	// for why the forward path needs it, #2651). Only the forwardable knock
	// family (IsForwardableKnockType: NHP_KNK, NHP_RKN, NHP_EXT) reaches
	// BasePacketContent() via buildKnockAck → req.OriginalPacket
	// (nhpauth.go:220). DHP_KNK returns early (nhpauth.go:109) before that
	// line and never needs the snapshot. Non-knock types skip the clone to
	// avoid a ~1–4 KiB per-packet allocation.
	if IsForwardableKnockType(ppd.HeaderType) {
		ppd.originalContent = bytes.Clone(ppd.basePacket.Content)
	}

	// evolve chainhash ChainHash3 -> ChainHash4: fold the HeaderCommon exactly as
	// received, so the body tag verifies only when preamble, type, payload size,
	// version, flags and counter are the ones the sender sealed under. The sender
	// folds these same 24 bytes immediately before its body Seal (initiator.go
	// encryptBody); any in-flight edit surfaces here as ErrAEADDecryptionFailed.
	ppd.chainHash.Write(ppd.header.Bytes()[:HeaderCommonSize])

	// decrypt body and reuse ppd.BasePacket.Content space
	body, err := ppd.bodyAead.Open(ppd.basePacket.Content[ppd.header.Size():ppd.header.Size()], ppd.header.NonceBytes(), ppd.basePacket.Content[ppd.header.Size():], ppd.chainHash.Sum(ppd.hashBuf[:0]))
	if err != nil {
		if !ppd.isHubLSTPublicPath() {
			log.Critical("decrypt body failed: %v", err)
		}
		return ErrAEADDecryptionFailed.WithExtra(err)
	}

	// Note: ppd.BodyMessage must be a separate []byte slice because ppd.BasePacket.Buf will be released later
	if ppd.BodyCompress {
		buf := getBytesBuffer()
		defer putBytesBuffer(buf)

		r, err := getZlibReader(bytes.NewReader(body))
		if err != nil {
			log.Critical("invalid compressed data: %v", err)
			return ErrDataDecompressionFailed.WithExtra(err)
		}
		// Close + pool-return on every exit. Close-then-Put is safe:
		// the next Get() calls zlib.Resetter.Reset which re-points the
		// reader at a fresh source regardless of prior Close state.
		// The Close error (which reports Adler-32 checksum mismatch) is
		// intentionally discarded: the ciphertext we just decrypted was
		// already authenticated by bodyAead.Open above, so the AEAD tag
		// rules out the tampering that a checksum would catch here.
		defer func() {
			_ = r.Close()
			putZlibReader(r)
		}()

		// Cap the inflated size as a decompression-bomb guard (#1131). The
		// Standard on-wire packets are capped at PacketBufferSize. The dedicated
		// authenticated relay envelope may reach RelayPacketBufferSize, but the
		// production relay sends it uncompressed; either way this guard bounds a
		// malicious authenticated peer's inflate. See constants.go for sizing.
		limitedReader := io.LimitReader(r, MaxDecompressedBodySize+1) // +1 to detect overflow
		n, err := io.Copy(buf, limitedReader)
		if err != nil {
			log.Critical("message decompression failed: %v", err)
			return ErrDataDecompressionFailed.WithExtra(err)
		}
		if n > MaxDecompressedBodySize {
			log.Critical("decompressed data exceeds maximum size limit (%d bytes)", MaxDecompressedBodySize)
			return ErrDataDecompressionFailed.WithExtra(fmt.Errorf("decompressed size %d exceeds limit %d", n, MaxDecompressedBodySize))
		}
		// Anomaly canary: the warn band (MaxDecompressedBodyWarnSize..ceiling, ~819
		// KiB–1 MiB) is unreachable by legitimate traffic (~73 KiB max; see
		// constants.go), so a decode here signals an anomalous compression ratio
		// (pathological near-duplicate list or a bomb probe under the ceiling), not
		// growth. Throttled so this per-packet path can't flood the file logs. The
		// sibling over-ceiling Critical stays per-occurrence by contrast: a rejected
		// bomb is an actionable security event worth logging every time.
		if n >= MaxDecompressedBodyWarnSize && decompressWarnAllowed(time.Now().UnixNano()) {
			log.Warning("decompressed body %d B reached the %d-byte warn threshold — anomalous compression ratio nearing the %d-byte ceiling", n, MaxDecompressedBodyWarnSize, MaxDecompressedBodySize)
		}

		// Deep-copy out of the pooled buffer; buf.Bytes() aliases pool storage.
		ppd.BodyMessage = bytes.Clone(buf.Bytes())
	} else {
		// Deep-copy; body aliases ppd.basePacket.Buf which may be released later.
		ppd.BodyMessage = bytes.Clone(body)
	}

	return nil
}

func (ppd *PacketParserData) makeCookieStore(cookieStore *CookieStore) *CookieStore {
	if cookieStore != nil {
		var tsBytes [TimestampSize]byte
		currTime := time.Now().UnixNano()
		if (currTime - cookieStore.LastCookieTime) > CookieRegenerateTime*int64(time.Second) {
			copy(cookieStore.PrevCookie[:], cookieStore.CurrCookie[:])
			binary.BigEndian.PutUint64(tsBytes[:], uint64(currTime))
			ppd.noise.KeyGen1(&cookieStore.CurrCookie, ppd.header.EphermeralBytes(), tsBytes[:])
			cookieStore.LastCookieTime = currTime
		}
		return cookieStore
	}

	return nil
}

func (ppd *PacketParserData) generateCookie() {
	var tsBytes [TimestampSize]byte
	currTime := time.Now().UnixNano()

	ppd.ConnData.Lock()
	defer ppd.ConnData.Unlock()

	if (currTime - ppd.ConnData.CookieStore.LastCookieTime) > CookieRegenerateTime*int64(time.Second) {
		copy(ppd.ConnData.CookieStore.PrevCookie[:], ppd.ConnData.CookieStore.CurrCookie[:])
		binary.BigEndian.PutUint64(tsBytes[:], uint64(currTime))
		ppd.noise.KeyGen1(&ppd.ConnData.CookieStore.CurrCookie, ppd.header.EphermeralBytes(), tsBytes[:])
		ppd.ConnData.CookieStore.LastCookieTime = currTime
	}
}

const (
	cookieMintFailureMissingCookieStore    = "missing_cookie_store"
	cookieMintFailureMissingRemoteBinding  = "missing_remote_binding"
	cookieMintFailureMarshalFailed         = "marshal_failed"
	cookieMintFailureWrongPeerPubkeyLength = "wrong_peer_pubkey_length"
)

func (ppd *PacketParserData) sendCookie() {
	var cookie []byte
	var statelessCookie [CookieSize]byte
	statelessConfigured := false
	if ppd.device != nil {
		var keyBuf [SymmetricKeySize]byte
		key, win := ppd.device.statelessCookieParamsInto(keyBuf[:])
		if len(key) > 0 && win > 0 {
			defer SetZero(key)
			statelessConfigured = true
			if len(ppd.RemotePubKey) != PublicKeySize {
				log.Error("sendCookie: cannot mint stateless cookie with peer pubkey length %d", len(ppd.RemotePubKey))
				ppd.device.recordCookieMintFailure(cookieMintFailureWrongPeerPubkeyLength)
				return
			}
			// COK mint and RKN verify must derive the same remote key. A
			// future relay that populates RealRemoteAddr must do it on both
			// paths; one-sided population fails closed as a cookie mismatch.
			remoteKey := cookieRemoteKey(ppd.ConnData)
			if remoteKey == "" {
				log.Error("sendCookie: cannot mint stateless cookie without a remote address binding")
				ppd.device.recordCookieMintFailure(cookieMintFailureMissingRemoteBinding)
				return
			}
			window := time.Now().Unix() / win
			deriveStatelessCookieInto(&statelessCookie, key, remoteKey, ppd.RemotePubKey, window)
			cookie = statelessCookie[:]
		}
	}
	if len(cookie) == 0 {
		if statelessConfigured {
			return
		}
		if ppd.ConnData == nil || ppd.ConnData.CookieStore == nil {
			log.Error("sendCookie: stateless cookies disabled and no connection CookieStore is available")
			ppd.device.recordCookieMintFailure(cookieMintFailureMissingCookieStore)
			return
		}
		if ppd.header != nil {
			ppd.generateCookie()
		}
		cookie = ppd.ConnData.CookieStore.CurrCookie[:]
	}

	cokStr := base64.StdEncoding.EncodeToString(cookie)
	cokMsg := &common.ServerCookieMsg{
		// Native agents correlate COK by this payload TransactionId. The relay
		// correlates by the cleartext wire counter, which PrevParserData below
		// also derives from SenderTrxId; the equality is intentional.
		TransactionId: ppd.SenderTrxId,
		Cookie:        cokStr,
	}
	cokBytes, err := json.Marshal(cokMsg)
	if err != nil {
		log.Error("sendCookie: failed to marshal cookie message: %v", err)
		ppd.device.recordCookieMintFailure(cookieMintFailureMarshalFailed)
		return
	}

	// Route through PrevParserData so the wire counter is the agent's
	// SenderTrxId — matching every other server→agent response (the ACK at
	// transaction.go SendMsgToPacket, which sets PrevParserData = t.parserData).
	// The HTTP relay (endpoints/relay) matches a pending request to its reply by
	// the cleartext header counter of the agent's inbound KNK, so a COK stamped
	// with a fresh server-side NextCounterIndex() never correlates: the relay
	// drops it and the browser times out under Overload (#2611 / #2529). Per
	// MsgData's with-prev contract derives the reply context from ppd instead
	// of standalone fields: CipherScheme, ConnData, TransactionId and PeerPk
	// are sourced from ppd, and RemoteAddr is represented through ppd.ConnData
	// on this server reply path. Those fields are omitted here.
	md := &MsgData{
		HeaderType:     NHP_COK,
		PrevParserData: ppd,
		Compress:       true,
		Message:        cokBytes,
	}

	// The cookie is a short-lived bearer capability. Keep the destination and
	// payload size for diagnostics without persisting the credential itself.
	log.Debug("Send cookie back to %s (%d bytes)", ppd.ConnData.RemoteAddr, len(md.Message))
	ppd.device.SendMsgToPacket(md)
}

// checkHubLSTCookieProofDigest verifies the assignment-Hub proof in the
// existing Curve header digest. It deliberately does not call or share the
// NHP_RKN stateless-cookie derivation: the domain, flag, source canonicalization
// and configuration seam are all distinct. The initiator static key must be
// decrypted before the cookie can be derived, and validatePeer later reuses the
// cached key so this does not repeat the Noise transcript.
func (ppd *PacketParserData) checkHubLSTCookieProofDigest() bool {
	defer func() {
		ppd.digestHash.Reset()
		ppd.digestHash = nil
	}()

	if !ppd.isHubLSTPublicPath() || ppd.HeaderFlag != common.NHP_FLAG_HUB_LST_COOKIE_PROOF ||
		ppd.device == nil || !ppd.device.hubLSTCookieKeyConfigured() {
		return false
	}
	peerPk, err := ppd.decryptInitiatorStaticPubKey()
	if err != nil || len(peerPk) != PublicKeySize {
		return false
	}
	family, sourceIP, ok := canonicalHubLSTSourceIP(ppd.ConnData)
	if !ok || ppd.LocalInitTime <= 0 {
		return false
	}

	var activeBuf, previousBuf [SymmetricKeySize]byte
	active, previous := ppd.device.hubLSTCookieKeysInto(activeBuf[:], previousBuf[:])
	if len(active) != SymmetricKeySize {
		return false
	}
	defer SetZero(active)
	defer SetZero(previous)

	headerPrefix := ppd.header.Bytes()[:ppd.header.Size()-HashSize]
	headerDigest := ppd.header.HeaderDigestBytes()
	serverPubKey := ppd.deviceEcdh.PublicKey()
	currentWindow := ppd.LocalInitTime / int64(time.Second) / HubLSTCookieWindowSeconds
	var cookie [CookieSize]byte
	defer SetZero(cookie[:])
	// Frozen verification order: active/current, active/previous-window,
	// previous/current, previous/previous-window. The order keeps the hot path
	// first while preserving both time-window and fleet-key rotation grace.
	for _, key := range [2][]byte{active, previous} {
		if len(key) == 0 {
			continue
		}
		for _, window := range [2]int64{currentWindow, currentWindow - 1} {
			deriveHubLSTCookieInto(&cookie, key, family, sourceIP, peerPk, window)
			ppd.digestHash.Reset()
			ppd.digestHash.Write(initialHashBytes)
			ppd.digestHash.Write(serverPubKey)
			ppd.digestHash.Write(headerPrefix)
			ppd.digestHash.Write(cookie[:])
			if hmac.Equal(ppd.digestHash.Sum(ppd.hashBuf[:0]), headerDigest) {
				return true
			}
		}
	}
	return false
}

// HubLSTCookieChallengeError carries the already-authenticated, encrypted COK
// datagram that a dedicated synchronous Hub worker may return to the observed
// UDP source. Error() never includes the cookie or packet. Packet returns an
// independent copy so the caller cannot alias core's scratch storage.
type HubLSTCookieChallengeError struct {
	packet []byte
}

func (e *HubLSTCookieChallengeError) Error() string {
	return ErrHubLSTCookieProofRequired.Error()
}

func (e *HubLSTCookieChallengeError) Unwrap() error {
	return ErrHubLSTCookieProofRequired
}

func (e *HubLSTCookieChallengeError) Packet() []byte {
	if e == nil {
		return nil
	}
	return bytes.Clone(e.packet)
}

func (e *HubLSTCookieChallengeError) clear() {
	if e == nil {
		return
	}
	SetZero(e.packet)
	e.packet = nil
}

// enforceHubLSTCookieChallenge runs after static/timestamp/body AEAD succeeds
// and before a decrypted LST can reach any endpoint handler. A source-unproven
// request receives at most one uncompressed COK, and only if the exact sealed
// response is strictly smaller than the received datagram. Equality and every
// construction/configuration failure are silent fail-closed drops represented
// by ErrHubLSTCookieProofRequired without response bytes.
//
// The dedicated Hub worker must use synchronous Device.PacketToMsg, inspect a
// HubLSTCookieChallengeError, and hand Packet() to its single UDP writer. The
// legacy asynchronous RecvPacketToMsg path still enforces the gate (so an
// unproven body cannot reach DecryptedMsgQueue) but intentionally does not send
// the embedded packet; its ordinary error lifecycle destroys parser state and
// drops the challenge fail closed.
func (ppd *PacketParserData) enforceHubLSTCookieChallenge() error {
	if !ppd.isHubLSTPublicPath() || ppd.hasHubLSTCookieProof() {
		return nil
	}
	// An asynchronous caller may receive the error-bearing parser object on a
	// completion channel. Never leave a source-unproven assignment body (which
	// may contain a setup credential) attached to that error result.
	defer func() {
		SetZero(ppd.BodyMessage)
		ppd.BodyMessage = nil
	}()
	if ppd.HeaderFlag != 0 || ppd.device == nil || !ppd.device.hubLSTCookieKeyConfigured() {
		return ErrHubLSTCookieProofRequired
	}
	family, sourceIP, ok := canonicalHubLSTSourceIP(ppd.ConnData)
	if !ok || len(ppd.RemotePubKey) != PublicKeySize || ppd.LocalInitTime <= 0 {
		return ErrHubLSTCookieProofRequired
	}

	var activeBuf, previousBuf [SymmetricKeySize]byte
	active, previous := ppd.device.hubLSTCookieKeysInto(activeBuf[:], previousBuf[:])
	if len(active) != SymmetricKeySize {
		return ErrHubLSTCookieProofRequired
	}
	defer SetZero(active)
	defer SetZero(previous)
	window := ppd.LocalInitTime / int64(time.Second) / HubLSTCookieWindowSeconds
	var cookie [CookieSize]byte
	defer SetZero(cookie[:])
	deriveHubLSTCookieInto(&cookie, active, family, sourceIP, ppd.RemotePubKey, window)

	var cookieBase64 [hubLSTCookieBase64Size]byte
	defer SetZero(cookieBase64[:])
	base64.StdEncoding.Encode(cookieBase64[:], cookie[:])
	// 86 bytes is the compact JSON maximum: 9-byte prefix + 20-digit uint64 +
	// 11-byte cookie prefix + 44-byte padded base64 + 2-byte suffix.
	cokBytes := make([]byte, 0, 86)
	cokBytes = append(cokBytes, `{"trxId":`...)
	cokBytes = strconv.AppendUint(cokBytes, ppd.SenderTrxId, 10)
	cokBytes = append(cokBytes, `,"cookie":"`...)
	cokBytes = append(cokBytes, cookieBase64[:]...)
	cokBytes = append(cokBytes, `"}`...)
	defer SetZero(cokBytes)
	mad, err := ppd.device.msgToPacketWithDiagnostics(&MsgData{
		HeaderType:     NHP_COK,
		PrevParserData: ppd,
		Compress:       false,
		Message:        cokBytes,
	}, true)
	if err != nil || mad == nil || mad.BasePacket == nil {
		return ErrHubLSTCookieProofRequired
	}
	packet := bytes.Clone(mad.BasePacket.Content)
	mad.Destroy() // explicit ownership release; idempotent after MsgToPacket.
	if len(packet) >= len(ppd.basePacket.Content) {
		SetZero(packet)
		return ErrHubLSTCookieProofRequired
	}
	return &HubLSTCookieChallengeError{packet: packet}
}

// checkHeaderDigest recomputes the unkeyed header digest (see
// curve.HeaderCurve.HeaderDigest) and compares it to the value on the wire.
// hmac.Equal is used only for constant-time comparison (#2033); it does not
// imply the digest is a keyed MAC. A passing check proves header integrity,
// not peer identity — real authentication is the static-decrypt + validatePeer
// path below.
func (ppd *PacketParserData) checkHeaderDigest(sumCookie bool) bool {
	defer func() {
		ppd.digestHash.Reset()
		ppd.digestHash = nil
	}()

	prefixLen := ppd.header.Size() - HashSize

	if sumCookie {
		if ppd.device != nil && ppd.device.statelessCookieParamsConfigured() {
			peerPk, err := ppd.decryptInitiatorStaticPubKey()
			if err != nil {
				log.Debug("checkHeaderDigest(sumCookie): cannot recover peer static pubkey: %v", err)
				return false
			}

			serverPubKey := ppd.deviceEcdh.PublicKey()
			headerPrefix := ppd.header.Bytes()[0:prefixLen]
			headerDigest := ppd.header.HeaderDigestBytes()
			// COK mint and RKN verify must derive the same remote key. A
			// future relay that populates RealRemoteAddr must do it on both
			// paths; one-sided population fails closed as a cookie mismatch.
			remoteKey := cookieRemoteKey(ppd.ConnData)
			if remoteKey == "" {
				log.Debug("checkHeaderDigest(sumCookie): missing remote address binding")
				return false
			}
			var keyBuf [SymmetricKeySize]byte
			key, win := ppd.device.statelessCookieParamsInto(keyBuf[:])
			if len(key) == 0 || win <= 0 {
				return false
			}
			defer SetZero(key)
			h := ppd.digestHash
			matched := false
			currWindow := time.Now().Unix() / win
			// Accept current and previous windows only. That absorbs a minter
			// clock behind the verifier; minter-ahead skew fails closed so the
			// replay window does not extend into the future.
			var cookie [CookieSize]byte
			for _, window := range [2]int64{currWindow, currWindow - 1} {
				deriveStatelessCookieInto(&cookie, key, remoteKey, peerPk, window)
				h.Reset()
				h.Write(initialHashBytes)
				h.Write(serverPubKey)
				h.Write(headerPrefix)
				h.Write(cookie[:])
				if hmac.Equal(h.Sum(ppd.hashBuf[:0]), headerDigest) {
					matched = true
					break
				}
			}
			return matched
		}

		if ppd.ConnData == nil || ppd.ConnData.CookieStore == nil {
			return false
		}
		ppd.digestHash.Write(ppd.header.Bytes()[0:prefixLen])
		ppd.ConnData.Lock()
		defer ppd.ConnData.Unlock()

		if ppd.LocalInitTime < ppd.ConnData.CookieStore.LastCookieTime+CookieRoundTripTimeMs*int64(time.Millisecond) {
			// cookie has already or nearly been updated, use previous cookie
			ppd.digestHash.Write(ppd.ConnData.CookieStore.PrevCookie[:])
			return hmac.Equal(ppd.digestHash.Sum(ppd.hashBuf[:0]), ppd.header.HeaderDigestBytes())
		}
		// use current cookie
		ppd.digestHash.Write(ppd.ConnData.CookieStore.CurrCookie[:])
		return hmac.Equal(ppd.digestHash.Sum(ppd.hashBuf[:0]), ppd.header.HeaderDigestBytes())
	}

	ppd.digestHash.Write(ppd.header.Bytes()[0:prefixLen])
	return hmac.Equal(ppd.digestHash.Sum(ppd.hashBuf[:0]), ppd.header.HeaderDigestBytes())
}

func (ppd *PacketParserData) Destroy() {
	ppd.device.ReleasePoolPacket(ppd.basePacket)
	if ppd.digestHash != nil {
		ppd.digestHash.Reset()
		ppd.digestHash = nil
	}
	if ppd.chainHash != nil {
		ppd.chainHash.Reset()
		ppd.chainHash = nil
	}
	// Defense-in-depth: clear scratch even though hash digests are not key material.
	SetZero(ppd.hashBuf[:])
	// Do not clear remotePubKeyBuf here: RemotePubKey is consumed after
	// Destroy releases packet/hash state on PacketToMsg and async paths.
}

func (ppd *PacketParserData) IsAllowedAtOverload() bool {
	switch ppd.HeaderType {
	case NHP_KNK, DHP_KNK, NHP_RKN, NHP_EXT, NHP_AOL, NHP_ART,
		// NHP_RLY is the authenticated relay envelope for an inner agent knock.
		// It must reach HandleRelayForward while overloaded so the inner KNK can
		// take the normal early-cookie path and the relay can return that opaque
		// COK to the agent. The outer Noise handshake still authenticates the
		// configured relay before its reported source address is trusted.
		NHP_RLY,
		// NHP_RVA is the AC→server revocation proof-of-delivery ack (#2793).
		// Dropping it under overload would strand the server's pending-revoke
		// tracker: the AC has already applied the revoke, but its ack is discarded,
		// so the retry engine keeps retransmitting and may age the (delivered)
		// revoke out to a FALSE RevocationAgedOut degraded signal. Admit it so the
		// degraded metric stays trustworthy.
		//
		// Threat model — explicitly accepted: this gate runs BEFORE the handshake
		// AEAD (see the IsAllowedAtOverload call site in the digest path above),
		// and unlike NHP_RKN an NHP_RVA carries no pre-validation overload cookie.
		// So a forged NHP_RVA now forces a handshake attempt during overload where
		// it would previously have been shed. This is the SAME class as the already-
		// admitted no-cookie types (NHP_KNK / DHP_KNK / NHP_AOL): the forgery fails
		// the AEAD (the attacker lacks the AC static key), so it adds no NEW DoS
		// primitive beyond what forged NHP_KNK already permits, and NHP_RVA is a
		// low-volume security-event-rate message with no separate rate-limit gap on
		// this path. The marginal cost is accepted to keep the revocation degraded
		// signal trustworthy under overload; if NHP_RVA volume ever rises, gate it
		// behind a cookie like NHP_RKN rather than removing it here.
		NHP_RVA:
		return true
	default:
		return false
	}
}

// BasePacketContent returns a clone of the original encrypted packet content
// captured by decryptBody (originalContent) before its in-place AEAD Open
// overwrote the body region with plaintext (#2651). It is used for
// server-to-server knock forwarding, where the assigned server re-decrypts the
// original packet with the shared registration keypair. The snapshot is a
// separate heap slice, so it stays valid even after Destroy() releases
// basePacket to the pool — the knock path reads this post-Destroy. The clone
// keeps the "caller cannot modify our internal state" contract. Returns nil
// for non-forwardable header types (the snapshot is only taken when
// IsForwardableKnockType returns true) and when no body was decrypted.
func (ppd *PacketParserData) BasePacketContent() []byte {
	if ppd.originalContent == nil {
		return nil
	}
	return bytes.Clone(ppd.originalContent)
}
