package core

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
)

type MsgData struct {
	RemoteAddr     *net.UDPAddr      // used by agent and ac create a new connection or pick an existing connection for msg sending
	ConnData       *ConnectionData   // used by server to pick an existing connection for msg sending
	PrevParserData *PacketParserData // when PrevParserData is set, CipherScheme, RemoteAddr, ConnData, TransactionId and PeerPk will be overridden
	CipherScheme   int               // 0: curve25519/aes-256-gcm/blake2s
	TransactionId  uint64
	HeaderType     int
	Compress       bool
	ExternalPacket *Packet
	ExternalCookie *[CookieSize]byte
	// HubLSTCookieProof is the raw 32-byte cookie returned by an assignment
	// Hub's NHP_COK challenge. It is valid only on an uncompressed NHP_LST sent
	// by an NHP_AGENT. Core stamps the dedicated proof flag and mixes the cookie
	// into the existing header digest; existing NHP_RKN ExternalCookie behavior
	// remains separate and unchanged.
	HubLSTCookieProof *[CookieSize]byte
	Message           []byte
	PeerPk            []byte
	EncryptedPktCh    chan *MsgAssemblerData
	ResponseMsgCh     chan *PacketParserData
}

func (d *Device) validateMsgData(md *MsgData) (err error) {
	if md.PrevParserData == nil {
		if d.deviceType == NHP_SERVER && md.ConnData == nil {
			err = errors.New("missing connection data for server")
		} else if d.deviceType != NHP_SERVER && md.RemoteAddr == nil {
			err = errors.New("missing remote address")
		}

		if md.PeerPk == nil {
			err = errors.New("missing remote peer public key")
		}
	}

	return err
}

type MsgAssemblerData struct {
	device     *Device
	BasePacket *Packet
	connData   *ConnectionData
	ciphers    *CipherSuite

	deviceEcdh     Ecdh
	ephermeralEcdh Ecdh
	header         Header
	digestHash     hash.Hash
	chainHash      hash.Hash
	bodyAead       cipher.AEAD
	chainKey       [SymmetricKeySize]byte
	// hashBuf avoids per-Sum result allocation. HashSize coverage is checked in crypto.go.
	hashBuf [HashSize]byte

	LocalInitTime int64
	TransactionId uint64
	noise         NoiseFactory // int
	CipherScheme  int
	HeaderType    int
	BodySize      int
	HeaderFlag    uint16
	BodyCompress  bool

	ExternalCookie       *[CookieSize]byte
	HubLSTCookieProof    [CookieSize]byte
	hasHubLSTCookieProof bool
	RemotePubKey         []byte
	bodyMessage          []byte

	encryptedPktCh      chan<- *MsgAssemblerData
	ResponseMsgCh       chan<- *PacketParserData
	Error               error
	suppressDiagnostics bool
}

func (d *Device) createMsgAssemblerData(md *MsgData) (mad *MsgAssemblerData, err error) {
	return d.createMsgAssemblerDataWithDiagnostics(md, false)
}

// createMsgAssemblerDataWithDiagnostics is the internal assembly seam used by
// the public Hub's COK challenge. Suppression is not exposed on MsgData: adding
// an unexported field to that public wire-input struct would break downstream
// unkeyed literals. Ordinary callers always go through createMsgAssemblerData.
func (d *Device) createMsgAssemblerDataWithDiagnostics(md *MsgData, suppressDiagnostics bool) (mad *MsgAssemblerData, err error) {
	if !suppressDiagnostics {
		log.Debug("createMsgAssemblerData: PeerPk len=%d, CipherScheme=%d, HeaderType=%d",
			len(md.PeerPk), md.CipherScheme, md.HeaderType)
	}
	// Returns a non-nil mad even on err so the callers' err defers
	// (device.go msgToPacketRoutine, MsgToPacket) can route through
	// mad.Error / mad.encryptedPktCh / mad.ResponseMsgCh and Destroy
	// the pool packet. Lifecycle is the caller's.
	if md.HubLSTCookieProof != nil {
		if d.deviceType != NHP_AGENT || md.HeaderType != NHP_LST || md.Compress || md.PrevParserData != nil || md.ExternalCookie != nil {
			return &MsgAssemblerData{device: d, HeaderType: md.HeaderType}, ErrInvalidHubLSTCookieProof
		}
	}
	if md.ExternalPacket != nil {
		if err = md.ExternalPacket.validateWritableCapacity(); err != nil {
			return &MsgAssemblerData{
				device:         d,
				BasePacket:     md.ExternalPacket,
				HeaderType:     md.HeaderType,
				encryptedPktCh: md.EncryptedPktCh,
				ResponseMsgCh:  md.ResponseMsgCh,
			}, err
		}
		if len(md.ExternalPacket.writableBuffer()) > PacketBufferSize {
			forwardEnvelope := d.deviceType == NHP_RELAY && md.HeaderType == NHP_RLY && md.PrevParserData == nil
			returnEnvelope := d.deviceType == NHP_SERVER && md.HeaderType == NHP_ACK &&
				md.PrevParserData != nil && md.PrevParserData.HeaderType == NHP_RLY
			if !forwardEnvelope && !returnEnvelope {
				return &MsgAssemblerData{
					device:         d,
					BasePacket:     md.ExternalPacket,
					HeaderType:     md.HeaderType,
					encryptedPktCh: md.EncryptedPktCh,
					ResponseMsgCh:  md.ResponseMsgCh,
				}, ErrPacketSizeExceedsBuffer
			}
		}
	}
	if md.PrevParserData != nil {
		// continue from previous received packet to form one transaction
		mad = md.PrevParserData.deriveMsgAssemblerData(md.HeaderType, md.Compress, md.Message, md.ExternalPacket)
	} else {
		mad = &MsgAssemblerData{}
		mad.device = d
		mad.CipherScheme = md.CipherScheme
		mad.HeaderType = md.HeaderType
		mad.RemotePubKey = md.PeerPk
		mad.BodyCompress = md.Compress
		mad.bodyMessage = md.Message
		mad.TransactionId = md.TransactionId
		mad.connData = md.ConnData

		// init packet buffer
		if md.ExternalPacket != nil {
			mad.BasePacket = md.ExternalPacket
		} else {
			mad.BasePacket = d.AllocatePoolPacket()
		}
		mad.BasePacket.HeaderType = mad.HeaderType
		if md.RemoteAddr != nil {
			mad.BasePacket.SendTo = md.RemoteAddr.AddrPort()
		}

		// init cookie if specified
		if md.ExternalCookie != nil {
			mad.ExternalCookie = md.ExternalCookie
		}
		if md.HubLSTCookieProof != nil {
			copy(mad.HubLSTCookieProof[:], md.HubLSTCookieProof[:])
			mad.hasHubLSTCookieProof = true
		}

		// create header and init device ecdh
		if !suppressDiagnostics {
			log.Debug("start encryption using CIPHER_SCHEME_CURVE")
		}
		mad.header = mad.BasePacket.HeaderWithCipherScheme(mad.CipherScheme)
		mad.ciphers = NewCipherSuite()
		mad.deviceEcdh = d.GetEcdhByCipherScheme(mad.CipherScheme)

		// init version
		mad.header.SetVersion(ProtocolVersionMajor, ProtocolVersionMinor)

		// init header counter
		mad.header.SetCounter(mad.TransactionId)
	}

	// Populate caller channels before the first fallible call below
	// so the err defer in device.go msgToPacketRoutine can deliver
	// the err. Pre-fix with-prev callers skipped this assignment;
	// all current with-prev callers leave both fields nil so the
	// unconditional copy is a no-op today, but a future with-prev
	// caller setting EncryptedPktCh will divert the encrypted packet
	// away from connData.ForwardOutboundPacket.
	mad.encryptedPktCh = md.EncryptedPktCh
	mad.ResponseMsgCh = md.ResponseMsgCh
	mad.suppressDiagnostics = suppressDiagnostics

	// init chain hash -> ChainHash0
	// Always reset per packet; intermediate chain-key carry-over was
	// removed (Go-Go agreed on zeros, JS-Go did not). Ported from
	// OpenNHP commit 03619015e. Invariant: this block runs for both
	// branches above — derivePacketParserData deliberately leaves
	// chain state alone, relying on this re-init.
	mad.chainHash, err = NewHash(mad.ciphers.HashType)
	if err != nil {
		err = fmt.Errorf("failed to create chain hash: %w", err)
		return
	}
	mad.chainHash.Write(initialHashBytes)

	// init chain key -> ChainKey0
	mad.noise.HashType = mad.ciphers.HashType
	mad.noise.MixKey(&mad.chainKey, mad.chainHash.Sum(mad.hashBuf[:0]), initialChainKeyBytes)

	// init timestamp
	mad.LocalInitTime = time.Now().UnixNano()

	// init header digest hash -> DigestHash0
	mad.digestHash, err = NewHash(mad.ciphers.HashType)
	if err != nil {
		err = fmt.Errorf("failed to create header digest hash: %w", err)
		return
	}
	mad.digestHash.Write(initialHashBytes)

	// create ephermeral key
	ephermalEccType := mad.ciphers.EccType
	mad.ephermeralEcdh, err = NewECDH(ephermalEccType)
	if err != nil {
		err = fmt.Errorf("failed to create ephemeral ECDH key: %w", err)
		return
	}
	copy(mad.header.EphermeralBytes(), mad.ephermeralEcdh.PublicKey())

	return mad, nil
}

func (mad *MsgAssemblerData) derivePacketParserData(pkt *Packet, initTime int64) (ppd *PacketParserData) {
	ppd = &PacketParserData{}
	ppd.device = mad.device
	ppd.basePacket = pkt
	ppd.CipherScheme = mad.CipherScheme
	ppd.ConnData = mad.connData
	ppd.ReceivedFrom = pkt.ReceivedFrom
	ppd.LocalInitTime = initTime
	ppd.feedbackMsgCh = mad.ResponseMsgCh

	// init header and init device ecdh
	ppd.HeaderFlag = ppd.basePacket.Flag()
	ppd.header = ppd.basePacket.HeaderWithCipherScheme(ppd.CipherScheme)
	ppd.Ciphers = NewCipherSuite()
	ppd.deviceEcdh = ppd.device.GetEcdhByCipherScheme(ppd.CipherScheme)

	// chain hash/key are reinitialized per packet by
	// responder.go createPacketParserData (OpenNHP 03619015e).

	return ppd
}

func (d *Device) createKeepalivePacket(md *MsgData) (mad *MsgAssemblerData, err error) {
	mad = &MsgAssemblerData{}
	mad.device = d
	mad.HeaderType = NHP_KPL
	mad.TransactionId = md.TransactionId
	mad.connData = md.ConnData
	// Keepalive callers are normally fire-and-forget. Preserve both optional
	// completion channels so an asynchronous caller that explicitly waits for
	// assembly receives either the packet or an error instead of hanging.
	mad.encryptedPktCh = md.EncryptedPktCh
	mad.ResponseMsgCh = md.ResponseMsgCh

	// init packet buffer
	if md.ExternalPacket != nil {
		mad.BasePacket = md.ExternalPacket
	} else {
		mad.BasePacket = d.AllocatePoolPacket()
	}
	mad.BasePacket.HeaderType = NHP_KPL
	if err = mad.BasePacket.validateWritableCapacity(); err != nil {
		return mad, err
	}
	if len(mad.BasePacket.writableBuffer()) > PacketBufferSize {
		return mad, ErrPacketSizeExceedsBuffer
	}

	// create header
	mad.header = mad.BasePacket.HeaderWithCipherScheme(common.CIPHER_SCHEME_CURVE)
	buf := mad.BasePacket.writableBuffer()
	mad.BasePacket.Content = buf[:mad.header.Size()]

	// init version
	mad.header.SetVersion(ProtocolVersionMajor, ProtocolVersionMinor)

	// init header counter
	mad.header.SetCounter(mad.TransactionId)

	// set header type and payload size
	mad.header.SetTypeAndPayloadSize(mad.HeaderType, 0)

	return mad, nil
}

func (mad *MsgAssemblerData) setPeerPublicKey(peerPk []byte) (err error) {
	// override peer public key
	if peerPk != nil {
		mad.RemotePubKey = peerPk
	}

	if mad.RemotePubKey == nil {
		log.Error("remote peer public key is not set")
		err = ErrEmptyPeerPublicKey
		return err
	}

	if !mad.suppressDiagnostics {
		log.Debug("setPeerPublicKey: checking key length: RemotePubKey len=%d, PublicKeySize=%d",
			len(mad.RemotePubKey), PublicKeySize)
	}
	if len(mad.RemotePubKey) != PublicKeySize {
		log.Error("remote peer public key length mismatch: got %d bytes, expected %d, key=%x",
			len(mad.RemotePubKey), PublicKeySize, mad.RemotePubKey)
		err = ErrDeviceECDHPeerFailed
		return err
	}

	// evolve header digest hash DigestHash0 -> DigestHash1
	mad.digestHash.Write(mad.RemotePubKey)

	// evolve chain hash ChainHash0 -> ChainHash1
	mad.chainHash.Write(mad.RemotePubKey)
	mad.chainHash.Write(mad.ephermeralEcdh.PublicKey())

	// evolve chain key ChainKey0 -> ChainKey1
	mad.noise.MixKey(&mad.chainKey, mad.chainKey[:], mad.ephermeralEcdh.PublicKey())

	// init ephermeral shared key
	ess := mad.ephermeralEcdh.SharedSecret(mad.RemotePubKey)
	if ess == nil {
		log.Error("ephermal ECDH failed with peer")
		err = ErrEphermalECDHPeerFailed
		return err
	}

	// prepare key for aead
	var key [SymmetricKeySize]byte

	// generate gcm key and encrypt device pubkey ChainKey1 -> ChainKey2
	mad.noise.KeyGen2(&mad.chainKey, &key, mad.chainKey[:], ess[:])
	SetZero(ess[:])

	// encrypt initiator's public key and evolve chainhash with the ciphertext
	aead, err := AeadFromKey(mad.ciphers.GcmType, &key)
	if err != nil {
		return fmt.Errorf("failed to create AEAD for static encryption: %w", err)
	}
	static := aead.Seal(mad.header.StaticBytes()[:0], mad.header.NonceBytes(), mad.deviceEcdh.PublicKey(), mad.chainHash.Sum(mad.hashBuf[:0]))

	//log.Debug("encrypted pubkey: %v, output: %v", mad.deviceEcdh.PublicKey(), static)

	// evolve chainhash ChainHash1 -> ChainHash2
	mad.chainHash.Write(static)

	// init shared key
	ss := mad.deviceEcdh.SharedSecret(mad.RemotePubKey)
	if ss == nil {
		log.Error("device ECDH failed with peer")
		err = ErrDeviceECDHPeerFailed
		return err
	}

	// generate gcm key and encrypt timestamp ChainKey2 -> ChainKey3
	mad.noise.KeyGen2(&mad.chainKey, &key, mad.chainKey[:], ss[:])
	SetZero(ss[:])

	var tsBytes [TimestampSize]byte
	binary.BigEndian.PutUint64(tsBytes[:], uint64(mad.LocalInitTime))
	aead, err = AeadFromKey(mad.ciphers.GcmType, &key)
	if err != nil {
		return fmt.Errorf("failed to create AEAD for timestamp encryption: %w", err)
	}
	ts := aead.Seal(mad.header.TimestampBytes()[:0], mad.header.NonceBytes(), tsBytes[:], mad.chainHash.Sum(mad.hashBuf[:0]))

	// evolve chainhash ChainHash2 -> ChainHash3
	mad.chainHash.Write(ts)

	// generate gcm key for body encryption ChainKey3 -> ChainKey4
	mad.noise.KeyGen2(&mad.chainKey, &key, mad.chainKey[:], ts[:])
	mad.bodyAead, err = AeadFromKey(mad.ciphers.GcmType, &key)
	if err != nil {
		return fmt.Errorf("failed to create AEAD for body encryption: %w", err)
	}

	return nil
}

func (mad *MsgAssemblerData) encryptBody() (err error) {
	defer func() {
		// clear secrets
		mad.chainHash.Reset()
		mad.chainHash = nil
		SetZero(mad.chainKey[:])
		SetZero(mad.hashBuf[:])
	}()

	if mad.hasHubLSTCookieProof {
		mad.HeaderFlag = common.NHP_FLAG_HUB_LST_COOKIE_PROOF
	}
	// Set flags before the empty-body branch so the proof contract is not
	// accidentally bypassed by an empty caller-owned message.
	mad.header.SetFlag(mad.HeaderFlag)

	// message body is empty, skip encryption. Set header and compute the header digest
	//
	// Residual gap, deliberate: with no body there is no AEAD operation left to
	// carry the HeaderCommon AAD folded below, so an empty-body packet's header
	// stays covered only by the unkeyed digest. It is contained rather than
	// exploitable — the COMPRESS branch below requires a non-empty body so the
	// decode-side compress bit is inert, the type is confined by the receiver's
	// CheckRecvHeaderType allowlist, and the counter is bound as the GCM nonce.
	// Closing it needs a header-only AEAD (a second tag on the wire), which is a
	// separate framing change; do not "fix" it by sealing a synthetic body.
	//
	// The version field is in that same unauthenticated span, so the receiver's
	// version gate is NOT a security control for these packets: anyone holding
	// the responder's static PUBLIC key can set any admitted version and
	// re-stamp the digest. Containment is the type allowlist and the nonce
	// binding above, nothing else. TestDecryptBody_EmptyBodyHeaderIsNotAADBound
	// pins that residual; when the header-only AEAD lands, that test is the one
	// that must change.
	if len(mad.bodyMessage) == 0 {
		// set header type and payload size
		mad.header.SetTypeAndPayloadSize(mad.HeaderType, 0)
		// set header digest
		mad.addHeaderDigest(mad.HeaderType == NHP_RKN)
		buf := mad.BasePacket.writableBuffer()
		mad.BasePacket.Content = buf[:mad.header.Size()]
		return nil
	}

	var body []byte

	if mad.BodyCompress {
		buf := getBytesBuffer()
		defer putBytesBuffer(buf)
		w := getZlibWriter(buf)
		// Defer order matters: LIFO unwinds putZlibWriter first, which
		// calls Reset(io.Discard) and detaches the writer from buf
		// before putBytesBuffer scrubs buf's backing array. Swapping
		// the two defers would leave the pooled writer briefly
		// pointing at a zeroed caller buffer.
		defer putZlibWriter(w)

		_, err = w.Write(mad.bodyMessage)
		if cerr := w.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			log.Critical("message compression failed: %v", err)
			return ErrDataCompressionFailed.WithExtra(err)
		}
		// No bytes.Clone needed here: body aliases pool storage, but
		// bodyAead.Seal below consumes it synchronously and does not
		// retain a reference. The deferred putBytesBuffer runs only
		// after Seal finishes, so the aliasing is safe.
		body = buf.Bytes()
		mad.BodySize = len(body) + GCMTagSize

		// set header flag
		mad.HeaderFlag |= common.NHP_FLAG_COMPRESS

	} else {
		// no compress
		body = mad.bodyMessage
		mad.BodySize = len(mad.bodyMessage) + GCMTagSize
	}
	// Compression is decided above, after the early empty-body flag write.
	// Commit the final flag set before hashing the serialized header.
	mad.header.SetFlag(mad.HeaderFlag)

	packetBuf := mad.BasePacket.writableBuffer()
	if mad.BodySize > len(packetBuf)-mad.header.Size() {
		log.Critical("message too long, send buffer exceeded")
		err = ErrPacketSizeExceedsBuffer
		return err
	}

	// calculate total data length
	packetLen := mad.header.Size() + mad.BodySize

	// set header type and payload size
	mad.header.SetTypeAndPayloadSize(mad.HeaderType, mad.BodySize)

	// set header digest
	mad.addHeaderDigest(mad.HeaderType == NHP_RKN)

	// evolve chainhash ChainHash3 -> ChainHash4: authenticate the finalized
	// HeaderCommon under the body tag. This is the earliest AEAD that can cover
	// it — the flag word and payload size are only known after compression, which
	// runs after the static and timestamp seals — and the responder folds the
	// same 24 bytes as received, so any in-flight edit to preamble, type, payload
	// size, version, flags or counter breaks the body Open.
	mad.chainHash.Write(mad.header.Bytes()[:HeaderCommonSize])

	// encrypt body and write into the packet's writable buffer
	mad.bodyAead.Seal(packetBuf[mad.header.Size():mad.header.Size()], mad.header.NonceBytes(), body, mad.chainHash.Sum(mad.hashBuf[:0]))

	// set valid packet
	mad.BasePacket.Content = packetBuf[:packetLen]

	return nil
}

// must be called after header is filled.
// Computes the unkeyed header digest (see curve.HeaderCurve.HeaderDigest);
// not an authenticator.
func (mad *MsgAssemblerData) addHeaderDigest(sumCookie bool) {
	defer func() {
		mad.digestHash.Reset()
		mad.digestHash = nil
	}()

	prefixLen := mad.header.Size() - HashSize
	mad.digestHash.Write(mad.header.Bytes()[0:prefixLen])

	if sumCookie {
		// use specified cookie, otherwise use connection's cookie
		if mad.ExternalCookie != nil {
			mad.digestHash.Write((*mad.ExternalCookie)[:])
		} else {
			mad.connData.Lock()
			mad.digestHash.Write(mad.connData.CookieStore.CurrCookie[:])
			mad.connData.Unlock()
		}
	} else if mad.hasHubLSTCookieProof {
		mad.digestHash.Write(mad.HubLSTCookieProof[:])
	}
	mad.digestHash.Sum(mad.header.HeaderDigestBytes()[:0])
}

func (mad *MsgAssemblerData) Destroy() {
	mad.device.ReleasePoolPacket(mad.BasePacket)
	if mad.digestHash != nil {
		mad.digestHash.Reset()
		mad.digestHash = nil
	}
	if mad.chainHash != nil {
		mad.chainHash.Reset()
		mad.chainHash = nil
	}
	// Defense-in-depth: clear scratch even though hash digests are not key material.
	SetZero(mad.hashBuf[:])
	SetZero(mad.HubLSTCookieProof[:])
}

// ConsumeEncryptedPacket takes ownership of every non-nil assembler result
// delivered through EncryptedPktCh, including error results. The channel
// transfers packet lifecycle to its caller, so Destroy runs before every return
// and the successful wire bytes are cloned before the pooled packet is released.
func ConsumeEncryptedPacket(mad *MsgAssemblerData) ([]byte, error) {
	if mad == nil {
		return nil, errors.New("encryption returned no assembler data")
	}
	// An async error result may already have been destroyed by the assembler
	// routine before it is delivered. Destroy is intentionally idempotent (the
	// packet release clears its pool-ownership fields), so retaining this defer
	// gives every consumer path the same ownership rule without a double Put.
	defer mad.Destroy()
	if mad.Error != nil {
		return nil, mad.Error
	}
	if mad.BasePacket == nil {
		return nil, errors.New("encryption returned no packet")
	}
	return bytes.Clone(mad.BasePacket.Content), nil
}
