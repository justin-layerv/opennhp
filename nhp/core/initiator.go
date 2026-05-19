package core

import (
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

type InitiatorScheme interface {
	CreateMsgAssemblerData(d *Device, md *MsgData) (mad *MsgAssemblerData, err error)
	DeriveMsgAssemblerDataFromPrevParserData(ppd *PacketParserData, t int, message []byte) (mad *MsgAssemblerData)
	SetPeerPublicKey(d *Device, mad *MsgAssemblerData, peerPk []byte) (err error)
	EncryptBody(d *Device, mad *MsgAssemblerData) (err error)
}

type MsgData struct {
	RemoteAddr     *net.UDPAddr      // used by agent and ac create a new connection or pick an existing connection for msg sending
	ConnData       *ConnectionData   // used by server to pick an existing connection for msg sending
	PrevParserData *PacketParserData // when PrevParserData is set, CipherScheme, RemoteAddr, ConnData, TransactionId and PeerPk will be overridden
	CipherScheme   int               // 0: curve25519/chacha20/blake2s
	TransactionId  uint64
	HeaderType     int
	Compress       bool
	ExternalPacket *Packet
	ExternalCookie *[CookieSize]byte
	Message        []byte
	PeerPk         []byte
	EncryptedPktCh chan *MsgAssemblerData
	ResponseMsgCh  chan *PacketParserData
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
	hmacHash       hash.Hash
	chainHash      hash.Hash
	bodyAead       cipher.AEAD
	chainKey       [SymmetricKeySize]byte

	LocalInitTime int64
	TransactionId uint64
	noise         NoiseFactory // int
	CipherScheme  int
	HeaderType    int
	BodySize      int
	HeaderFlag    uint16
	BodyCompress  bool

	ExternalCookie *[CookieSize]byte
	RemotePubKey   []byte
	bodyMessage    []byte

	encryptedPktCh chan<- *MsgAssemblerData
	ResponseMsgCh  chan<- *PacketParserData
	Error          error
}

func (d *Device) createMsgAssemblerData(md *MsgData) (mad *MsgAssemblerData, err error) {
	log.Debug("createMsgAssemblerData: PeerPk len=%d, CipherScheme=%d, HeaderType=%d",
		len(md.PeerPk), md.CipherScheme, md.HeaderType)
	// Returns a non-nil mad even on err so the callers' err defers
	// (device.go msgToPacketRoutine, MsgToPacket) can route through
	// mad.Error / mad.encryptedPktCh / mad.ResponseMsgCh and Destroy
	// the pool packet. Lifecycle is the caller's.
	if md.PrevParserData != nil {
		// continue from previous received packet to form one transaction
		mad = md.PrevParserData.deriveMsgAssemblerData(md.HeaderType, md.Compress, md.Message)
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

		// init cookie if specified
		if md.ExternalCookie != nil {
			mad.ExternalCookie = md.ExternalCookie
		}

		// create header and init device ecdh
		log.Info("start encryption using CIPHER_SCHEME_CURVE")
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
	mad.noise.MixKey(&mad.chainKey, mad.chainHash.Sum(nil), initialChainKeyBytes)

	// init timestamp
	mad.LocalInitTime = time.Now().UnixNano()

	// init hmac hash -> HmacHash0
	mad.hmacHash, err = NewHash(mad.ciphers.HashType)
	if err != nil {
		err = fmt.Errorf("failed to create hmac hash: %w", err)
		return
	}
	mad.hmacHash.Write(initialHashBytes)

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

	// init packet buffer
	if md.ExternalPacket != nil {
		mad.BasePacket = md.ExternalPacket
	} else {
		mad.BasePacket = d.AllocatePoolPacket()
	}
	mad.BasePacket.HeaderType = NHP_KPL

	// create header
	mad.header = mad.BasePacket.HeaderWithCipherScheme(common.CIPHER_SCHEME_CURVE)
	mad.BasePacket.Content = mad.BasePacket.Buf[:mad.header.Size()]

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

	log.Debug("setPeerPublicKey: checking key length: RemotePubKey len=%d, PublicKeySize=%d",
		len(mad.RemotePubKey), PublicKeySize)
	if len(mad.RemotePubKey) != PublicKeySize {
		log.Error("remote peer public key length mismatch: got %d bytes, expected %d, key=%x",
			len(mad.RemotePubKey), PublicKeySize, mad.RemotePubKey)
		err = ErrDeviceECDHPeerFailed
		return err
	}

	// evolve hmac hash HmacHash0 -> HmacHash1
	mad.hmacHash.Write(mad.RemotePubKey)

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
	static := aead.Seal(mad.header.StaticBytes()[:0], mad.header.NonceBytes(), mad.deviceEcdh.PublicKey(), mad.chainHash.Sum(nil))

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
	ts := aead.Seal(mad.header.TimestampBytes()[:0], mad.header.NonceBytes(), tsBytes[:], mad.chainHash.Sum(nil))

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
	}()

	// message body is empty, skip encryption. Set header and calculate HMAC
	if len(mad.bodyMessage) == 0 {
		// set header type and payload size
		mad.header.SetTypeAndPayloadSize(mad.HeaderType, 0)
		// set HMAC
		mad.addHMAC(mad.HeaderType == NHP_RKN)
		mad.BasePacket.Content = mad.BasePacket.Buf[:mad.header.Size()]
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

	if mad.BodySize > PacketBufferSize-mad.header.Size() {
		log.Critical("message too long, send buffer exceeded")
		err = ErrPacketSizeExceedsBuffer
		return err
	}

	// set header flag
	mad.header.SetFlag(mad.HeaderFlag)

	// calculate total data length
	packetLen := mad.header.Size() + mad.BodySize

	// set header type and payload size
	mad.header.SetTypeAndPayloadSize(mad.HeaderType, mad.BodySize)

	// set HMAC
	mad.addHMAC(mad.HeaderType == NHP_RKN)

	// encrypt body and write into mad.BasePacket.Buf space
	ciphertext := mad.bodyAead.Seal(mad.BasePacket.Buf[mad.header.Size():mad.header.Size()], mad.header.NonceBytes(), body, mad.chainHash.Sum(nil))
	_ = ciphertext
	//log.Debug("encrypted body: %v, output: %v", body, ciphertext)

	// set valid packet
	mad.BasePacket.Content = mad.BasePacket.Buf[:packetLen]

	return nil
}

// must be called after header is filled
func (mad *MsgAssemblerData) addHMAC(sumCookie bool) {
	defer func() {
		mad.hmacHash.Reset()
		mad.hmacHash = nil
	}()

	len := mad.header.Size() - HashSize
	mad.hmacHash.Write(mad.header.Bytes()[0:len])

	if sumCookie {
		// use specified cookie, otherwise use connection's cookie
		if mad.ExternalCookie != nil {
			mad.hmacHash.Write((*mad.ExternalCookie)[:])
		} else {
			mad.connData.Lock()
			mad.hmacHash.Write(mad.connData.CookieStore.CurrCookie[:])
			mad.connData.Unlock()
		}
	}
	mad.hmacHash.Sum(mad.header.HMACBytes()[:0])
}

func (mad *MsgAssemblerData) Destroy() {
	mad.device.ReleasePoolPacket(mad.BasePacket)
	if mad.hmacHash != nil {
		mad.hmacHash.Reset()
		mad.hmacHash = nil
	}
	if mad.chainHash != nil {
		mad.chainHash.Reset()
		mad.chainHash = nil
	}
}
