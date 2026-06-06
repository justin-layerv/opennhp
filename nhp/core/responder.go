package core

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"slices"
	"sync/atomic"
	"time"

	common "github.com/OpenNHP/opennhp/nhp/common"
	log "github.com/OpenNHP/opennhp/nhp/log"
)

type ResponderScheme interface {
	CreatePacketParserData(d *Device, pd *PacketData) (ppd *PacketParserData, err error)
	DerivePacketParserDataFromPrevAssemblerData(mad *MsgAssemblerData, pkt *Packet, initTime int64) (ppd *PacketParserData)
	validatePeer(d *Device, ppd *PacketParserData) (err error)
	decryptBody(d *Device, ppd *PacketParserData) (err error)
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
	device       *Device
	basePacket   *Packet
	ConnData     *ConnectionData
	CipherScheme int
	Ciphers      *CipherSuite

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
	// after the timestamp passes the staleness floor and the
	// per-connection LastRemoteSendTime gate. Downstream handlers
	// (e.g., AC AOP dedupe in endpoints/ac/aop_replay_cache.go) use
	// it to distinguish a captured-and-replayed packet (same
	// timestamp) from a fresh post-restart packet that happens to
	// reuse the sender's in-memory counter (different timestamp).
	// Zero value means "not populated" (e.g., AEAD failed before the
	// timestamp gate); callers that key on it must not invoke before
	// AEAD verification has succeeded.
	RemoteSendTime int64

	noise        NoiseFactory // int
	HeaderType   int
	BodySize     int
	HeaderFlag   uint16
	BodyCompress bool
	Overload     bool

	SenderIdentity         []byte
	SenderMidPublicKey     []byte
	ConnLastRemoteSendTime *int64
	ConnCookieStore        *CookieStore
	ConnPeerPublicKey      *[PublicKeySizeEx]byte
	RemotePubKey           []byte
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
		ppd.ConnCookieStore = pd.ConnCookieStore
		ppd.LocalInitTime = pd.InitTime
		ppd.ConnLastRemoteSendTime = pd.ConnLastRemoteSendTime
		ppd.ConnPeerPublicKey = pd.ConnPeerPublicKey

		// init header and init device ecdh
		ppd.HeaderFlag = ppd.basePacket.Flag()
		ppd.header = ppd.basePacket.Header()
		ppd.CipherScheme = ppd.header.CipherScheme()
		log.Info("start decryption using CIPHER_SCHEME_CURVE")
		ppd.Ciphers = NewCipherSuite()
		ppd.deviceEcdh = d.GetEcdhByCipherScheme(ppd.CipherScheme)
	}

	// Populate caller channel before the first fallible call below so
	// the err defer in device.go packetToMsgRoutine can deliver the
	// err. One place rather than per-branch.
	ppd.decryptedMsgCh = pd.DecryptedMsgCh

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
				log.Critical("discard packet type %d due to overload", ppd.HeaderType)
				err = ErrServerOverload
				return
			}
		}

		// for RKN, check the header digest with cookie. For remaining allowed key messages, check it without cookie.
		sumCookie := overload && ppd.HeaderType == NHP_RKN
		if !ppd.checkHeaderDigest(sumCookie) {
			// "HMAC" string kept deliberately (#1126): operator-facing log
			// breadcrumb, matches the preserved ErrServer... message + terraform.
			log.Error("HMAC validation failed on server side. sumCookie: %v", sumCookie)
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

func (ppd *PacketParserData) deriveMsgAssemblerData(t int, compress bool, message []byte) (mad *MsgAssemblerData) {
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
	mad.BasePacket = mad.device.AllocatePoolPacket()
	mad.BasePacket.HeaderType = t

	// create header and init device ecdh
	mad.header = mad.BasePacket.HeaderWithCipherScheme(mad.CipherScheme)
	mad.deviceEcdh = mad.device.GetEcdhByCipherScheme(mad.CipherScheme)

	// continue with the sender's counter
	mad.header.SetCounter(ppd.SenderTrxId)

	// chain hash/key are reinitialized per packet by
	// initiator.go createMsgAssemblerData (OpenNHP 03619015e).

	return mad
}

// shouldCheckRecvAttack gates the per-connection
// LastRemoteSendTime *replay* check (timestamp regression). Split
// from shouldCheckFlood (#1123 round-7) so a peer-msgType pair can
// participate in the replay gate without also being subject to the
// 20 ms flood interval — see shouldCheckFlood for why AOP needs
// that asymmetry.
//
// NHP_ART (AC → server) remains exempt because the server's
// transaction layer already correlates responses by TransactionId
// and the AC→server hop occasionally exceeds the flood-gate
// threshold (MinimalRecvIntervalMs in nhp/core/constants.go) under
// legitimate latency. Symmetric dedupe is tracked in #1457.
//
// NHP_AOP (server → AC) was previously exempt; #1123 removed it so
// in-connection replays are caught here. The cross-connection cousin
// (server restart / AC failover / NAT flush) lives in
// endpoints/ac/aop_replay_cache.go.
//
// AOP-specific trade-off — the strict less-than comparison at the
// replay site means a UDP reorder of two µs-spaced AOPs from the
// same server arrives with the earlier-stamped one rejected as a
// "replay" by this gate. In sandbox/prod (single-VPC, NLB)
// reordering is rare so this is tolerable; #1463 (deployed-binary
// smoke) and any future #1458 (duplicate-drop counter) work should
// keep an eye on the AOP-drop rate to catch any reorder pattern
// that turns this into an availability issue. ART (#1457) will
// face the symmetric concern when its own dedupe lands.
func shouldCheckRecvAttack(deviceType int, peerType int, msgType int) bool {
	if deviceType == NHP_SERVER && peerType == NHP_AC && msgType == NHP_ART {
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
// NHP_ART (AC → server) keeps the same exemption it has from the
// replay gate — same legitimate-latency rationale.
func shouldCheckFlood(deviceType int, peerType int, msgType int) bool {
	if deviceType == NHP_AC && peerType == NHP_SERVER && msgType == NHP_AOP {
		return false
	}
	if deviceType == NHP_SERVER && peerType == NHP_AC && msgType == NHP_ART {
		return false
	}
	return true
}

func (ppd *PacketParserData) validatePeer() (err error) {
	// evolve chain hash ChainHash0 -> ChainHash1
	ppd.chainHash.Write(ppd.deviceEcdh.PublicKey())
	ppd.chainHash.Write(ppd.header.EphermeralBytes())

	// evolve chain key ChainKey0 -> ChainKey1
	ppd.noise.MixKey(&ppd.chainKey, ppd.chainKey[:], ppd.header.EphermeralBytes())
	// get ephermeral shared key
	ess := ppd.deviceEcdh.SharedSecret(ppd.header.EphermeralBytes())
	if ess == nil {
		log.Error("device ECDH failed with ephermal")
		err = ErrDeviceECDHEphermalFailed
		return err
	}

	// prepare key for aead
	var key [SymmetricKeySize]byte
	var aead cipher.AEAD

	// generate gcm key and decrypt device pubkey ChainKey1 -> ChainKey2
	ppd.noise.KeyGen2(&ppd.chainKey, &key, ppd.chainKey[:], ess[:])
	SetZero(ess[:])
	peerPk := ppd.remotePubKeyBuf[:]
	aead, err = AeadFromKey(ppd.Ciphers.GcmType, &key)
	if err != nil {
		log.Error("failed to create AEAD for peer pubkey decryption: %v", err)
		return err
	}
	_, err = aead.Open(peerPk[:0], ppd.header.NonceBytes(), ppd.header.StaticBytes(), ppd.chainHash.Sum(ppd.hashBuf[:0]))
	if err != nil {
		log.Error("failed to decrypt peer pubkey")
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
	switch peerDeviceType {
	case NHP_AGENT:
		toValidate = !option.DisableAgentPeerValidation

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

	ppd.RemotePubKey = peerPk
	if ppd.ConnPeerPublicKey != nil {
		copy((*ppd.ConnPeerPublicKey)[:], peerPk)
	}

	// evolve chainhash ChainHash1 -> ChainHash2
	ppd.chainHash.Write(ppd.header.StaticBytes())

	// init shared key
	ss := ppd.deviceEcdh.SharedSecret(peerPk)
	if ss == nil {
		log.Error("device ECDH failed with obtained peer")
		err = ErrDeviceECDHObtainedPeerFailed
		return err
	}

	// generate gcm key and decrypt timestamp ChainKey2 -> ChainKey3
	ppd.noise.KeyGen2(&ppd.chainKey, &key, ppd.chainKey[:], ss[:])
	SetZero(ss[:])

	var tsBytes [TimestampSize]byte
	aead, err = AeadFromKey(ppd.Ciphers.GcmType, &key)
	if err != nil {
		log.Error("failed to create AEAD for timestamp decryption: %v", err)
		return err
	}
	_, err = aead.Open(tsBytes[:0], ppd.header.NonceBytes(), ppd.header.TimestampBytes(), ppd.chainHash.Sum(ppd.hashBuf[:0]))
	if err != nil {
		log.Error("failed to decrypt timestamp")
		return err
	}

	remoteSendTime := int64(binary.BigEndian.Uint64(tsBytes[:]))

	if shouldCheckRecvAttack(ppd.device.deviceType, peerDeviceType, ppd.HeaderType) {
		// block remote if threat level is reached
		if remoteSendTime < ppd.ConnData.LastRemoteSendTime {
			// replay packet, drop
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
			err = ErrReplayPacketReceived
			return err
		}
	}
	if shouldCheckFlood(ppd.device.deviceType, peerDeviceType, ppd.HeaderType) {
		if remoteSendTime < ppd.ConnData.LastRemoteSendTime+MinimalRecvIntervalMs*int64(time.Millisecond) {
			// flood packet, drop
			log.Critical("received flood packet from %s, drop packet", ppd.ConnData.RemoteAddr.String())
			// threat plus 1
			threat := atomic.AddInt32(&ppd.ConnData.RecvThreatCount, 1)
			if threat > ThreatCountBeforeBlock && !ppd.ConnData.IsClosed() {
				// clamp threat count to avoid overflow
				atomic.StoreInt32(&ppd.ConnData.RecvThreatCount, ThreatCountBeforeBlock)
				// block source address
				ppd.ConnData.SendBlockSignal()
			}
			err = ErrFloodPacketReceived
			return err
		}
	}
	if remoteSendTime < (ppd.LocalInitTime - 600*int64(time.Second)) {
		// send remote timestamp is too old than receive local time, drop
		// note there might be time calibration error between remote and local devices
		log.Critical("received stale packet from %s, drop packet", ppd.ConnData.RemoteAddr.String())
		threat := atomic.AddInt32(&ppd.ConnData.RecvThreatCount, 1)
		if threat > ThreatCountBeforeBlock && !ppd.ConnData.IsClosed() {
			// clamp threat count to avoid overflow
			atomic.StoreInt32(&ppd.ConnData.RecvThreatCount, ThreatCountBeforeBlock)
			// block source address
			ppd.ConnData.SendBlockSignal()
		}
		err = ErrStalePacketReceived
		return err
	}

	// update remote last send time
	atomic.StoreInt64(&ppd.ConnData.LastRemoteSendTime, remoteSendTime)
	// Surface the AEAD-authenticated per-packet timestamp to
	// downstream handlers — set here (not inside the
	// shouldCheckRecvAttack branch) so the AC AOP dedupe and any
	// future ART consumer get a populated value on every accepted
	// packet, including the ART/AOP exemption paths.
	//
	// Cross-package contract: the AC AOP replay cache in
	// endpoints/ac/aop_replay_cache.go keys on this field. A
	// refactor that moves or skips this assignment silently
	// degrades the AC dedupe to (pubkey, txid, 0) keying — the
	// post-restart counter-collision regression test in
	// aop_replay_cache_test.go fences the cache layer but not the
	// responder wire-up. Issue #1468 tracks an integration-style
	// test that drives a real AOP through validatePeer to fence
	// this assignment end-to-end (a minimal-fixture unit test
	// would require the full noise-handshake context — Device,
	// Peer, ECDH, AEAD chain — which is substantively heavier
	// than this assignment justifies as a unit test). Until #1468
	// lands, the next reviewer of validatePeer must catch any
	// reordering here.
	ppd.RemoteSendTime = remoteSendTime
	// clear threat
	atomic.StoreInt32(&ppd.ConnData.RecvThreatCount, 0)

	// handle knock packet at overload before going into body decryption
	if ppd.device.deviceType == NHP_SERVER && ppd.Overload && (ppd.HeaderType == NHP_KNK || ppd.HeaderType == DHP_KNK) {
		ppd.generateCookie()
		ppd.sendCookie()
		return ErrServerRejectWithCookie
	}

	// evolve chainhash ChainHash2 -> ChainHash3
	ppd.chainHash.Write(ppd.header.TimestampBytes())

	// generate gcm key for body decryption ChainKey3 -> ChainKey4
	ppd.noise.KeyGen2(&ppd.chainKey, &key, ppd.chainKey[:], ppd.header.TimestampBytes())
	ppd.bodyAead, err = AeadFromKey(ppd.Ciphers.GcmType, &key)
	if err != nil {
		log.Error("failed to create AEAD for body decryption: %v", err)
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

	// message body is empty, skip decryption
	if len(ppd.basePacket.Content) == ppd.header.Size() {
		return nil
	}

	// decrypt body and reuse ppd.BasePacket.Content space
	body, err := ppd.bodyAead.Open(ppd.basePacket.Content[ppd.header.Size():ppd.header.Size()], ppd.header.NonceBytes(), ppd.basePacket.Content[ppd.header.Size():], ppd.chainHash.Sum(ppd.hashBuf[:0]))
	if err != nil {
		log.Critical("decrypt body failed: %v", err)
		return ErrAEADDecryptionFailed.WithExtra(err)
	}

	//log.Debug("decrypted body: %v, input: %v", body, ppd.basePacket.Content[ppd.header.Size():])

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
		// on-wire packet is hard-capped at PacketBufferSize, so a single packet
		// can never reach the former 10 MiB ceiling anyway; MaxDecompressedBodySize
		// bounds the per-packet decode an order of magnitude below that while
		// leaving ample headroom over legitimate payloads. See its doc in
		// constants.go for the measured sizing.
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

func (ppd *PacketParserData) sendCookie() {
	cokStr := base64.StdEncoding.EncodeToString(ppd.ConnData.CookieStore.CurrCookie[:])
	cokMsg := &common.ServerCookieMsg{
		TransactionId: ppd.SenderTrxId,
		Cookie:        cokStr,
	}
	cokBytes, err := json.Marshal(cokMsg)
	if err != nil {
		log.Error("sendCookie: failed to marshal cookie message: %v", err)
		return
	}

	md := &MsgData{
		HeaderType:    NHP_COK,
		CipherScheme:  ppd.CipherScheme,
		TransactionId: ppd.device.NextCounterIndex(),
		Compress:      true,
		ConnData:      ppd.ConnData,
		PeerPk:        ppd.RemotePubKey,
		Message:       cokBytes,
	}

	log.Debug("Send cookie back to %s: %s ", ppd.ConnData.RemoteAddr, string(md.Message))
	ppd.device.SendMsgToPacket(md)
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
	ppd.digestHash.Write(ppd.header.Bytes()[0:prefixLen])

	if sumCookie {
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
	case NHP_KNK, DHP_KNK, NHP_RKN, NHP_EXT, NHP_AOL, NHP_ART:
		return true
	default:
		return false
	}
}

// BasePacketContent returns a copy of the original encrypted packet content.
// This is used for server-to-server knock forwarding where the receiving server
// needs to decrypt the original packet using the shared registration keypair.
// Returns nil if the base packet is not available.
func (ppd *PacketParserData) BasePacketContent() []byte {
	if ppd == nil || ppd.basePacket == nil || len(ppd.basePacket.Content) == 0 {
		return nil
	}
	// Return a copy to prevent modification of the original
	return slices.Clone(ppd.basePacket.Content)
}
